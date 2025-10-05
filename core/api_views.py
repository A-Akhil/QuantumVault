"""
Django REST API views for testing quantum-safe file storage backend.
"""

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from django.core.files.uploadedfile import InMemoryUploadedFile
from django.http import HttpResponse
import base64
import json
import logging

from .models import QuantumUser, EncryptedFile, FileAccess, AuditLog
from .crypto_utils import (
    generate_kyber768_keypair,
    generate_dilithium3_keypair,
    aes_encrypt_file,
    aes_decrypt_file,
    wrap_aes_key_for_user,
    unwrap_aes_key_for_user,
    create_file_metadata_for_signature,
    dilithium_sign,
    dilithium_verify,
    validate_quantum_keys,
    QuantumCryptoError
)

logger = logging.getLogger(__name__)


@api_view(['POST'])
@permission_classes([AllowAny])
def api_register(request):
    """
    API endpoint for user registration with quantum key generation.
    
    POST /api/register/
    {
        "username": "testuser",
        "email": "test@example.com",
        "password": "testpass123",
        "first_name": "Test",
        "last_name": "User"
    }
    """
    try:
        data = request.data
        
        # Validate required fields
        required_fields = ['username', 'email', 'password']
        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            return Response({
                'error': f'Missing required fields: {", ".join(missing_fields)}'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if user already exists
        if QuantumUser.objects.filter(username=data['username']).exists():
            return Response({
                'error': 'Username already exists'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if QuantumUser.objects.filter(email=data['email']).exists():
            return Response({
                'error': 'Email already exists'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Generate quantum keys
        logger.info(f"Generating quantum keys for user: {data['email']}")
        kyber_public, kyber_private = generate_kyber768_keypair()
        dilithium_public, dilithium_private = generate_dilithium3_keypair()
        
        # Validate keys
        if not validate_quantum_keys(kyber_public, kyber_private, dilithium_public, dilithium_private):
            raise QuantumCryptoError("Generated keys failed validation")
        
        # Create user
        user = QuantumUser.objects.create_user(
            username=data['username'],
            email=data['email'],
            password=data['password'],
            first_name=data.get('first_name', ''),
            last_name=data.get('last_name', ''),
            kyber_public_key=kyber_public,
            kyber_private_key=kyber_private,
            dilithium_public_key=dilithium_public,
            dilithium_private_key=dilithium_private
        )
        
        # Log registration
        AuditLog.log_action(
            user_email=user.email,
            action='register',
            details={
                'username': user.username,
                'kyber_key_size': len(kyber_public),
                'dilithium_key_size': len(dilithium_public)
            },
            request=request,
            success=True
        )
        
        return Response({
            'message': 'User registered successfully',
            'user_id': user.id,
            'username': user.username,
            'email': user.email,
            'quantum_keys_generated': True,
            'kyber_public_key_size': len(kyber_public),
            'dilithium_public_key_size': len(dilithium_public)
        }, status=status.HTTP_201_CREATED)
        
    except QuantumCryptoError as e:
        logger.error(f"Quantum key generation failed: {e}")
        return Response({
            'error': f'Quantum key generation failed: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    except Exception as e:
        logger.error(f"Registration failed: {e}")
        return Response({
            'error': f'Registration failed: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])
def api_login(request):
    """
    API endpoint for user login.
    
    POST /api/login/
    {
        "username": "testuser",
        "password": "testpass123"
    }
    """
    try:
        username = request.data.get('username')
        password = request.data.get('password')
        
        if not username or not password:
            return Response({
                'error': 'Username and password are required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Authenticate user
        user = authenticate(username=username, password=password)
        if not user:
            # Try with email
            try:
                user_by_email = QuantumUser.objects.get(email=username)
                user = authenticate(username=user_by_email.username, password=password)
            except QuantumUser.DoesNotExist:
                pass
        
        if not user:
            AuditLog.log_action(
                user_email=username,
                action='login',
                details={'error': 'invalid_credentials'},
                request=request,
                success=False,
                error_message='Invalid credentials'
            )
            return Response({
                'error': 'Invalid credentials'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        # Check if user has quantum keys
        if not user.has_quantum_keys():
            return Response({
                'error': 'User missing quantum keys'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Create or get token
        token, created = Token.objects.get_or_create(user=user)
        
        # Log successful login
        AuditLog.log_action(
            user_email=user.email,
            action='login',
            details={'username': user.username},
            request=request,
            success=True
        )
        
        return Response({
            'message': 'Login successful',
            'token': token.key,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'has_quantum_keys': user.has_quantum_keys()
            }
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Login failed: {e}")
        return Response({
            'error': f'Login failed: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def api_upload_file(request):
    """
    API endpoint for file upload with encryption.
    
    POST /api/upload/
    Content-Type: multipart/form-data
    Authorization: Token <token>
    
    Form data:
    - file: file to upload
    - recipients: JSON array of recipient emails
    - description: optional description
    """
    try:
        if 'file' not in request.FILES:
            return Response({
                'error': 'No file provided'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        uploaded_file = request.FILES['file']
        recipients_json = request.data.get('recipients', '[]')
        description = request.data.get('description', '')
        
        try:
            recipients = json.loads(recipients_json)
            if not isinstance(recipients, list):
                raise ValueError("Recipients must be a list")
        except (json.JSONDecodeError, ValueError):
            return Response({
                'error': 'Invalid recipients format. Must be JSON array of emails.'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Validate recipients
        for email in recipients:
            if not QuantumUser.objects.filter(email=email).exists():
                return Response({
                    'error': f'Recipient user not found: {email}'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        # Read and encrypt file
        file_data = uploaded_file.read()
        aes_key, nonce, ciphertext = aes_encrypt_file(file_data)
        
        # Create encrypted file record
        encrypted_file = EncryptedFile(
            filename=uploaded_file.name,
            original_filename=uploaded_file.name,
            file_size=len(file_data),
            mime_type=uploaded_file.content_type or 'application/octet-stream',
            uploaded_by=request.user,
            aes_nonce=nonce,
            wrapped_keys={}
        )
        
        # Save encrypted file
        import tempfile
        import os
        from django.conf import settings
        
        upload_dir = settings.QUANTUM_STORAGE_SETTINGS['ENCRYPTED_FILES_DIR']
        os.makedirs(upload_dir, exist_ok=True)
        
        file_id = f"{request.user.id}_{uploaded_file.name}"
        file_path = os.path.join(upload_dir, file_id)
        
        with open(file_path, 'wb') as f:
            f.write(ciphertext)
        
        encrypted_file.file_path = file_path
        
        # Wrap AES key for recipients
        all_recipients = recipients + [request.user.email]
        all_recipients = list(set(all_recipients))
        
        for recipient_email in all_recipients:
            recipient_user = QuantumUser.objects.get(email=recipient_email)
            kyber_ct, key_nonce, wrapped_key = wrap_aes_key_for_user(
                aes_key, recipient_user.kyber_public_key
            )
            encrypted_file.add_wrapped_key_for_user(recipient_email, wrapped_key, key_nonce)
            
            # Store Kyber ciphertext
            encrypted_file.wrapped_keys[recipient_email + "_kyber_ct"] = {
                'ciphertext': base64.b64encode(kyber_ct).decode('utf-8'),
                'key_nonce': base64.b64encode(b"").decode('utf-8')
            }
        
        # Sign metadata
        metadata = create_file_metadata_for_signature(
            uploaded_file.name, len(file_data), recipients, request.user.email
        )
        signature = dilithium_sign(request.user.dilithium_private_key, metadata)
        encrypted_file.metadata_signature = signature
        
        encrypted_file.save()
        
        # Create access records
        for recipient_email in recipients:
            FileAccess.objects.get_or_create(
                file=encrypted_file,
                user_email=recipient_email,
                defaults={'granted_by': request.user}
            )
        
        # Log upload
        AuditLog.log_action(
            user_email=request.user.email,
            action='upload',
            file=encrypted_file,
            details={
                'filename': uploaded_file.name,
                'file_size': len(file_data),
                'recipients': recipients,
                'description': description
            },
            request=request,
            success=True
        )
        
        return Response({
            'message': 'File uploaded and encrypted successfully',
            'file_id': encrypted_file.id,
            'filename': uploaded_file.name,
            'file_size': len(file_data),
            'recipients': recipients,
            'encrypted_file_size': len(ciphertext),
            'upload_time': encrypted_file.created_at.isoformat()
        }, status=status.HTTP_201_CREATED)
        
    except Exception as e:
        logger.error(f"File upload failed: {e}")
        return Response({
            'error': f'File upload failed: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_list_files(request):
    """
    API endpoint to list user's files.
    
    GET /api/files/
    Authorization: Token <token>
    """
    try:
        # Get files uploaded by user
        uploaded_files = EncryptedFile.objects.filter(uploaded_by=request.user)
        
        # Get files accessible to user
        accessible_files = EncryptedFile.objects.filter(
            wrapped_keys__has_key=request.user.email
        ).exclude(uploaded_by=request.user)
        
        uploaded_data = []
        for file in uploaded_files:
            uploaded_data.append({
                'id': file.id,
                'filename': file.filename,
                'file_size': file.file_size,
                'mime_type': file.mime_type,
                'recipients': file.get_recipient_emails(),
                'created_at': file.created_at.isoformat(),
                'is_owner': True
            })
        
        accessible_data = []
        for file in accessible_files:
            accessible_data.append({
                'id': file.id,
                'filename': file.filename,
                'file_size': file.file_size,
                'mime_type': file.mime_type,
                'uploaded_by': file.uploaded_by.email,
                'created_at': file.created_at.isoformat(),
                'is_owner': False
            })
        
        return Response({
            'uploaded_files': uploaded_data,
            'accessible_files': accessible_data,
            'total_uploaded': len(uploaded_data),
            'total_accessible': len(accessible_data)
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"File listing failed: {e}")
        return Response({
            'error': f'File listing failed: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_download_file(request, file_id):
    """
    API endpoint for file download with decryption.
    
    GET /api/download/<file_id>/
    Authorization: Token <token>
    """
    try:
        encrypted_file = EncryptedFile.objects.get(id=file_id)
        
        # Check access
        if request.user.email not in encrypted_file.get_recipient_emails():
            AuditLog.log_action(
                user_email=request.user.email,
                action='access_denied',
                file=encrypted_file,
                details={'reason': 'not_in_recipients'},
                request=request,
                success=False
            )
            return Response({
                'error': 'Access denied'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Get wrapped keys
        wrapped_key_data = encrypted_file.get_wrapped_key_for_user(request.user.email)
        kyber_ct_data = encrypted_file.wrapped_keys.get(request.user.email + "_kyber_ct")
        
        if not wrapped_key_data or not kyber_ct_data:
            return Response({
                'error': 'Decryption key not available'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        # Read encrypted file
        with open(encrypted_file.file_path, 'rb') as f:
            ciphertext = f.read()
        
        # Unwrap AES key
        kyber_ciphertext = base64.b64decode(kyber_ct_data['ciphertext'])
        aes_key = unwrap_aes_key_for_user(
            kyber_ciphertext,
            wrapped_key_data['key_nonce'],
            wrapped_key_data['ciphertext'],
            request.user.kyber_private_key
        )
        
        # Decrypt file
        file_data = aes_decrypt_file(aes_key, encrypted_file.aes_nonce, ciphertext)
        
        # Verify signature
        # Get the original recipients (exclude uploader and kyber_ct entries)
        all_recipients = [email for email in encrypted_file.get_recipient_emails() 
                         if email != encrypted_file.uploaded_by.email and not email.endswith('_kyber_ct')]
        
        metadata = create_file_metadata_for_signature(
            encrypted_file.original_filename,
            encrypted_file.file_size,
            all_recipients,
            encrypted_file.uploaded_by.email
        )
        
        signature_valid = dilithium_verify(
            encrypted_file.uploaded_by.dilithium_public_key,
            metadata,
            encrypted_file.metadata_signature
        )
        
        if not signature_valid:
            AuditLog.log_action(
                user_email=request.user.email,
                action='signature_verification',
                file=encrypted_file,
                details={'result': 'failed'},
                request=request,
                success=False
            )
            return Response({
                'error': 'File integrity verification failed'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Log download
        AuditLog.log_action(
            user_email=request.user.email,
            action='download',
            file=encrypted_file,
            details={
                'filename': encrypted_file.original_filename,
                'file_size': len(file_data)
            },
            request=request,
            success=True
        )
        
        # Return file as response
        response = HttpResponse(file_data)
        response['Content-Type'] = encrypted_file.mime_type
        response['Content-Disposition'] = f'attachment; filename="{encrypted_file.original_filename}"'
        response['Content-Length'] = len(file_data)
        
        return response
        
    except EncryptedFile.DoesNotExist:
        return Response({
            'error': 'File not found'
        }, status=status.HTTP_404_NOT_FOUND)
        
    except Exception as e:
        logger.error(f"File download failed: {e}")
        return Response({
            'error': f'File download failed: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_audit_logs(request):
    """
    API endpoint to get user's audit logs.
    
    GET /api/audit/
    Authorization: Token <token>
    """
    try:
        logs = AuditLog.objects.filter(
            user_email=request.user.email
        ).order_by('-timestamp')[:50]
        
        logs_data = []
        for log in logs:
            logs_data.append({
                'id': log.id,
                'action': log.action,
                'action_display': log.get_action_display(),
                'file_id': log.file.id if log.file else None,
                'filename': log.file.filename if log.file else None,
                'details': log.details,
                'success': log.success,
                'error_message': log.error_message,
                'ip_address': log.ip_address,
                'timestamp': log.timestamp.isoformat()
            })
        
        return Response({
            'logs': logs_data,
            'total_count': len(logs_data)
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Audit logs retrieval failed: {e}")
        return Response({
            'error': f'Audit logs retrieval failed: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([AllowAny])
def api_status(request):
    """
    API endpoint to check system status.
    
    GET /api/status/
    """
    return Response({
        'status': 'online',
        'message': 'Quantum-safe file storage system is running',
        'features': {
            'post_quantum_encryption': True,
            'kyber768_kem': True,
            'dilithium3_signatures': True,
            'aes256_gcm': True,
            'audit_logging': True
        }
    }, status=status.HTTP_200_OK)