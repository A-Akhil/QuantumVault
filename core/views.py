"""
Django views for quantum-safe file storage system.
"""

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import HttpResponse, Http404, JsonResponse
from django.core.exceptions import PermissionDenied
from django.conf import settings
from django.utils import timezone
from django.views.decorators.http import require_http_methods
import os
import logging
import mimetypes
import base64
from typing import Optional

from .models import QuantumUser, EncryptedFile, FileAccess, AuditLog
from .forms import QuantumUserRegistrationForm, QuantumUserLoginForm, FileUploadForm, FileShareForm
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


def register_view(request):
    """
    User registration with automatic post-quantum key generation.
    """
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        form = QuantumUserRegistrationForm(request.POST)
        if form.is_valid():
            try:
                # Create user without saving to database yet
                user = form.save(commit=False)
                
                # Generate post-quantum cryptographic keys
                logger.info(f"Generating quantum keys for user: {user.email}")
                
                kyber_public, kyber_private = generate_kyber768_keypair()
                dilithium_public, dilithium_private = generate_dilithium3_keypair()
                
                # Validate keys
                if not validate_quantum_keys(kyber_public, kyber_private, dilithium_public, dilithium_private):
                    raise QuantumCryptoError("Generated keys failed validation")
                
                # Store keys in user model
                user.kyber_public_key = kyber_public
                user.kyber_private_key = kyber_private
                user.dilithium_public_key = dilithium_public
                user.dilithium_private_key = dilithium_private
                
                # Save user to database
                user.save()
                
                # Log successful registration
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
                
                # Log in the user
                login(request, user)
                messages.success(request, 'Registration successful! Your quantum-safe keys have been generated.')
                return redirect('dashboard')
                
            except QuantumCryptoError as e:
                logger.error(f"Quantum key generation failed for {form.cleaned_data.get('email')}: {e}")
                messages.error(request, 'Failed to generate security keys. Please try again.')
                
                # Log failed registration
                AuditLog.log_action(
                    user_email=form.cleaned_data.get('email', 'unknown'),
                    action='register',
                    details={'error': str(e)},
                    request=request,
                    success=False,
                    error_message=str(e)
                )
                
            except Exception as e:
                logger.error(f"Registration failed for {form.cleaned_data.get('email')}: {e}")
                messages.error(request, 'Registration failed. Please try again.')
    else:
        form = QuantumUserRegistrationForm()
    
    return render(request, 'core/register.html', {'form': form})


def login_view(request):
    """
    User login with audit logging.
    """
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        form = QuantumUserLoginForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            
            # Verify user has quantum keys
            if not user.has_quantum_keys():
                logger.warning(f"User {user.email} attempted login without quantum keys")
                messages.error(request, 'Your account is missing security keys. Please contact support.')
                
                AuditLog.log_action(
                    user_email=user.email,
                    action='login',
                    details={'error': 'missing_quantum_keys'},
                    request=request,
                    success=False,
                    error_message='Missing quantum keys'
                )
                return render(request, 'core/login.html', {'form': form})
            
            login(request, user)
            
            # Log successful login
            AuditLog.log_action(
                user_email=user.email,
                action='login',
                details={'username': user.username},
                request=request,
                success=True
            )
            
            messages.success(request, f'Welcome back, {user.first_name}!')
            next_url = request.GET.get('next', 'dashboard')
            return redirect(next_url)
        else:
            # Log failed login attempt
            username = request.POST.get('username', 'unknown')
            AuditLog.log_action(
                user_email=username,
                action='login',
                details={'error': 'invalid_credentials'},
                request=request,
                success=False,
                error_message='Invalid credentials'
            )
    else:
        form = QuantumUserLoginForm()
    
    return render(request, 'core/login.html', {'form': form})


@login_required
def logout_view(request):
    """
    User logout with audit logging.
    """
    user_email = request.user.email
    
    # Log logout
    AuditLog.log_action(
        user_email=user_email,
        action='logout',
        details={'username': request.user.username},
        request=request,
        success=True
    )
    
    logout(request)
    messages.info(request, 'You have been logged out successfully.')
    return redirect('login')


@login_required
def dashboard_view(request):
    """
    User dashboard showing uploaded and accessible files.
    """
    # Get files uploaded by the user
    my_files = EncryptedFile.objects.filter(uploaded_by=request.user).order_by('-created_at')
    
    # Get files shared with the user via FileAccess (using user_email field)
    shared_files = FileAccess.objects.filter(
        user_email=request.user.email
    ).select_related('file', 'file__uploaded_by').order_by('-created_at')
    
    # Get recent audit logs for the user
    recent_audit_logs = AuditLog.objects.filter(
        user_email=request.user.email
    ).order_by('-timestamp')[:10]
    
    # Calculate statistics
    my_files_count = my_files.count()
    shared_files_count = shared_files.count()
    
    # Count total shares (how many times user's files have been shared)
    total_shares = FileAccess.objects.filter(file__uploaded_by=request.user).count()
    
    # Count recent activities (last 7 days)
    from datetime import datetime, timedelta
    week_ago = timezone.now() - timedelta(days=7)
    recent_activities = AuditLog.objects.filter(
        user_email=request.user.email,
        timestamp__gte=week_ago
    ).count()
    
    context = {
        'my_files': my_files,
        'shared_files': shared_files,
        'recent_audit_logs': recent_audit_logs,
        'my_files_count': my_files_count,
        'shared_files_count': shared_files_count,
        'total_shares': total_shares,
        'recent_activities': recent_activities,
    }
    
    return render(request, 'core/dashboard.html', context)


@login_required
def upload_file_view(request):
    """
    File upload with AES encryption and Kyber key wrapping.
    """
    if request.method == 'POST':
        form = FileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                uploaded_file = request.FILES['file']
                recipients = form.cleaned_data['recipients']
                description = form.cleaned_data.get('description', '')
                
                # Read file data
                file_data = uploaded_file.read()
                
                # Encrypt file with AES-256-GCM
                logger.info(f"Encrypting file {uploaded_file.name} for user {request.user.email}")
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
                
                # Save encrypted file to filesystem
                upload_dir = settings.QUANTUM_STORAGE_SETTINGS['ENCRYPTED_FILES_DIR']
                os.makedirs(upload_dir, exist_ok=True)
                
                file_id = f"{timezone.now().strftime('%Y%m%d_%H%M%S')}_{request.user.id}_{uploaded_file.name}"
                file_path = os.path.join(upload_dir, file_id)
                
                with open(file_path, 'wb') as f:
                    f.write(ciphertext)
                
                encrypted_file.file_path = file_path
                
                # Wrap AES key for each recipient (including uploader)
                all_recipients = recipients + [request.user.email]
                all_recipients = list(set(all_recipients))  # Remove duplicates
                
                for recipient_email in all_recipients:
                    try:
                        recipient_user = QuantumUser.objects.get(email=recipient_email)
                        kyber_ct, key_nonce, wrapped_key = wrap_aes_key_for_user(
                            aes_key, recipient_user.kyber_public_key
                        )
                        encrypted_file.add_wrapped_key_for_user(recipient_email, wrapped_key, key_nonce)
                        
                        # Store Kyber ciphertext separately for unwrapping
                        encrypted_file.wrapped_keys[recipient_email + "_kyber_ct"] = {
                            'ciphertext': base64.b64encode(kyber_ct).decode('utf-8'),
                            'key_nonce': base64.b64encode(b"").decode('utf-8')  # Not used for Kyber CT
                        }
                        
                    except QuantumUser.DoesNotExist:
                        logger.error(f"Recipient user not found: {recipient_email}")
                        continue
                
                # Create metadata for signature
                metadata = create_file_metadata_for_signature(
                    uploaded_file.name,
                    len(file_data),
                    recipients,
                    request.user.email
                )
                
                # Sign metadata with uploader's Dilithium key
                signature = dilithium_sign(request.user.dilithium_private_key, metadata)
                encrypted_file.metadata_signature = signature
                
                # Save to database
                encrypted_file.save()
                
                # Create access records
                for recipient_email in recipients:
                    FileAccess.objects.get_or_create(
                        file=encrypted_file,
                        user_email=recipient_email,
                        defaults={'granted_by': request.user}
                    )
                
                # Log successful upload
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
                
                messages.success(request, f'File "{uploaded_file.name}" uploaded and encrypted successfully!')
                return redirect('dashboard')
                
            except Exception as e:
                logger.error(f"File upload failed for user {request.user.email}: {e}")
                messages.error(request, f'File upload failed: {str(e)}')
                
                # Log failed upload
                AuditLog.log_action(
                    user_email=request.user.email,
                    action='upload',
                    details={
                        'filename': request.FILES.get('file', {}).get('name', 'unknown'),
                        'error': str(e)
                    },
                    request=request,
                    success=False,
                    error_message=str(e)
                )
    else:
        form = FileUploadForm()
    
    return render(request, 'core/upload.html', {'form': form})


@login_required
def download_file_view(request, file_id):
    """
    Secure file download with access control and decryption.
    """
    try:
        encrypted_file = get_object_or_404(EncryptedFile, id=file_id)
        
        # Check if user has access
        if request.user.email not in encrypted_file.get_recipient_emails():
            logger.warning(f"Access denied for user {request.user.email} to file {file_id}")
            
            AuditLog.log_action(
                user_email=request.user.email,
                action='access_denied',
                file=encrypted_file,
                details={'reason': 'not_in_recipients'},
                request=request,
                success=False,
                error_message='Access denied'
            )
            
            raise PermissionDenied("You don't have access to this file.")
        
        # Get wrapped key for this user
        wrapped_key_data = encrypted_file.get_wrapped_key_for_user(request.user.email)
        kyber_ct_data = encrypted_file.wrapped_keys.get(request.user.email + "_kyber_ct")
        
        if not wrapped_key_data or not kyber_ct_data:
            logger.error(f"No wrapped key found for user {request.user.email} and file {file_id}")
            raise PermissionDenied("Decryption key not available.")
        
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
        
        # Verify metadata signature
        metadata = create_file_metadata_for_signature(
            encrypted_file.original_filename,
            encrypted_file.file_size,
            [email for email in encrypted_file.get_recipient_emails() if email != encrypted_file.uploaded_by.email],
            encrypted_file.uploaded_by.email
        )
        
        signature_valid = dilithium_verify(
            encrypted_file.uploaded_by.dilithium_public_key,
            metadata,
            encrypted_file.metadata_signature
        )
        
        if not signature_valid:
            logger.error(f"Signature verification failed for file {file_id}")
            AuditLog.log_action(
                user_email=request.user.email,
                action='signature_verification',
                file=encrypted_file,
                details={'result': 'failed'},
                request=request,
                success=False,
                error_message='Signature verification failed'
            )
            raise PermissionDenied("File integrity verification failed.")
        
        # Log successful download
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
        
        # Prepare response
        response = HttpResponse(file_data)
        response['Content-Type'] = encrypted_file.mime_type
        response['Content-Disposition'] = f'attachment; filename="{encrypted_file.original_filename}"'
        response['Content-Length'] = len(file_data)
        
        return response
        
    except PermissionDenied:
        raise
    except Exception as e:
        logger.error(f"File download failed for user {request.user.email}, file {file_id}: {e}")
        
        AuditLog.log_action(
            user_email=request.user.email,
            action='download',
            details={
                'file_id': file_id,
                'error': str(e)
            },
            request=request,
            success=False,
            error_message=str(e)
        )
        
        messages.error(request, 'File download failed.')
        return redirect('dashboard')


@login_required
def audit_logs_view(request):
    """
    View audit logs for the current user.
    """
    logs = AuditLog.objects.filter(
        user_email=request.user.email
    ).order_by('-timestamp')[:50]  # Last 50 entries
    
    return render(request, 'core/audit_logs.html', {'logs': logs})


def home_view(request):
    """
    Home page view.
    """
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'core/home.html')
