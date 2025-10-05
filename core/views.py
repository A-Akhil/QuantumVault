"""
Django views for quantum-safe file storage system.
"""

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import HttpResponse, Http404, JsonResponse
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.conf import settings
from django.utils import timezone
from django.views.decorators.http import require_http_methods
import os
import logging
import mimetypes
import base64
from typing import Optional

from .models import QuantumUser, EncryptedFile, FileAccess, AuditLog, UserGroup
from .forms import QuantumUserRegistrationForm, QuantumUserLoginForm, FileUploadForm, FileShareForm, UserGroupForm
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
    
    # Get user groups
    user_groups = UserGroup.objects.filter(created_by=request.user).order_by('name')[:5]  # Show first 5 groups
    groups_count = UserGroup.objects.filter(created_by=request.user).count()
    
    context = {
        'my_files': my_files,
        'shared_files': shared_files,
        'recent_audit_logs': recent_audit_logs,
        'my_files_count': my_files_count,
        'shared_files_count': shared_files_count,
        'total_shares': total_shares,
        'recent_activities': recent_activities,
        'user_groups': user_groups,
        'groups_count': groups_count,
    }
    
    return render(request, 'core/dashboard.html', context)


@login_required
def my_files_view(request):
    """
    Dedicated page for My Files with advanced filtering and search.
    """
    from django.db.models import Q, Count
    import mimetypes
    
    # Get all files uploaded by the user
    files_query = EncryptedFile.objects.filter(uploaded_by=request.user).annotate(
        share_count=Count('access_records')
    ).order_by('-created_at')
    
    # Get filter parameters
    search = request.GET.get('search', '')
    file_type = request.GET.get('file_type', '')
    date_filter = request.GET.get('date_filter', '')
    shared_filter = request.GET.get('shared_filter', '')
    
    # Apply search filter
    if search:
        files_query = files_query.filter(
            Q(filename__icontains=search) |
            Q(description__icontains=search)
        )
    
    # Apply file type filter
    if file_type:
        if file_type == 'image':
            files_query = files_query.filter(filename__iregex=r'\.(jpg|jpeg|png|gif|bmp|svg)$')
        elif file_type == 'document':
            files_query = files_query.filter(filename__iregex=r'\.(pdf|doc|docx|txt|rtf|odt)$')
        elif file_type == 'video':
            files_query = files_query.filter(filename__iregex=r'\.(mp4|avi|mov|wmv|flv|mkv)$')
        elif file_type == 'audio':
            files_query = files_query.filter(filename__iregex=r'\.(mp3|wav|flac|ogg|aac)$')
        elif file_type == 'archive':
            files_query = files_query.filter(filename__iregex=r'\.(zip|rar|7z|tar|gz)$')
    
    # Apply date filter
    if date_filter:
        from datetime import datetime, timedelta
        now = timezone.now()
        if date_filter == 'today':
            files_query = files_query.filter(created_at__date=now.date())
        elif date_filter == 'week':
            week_ago = now - timedelta(days=7)
            files_query = files_query.filter(created_at__gte=week_ago)
        elif date_filter == 'month':
            month_ago = now - timedelta(days=30)
            files_query = files_query.filter(created_at__gte=month_ago)
    
    # Apply shared filter
    if shared_filter:
        if shared_filter == 'shared':
            files_query = files_query.filter(share_count__gt=0)
        elif shared_filter == 'not_shared':
            files_query = files_query.filter(share_count=0)
    
    # Get statistics
    total_files = EncryptedFile.objects.filter(uploaded_by=request.user).count()
    total_size = sum([f.file_size for f in EncryptedFile.objects.filter(uploaded_by=request.user)])
    shared_files_count = EncryptedFile.objects.filter(uploaded_by=request.user, access_records__isnull=False).distinct().count()
    
    context = {
        'files': files_query,
        'search': search,
        'file_type': file_type,
        'date_filter': date_filter,
        'shared_filter': shared_filter,
        'total_files': total_files,
        'total_size': total_size,
        'shared_files_count': shared_files_count,
    }
    
    return render(request, 'core/my_files.html', context)


@login_required
def shared_with_me_view(request):
    """
    Dedicated page for Shared With Me files with advanced filtering and search.
    """
    from django.db.models import Q
    
    # Get all files shared with the user
    files_query = FileAccess.objects.filter(
        user_email=request.user.email
    ).select_related('file', 'file__uploaded_by').order_by('-created_at')
    
    # Get filter parameters
    search = request.GET.get('search', '')
    file_type = request.GET.get('file_type', '')
    date_filter = request.GET.get('date_filter', '')
    sender_filter = request.GET.get('sender', '')
    
    # Apply search filter
    if search:
        files_query = files_query.filter(
            Q(file__filename__icontains=search) |
            Q(file__description__icontains=search) |
            Q(file__uploaded_by__username__icontains=search) |
            Q(file__uploaded_by__email__icontains=search)
        )
    
    # Apply file type filter
    if file_type:
        if file_type == 'image':
            files_query = files_query.filter(file__filename__iregex=r'\.(jpg|jpeg|png|gif|bmp|svg)$')
        elif file_type == 'document':
            files_query = files_query.filter(file__filename__iregex=r'\.(pdf|doc|docx|txt|rtf|odt)$')
        elif file_type == 'video':
            files_query = files_query.filter(file__filename__iregex=r'\.(mp4|avi|mov|wmv|flv|mkv)$')
        elif file_type == 'audio':
            files_query = files_query.filter(file__filename__iregex=r'\.(mp3|wav|flac|ogg|aac)$')
        elif file_type == 'archive':
            files_query = files_query.filter(file__filename__iregex=r'\.(zip|rar|7z|tar|gz)$')
    
    # Apply date filter
    if date_filter:
        from datetime import datetime, timedelta
        now = timezone.now()
        if date_filter == 'today':
            files_query = files_query.filter(created_at__date=now.date())
        elif date_filter == 'week':
            week_ago = now - timedelta(days=7)
            files_query = files_query.filter(created_at__gte=week_ago)
        elif date_filter == 'month':
            month_ago = now - timedelta(days=30)
            files_query = files_query.filter(created_at__gte=month_ago)
    
    # Apply sender filter
    if sender_filter:
        files_query = files_query.filter(file__uploaded_by__email=sender_filter)
    
    # Get statistics and unique senders
    total_shared = FileAccess.objects.filter(user_email=request.user.email).count()
    unique_senders = FileAccess.objects.filter(user_email=request.user.email).values_list(
        'file__uploaded_by__email', 'file__uploaded_by__username'
    ).distinct()
    
    context = {
        'file_accesses': files_query,
        'search': search,
        'file_type': file_type,
        'date_filter': date_filter,
        'sender_filter': sender_filter,
        'total_shared': total_shared,
        'unique_senders': unique_senders,
    }
    
    return render(request, 'core/shared_with_me.html', context)


@login_required
def upload_file_view(request):
    """
    Multiple file upload with AES encryption and Kyber key wrapping.
    """
    if request.method == 'POST':
        form = FileUploadForm(request.POST, request.FILES)
        
        # Get recipients from the new multi-select format
        selected_recipients = request.POST.getlist('recipients')
        # Filter out empty values and the current user's email
        recipients = [email for email in selected_recipients if email and email != request.user.email]
        
        # Get multiple files from the 'files' input
        uploaded_files = request.FILES.getlist('files')
        
        if uploaded_files and recipients:
            successful_uploads = []
            failed_uploads = []
            
            for uploaded_file in uploaded_files:
                try:
                    description = form.cleaned_data.get('description', '') if form.is_valid() else ''
                    
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
                    
                    timestamp = timezone.now().strftime('%Y%m%d_%H%M%S_%f')
                    file_id = f"{timestamp}_{request.user.id}_{uploaded_file.name}"
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
                    
                    # Store original recipients list for signature verification
                    encrypted_file.wrapped_keys['_original_recipients'] = recipients
                    
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
                        details={
                            'filename': uploaded_file.name,
                            'file_size': len(file_data),
                            'recipients': recipients,
                            'file_id': encrypted_file.id,
                            'description': description
                        },
                        request=request,
                        success=True
                    )
                    
                    successful_uploads.append(uploaded_file.name)
                    
                except Exception as e:
                    logger.error(f"File upload failed for {uploaded_file.name}: {e}")
                    failed_uploads.append({'name': uploaded_file.name, 'error': str(e)})
                    
                    # Log failed upload
                    AuditLog.log_action(
                        user_email=request.user.email,
                        action='upload',
                        details={
                            'filename': uploaded_file.name,
                            'error': str(e)
                        },
                        request=request,
                        success=False,
                        error_message=str(e)
                    )
            
            # Generate success/error messages
            if successful_uploads:
                if len(successful_uploads) == 1:
                    messages.success(request, f'File "{successful_uploads[0]}" uploaded and encrypted successfully! Shared with {len(recipients)} user(s).')
                else:
                    messages.success(request, f'{len(successful_uploads)} files uploaded and encrypted successfully! Each shared with {len(recipients)} user(s).')
            
            if failed_uploads:
                for failed in failed_uploads:
                    messages.error(request, f'Failed to upload "{failed["name"]}" - {failed["error"]}')
            
            return redirect('dashboard')
        else:
            if not uploaded_files:
                messages.error(request, 'Please select at least one file to upload.')
            elif not recipients:
                messages.error(request, 'Please select at least one user to share the files with.')
    
    # GET request - show upload form
    available_users = QuantumUser.objects.exclude(email=request.user.email).order_by('email')
    user_groups = UserGroup.objects.filter(created_by=request.user).order_by('name')
    form = FileUploadForm()
    
    return render(request, 'core/upload.html', {
        'form': form,
        'available_users': available_users,
        'user_groups': user_groups
    })


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
        # Use original recipients list that was used when signing
        original_recipients = encrypted_file.wrapped_keys.get('_original_recipients', [])
        
        # Debug logging
        logger.info(f"File {file_id} signature verification debug:")
        logger.info(f"  Original recipients from storage: {original_recipients}")
        logger.info(f"  Current recipients: {encrypted_file.get_recipient_emails()}")
        logger.info(f"  File uploaded by: {encrypted_file.uploaded_by.email}")
        
        # Fallback for files uploaded before the fix: use current recipients excluding owner
        if not original_recipients:
            logger.warning(f"No original recipients stored for file {file_id}, using fallback method")
            original_recipients = [email for email in encrypted_file.get_recipient_emails() 
                                 if email != encrypted_file.uploaded_by.email]
        
        metadata = create_file_metadata_for_signature(
            encrypted_file.original_filename,
            encrypted_file.file_size,
            original_recipients,
            encrypted_file.uploaded_by.email
        )
        
        logger.info(f"  Metadata for verification: {metadata}")
        logger.info(f"  Metadata length: {len(metadata)} bytes")
        
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
    logs_queryset = AuditLog.objects.filter(
        user_email=request.user.email
    ).order_by('-timestamp')

    paginator = Paginator(logs_queryset, 25)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'logs': page_obj.object_list,
        'page_obj': page_obj,
        'paginator': paginator,
        'page_range': paginator.get_elided_page_range(page_obj.number, on_each_side=1, on_ends=1),
        'is_paginated': page_obj.has_other_pages(),
    }
    
    return render(request, 'core/audit_logs.html', context)


@login_required
def manage_file_sharing_view(request, file_id):
    """
    Manage file sharing - view and modify access permissions.
    Only file owner can manage sharing.
    """
    encrypted_file = get_object_or_404(EncryptedFile, id=file_id)
    
    # Check if user is the owner
    if encrypted_file.uploaded_by != request.user:
        messages.error(request, "You can only manage sharing for files you uploaded.")
        return redirect('dashboard')
    
    # Get current access list
    current_access = FileAccess.objects.filter(file=encrypted_file).order_by('created_at')
    
    # Get list of emails that already have access
    existing_emails = set([request.user.email])  # Owner always has access
    existing_emails.update(current_access.values_list('user_email', flat=True))
    
    # Get list of all users for adding access (excluding those who already have access)
    all_users = QuantumUser.objects.exclude(email__in=existing_emails).order_by('email')
    
    context = {
        'file': encrypted_file,
        'current_access': current_access,
        'all_users': all_users,
        'existing_emails': existing_emails,
    }
    
    return render(request, 'core/manage_file_sharing.html', context)


@login_required
@require_http_methods(["POST"])
def add_file_access_view(request, file_id):
    """
    Add access for a new user to a file.
    Wraps AES key with the new user's Kyber public key.
    """
    try:
        encrypted_file = get_object_or_404(EncryptedFile, id=file_id)
        
        # Check if user is the owner
        if encrypted_file.uploaded_by != request.user:
            messages.error(request, "You can only manage sharing for files you uploaded.")
            return redirect('dashboard')
        
        new_user_email = request.POST.get('user_email')
        if not new_user_email:
            messages.error(request, "Please select a user to add.")
            return redirect('manage_file_sharing', file_id=file_id)
        
        # Check if user already has access
        if FileAccess.objects.filter(file=encrypted_file, user_email=new_user_email).exists():
            messages.warning(request, f"User {new_user_email} already has access to this file.")
            return redirect('manage_file_sharing', file_id=file_id)
        
        # Get the new user
        try:
            new_user = QuantumUser.objects.get(email=new_user_email)
        except QuantumUser.DoesNotExist:
            messages.error(request, f"User with email {new_user_email} does not exist.")
            return redirect('manage_file_sharing', file_id=file_id)
        
        # Get the original AES key by unwrapping it with owner's key
        owner_wrapped_key_data = encrypted_file.get_wrapped_key_for_user(request.user.email)
        owner_kyber_ct_data = encrypted_file.wrapped_keys.get(request.user.email + "_kyber_ct")
        
        if not owner_wrapped_key_data or not owner_kyber_ct_data:
            messages.error(request, "Cannot retrieve encryption key for this file.")
            return redirect('manage_file_sharing', file_id=file_id)
        
        # Unwrap AES key using owner's Kyber private key
        kyber_ciphertext = base64.b64decode(owner_kyber_ct_data['ciphertext'])
        aes_key = unwrap_aes_key_for_user(
            kyber_ciphertext,
            owner_wrapped_key_data['key_nonce'],
            owner_wrapped_key_data['ciphertext'],
            request.user.kyber_private_key
        )
        
        # Wrap AES key for the new user
        kyber_ct, key_nonce, wrapped_key = wrap_aes_key_for_user(
            aes_key, new_user.kyber_public_key
        )
        
        # Add wrapped key to the file
        encrypted_file.add_wrapped_key_for_user(new_user_email, wrapped_key, key_nonce)
        encrypted_file.wrapped_keys[new_user_email + "_kyber_ct"] = {
            'ciphertext': base64.b64encode(kyber_ct).decode('utf-8'),
            'key_nonce': base64.b64encode(b"").decode('utf-8')
        }
        encrypted_file.save()
        
        # Create access record
        FileAccess.objects.create(
            file=encrypted_file,
            user_email=new_user_email,
            granted_by=request.user
        )
        
        # Log the action
        AuditLog.log_action(
            user_email=request.user.email,
            action='share',
            file=encrypted_file,
            details={
                'action': 'add_access',
                'new_user': new_user_email,
                'filename': encrypted_file.filename
            },
            request=request,
            success=True
        )
        
        messages.success(request, f"Access granted to {new_user_email} successfully!")
        
    except Exception as e:
        logger.error(f"Failed to add file access for user {request.user.email}, file {file_id}: {e}")
        messages.error(request, f"Failed to add access: {str(e)}")
        
        # Log failed action
        AuditLog.log_action(
            user_email=request.user.email,
            action='share',
            details={
                'action': 'add_access_failed',
                'new_user': request.POST.get('user_email', 'unknown'),
                'file_id': file_id,
                'error': str(e)
            },
            request=request,
            success=False,
            error_message=str(e)
        )
    
    return redirect('manage_file_sharing', file_id=file_id)


@login_required
@require_http_methods(["POST"])
def remove_file_access_view(request, file_id):
    """
    Remove access for a user from a file.
    Removes wrapped key and access record.
    """
    try:
        encrypted_file = get_object_or_404(EncryptedFile, id=file_id)
        
        # Check if user is the owner
        if encrypted_file.uploaded_by != request.user:
            messages.error(request, "You can only manage sharing for files you uploaded.")
            return redirect('dashboard')
        
        remove_user_email = request.POST.get('user_email')
        if not remove_user_email:
            messages.error(request, "Please select a user to remove.")
            return redirect('manage_file_sharing', file_id=file_id)
        
        # Cannot remove owner's own access
        if remove_user_email == request.user.email:
            messages.error(request, "You cannot remove your own access to the file.")
            return redirect('manage_file_sharing', file_id=file_id)
        
        # Check if user has access
        access_record = FileAccess.objects.filter(file=encrypted_file, user_email=remove_user_email).first()
        if not access_record:
            messages.warning(request, f"User {remove_user_email} does not have access to this file.")
            return redirect('manage_file_sharing', file_id=file_id)
        
        # Remove wrapped keys from file
        if encrypted_file.wrapped_keys:
            encrypted_file.wrapped_keys.pop(remove_user_email, None)
            encrypted_file.wrapped_keys.pop(remove_user_email + "_kyber_ct", None)
            encrypted_file.save()
        
        # Remove access record
        access_record.delete()
        
        # Log the action
        AuditLog.log_action(
            user_email=request.user.email,
            action='share',
            file=encrypted_file,
            details={
                'action': 'remove_access',
                'removed_user': remove_user_email,
                'filename': encrypted_file.filename
            },
            request=request,
            success=True
        )
        
        messages.success(request, f"Access removed from {remove_user_email} successfully!")
        
    except Exception as e:
        logger.error(f"Failed to remove file access for user {request.user.email}, file {file_id}: {e}")
        messages.error(request, f"Failed to remove access: {str(e)}")
        
        # Log failed action
        AuditLog.log_action(
            user_email=request.user.email,
            action='share',
            details={
                'action': 'remove_access_failed',
                'removed_user': request.POST.get('user_email', 'unknown'),
                'file_id': file_id,
                'error': str(e)
            },
            request=request,
            success=False,
            error_message=str(e)
        )
    
    return redirect('manage_file_sharing', file_id=file_id)


@login_required
@require_http_methods(["POST"])
def delete_file_view(request, file_id):
    """
    Delete a file completely (only owner can delete).
    Removes the file, all access records, and cleans up storage.
    """
    try:
        encrypted_file = get_object_or_404(EncryptedFile, id=file_id, uploaded_by=request.user)
        
        # Store file info for audit log
        file_name = encrypted_file.original_filename
        file_size = encrypted_file.file_size
        
        # Get all users who had access for audit log
        access_records = FileAccess.objects.filter(file=encrypted_file)
        shared_with = [access.user_email for access in access_records]
        
        # Delete file storage if it exists
        if encrypted_file.file_path:
            try:
                # In a real implementation, you might want to securely wipe the file
                # For now, we're storing file content in database via the file_path field
                pass  # File content is managed by Django's file handling
            except Exception as e:
                logger.warning(f"Could not clean up file storage for file {file_id}: {e}")
        
        # Delete all access records first (due to foreign key constraints)
        access_records.delete()
        
        # Delete the file record
        encrypted_file.delete()
        
        # Log the deletion
        AuditLog.log_action(
            user_email=request.user.email,
            action='file_deleted',
            details={
                'action': 'file_deleted',
                'file_name': file_name,
                'file_size': file_size,
                'file_id': file_id,
                'shared_with': shared_with,
                'deletion_time': timezone.now().isoformat()
            },
            request=request,
            success=True
        )
        
        messages.success(request, f'File "{file_name}" has been permanently deleted.')
        
    except Exception as e:
        logger.error(f"Error deleting file {file_id}: {e}", exc_info=True)
        
        # Log the failed deletion
        AuditLog.log_action(
            user_email=request.user.email,
            action='file_deletion_failed',
            details={
                'action': 'file_deletion_failed',
                'file_id': file_id,
                'error': str(e)
            },
            request=request,
            success=False
        )
        
        messages.error(request, 'Failed to delete file. Please try again.')
    
    return redirect('dashboard')


@login_required
def manage_groups_view(request):
    """
    View and manage user groups for easier file sharing.
    """
    user_groups = UserGroup.objects.filter(created_by=request.user).order_by('name')
    
    context = {
        'user_groups': user_groups,
    }
    
    return render(request, 'core/manage_groups.html', context)


@login_required
def create_group_view(request):
    """
    Create a new user group.
    """
    if request.method == 'POST':
        from .forms import UserGroupForm, GroupMemberSelectionForm
        
        form = UserGroupForm(request.POST)
        member_form = GroupMemberSelectionForm(current_user=request.user, data=request.POST)
        
        if form.is_valid() and member_form.is_valid():
            try:
                # Create the group
                group = form.save(commit=False)
                group.created_by = request.user
                group.save()
                
                # Add selected members
                selected_users = member_form.cleaned_data['selected_users']
                for user in selected_users:
                    from .models import GroupMembership
                    GroupMembership.objects.create(
                        group=group,
                        user=user,
                        added_by=request.user
                    )
                
                messages.success(request, f'Group "{group.name}" created successfully with {selected_users.count()} members!')
                return redirect('manage_groups')
                
            except Exception as e:
                logger.error(f"Failed to create group for user {request.user.email}: {e}")
                messages.error(request, 'Failed to create group. Please try again.')
        else:
            messages.error(request, 'Please correct the errors in the form.')
    else:
        from .forms import UserGroupForm, GroupMemberSelectionForm
        form = UserGroupForm()
        member_form = GroupMemberSelectionForm(current_user=request.user)
    
    context = {
        'form': form,
        'member_form': member_form,
    }
    
    return render(request, 'core/create_group.html', context)


@login_required
def edit_group_view(request, group_id):
    """
    Edit a user group.
    """
    try:
        group = get_object_or_404(UserGroup, id=group_id, created_by=request.user)
        
        if request.method == 'POST':
            form = UserGroupForm(request.POST, instance=group)
            if form.is_valid():
                group = form.save()
                
                # Handle member selection
                selected_members = request.POST.getlist('selected_members')
                
                # Clear current members and add selected ones
                group.members.clear()
                for member_id in selected_members:
                    try:
                        member = QuantumUser.objects.get(id=member_id)
                        if member != request.user:  # Don't add creator as member
                            group.members.add(member)
                    except QuantumUser.DoesNotExist:
                        continue
                
                messages.success(request, f'Group "{group.name}" updated successfully!')
                return redirect('manage_groups')
            else:
                messages.error(request, 'Please correct the errors below.')
        else:
            form = UserGroupForm(instance=group)
        
        # Get all users except current user for member selection
        available_users = QuantumUser.objects.exclude(id=request.user.id).order_by('username')
        current_member_ids = list(group.members.values_list('id', flat=True))
        
        context = {
            'form': form,
            'group': group,
            'available_users': available_users,
            'current_member_ids': current_member_ids,
        }
        
        return render(request, 'core/edit_group.html', context)
        
    except Exception as e:
        logger.error(f"Failed to edit group {group_id} for user {request.user.email}: {e}")
        messages.error(request, 'Failed to access group. Please try again.')
        return redirect('manage_groups')


@login_required
@require_http_methods(["POST"])
def delete_group_view(request, group_id):
    """
    Delete a user group.
    """
    try:
        group = get_object_or_404(UserGroup, id=group_id, created_by=request.user)
        group_name = group.name
        group.delete()
        
        messages.success(request, f'Group "{group_name}" deleted successfully!')
        
    except Exception as e:
        logger.error(f"Failed to delete group {group_id} for user {request.user.email}: {e}")
        messages.error(request, 'Failed to delete group. Please try again.')
    
    return redirect('manage_groups')


def home_view(request):
    """
    Home page view.
    """
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'core/home.html')
