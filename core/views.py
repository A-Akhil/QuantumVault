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
from django.db.models import Q
import os
import logging
import mimetypes
import base64
from typing import Optional

from .models import QuantumUser, EncryptedFile, FileAccess, AuditLog, UserGroup, BB84Session, OnlineStatus
from .forms import QuantumUserRegistrationForm, QuantumUserLoginForm, FileUploadForm, FileShareForm, UserGroupForm
from .crypto_utils import (
    generate_dilithium3_keypair,
    aes_encrypt_file,
    aes_decrypt_file,
    initiate_bb84_session,
    wrap_aes_key_with_shared_secret,
    unwrap_aes_key_with_shared_secret,
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
                
                dilithium_public, dilithium_private = generate_dilithium3_keypair()
                
                # Validate keys
                if not validate_quantum_keys(None, None, dilithium_public, dilithium_private):
                    raise QuantumCryptoError("Generated keys failed validation")
                
                # Store keys in user model
                user.kyber_public_key = b""
                user.kyber_private_key = b""
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
                        'bb84_shared_key_bytes': 32,
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
@login_required
def upload_file_view(request):
    """
    Multiple file upload with AES encryption and BB84 key distribution.
    Requires valid BB84 sessions with recipients before upload.
    """
    if request.method == 'POST':
        form = FileUploadForm(request.POST, request.FILES)
        
        # NEW: Detect if uploading to a group
        selected_group_id = request.POST.get('group')
        selected_group = None
        context_type = 'personal'
        
        if selected_group_id:
            try:
                selected_group = UserGroup.objects.get(id=selected_group_id, created_by=request.user)
                context_type = 'group'
            except UserGroup.DoesNotExist:
                messages.error(request, "Selected group not found.")
                return redirect('upload')
        
        # Get recipients from the new multi-select format
        selected_recipients = request.POST.getlist('recipients')
        # Filter out empty values and the current user's email
        recipients = [email for email in selected_recipients if email and email != request.user.email]
        
        # Get multiple files from the 'files' input
        uploaded_files = request.FILES.getlist('files')
        
        if not uploaded_files:
            messages.error(request, "Please select at least one file to upload.")
            return redirect('upload')
        
        if not recipients:
            messages.error(request, "Please select at least one recipient.")
            return redirect('upload')
        
        # *** Check for valid BB84 sessions with ALL recipients ***
        # Sessions are BIDIRECTIONAL and PERMANENT - can be reused
        # NEW: Context-aware validation (personal vs group)
        missing_sessions = []
        recipient_users = QuantumUser.objects.filter(email__in=recipients)
        
        for recipient in recipient_users:
            # Check if there's a completed BB84 session (bidirectional)
            # Can be sender→receiver OR receiver→sender
            # CONTEXT-AWARE: Check for appropriate context type
            session_filter = Q(
                (Q(sender=request.user, receiver=recipient) |
                 Q(sender=recipient, receiver=request.user)),
                status='completed',
                context_type=context_type
            )
            
            # For group context, also match the specific group
            if context_type == 'group' and selected_group:
                session_filter &= Q(group=selected_group)
            else:
                # For personal context, ensure group is NULL
                session_filter &= Q(group__isnull=True)
            
            valid_session = BB84Session.objects.filter(session_filter).order_by('-created_at').first()
            
            if not valid_session:
                if context_type == 'group':
                    missing_sessions.append(f"{recipient.email} (group: {selected_group.name})")
                else:
                    missing_sessions.append(recipient.email)
        
        if missing_sessions:
            if context_type == 'group':
                messages.error(
                    request,
                    f"Group BB84 key exchange required for group '{selected_group.name}'! "
                    f"You must establish quantum sessions with: {', '.join(missing_sessions)}. "
                    "Please complete group key exchange before uploading."
                )
                return redirect('establish_group_keys', group_id=selected_group.id)
            else:
                messages.error(
                    request,
                    f"BB84 key exchange required! You must establish quantum sessions with: {', '.join(missing_sessions)}. "
                    "Please complete key exchange before uploading."
                )
                return redirect('key_exchange')
        
        # Proceed with upload if all sessions exist
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
                    
                    # Wrap AES key for each recipient using existing BB84 sessions
                    all_recipients = recipients + [request.user.email]
                    all_recipients = list(set(all_recipients))  # Remove duplicates
                    
                    # Store BB84 sessions that will be linked after file save
                    sessions_to_link = []
                    
                    for recipient_email in all_recipients:
                        try:
                            recipient_user = QuantumUser.objects.get(email=recipient_email)
                        except QuantumUser.DoesNotExist:
                            logger.error(f"Recipient user not found: {recipient_email}")
                            continue

                        try:
                            # For uploader, create a new BB84 session on-the-fly
                            if recipient_email == request.user.email:
                                session_result = initiate_bb84_session()
                                shared_key = session_result['shared_key']
                                
                                session_summary = {
                                    'error_rate': session_result['error_rate'],
                                    'sifted_key_length': session_result['sifted_key_length'],
                                    'num_intercepted': session_result['num_intercepted'],
                                    'eavesdropper_present': session_result['eavesdropper_present'],
                                }
                            else:
                                # Use existing BB84 session (bidirectional + reusable + context-aware)
                                session_filter = Q(
                                    (Q(sender=request.user, receiver=recipient_user) |
                                     Q(sender=recipient_user, receiver=request.user)),
                                    status='completed',
                                    context_type=context_type
                                )
                                
                                # For group context, match the specific group
                                if context_type == 'group' and selected_group:
                                    session_filter &= Q(group=selected_group)
                                else:
                                    # For personal context, ensure group is NULL
                                    session_filter &= Q(group__isnull=True)
                                
                                bb84_session = BB84Session.objects.filter(session_filter).order_by('-created_at').first()
                                
                                if not bb84_session:
                                    logger.error(f"No valid BB84 session found for {recipient_email} in {context_type} context")
                                    continue
                                
                                shared_key = bb84_session.shared_key
                                
                                # Store session to link after file is saved (optional now)
                                # Multiple files can use the same session
                                sessions_to_link.append(bb84_session)
                                
                                session_summary = bb84_session.get_protocol_summary()
                            
                            # Wrap AES key with BB84-derived shared secret
                            wrapped_key, key_nonce = wrap_aes_key_with_shared_secret(aes_key, shared_key)

                            encrypted_file.add_wrapped_key_for_user(
                                recipient_email,
                                wrapped_key,
                                key_nonce,
                                shared_key=shared_key,
                                session_info=session_summary,
                            )

                        except QuantumCryptoError as exc:
                            logger.error(
                                "Key wrapping failed for recipient %s: %s", recipient_email, exc
                            )
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
                    
                    # NOW link BB84 sessions to the saved file
                    for session in sessions_to_link:
                        session.file = encrypted_file
                        session.save()
                    
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
    # Only show users with whom the sender has completed BB84 sessions (bidirectional)
    completed_sessions = BB84Session.objects.filter(
        Q(sender=request.user) | Q(receiver=request.user),
        status='completed'
    ).select_related('sender', 'receiver')
    
    # Extract unique user IDs from sessions (excluding current user)
    user_ids = set()
    for session in completed_sessions:
        if session.sender == request.user:
            user_ids.add(session.receiver_id)
        else:
            user_ids.add(session.sender_id)
    
    # Filter available users to only those with completed sessions
    available_users = QuantumUser.objects.filter(
        id__in=user_ids
    ).order_by('email')
    
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
        
        if not wrapped_key_data or 'shared_key' not in wrapped_key_data:
            logger.error(f"No BB84 shared key found for user {request.user.email} and file {file_id}")
            raise PermissionDenied("Decryption key not available.")
        
        # Read encrypted file
        with open(encrypted_file.file_path, 'rb') as f:
            ciphertext = f.read()
        
        # Unwrap AES key
        aes_key = unwrap_aes_key_with_shared_secret(
            wrapped_key_data['ciphertext'],
            wrapped_key_data['key_nonce'],
            wrapped_key_data['shared_key'],
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
    Wraps AES key for the new user using a BB84-derived shared secret.
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
        
        if not owner_wrapped_key_data or 'shared_key' not in owner_wrapped_key_data:
            messages.error(request, "Cannot retrieve encryption key for this file.")
            return redirect('manage_file_sharing', file_id=file_id)
        
        # Unwrap AES key using owner's shared secret
        aes_key = unwrap_aes_key_with_shared_secret(
            owner_wrapped_key_data['ciphertext'],
            owner_wrapped_key_data['key_nonce'],
            owner_wrapped_key_data['shared_key'],
        )
        
        # Wrap AES key for the new user
        session_result = initiate_bb84_session()
        shared_key = session_result['shared_key']
        wrapped_key, key_nonce = wrap_aes_key_with_shared_secret(aes_key, shared_key)
        
        # Add wrapped key to the file
        encrypted_file.add_wrapped_key_for_user(
            new_user_email,
            wrapped_key,
            key_nonce,
            shared_key=shared_key,
            session_info={
                'error_rate': session_result['error_rate'],
                'sifted_key_length': session_result['sifted_key_length'],
                'num_intercepted': session_result['num_intercepted'],
                'eavesdropper_present': session_result['eavesdropper_present'],
            },
        )
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
                pending_sessions_count = 0
                
                for user in selected_users:
                    from .models import GroupMembership
                    GroupMembership.objects.create(
                        group=group,
                        user=user,
                        added_by=request.user
                    )
                    
                    # NEW: Establish pending BB84 session for group context
                    from .models import BB84Session
                    
                    # Check if session already exists
                    existing_session = BB84Session.objects.filter(
                        Q(sender=request.user, receiver=user) | Q(sender=user, receiver=request.user),
                        context_type='group',
                        group=group
                    ).first()
                    
                    if not existing_session:
                        # Create pending group-context session
                        BB84Session.objects.create(
                            sender=request.user,
                            receiver=user,
                            status='pending',
                            context_type='group',
                            group=group
                        )
                        pending_sessions_count += 1
                
                messages.success(
                    request, 
                    f'Group "{group.name}" created successfully with {selected_users.count()} members! '
                    f'{pending_sessions_count} group key exchange(s) pending.'
                )
                
                # Redirect to group key establishment page
                if pending_sessions_count > 0:
                    messages.info(request, 'Please establish group keys with all members before sharing files to this group.')
                    return redirect('establish_group_keys', group_id=group.id)
                else:
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


@login_required
def establish_group_keys_view(request, group_id):
    """
    View for establishing BB84 keys for a group context.
    Shows pending group key exchanges and allows users to initiate them.
    """
    try:
        group = get_object_or_404(UserGroup, id=group_id, created_by=request.user)
        
        # Get all group-context BB84 sessions for this group
        group_sessions = BB84Session.objects.filter(
            Q(sender=request.user) | Q(receiver=request.user),
            context_type='group',
            group=group
        ).select_related('sender', 'receiver')
        
        # Separate by status
        pending_sessions = group_sessions.filter(status='pending')
        active_sessions = group_sessions.filter(status__in=['accepted', 'transmitting', 'sifting', 'checking'])
        completed_sessions = group_sessions.filter(status='completed')
        failed_sessions = group_sessions.filter(status__in=['failed', 'aborted', 'expired'])
        
        # Get group members without completed keys
        all_members = group.members.exclude(id=request.user.id)
        members_with_keys = completed_sessions.values_list('sender_id', 'receiver_id')
        
        # Flatten the list and get unique member IDs with completed keys
        member_ids_with_keys = set()
        for sender_id, receiver_id in members_with_keys:
            if sender_id == request.user.id:
                member_ids_with_keys.add(receiver_id)
            else:
                member_ids_with_keys.add(sender_id)
        
        members_without_keys = all_members.exclude(id__in=member_ids_with_keys)
        
        context = {
            'group': group,
            'pending_sessions': pending_sessions,
            'active_sessions': active_sessions,
            'completed_sessions': completed_sessions,
            'failed_sessions': failed_sessions,
            'members_without_keys': members_without_keys,
            'total_members': all_members.count(),
            'keys_established': len(member_ids_with_keys),
        }
        
        return render(request, 'core/establish_group_keys.html', context)
        
    except Exception as e:
        logger.error(f"Failed to load group keys page for group {group_id}: {e}")
        messages.error(request, 'Failed to load group keys page.')
        return redirect('manage_groups')


def home_view(request):
    """
    Home page view.
    """
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'core/home.html')


@login_required
def key_exchange_view(request):
    """
    Unified BB84 quantum key exchange page.
    Shows:
    - Available recipients for new key exchange
    - Sent sessions (initiated by you)
    - Received sessions (pending your acceptance)
    """
    # Get or create online status for current user
    online_status, created = OnlineStatus.objects.get_or_create(user=request.user)
    online_status.update_heartbeat()
    
    # Get all users except current user
    available_users = QuantumUser.objects.exclude(id=request.user.id).order_by('email')
    
    # Ensure all users have online status records
    for user in available_users:
        OnlineStatus.objects.get_or_create(user=user)
    
    # Refresh to get online status for all
    available_users = QuantumUser.objects.exclude(id=request.user.id).select_related('online_status').order_by('email')
    
    # Get sessions where user is sender
    sent_sessions = BB84Session.objects.filter(
        sender=request.user
    ).select_related('receiver', 'file').order_by('-created_at')
    
    # Get sessions where user is receiver
    received_sessions = BB84Session.objects.filter(
        receiver=request.user
    ).select_related('sender', 'file').order_by('-created_at')
    
    context = {
        'available_users': available_users,
        'sent_sessions': sent_sessions,
        'received_sessions': received_sessions,
    }
    
    return render(request, 'core/key_exchange.html', context)


@login_required
@require_http_methods(["POST"])
def initiate_key_exchange_view(request):
    """
    Initiate BB84 key exchange REQUEST with selected recipients.
    Creates PENDING sessions that require receiver acceptance.
    BB84 protocol runs ONLY after receiver accepts.
    Supports both personal and group context.
    """
    recipient_emails = request.POST.getlist('recipients')
    
    # NEW: Check for group context
    group_id = request.GET.get('group') or request.POST.get('group')
    selected_group = None
    context_type = 'personal'
    
    if group_id:
        try:
            selected_group = UserGroup.objects.get(id=group_id, created_by=request.user)
            context_type = 'group'
        except UserGroup.DoesNotExist:
            messages.error(request, "Selected group not found.")
            return redirect('key_exchange')
    
    if not recipient_emails:
        messages.error(request, "Please select at least one recipient for key exchange.")
        if context_type == 'group':
            return redirect('establish_group_keys', group_id=selected_group.id)
        return redirect('key_exchange')
    
    # Validate recipients exist and are not the sender
    recipients = QuantumUser.objects.filter(email__in=recipient_emails).exclude(id=request.user.id)
    
    if len(recipients) != len(recipient_emails):
        messages.error(request, "Some selected recipients are invalid.")
        if context_type == 'group':
            return redirect('establish_group_keys', group_id=selected_group.id)
        return redirect('key_exchange')
    
    # Check if recipients are online (optional warning)
    offline_recipients = []
    for recipient in recipients:
        online_status = getattr(recipient, 'online_status', None)
        if not online_status or not online_status.check_online_status():
            offline_recipients.append(recipient.email)
    
    if offline_recipients:
        messages.warning(
            request,
            f"Note: Some recipients are offline: {', '.join(offline_recipients)}. "
            "They must come online to accept the key exchange request."
        )
    
    # Create PENDING BB84 sessions for each recipient (NO BB84 protocol run yet)
    created_sessions = []
    
    for recipient in recipients:
        # Check if there's already a pending or completed session with this recipient in the SAME CONTEXT
        session_filter = Q(
            sender=request.user,
            receiver=recipient,
            status__in=['pending', 'completed'],
            context_type=context_type
        )
        
        # For group context, match the specific group
        if context_type == 'group' and selected_group:
            session_filter &= Q(group=selected_group)
        else:
            # For personal context, ensure group is NULL
            session_filter &= Q(group__isnull=True)
        
        existing_session = BB84Session.objects.filter(session_filter).order_by('-created_at').first()
        
        if existing_session:
            if existing_session.status == 'pending':
                logger.info(f"Pending {context_type} session already exists: {existing_session.session_id} for {recipient.email}")
                created_sessions.append(existing_session)
                continue
            elif existing_session.status == 'completed':
                logger.info(f"Reusing existing completed {context_type} session {existing_session.session_id} for {recipient.email}")
                created_sessions.append(existing_session)
                continue
        
        # Create NEW pending session (awaiting receiver acceptance)
        logger.info(f"Creating pending BB84 {context_type} session request: {request.user.username} → {recipient.username}")
        
        session = BB84Session.objects.create(
            sender=request.user,
            receiver=recipient,
            status='pending',  # Waiting for receiver to accept
            receiver_accepted=False,
            progress_percentage=0,
            context_type=context_type,
            group=selected_group  # NULL for personal, group object for group context
        )
        
        created_sessions.append(session)
        
        # Log session creation
        AuditLog.log_action(
            user_email=request.user.email,
            action='bb84_session_initiated',
            details={
                'recipient': recipient.email,
                'session_id': str(session.session_id),
                'status': 'pending_receiver_acceptance',
                'context_type': context_type,
                'group': selected_group.name if selected_group else None
            },
            request=request,
            success=True
        )
        
        # TODO: Send email/notification to receiver about pending request
    
    # Show results to user
    if created_sessions:
        if context_type == 'group':
            messages.success(
                request,
                f"BB84 group key exchange request sent to {len(created_sessions)} recipient(s) for group '{selected_group.name}'. "
                "Waiting for them to accept before quantum key exchange begins."
            )
        else:
            messages.success(
                request,
                f"BB84 key exchange request sent to {len(created_sessions)} recipient(s). "
                "Waiting for them to accept before quantum key exchange begins."
            )
    
    # Redirect to sessions view or group keys view
    if context_type == 'group':
        return redirect('establish_group_keys', group_id=selected_group.id)
    return redirect('key_exchange')
    return redirect('bb84_sessions')


@login_required
def bb84_sessions_view(request):
    """
    View all BB84 sessions (sent and received).
    """
    # Update current user's heartbeat
    online_status, _ = OnlineStatus.objects.get_or_create(user=request.user)
    online_status.update_heartbeat()
    
    # Get sessions where user is sender
    sent_sessions = BB84Session.objects.filter(
        sender=request.user
    ).select_related('receiver', 'file').order_by('-created_at')
    
    # Get sessions where user is receiver
    received_sessions = BB84Session.objects.filter(
        receiver=request.user
    ).select_related('sender', 'file').order_by('-created_at')
    
    context = {
        'sent_sessions': sent_sessions,
        'received_sessions': received_sessions,
    }
    
    return render(request, 'core/bb84_sessions.html', context)


@login_required
def accept_bb84_session_view(request, session_id):
    """
    Receiver accepts a pending BB84 session and triggers the actual quantum key exchange.
    BB84 protocol runs with 10+ second timeline for educational visualization.
    """
    from .bb84_utils import run_bb84_protocol_with_timeline
    from .models import ActiveEavesdropper
    import threading
    
    session = get_object_or_404(BB84Session, session_id=session_id, receiver=request.user)
    
    if session.status != 'pending':
        messages.warning(request, "This session is no longer pending.")
        return redirect('bb84_sessions')
    
    # Mark as accepted by receiver
    session.receiver_accepted = True
    session.accepted_at = timezone.now()
    session.status = 'accepted'
    session.current_phase = 'Preparing quantum channel...'
    session.progress_percentage = 5
    session.save()
    
    messages.success(
        request,
        f"Accepted key exchange from {session.sender.username}. "
        "BB84 quantum protocol starting now (10-15 seconds)..."
    )
    
    # Check if there's an active eavesdropper in the system
    active_eve = ActiveEavesdropper.get_active()
    simulate_eve = active_eve is not None
    eve_probability = active_eve.intercept_probability if simulate_eve else 0.0
    eve_injector = active_eve.injected_by if simulate_eve else None
    
    # Run BB84 protocol in background thread (with 10+ second timeline)
    def run_bb84_async():
        try:
            logger.info(
                f"Starting BB84 protocol with timeline: {session.sender.username} → {session.receiver.username}"
                f"{' [EAVESDROPPER ACTIVE]' if simulate_eve else ''}"
            )
            
            # This function will take 10-15 seconds and update session.current_phase as it goes
            bb84_result = run_bb84_protocol_with_timeline(
                session=session,
                eavesdropper_present=simulate_eve,
                eavesdrop_probability=eve_probability
            )
            
            # Update session with final results
            session.status = 'completed'
            session.sender_bits = bb84_result['sender_bits']
            session.sender_bases = bb84_result['sender_bases']
            session.receiver_bases = bb84_result['receiver_bases']
            session.receiver_measurements = bb84_result['receiver_measurements']
            session.matched_indices = bb84_result['matched_indices']
            session.sifted_key_length = bb84_result['sifted_key_length']
            session.error_rate = bb84_result['error_rate']
            session.sampled_indices = bb84_result.get('sampled_indices', [])
            session.shared_key = bb84_result['shared_key']
            session.eavesdropper_present = simulate_eve
            session.eavesdrop_probability = eve_probability
            session.num_intercepted = bb84_result.get('num_intercepted', 0)
            session.eavesdropper_injected_by = eve_injector
            session.current_phase = 'Completed - Shared key established'
            session.progress_percentage = 100
            session.completed_at = timezone.now()
            session.save()
            
            # Update eavesdropper statistics if Eve was active
            if simulate_eve and active_eve:
                active_eve.sessions_intercepted += 1
                active_eve.total_qubits_intercepted += bb84_result.get('num_intercepted', 0)
                if bb84_result['error_rate'] > 0.15:  # Detection threshold
                    active_eve.detections_count += 1
                active_eve.save()
            
            # Log successful completion
            AuditLog.log_action(
                user_email=session.receiver.email,
                action='bb84_protocol_completed',
                details={
                    'sender': session.sender.email,
                    'session_id': str(session.session_id),
                    'error_rate': bb84_result['error_rate'],
                    'sifted_bits': bb84_result['sifted_key_length'],
                    'eavesdropper_active': simulate_eve,
                    'eavesdropper_detected': bb84_result['error_rate'] > 0.15
                },
                request=None,  # Background thread
                success=True
            )
            
            # Send webhook notification if eavesdropping detected
            if simulate_eve and bb84_result['error_rate'] > 0.15:
                from .webhooks import send_eavesdropper_detection_webhook
                send_eavesdropper_detection_webhook(session, bb84_result)
            
        except Exception as e:
            logger.error(f"BB84 protocol failed: {e}")
            session.status = 'failed'
            session.current_phase = f'Failed: {str(e)}'
            session.progress_percentage = 0
            session.save()
            
            AuditLog.log_action(
                user_email=session.receiver.email,
                action='bb84_protocol_failed',
                details={
                    'sender': session.sender.email,
                    'session_id': str(session.session_id),
                    'error': str(e)
                },
                request=None,
                success=False,
                error_message=str(e)
            )
    
    # Start BB84 in background
    thread = threading.Thread(target=run_bb84_async, daemon=True)
    thread.start()
    
    # Redirect to sessions page where user can watch progress
    return redirect('bb84_sessions')


@login_required
def bb84_session_status_view(request, session_id):
    """
    Get BB84 session status as JSON (for AJAX polling with real-time timeline).
    """
    session = get_object_or_404(
        BB84Session,
        session_id=session_id
    )
    
    # Check authorization
    if request.user != session.sender and request.user != session.receiver:
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    summary = session.get_protocol_summary()
    
    return JsonResponse({
        'session_id': str(session.session_id),
        'status': session.status,
        'current_phase': session.current_phase,
        'progress_percentage': session.progress_percentage,
        'phase_timeline': session.phase_timeline or [],
        'summary': summary,
        'can_proceed': session.can_proceed_to_upload()
    })

