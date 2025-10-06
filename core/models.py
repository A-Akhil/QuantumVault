from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
import json
import base64
import uuid
from datetime import timedelta


class QuantumUser(AbstractUser):
    """
    Extended User model with post-quantum cryptographic keys.
    Retains Kyber fields for backward compatibility but BB84 provides session keys.
    """
    email = models.EmailField(unique=True)
    
    # Kyber768 key material retained for legacy migrations (unused in BB84 flow)
    kyber_public_key = models.BinaryField(
        max_length=2048,
        blank=True,
        default=b"",
        help_text="Legacy Kyber768 public key (preserved for backward compatibility)",
    )
    kyber_private_key = models.BinaryField(
        max_length=2048,
        blank=True,
        default=b"",
        help_text="Legacy Kyber768 private key (preserved for backward compatibility)",
    )
    
    # Dilithium3 Digital Signature keys (for file integrity)
    dilithium_public_key = models.BinaryField(max_length=4096, help_text="Dilithium3 public key (raw bytes)")
    dilithium_private_key = models.BinaryField(max_length=4096, help_text="Dilithium3 private key (raw bytes)")
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'quantum_users'

    def __str__(self):
        return f"{self.username} ({self.email})"

    def has_quantum_keys(self):
        """Check if user has the minimum quantum-era credentials (Dilithium keys)."""
        return all([
            self.dilithium_public_key,
            self.dilithium_private_key,
        ])


class EncryptedFile(models.Model):
    """
    Model for storing encrypted files with post-quantum security.
    Files are encrypted with AES-256-GCM and AES keys are wrapped with BB84-derived secrets.
    """
    # File identification
    filename = models.CharField(max_length=255, help_text="Display filename")
    original_filename = models.CharField(max_length=255, help_text="Original uploaded filename")
    file_path = models.CharField(max_length=500, help_text="Path to encrypted file on filesystem")
    file_size = models.BigIntegerField(help_text="Size of original file in bytes")
    mime_type = models.CharField(max_length=100, blank=True, help_text="MIME type of original file")
    
    # Ownership and access
    uploaded_by = models.ForeignKey(QuantumUser, on_delete=models.CASCADE, related_name='uploaded_files')
    
    # Encryption metadata
    aes_nonce = models.BinaryField(max_length=16, help_text="AES-GCM nonce (12 bytes)")
    wrapped_keys = models.JSONField(help_text="JSON mapping user emails to their wrapped AES keys")
    
    # Digital signature for integrity
    metadata_signature = models.BinaryField(max_length=4096, help_text="Dilithium3 signature of file metadata")
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'encrypted_files'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.filename} (uploaded by {self.uploaded_by.username})"

    def get_wrapped_key_for_user(self, user_email):
        """Get the wrapped AES key and BB84 artefacts for a specific user."""
        wrapped_data = self.wrapped_keys.get(user_email)
        if wrapped_data:
            result = {
                'ciphertext': base64.b64decode(wrapped_data['ciphertext']),
                'key_nonce': base64.b64decode(wrapped_data['key_nonce'])
            }
            if 'shared_key' in wrapped_data:
                result['shared_key'] = base64.b64decode(wrapped_data['shared_key'])
            if 'bb84_session' in wrapped_data:
                result['bb84_session'] = wrapped_data['bb84_session']
            return result
        return None

    def add_wrapped_key_for_user(self, user_email, ciphertext, key_nonce, shared_key=None, session_info=None):
        """Add a wrapped AES key for a specific user."""
        if not self.wrapped_keys:
            self.wrapped_keys = {}
        
        entry = {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'key_nonce': base64.b64encode(key_nonce).decode('utf-8')
        }
        if shared_key is not None:
            entry['shared_key'] = base64.b64encode(shared_key).decode('utf-8')
        if session_info is not None:
            entry['bb84_session'] = session_info

        self.wrapped_keys[user_email] = entry

    def get_recipient_emails(self):
        """Get list of all users who have access to this file"""
        if not self.wrapped_keys:
            return []
        
        # Filter out non-email entries (metadata keys)
        emails = []
        for key in self.wrapped_keys.keys():
            if not key.startswith('_'):
                emails.append(key)
        return emails


class FileAccess(models.Model):
    """
    Model for tracking file access permissions.
    Records which users have been granted access to which files.
    """
    file = models.ForeignKey(EncryptedFile, on_delete=models.CASCADE, related_name='access_records')
    user_email = models.EmailField(help_text="Email of user with access")
    granted_by = models.ForeignKey(QuantumUser, on_delete=models.CASCADE, related_name='granted_access')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'file_access'
        unique_together = ['file', 'user_email']  # Prevent duplicate access records
        ordering = ['-created_at']

    def __str__(self):
        return f"Access to {self.file.filename} granted to {self.user_email}"


class AuditLog(models.Model):
    """
    Model for comprehensive audit logging of all file operations.
    Tracks uploads, downloads, shares, and other security-relevant events.
    """
    ACTION_CHOICES = [
        ('register', 'User Registration'),
        ('login', 'User Login'),
        ('logout', 'User Logout'),
        ('upload', 'File Upload'),
        ('download', 'File Download'),
        ('share', 'File Share'),
        ('access_granted', 'Access Granted'),
        ('access_denied', 'Access Denied'),
        ('key_generation', 'Key Generation'),
        ('signature_verification', 'Signature Verification'),
    ]

    # Core audit information
    user_email = models.EmailField(help_text="Email of user performing action")
    action = models.CharField(max_length=30, choices=ACTION_CHOICES)
    
    # Optional file reference
    file = models.ForeignKey(EncryptedFile, on_delete=models.SET_NULL, null=True, blank=True)
    
    # Additional details in JSON format
    details = models.JSONField(default=dict, help_text="Additional context and metadata")
    
    # Network and security context
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    
    # Success/failure tracking
    success = models.BooleanField(default=True)
    error_message = models.TextField(blank=True)
    
    # Timestamp
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'audit_logs'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user_email', '-timestamp']),
            models.Index(fields=['action', '-timestamp']),
            models.Index(fields=['success', '-timestamp']),
        ]

    def __str__(self):
        status = "✓" if self.success else "✗"
        return f"{status} {self.user_email} - {self.get_action_display()} ({self.timestamp})"

    @classmethod
    def log_action(cls, user_email, action, file=None, details=None, request=None, success=True, error_message=""):
        """
        Convenience method for logging actions
        """
        log_entry = cls(
            user_email=user_email,
            action=action,
            file=file,
            details=details or {},
            success=success,
            error_message=error_message
        )
        
        if request:
            log_entry.ip_address = cls.get_client_ip(request)
            log_entry.user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        log_entry.save()
        return log_entry

    @staticmethod
    def get_client_ip(request):
        """Extract client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class UserGroup(models.Model):
    """
    Model for user-created groups to simplify file sharing.
    Users can create groups of people they frequently share files with.
    """
    name = models.CharField(max_length=100, help_text="Group name")
    description = models.TextField(blank=True, help_text="Optional group description")
    created_by = models.ForeignKey(QuantumUser, on_delete=models.CASCADE, related_name='created_groups')
    members = models.ManyToManyField(
        QuantumUser, 
        through='GroupMembership', 
        through_fields=('group', 'user'),
        related_name='member_of_groups'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'user_groups'
        unique_together = ['name', 'created_by']  # Each user can have unique group names

    def __str__(self):
        return f"{self.name} (by {self.created_by.username})"

    def get_member_emails(self):
        """Get list of member email addresses"""
        return list(self.members.values_list('email', flat=True))

    def get_member_count(self):
        """Get number of members in the group"""
        return self.members.count()


class GroupMembership(models.Model):
    """
    Through model for UserGroup many-to-many relationship with QuantumUser.
    Tracks when users were added to groups.
    """
    group = models.ForeignKey(UserGroup, on_delete=models.CASCADE)
    user = models.ForeignKey(QuantumUser, on_delete=models.CASCADE)
    added_at = models.DateTimeField(auto_now_add=True)
    added_by = models.ForeignKey(QuantumUser, on_delete=models.CASCADE, related_name='group_additions')

    class Meta:
        db_table = 'group_memberships'
        unique_together = ['group', 'user']  # Each user can only be in a group once

    def __str__(self):
        return f"{self.user.username} in {self.group.name}"


class OnlineStatus(models.Model):
    """
    Track online/offline status of users for real-time BB84 key exchange sessions.
    Users must be online to participate in quantum key distribution.
    """
    user = models.OneToOneField(
        QuantumUser,
        on_delete=models.CASCADE,
        related_name='online_status',
        primary_key=True
    )
    is_online = models.BooleanField(default=False)
    last_seen = models.DateTimeField(auto_now=True)
    last_heartbeat = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'online_status'
        verbose_name_plural = 'online statuses'

    def __str__(self):
        status = "Online" if self.is_online else "Offline"
        return f"{self.user.username} - {status}"

    def update_heartbeat(self):
        """Update heartbeat timestamp and mark user as online"""
        self.last_heartbeat = timezone.now()
        self.is_online = True
        self.save(update_fields=['last_heartbeat', 'is_online'])

    def check_online_status(self):
        """Check if user is still online (heartbeat within last 60 seconds)"""
        timeout_threshold = timezone.now() - timedelta(seconds=60)
        if self.last_heartbeat < timeout_threshold:
            self.is_online = False
            self.save(update_fields=['is_online'])
        return self.is_online


class BB84Session(models.Model):
    """
    Represents a pairwise BB84 quantum key distribution session between sender and receiver.
    Each file sharing requires separate BB84 sessions for each recipient.
    
    Protocol Flow:
    1. Sender creates session (status='pending')
    2. Receiver accepts and provides measurement bases (status='active')
    3. Basis reconciliation and sifting (status='sifting')
    4. Error estimation and privacy amplification (status='completed')
    5. Shared key used to wrap AES file encryption key
    """
    # Session identification
    session_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    
    # Parties involved (pairwise session)
    sender = models.ForeignKey(
        QuantumUser,
        on_delete=models.CASCADE,
        related_name='bb84_sessions_as_sender'
    )
    receiver = models.ForeignKey(
        QuantumUser,
        on_delete=models.CASCADE,
        related_name='bb84_sessions_as_receiver'
    )
    
    # File association (set after file upload completes)
    file = models.ForeignKey(
        EncryptedFile,
        on_delete=models.CASCADE,
        related_name='bb84_sessions',
        null=True,
        blank=True
    )
    
    # Session state
    STATUS_CHOICES = [
        ('pending', 'Pending - Waiting for receiver acceptance'),
        ('accepted', 'Accepted - Preparing key exchange'),
        ('transmitting', 'Transmitting - Quantum states in transit'),
        ('sifting', 'Sifting - Reconciling measurement bases'),
        ('checking', 'Checking - Verifying error rate'),
        ('completed', 'Completed - Shared key established'),
        ('failed', 'Failed - Eavesdropping detected or error threshold exceeded'),
        ('aborted', 'Aborted - Session cancelled by user'),
        ('expired', 'Expired - Session timeout'),
    ]
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    # Receiver acceptance
    receiver_accepted = models.BooleanField(
        default=False,
        help_text="Whether receiver has accepted this BB84 session request"
    )
    accepted_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp when receiver accepted the session"
    )
    
    # BB84 Protocol Data (JSON fields for flexibility)
    sender_bits = models.JSONField(
        null=True,
        blank=True,
        help_text="Sender's random bit sequence for quantum state preparation"
    )
    sender_bases = models.JSONField(
        null=True,
        blank=True,
        help_text="Sender's basis choices ('+' rectilinear, '×' diagonal)"
    )
    receiver_bases = models.JSONField(
        null=True,
        blank=True,
        help_text="Receiver's measurement basis choices"
    )
    receiver_measurements = models.JSONField(
        null=True,
        blank=True,
        help_text="Receiver's measurement results"
    )
    
    # Sifting and reconciliation results
    matched_indices = models.JSONField(
        null=True,
        blank=True,
        help_text="Indices where sender and receiver bases matched"
    )
    sifted_key_length = models.IntegerField(
        null=True,
        blank=True,
        help_text="Number of bits after basis sifting"
    )
    error_rate = models.FloatField(
        null=True,
        blank=True,
        help_text="Quantum Bit Error Rate (QBER) from sample comparison"
    )
    sampled_indices = models.JSONField(
        null=True,
        blank=True,
        help_text="Indices used for error rate estimation"
    )
    
    # Final shared key (256-bit after privacy amplification)
    shared_key = models.BinaryField(
        max_length=32,
        null=True,
        blank=True,
        help_text="Final 256-bit shared secret for AES key wrapping"
    )
    
    # Eavesdropping simulation (for educational demos - EXTERNAL CONTROL ONLY)
    eavesdropper_present = models.BooleanField(
        default=False,
        help_text="Simulate eavesdropper (Eve) - controlled by external script/API only"
    )
    eavesdrop_probability = models.FloatField(
        default=0.0,
        help_text="Probability of Eve intercepting each qubit (0.0 to 1.0)"
    )
    num_intercepted = models.IntegerField(
        default=0,
        help_text="Number of qubits intercepted by simulated eavesdropper"
    )
    eavesdropper_injected_by = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        help_text="Email/ID of external entity that injected eavesdropper"
    )
    
    # Timeline tracking for 10-second visualization
    phase_timeline = models.JSONField(
        null=True,
        blank=True,
        help_text="Timeline of BB84 protocol phases with timestamps"
    )
    current_phase = models.CharField(
        max_length=50,
        null=True,
        blank=True,
        help_text="Current phase of BB84 protocol for real-time display"
    )
    progress_percentage = models.IntegerField(
        default=0,
        help_text="Progress percentage (0-100) for UI display"
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Session expiration time (15 minutes from creation)"
    )

    class Meta:
        db_table = 'bb84_sessions'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['sender', 'receiver', 'status']),
            models.Index(fields=['session_id']),
            models.Index(fields=['status', 'created_at']),
        ]

    def __str__(self):
        return f"BB84 Session {self.session_id} ({self.sender.username} → {self.receiver.username}): {self.status}"

    def save(self, *args, **kwargs):
        # Set expiration time on creation (15 minutes)
        if not self.pk and not self.expires_at:
            self.expires_at = timezone.now() + timedelta(minutes=15)
        
        # Set completion timestamp when status changes to completed
        if self.status == 'completed' and not self.completed_at:
            self.completed_at = timezone.now()
        
        super().save(*args, **kwargs)

    def is_expired(self):
        """Check if session has expired"""
        if self.expires_at:
            return timezone.now() > self.expires_at
        return False

    def can_proceed_to_upload(self):
        """Check if this session can be used for file upload"""
        return (
            self.status == 'completed' and
            self.shared_key is not None and
            not self.is_expired()
        )

    def get_protocol_summary(self):
        """Get human-readable summary of BB84 protocol execution"""
        if self.status == 'pending':
            return "Waiting for receiver to accept key exchange request"
        
        summary = {
            'session_id': str(self.session_id),
            'status': self.get_status_display(),
            'sifted_bits': self.sifted_key_length,
            'error_rate': f"{self.error_rate * 100:.2f}%" if self.error_rate is not None else "N/A",
            'eavesdropper': "Detected" if self.eavesdropper_present and self.num_intercepted > 0 else "None",
            'shared_key_established': self.shared_key is not None,
        }
        
        if self.completed_at:
            duration = (self.completed_at - self.created_at).total_seconds()
            summary['duration'] = f"{duration:.2f} seconds"
        
        return summary


class ActiveEavesdropper(models.Model):
    """
    Singleton model - Only ONE active eavesdropper allowed system-wide.
    Represents external eavesdropper injected via API/script.
    """
    # Identification
    eavesdropper_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    injected_by = models.CharField(
        max_length=255,
        help_text="Email or identifier of entity that injected eavesdropper"
    )
    
    # Control parameters
    intercept_probability = models.FloatField(
        default=0.5,
        help_text="Probability of intercepting each qubit (0.0 to 1.0)"
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Whether eavesdropper is currently active"
    )
    
    # Statistics
    sessions_intercepted = models.IntegerField(
        default=0,
        help_text="Total number of BB84 sessions this eavesdropper has intercepted"
    )
    total_qubits_intercepted = models.IntegerField(
        default=0,
        help_text="Total number of qubits intercepted across all sessions"
    )
    detections_count = models.IntegerField(
        default=0,
        help_text="Number of times this eavesdropper was detected"
    )
    
    # Timestamps
    activated_at = models.DateTimeField(auto_now_add=True)
    deactivated_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'active_eavesdropper'
        verbose_name = 'Active Eavesdropper'
        verbose_name_plural = 'Active Eavesdroppers'
    
    def __str__(self):
        status = "Active" if self.is_active else "Deactivated"
        return f"Eavesdropper {self.eavesdropper_id} ({status}) - injected by {self.injected_by}"
    
    def deactivate(self):
        """Deactivate this eavesdropper"""
        self.is_active = False
        self.deactivated_at = timezone.now()
        self.save()
    
    @classmethod
    def get_active(cls):
        """Get the currently active eavesdropper, if any"""
        return cls.objects.filter(is_active=True).first()
    
    @classmethod
    def ensure_singleton(cls):
        """Ensure only one active eavesdropper exists (deactivate others)"""
        active_eves = cls.objects.filter(is_active=True)
        if active_eves.count() > 1:
            # Keep the most recent, deactivate others
            most_recent = active_eves.order_by('-activated_at').first()
            for eve in active_eves:
                if eve.id != most_recent.id:
                    eve.deactivate()
        return active_eves.first()

