from django.db import models
from django.contrib.auth.models import AbstractUser
import json
import base64


class QuantumUser(AbstractUser):
    """
    Extended User model with post-quantum cryptographic keys.
    Stores Kyber768 and Dilithium3 keypairs for each user.
    """
    email = models.EmailField(unique=True)
    
    # Kyber768 Key Encapsulation Mechanism keys (for file encryption)
    kyber_public_key = models.BinaryField(max_length=2048, help_text="Kyber768 public key (raw bytes)")
    kyber_private_key = models.BinaryField(max_length=2048, help_text="Kyber768 private key (raw bytes)")
    
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
        """Check if user has all required quantum cryptographic keys"""
        return all([
            self.kyber_public_key,
            self.kyber_private_key,
            self.dilithium_public_key,
            self.dilithium_private_key
        ])


class EncryptedFile(models.Model):
    """
    Model for storing encrypted files with post-quantum security.
    Files are encrypted with AES-256-GCM, and AES keys are wrapped with Kyber768.
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
        """Get the wrapped AES key for a specific user"""
        wrapped_data = self.wrapped_keys.get(user_email)
        if wrapped_data:
            return {
                'ciphertext': base64.b64decode(wrapped_data['ciphertext']),
                'key_nonce': base64.b64decode(wrapped_data['key_nonce'])
            }
        return None

    def add_wrapped_key_for_user(self, user_email, ciphertext, key_nonce):
        """Add a wrapped AES key for a specific user"""
        if not self.wrapped_keys:
            self.wrapped_keys = {}
        
        self.wrapped_keys[user_email] = {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'key_nonce': base64.b64encode(key_nonce).decode('utf-8')
        }

    def get_recipient_emails(self):
        """Get list of all users who have access to this file"""
        return list(self.wrapped_keys.keys()) if self.wrapped_keys else []


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
