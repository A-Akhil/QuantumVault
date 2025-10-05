"""
Django forms for quantum-safe file storage system.
"""

from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.core.exceptions import ValidationError
from .models import QuantumUser, EncryptedFile, UserGroup
import logging

logger = logging.getLogger(__name__)


class QuantumUserRegistrationForm(UserCreationForm):
    """
    Registration form for new users with quantum key generation.
    """
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your email address'
        })
    )
    
    first_name = forms.CharField(
        max_length=30,
        required=True,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'First name'
        })
    )
    
    last_name = forms.CharField(
        max_length=30,
        required=True,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Last name'
        })
    )

    class Meta:
        model = QuantumUser
        fields = ('username', 'first_name', 'last_name', 'email', 'password1', 'password2')
        widgets = {
            'username': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Choose a username'
            }),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['password1'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Create a password'
        })
        self.fields['password2'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Confirm your password'
        })

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if QuantumUser.objects.filter(email=email).exists():
            raise ValidationError("A user with this email already exists.")
        return email

    def save(self, commit=True):
        """
        Save user with quantum cryptographic key generation.
        """
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        
        if commit:
            # The key generation will be handled in the view
            # to properly handle errors and logging
            user.save()
        return user


class QuantumUserLoginForm(AuthenticationForm):
    """
    Login form with improved styling.
    """
    username = forms.CharField(
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Username or email'
        })
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Password'
        })
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['username'].label = 'Username or Email'


class FileUploadForm(forms.Form):
    """
    Form for uploading and encrypting files.
    """
    file = forms.FileField(
        widget=forms.ClearableFileInput(attrs={
            'class': 'form-control',
            'accept': '.txt,.pdf,.doc,.docx,.jpg,.jpeg,.png,.zip'
        }),
        help_text="Maximum file size: 50MB. Allowed types: TXT, PDF, DOC, DOCX, JPG, PNG, ZIP"
    )
    
    recipients = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 3,
            'placeholder': 'Enter recipient email addresses, one per line'
        }),
        help_text="Enter email addresses of users who should have access to this file"
    )
    
    description = forms.CharField(
        max_length=500,
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 2,
            'placeholder': 'Optional: Describe the file contents'
        })
    )

    def clean_file(self):
        file = self.cleaned_data.get('file')
        if not file:
            return file
        
        # Check file size (50MB limit)
        max_size = 50 * 1024 * 1024  # 50MB
        if file.size > max_size:
            raise ValidationError(f"File too large. Maximum size is {max_size // (1024*1024)}MB.")
        
        # Check file extension
        allowed_extensions = ['.txt', '.pdf', '.doc', '.docx', '.jpg', '.jpeg', '.png', '.zip']
        file_name = file.name.lower()
        if not any(file_name.endswith(ext) for ext in allowed_extensions):
            raise ValidationError(f"File type not allowed. Allowed types: {', '.join(allowed_extensions)}")
        
        return file

    def clean_recipients(self):
        recipients_text = self.cleaned_data.get('recipients', '')
        
        # Parse email addresses
        email_lines = [line.strip() for line in recipients_text.split('\n') if line.strip()]
        
        if not email_lines:
            raise ValidationError("At least one recipient email is required.")
        
        # Validate each email
        valid_emails = []
        for email in email_lines:
            email = email.strip()
            if email:
                # Basic email validation
                forms.EmailField().clean(email)
                
                # Check if user exists
                if not QuantumUser.objects.filter(email=email).exists():
                    raise ValidationError(f"No user found with email: {email}")
                
                valid_emails.append(email)
        
        if not valid_emails:
            raise ValidationError("No valid recipient emails provided.")
        
        # Remove duplicates while preserving order
        seen = set()
        unique_emails = []
        for email in valid_emails:
            if email not in seen:
                seen.add(email)
                unique_emails.append(email)
        
        return unique_emails


class FileShareForm(forms.Form):
    """
    Form for sharing existing files with additional users.
    """
    additional_recipients = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 3,
            'placeholder': 'Enter additional recipient email addresses, one per line'
        }),
        help_text="Enter email addresses of additional users who should have access to this file"
    )

    def clean_additional_recipients(self):
        recipients_text = self.cleaned_data.get('additional_recipients', '')
        
        # Parse email addresses
        email_lines = [line.strip() for line in recipients_text.split('\n') if line.strip()]
        
        if not email_lines:
            raise ValidationError("At least one additional recipient email is required.")
        
        # Validate each email
        valid_emails = []
        for email in email_lines:
            email = email.strip()
            if email:
                # Basic email validation
                forms.EmailField().clean(email)
                
                # Check if user exists
                if not QuantumUser.objects.filter(email=email).exists():
                    raise ValidationError(f"No user found with email: {email}")
                
                valid_emails.append(email)
        
        if not valid_emails:
            raise ValidationError("No valid additional recipient emails provided.")
        
        # Remove duplicates
        return list(set(valid_emails))


class UserSearchForm(forms.Form):
    """
    Form for searching users by email or username.
    """
    query = forms.CharField(
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Search by username or email...'
        })
    )

    def clean_query(self):
        query = self.cleaned_data.get('query', '').strip()
        if len(query) < 2:
            raise ValidationError("Search query must be at least 2 characters long.")
        return query


class UserGroupForm(forms.ModelForm):
    """
    Form for creating and editing user groups.
    """
    class Meta:
        model = UserGroup
        fields = ['name', 'description']
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter group name (e.g., "Project Team", "Family")',
                'maxlength': 100
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'placeholder': 'Optional description of the group...',
                'rows': 3
            })
        }

    def clean_name(self):
        name = self.cleaned_data.get('name', '').strip()
        if len(name) < 2:
            raise ValidationError("Group name must be at least 2 characters long.")
        if len(name) > 100:
            raise ValidationError("Group name cannot exceed 100 characters.")
        return name


class GroupMemberSelectionForm(forms.Form):
    """
    Form for selecting users to add to a group.
    """
    selected_users = forms.ModelMultipleChoiceField(
        queryset=None,  # Will be set in __init__
        widget=forms.CheckboxSelectMultiple(attrs={
            'class': 'form-check-input'
        }),
        required=False,
        label="Select users to add to group"
    )

    def __init__(self, current_user=None, existing_members=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Get all users except current user and existing members
        queryset = QuantumUser.objects.exclude(id=current_user.id if current_user else None)
        if existing_members:
            queryset = queryset.exclude(id__in=[member.id for member in existing_members])
        
        self.fields['selected_users'].queryset = queryset.order_by('username')