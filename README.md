# QuantumVault

A quantum-safe file storage and sharing system built with Django, implementing post-quantum cryptography algorithms for secure file encryption and sharing.

## Overview

QuantumVault is a secure file storage platform that uses post-quantum cryptographic algorithms to protect files against both classical and quantum computing attacks. The system implements Kyber768 for key encapsulation and Dilithium3 for digital signatures, ensuring long-term security even in a post-quantum world.

## Features

### Core Security Features
- **Post-Quantum Cryptography**: Implements NIST-approved algorithms (Kyber768, Dilithium3)
- **Hybrid Encryption**: Combines AES-256-GCM with Kyber768 key wrapping
- **Digital Signatures**: File integrity verification using Dilithium3 signatures
- **Quantum-Safe Key Generation**: Automatic generation of post-quantum key pairs for each user

### File Management
- **Multiple File Upload**: Upload and encrypt multiple files simultaneously
- **Secure File Sharing**: Share encrypted files with specific users
- **Access Control Management**: Grant and revoke file access permissions
- **File Integrity Verification**: Cryptographic verification of file authenticity

### User Interface
- **Modern Design**: Professional glassmorphism UI with responsive layout
- **Two-Column Layout**: Optimized file upload interface with user selection
- **Real-time File Preview**: JavaScript-powered file management with live preview
- **Intuitive Dashboard**: Comprehensive view of uploaded and shared files

### Security & Audit
- **Comprehensive Audit Logging**: Track all user actions and file operations
- **Access Control**: Role-based permissions and file-level access control
- **Secure Session Management**: Django-based authentication with quantum-safe enhancements
- **Error Handling**: Robust error handling and security logging

## Installation

### Prerequisites
- Python 3.8 or higher
- Git
- Virtual environment support

### Clone Repository
```bash
git clone https://github.com/A-Akhil/QuantumVault.git
cd QuantumVault
```

### Setup Virtual Environment
```bash
python -m venv quantum_storage_env
source quantum_storage_env/bin/activate  # On Linux/Mac
# quantum_storage_env\Scripts\activate  # On Windows
```

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Configure Settings
The project comes with a pre-configured settings.py file. For production deployment, you may want to:
- Update the SECRET_KEY in quantum_storage/settings.py
- Configure database settings if using a different database
- Set DEBUG = False for production
- Configure allowed hosts and static file serving

### Database Setup
```bash
python manage.py makemigrations
python manage.py migrate
```

### Create Superuser (Optional)
```bash
python manage.py createsuperuser
```

### Run Development Server
```bash
python manage.py runserver
```

Visit `http://127.0.0.1:8000` to access the application.

## Architecture

### Cryptographic Components
- **Kyber768**: NIST Post-Quantum Key Encapsulation Mechanism
- **Dilithium3**: NIST Post-Quantum Digital Signature Algorithm
- **AES-256-GCM**: Symmetric encryption for file content
- **Secure Random Generation**: Cryptographically secure random number generation

### Key Workflow
1. **User Registration**: Generate Kyber768 and Dilithium3 key pairs
2. **File Upload**: Encrypt files with AES-256-GCM, wrap keys with Kyber768
3. **File Sharing**: Re-wrap AES keys for additional recipients
4. **File Download**: Unwrap keys and decrypt files with access verification
5. **Signature Verification**: Verify file integrity using Dilithium3 signatures

### Security Model
- **End-to-End Encryption**: Files are encrypted before storage
- **Key Separation**: Each file uses unique AES keys
- **Forward Secrecy**: Individual file keys cannot compromise other files
- **Quantum Resistance**: All cryptographic operations use post-quantum algorithms

## Usage

### User Registration
1. Navigate to the registration page
2. Provide username, email, and password
3. System automatically generates quantum-safe key pairs
4. User is logged in with full access to features

### File Upload and Sharing
1. Access the upload page from the dashboard
2. Select multiple files using the file picker
3. Choose recipients from the user list
4. Upload files - each is encrypted individually
5. Recipients receive access to decrypt and download files

### File Management
1. View uploaded and shared files on the dashboard
2. Manage file access permissions
3. Add or remove user access to specific files
4. Delete files permanently (owner only)

### Audit and Monitoring
1. View personal audit logs
2. Track file access and sharing activities
3. Monitor security events and system usage

## Project Structure

```
quantum_storage/
├── core/                   # Main application
│   ├── models.py          # Database models
│   ├── views.py           # View controllers
│   ├── crypto_utils.py    # Cryptographic utilities
│   ├── forms.py           # Django forms
│   └── templates/         # HTML templates
├── quantum_storage/       # Django project settings
├── static/               # Static files (CSS, JS)
├── requirements.txt      # Python dependencies
└── manage.py            # Django management script
```

## Security Considerations

### Quantum Threat Model
- **Current Protection**: Secure against classical computing attacks
- **Future Protection**: Resistant to quantum computing attacks
- **Algorithm Selection**: Based on NIST Post-Quantum Cryptography standards

### Implementation Security
- **Secure Coding**: Follows Django security best practices
- **Input Validation**: Comprehensive validation and sanitization
- **Error Handling**: Secure error handling without information leakage
- **Audit Trail**: Complete logging of security-relevant events

### Deployment Security
- **HTTPS Required**: All communications must use TLS
- **Secure Headers**: Implement security headers for web protection
- **Database Security**: Encrypt sensitive data at rest
- **File Storage**: Secure file storage with appropriate permissions

## Development

### Contributing
1. Fork the repository
2. Create a feature branch
3. Implement changes with tests
4. Submit a pull request

### Testing
```bash
python manage.py test
```

### Code Quality
- Follow PEP 8 style guidelines
- Include comprehensive documentation
- Implement unit tests for new features
- Maintain security-focused code reviews

## Technical Requirements

### Dependencies
- Django 4.2+
- liboqs (Post-Quantum Cryptography library)
- Python cryptographic libraries
- Bootstrap 5.3 (Frontend)

### System Requirements
- Memory: Minimum 2GB RAM
- Storage: Depends on file storage needs
- CPU: Modern processor for cryptographic operations

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Support

For questions, issues, or contributions:
- Create an issue on GitHub
- Review existing documentation
- Follow security disclosure procedures for vulnerabilities

## Acknowledgments

- NIST Post-Quantum Cryptography Standardization
- Open Quantum Safe (OQS) project
- Django web framework community
- Post-quantum cryptography research community

## Disclaimer

This implementation is for educational and research purposes. For production use, conduct thorough security audits and follow enterprise security practices.
