# QuantumVault

A quantum-safe file storage and sharing system built with Django, implementing post-quantum cryptography algorithms for secure file encryption and sharing.

## Overview

QuantumVault is a secure file storage platform that uses **post-quantum cryptographic algorithms** to protect files against both classical and quantum computing attacks. The system implements:

- **BB84 Quantum Key Distribution Protocol** (classical simulation) for secure key exchange between users
- **Dilithium3 Digital Signatures** (NIST FIPS 204) for file integrity and authenticity
- **AES-256-GCM** for authenticated encryption of file content
- **BB84-based key wrapping** for secure multi-user file sharing

**Note on Kyber768**: The system retains Kyber768 fields in the database for backward compatibility, but the **current implementation uses BB84 exclusively** for key exchange. Kyber is not actively used.

## Features

### Core Functionality
- **Quantum-Safe File Encryption**: Files are encrypted using AES-256-GCM with keys protected by BB84-derived secrets
- **Secure Key Exchange**: BB84 protocol simulation for establishing shared secrets between users
- **Digital Signatures**: Dilithium3 signatures ensure file integrity and non-repudiation
- **Group Management**: Create and manage user groups for collaborative file sharing
- **Access Control**: Fine-grained control over who can access encrypted files
- **Audit Logging**: Comprehensive activity logs for security monitoring and compliance

### Security Features
- **Post-Quantum Cryptography**: Protection against quantum computer attacks using NIST-approved algorithms
- **Eavesdropping Detection**: BB84 protocol includes quantum error rate monitoring
- **Session Management**: Secure BB84 sessions with expiration and context tracking
- **Multi-User Encryption**: Files can be securely shared with multiple users using individual key wrapping

### User Experience
- **Dashboard**: Centralized view of files, groups, and key exchange sessions
- **Real-time Updates**: AJAX-based partial page updates for BB84 session status
- **File Management**: Upload, download, and manage encrypted files
- **Group Collaboration**: Establish group keys and share files with entire groups
- **Responsive Design**: Bootstrap 5-based UI with mobile support

## Technical Architecture

### Cryptographic Components

#### 1. BB84 Quantum Key Distribution (Primary Key Exchange)

QuantumVault implements a **classical simulation** of the BB84 protocol for establishing shared secrets between users. This is the **primary mechanism** for key exchange, replacing traditional key encapsulation methods.

**BB84 Protocol Phases:**

**Phase 1: Quantum State Preparation**
- Alice generates random bit sequence (default: 1024 bits) using `generate_random_bits()`
- Alice generates random basis sequence ('+' rectilinear or '×' diagonal) using `generate_random_bases()`
- Each bit is encoded into a quantum state representation:
  - Bit 0 + Basis '+' → |0⟩ state
  - Bit 1 + Basis '+' → |1⟩ state
  - Bit 0 + Basis '×' → |+⟩ state
  - Bit 1 + Basis '×' → |-⟩ state

**Phase 2: Quantum Transmission (with optional eavesdropping)**
- Simulated quantum states are "transmitted" over a quantum channel
- **Eavesdropper simulation**: If enabled, Eve intercepts qubits with configurable probability
  - Eve measures intercepted qubits in random basis
  - Eve re-encodes and re-transmits, introducing detectable errors
  - System tracks number of intercepted qubits
- Bob receives quantum states and measures them using his own random bases

**Phase 3: Basis Reconciliation (Sifting)**
- Alice and Bob publicly compare which bases they used (without revealing bit values)
- Key sifting via `sift_key()`: Keep only bits where Alice and Bob used matching bases
- Typically ~50% of bits survive sifting (matched bases)
- Unmatched basis measurements are discarded

**Phase 4: Error Estimation**
- Alice and Bob randomly sample bits (default: 50 bits) from sifted key
- They publicly compare these sampled bits to calculate **Quantum Bit Error Rate (QBER)**
- QBER formula: `errors / sample_size`
- **Eavesdropping Detection**: If QBER > 15% threshold, protocol aborts with `EavesdroppingDetected` exception
- This is based on quantum mechanics: eavesdropping introduces measurable errors

**Phase 5: Privacy Amplification**
- Sampled bits (used for error estimation) are removed from the key
- Remaining bits are hashed using SHA-256 to derive a 256-bit shared secret
- This step compresses information known to potential eavesdropper
- Final output: 32-byte (256-bit) shared secret stored in `BB84Session.shared_key`

**Timeline Visualization:**
The `run_bb84_protocol_with_timeline()` function provides a 10+ second educational visualization with progress updates:
- Updates `BB84Session.current_phase` and `progress_percentage` 
- Real-time progress: 10% → 30% → 60% → 75% → 90% → 100%
- Stores phase timeline in JSON for frontend display

**Implementation Details:**
```python
# Located in: core/bb84_utils.py
DEFAULT_KEY_LENGTH = 1024      # Initial bits before sifting
DEFAULT_ERROR_THRESHOLD = 0.15 # 15% maximum QBER
DEFAULT_SAMPLE_SIZE = 50       # Bits revealed for error check
TARGET_KEY_BYTES = 32          # Final 256-bit shared secret
BASES = ['+', '×']             # Rectilinear and Diagonal
```

#### 2. Dilithium3 Digital Signatures (File Integrity)

**Purpose**: Provides post-quantum authentication and integrity verification for file metadata.

**Implementation** (via liboqs-python library):
- **Algorithm**: Dilithium3 (NIST FIPS 204 - Module-Lattice-Based Digital Signature Standard)
- **Public Key Size**: ~1952 bytes
- **Private Key Size**: ~4000 bytes  
- **Signature Size**: ~3293 bytes

**Key Generation:**
```python
# Located in: core/crypto_utils.py
def generate_dilithium3_keypair() -> Tuple[bytes, bytes]:
    sig = oqs.Signature("Dilithium3")
    public_key = sig.generate_keypair()  # Generated during user registration
    private_key = sig.export_secret_key()
    return public_key, private_key
```

**Signing Process:**
```python
def dilithium_sign(private_key: bytes, message: bytes) -> bytes:
    sig = oqs.Signature("Dilithium3", private_key)
    signature = sig.sign(message)
    return signature
```

**What Gets Signed:**
- File metadata: `filename|file_size|recipient_emails|uploader_email`
- Deterministic serialization ensures consistent signatures
- Signature stored in `EncryptedFile.metadata_signature`

**Verification:**
```python
def dilithium_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    sig = oqs.Signature("Dilithium3")
    return sig.verify(message, signature, public_key)
```

**Usage Flow:**
1. File upload: Sign metadata with uploader's Dilithium3 private key
2. File download: Verify signature with uploader's public key
3. Rejection: If signature verification fails, file is considered tampered

#### 3. AES-256-GCM Authenticated Encryption (File Content)

**Purpose**: Symmetric encryption of actual file data with built-in authentication.

**Algorithm Details:**
- **Cipher**: AES (Advanced Encryption Standard)
- **Key Size**: 256 bits (32 bytes)
- **Mode**: GCM (Galois/Counter Mode) - provides both confidentiality and authenticity
- **Nonce**: 96 bits (12 bytes) - randomly generated per file
- **Authentication Tag**: Automatically included in ciphertext by GCM

**Encryption Process:**
```python
def aes_encrypt_file(file_data: bytes) -> Tuple[bytes, bytes, bytes]:
    aes_key = AESGCM.generate_key(bit_length=256)  # Random AES key per file
    nonce = os.urandom(12)                          # Random nonce per file
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, file_data, None)
    return aes_key, nonce, ciphertext
```

**Decryption Process:**
```python
def aes_decrypt_file(aes_key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)  # Raises exception if tampered
    return plaintext
```

**Why GCM:**
- Provides authenticated encryption (AEAD - Authenticated Encryption with Associated Data)
- Detects any tampering with ciphertext
- Fast and widely supported
- No need for separate MAC (Message Authentication Code)

#### 4. BB84-Based Key Wrapping (Multi-User Encryption)

**Purpose**: Securely distribute the AES file encryption key to multiple authorized users.

**Process:**
Each recipient gets their own wrapped copy of the AES key, encrypted with their BB84 shared secret.

**Wrapping (performed during file upload):**
```python
def wrap_aes_key_with_bb84_key(master_aes_key: bytes, bb84_shared_key: bytes) -> Tuple[bytes, bytes]:
    nonce = os.urandom(12)
    aesgcm = AESGCM(bb84_shared_key)  # Use BB84-derived 256-bit key as KEK
    wrapped_key = aesgcm.encrypt(nonce, master_aes_key, None)
    return wrapped_key, nonce
```

**Unwrapping (performed during file download):**
```python
def unwrap_aes_key_with_bb84_key(wrapped_key: bytes, nonce: bytes, bb84_shared_key: bytes) -> bytes:
    aesgcm = AESGCM(bb84_shared_key)
    master_aes_key = aesgcm.decrypt(nonce, wrapped_key, None)
    return master_aes_key
```

**Storage Format:**
Stored in `EncryptedFile.wrapped_keys` as JSON:
```json
{
  "alice@example.com": {
    "ciphertext": "base64_wrapped_aes_key",
    "key_nonce": "base64_wrapping_nonce",
    "shared_key": "base64_bb84_shared_secret",
    "bb84_session": "session_uuid"
  },
  "bob@example.com": { ... }
}
```

#### 5. Kyber768 (Legacy - NOT Currently Used)

**Status**: Retained for backward compatibility but **not actively used** in current BB84 flow.

- Fields `kyber_public_key` and `kyber_private_key` exist in `QuantumUser` model
- Marked as "Legacy" in help text and comments
- BB84 protocol has replaced Kyber for key exchange
- May be removed in future versions

### Complete Cryptographic Flow

#### File Upload Flow (Detailed)

**Step 1: Pre-requisites**
- Uploader and all recipients must have Dilithium3 keypairs (auto-generated at registration)
- BB84 sessions must exist between uploader and each recipient
  - If not, user initiates BB84 key exchange via "Key Exchange" page
  - Receiver accepts request → BB84 protocol executes → 256-bit shared secret established

**Step 2: File Encryption**
```python
# 1. Generate random AES-256 key for this file
aes_key, nonce, ciphertext = aes_encrypt_file(file_data)
# Result: aes_key=32 bytes, nonce=12 bytes, ciphertext=original_size+16 bytes (GCM tag)

# 2. Store encrypted file to filesystem
file_path = f"media/encrypted_files/{user_id}_{filename}"
# Save ciphertext to disk
```

**Step 3: Key Wrapping (per recipient)**
```python
for recipient_email in recipients:
    # Retrieve BB84 shared secret from database
    bb84_session = BB84Session.objects.get(
        initiator=uploader, 
        receiver=recipient,
        status='completed'
    )
    bb84_shared_key = bb84_session.shared_key  # 32 bytes
    
    # Wrap the AES key using BB84-derived key
    wrapped_key, key_nonce = wrap_aes_key_with_bb84_key(aes_key, bb84_shared_key)
    
    # Store wrapped key in JSON
    wrapped_keys[recipient_email] = {
        'ciphertext': base64.b64encode(wrapped_key),
        'key_nonce': base64.b64encode(key_nonce),
        'shared_key': base64.b64encode(bb84_shared_key),
        'bb84_session': str(bb84_session.id)
    }
```

**Step 4: Metadata Signing**
```python
# Create deterministic metadata
metadata = f"{filename}|{file_size}|{sorted_recipients}|{uploader_email}"
metadata_bytes = metadata.encode('utf-8')

# Sign with uploader's Dilithium3 private key
signature = dilithium_sign(uploader.dilithium_private_key, metadata_bytes)
```

**Step 5: Database Storage**
```python
encrypted_file = EncryptedFile.objects.create(
    filename=display_name,
    original_filename=original_name,
    file_path=encrypted_file_path,
    file_size=original_size,
    mime_type=detected_mime,
    uploaded_by=uploader,
    aes_nonce=nonce,                          # 12 bytes for AES-GCM
    wrapped_keys=wrapped_keys_json,           # JSON with all recipients
    metadata_signature=signature              # Dilithium3 signature
)
```

#### File Download Flow (Detailed)

**Step 1: Authorization Check**
```python
# Verify user is authorized (uploader or in wrapped_keys)
if user.email not in encrypted_file.wrapped_keys:
    raise PermissionDenied
```

**Step 2: Key Unwrapping**
```python
# Retrieve wrapped key for this user
wrapped_data = encrypted_file.wrapped_keys[user.email]
wrapped_key = base64.b64decode(wrapped_data['ciphertext'])
key_nonce = base64.b64decode(wrapped_data['key_nonce'])
bb84_shared_key = base64.b64decode(wrapped_data['shared_key'])

# Unwrap AES key using BB84 shared secret
aes_key = unwrap_aes_key_with_bb84_key(wrapped_key, key_nonce, bb84_shared_key)
```

**Step 3: File Decryption**
```python
# Read encrypted file from disk
with open(encrypted_file.file_path, 'rb') as f:
    ciphertext = f.read()

# Decrypt using AES-256-GCM
plaintext = aes_decrypt_file(aes_key, encrypted_file.aes_nonce, ciphertext)
# GCM mode automatically verifies authentication tag - raises exception if tampered
```

**Step 4: Signature Verification**
```python
# Reconstruct metadata
metadata = create_file_metadata_for_signature(
    encrypted_file.filename,
    encrypted_file.file_size,
    list(encrypted_file.wrapped_keys.keys()),
    encrypted_file.uploaded_by.email
)

# Verify Dilithium3 signature
is_valid = dilithium_verify(
    encrypted_file.uploaded_by.dilithium_public_key,
    metadata,
    encrypted_file.metadata_signature
)

if not is_valid:
    raise SignatureError("File metadata has been tampered with")
```

**Step 5: Secure Delivery**
```python
# Create HTTP response with decrypted file
response = HttpResponse(plaintext, content_type=encrypted_file.mime_type)
response['Content-Disposition'] = f'attachment; filename="{encrypted_file.filename}"'
return response
```

#### BB84 Session Establishment Flow

**Step 1: Initiation**
```python
# User A clicks "Initiate Key Exchange" with User B
session = BB84Session.objects.create(
    initiator=user_a,
    receiver=user_b,
    status='pending',
    expires_at=timezone.now() + timedelta(hours=24)
)
```

**Step 2: Acceptance**
```python
# User B accepts request
session.status = 'accepted'
session.accepted_at = timezone.now()
session.save()
```

**Step 3: BB84 Protocol Execution**
```python
# Backend runs BB84 protocol (with 10-second timeline)
result = run_bb84_protocol_with_timeline(
    session,
    key_length=1024,
    eavesdropper_present=False,
    error_threshold=0.15,
    sample_size=50
)

# Store protocol results in session
session.sender_bits = result['sender_bits']           # Alice's random bits
session.sender_bases = result['sender_bases']         # Alice's bases
session.receiver_bases = result['receiver_bases']     # Bob's bases
session.receiver_measurements = result['receiver_measurements']
session.matched_indices = result['matched_indices']   # Sifted positions
session.sifted_key_length = result['sifted_key_length']
session.error_rate = result['error_rate']
session.shared_key = result['shared_key']             # 32-byte final key
session.status = 'completed'
session.save()
```

**Step 4: Eavesdropping Detection (if triggered)**
```python
try:
    result = run_bb84_protocol_with_timeline(...)
except EavesdroppingDetected as e:
    session.status = 'rejected'
    session.current_phase = "❌ EAVESDROPPING DETECTED!"
    session.error_rate = high_error_rate
    session.shared_key = None  # No key established
    session.save()
    # User notified via frontend
```

### Security Architecture

#### Defense-in-Depth Layers

**Layer 1: Quantum-Resistant Key Exchange**
- BB84 protocol provides information-theoretic security (in ideal quantum scenario)
- Classical simulation provides strong security assuming secure classical channels
- Eavesdropping detection via QBER monitoring

**Layer 2: Post-Quantum Signatures**
- Dilithium3 protects against quantum attacks on RSA/ECDSA
- NIST FIPS 204 standardized algorithm
- Prevents file metadata tampering and impersonation

**Layer 3: Authenticated Encryption**
- AES-256-GCM provides confidentiality + integrity
- Random keys per file (no key reuse)
- Authentication tag prevents ciphertext modification

**Layer 4: Key Isolation**
- Each user-file pair has unique wrapped AES key
- Compromise of one user's BB84 key doesn't affect others
- BB84 shared secrets stored encrypted in database

**Layer 5: Application-Level Controls**
- Django authentication and session management
- CSRF protection
- Audit logging of all sensitive operations

#### Threat Model

**Protects Against:**
- ✅ Quantum computer attacks on key exchange (BB84 replaces Diffie-Hellman)
- ✅ Quantum computer attacks on signatures (Dilithium3 replaces RSA/ECDSA)
- ✅ Eavesdropping on key distribution (QBER detection)
- ✅ File tampering (GCM authentication + Dilithium3 signatures)
- ✅ Unauthorized access (wrapped keys per user)
- ✅ Insider threats (audit logs)

**Does NOT Protect Against:**
- ❌ Compromised user credentials (use 2FA in production)
- ❌ Server compromise (consider HSM for key storage)
- ❌ Side-channel attacks on implementation
- ❌ Social engineering

**Assumptions:**
- Classical communication channels are secure (HTTPS in production)
- Database is protected from unauthorized access
- User devices are not compromised
- Random number generators are cryptographically secure

### Database Models

#### QuantumUser
Extended Django User with post-quantum keys:
- Dilithium3 keypair (public/private)
- Kyber768 keypair (legacy)
- Online status tracking

#### EncryptedFile
Stores encrypted files and metadata:
- File path, size, MIME type
- AES-GCM nonce
- Wrapped keys (JSON mapping users to wrapped AES keys)
- Dilithium3 signature
- Upload timestamp and ownership

#### BB84Session
Tracks quantum key exchange sessions:
- Initiator and receiver users
- Alice's bits, bases, and Bob's bases
- Sifted key and shared secret
- Session status (pending, accepted, completed, rejected)
- Expiration and eavesdropping detection flags

#### UserGroup
Group management:
- Group name, description, owner
- Member management with join timestamps
- Group key establishment tracking

#### AuditLog
Security and compliance logging:
- User actions (upload, download, share, key exchange)
- Timestamps and IP addresses
- Related file and user references

## Installation

### Prerequisites
- Python 3.11+
- pip and virtualenv
- SQLite (default) or PostgreSQL/MySQL for production

### Setup

1. **Clone the repository**
```bash
git clone https://github.com/A-Akhil/QuantumVault.git
cd QuantumVault
```

2. **Create and activate virtual environment**
```bash
python -m venv quantum_storage_env
source quantum_storage_env/bin/activate  # On Linux/Mac
# quantum_storage_env\Scripts\activate  # On Windows
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Run database migrations**
```bash
python manage.py migrate
```

5. **Create superuser (optional)**
```bash
python manage.py createsuperuser
```

6. **Run development server**
```bash
python manage.py runserver
```

7. **Access the application**
Open your browser and navigate to `http://127.0.0.1:8000`

## Dependencies

- **Django 5.2.7**: Web framework
- **djangorestframework 3.16.1**: REST API support
- **liboqs-python 0.14.1**: Open Quantum Safe library for post-quantum algorithms
- **cryptography 46.0.2**: Cryptographic primitives
- **requests 2.32.5**: HTTP library for API calls

See `requirements.txt` for complete dependency list.

## Usage

### User Registration and Key Generation
1. Register a new account at `/register/`
2. System automatically generates:
   - Dilithium3 keypair for digital signatures
   - Kyber768 keypair (legacy)

### File Upload and Sharing
1. Navigate to Dashboard
2. Click "Upload File"
3. Select file and choose recipients (individual users or groups)
4. System performs:
   - BB84 key exchange with each recipient (if not already established)
   - File encryption with AES-256-GCM
   - Key wrapping for each recipient
   - Metadata signing with Dilithium3

### BB84 Key Exchange
1. Go to "Key Exchange" page
2. Select a recipient and click "Initiate Key Exchange"
3. Recipient accepts the request
4. BB84 protocol executes:
   - Bit and basis generation
   - Quantum state simulation
   - Key sifting
   - Error estimation
   - Privacy amplification
5. 256-bit shared secret is established and stored

### Group Management
1. Create a group from "Manage Groups"
2. Add members to the group
3. Establish group keys (BB84 sessions with all members)
4. Share files with the entire group

### File Download
1. Navigate to "My Files" or "Shared With Me"
2. Click download on desired file
3. System performs:
   - Key unwrapping using BB84 shared secret
   - File decryption
   - Signature verification
4. File is delivered securely

## API Endpoints

### Authentication
- `POST /api/auth/login/` - User login
- `POST /api/auth/logout/` - User logout

### File Operations
- `POST /api/files/upload/` - Upload encrypted file
- `GET /api/files/<id>/download/` - Download and decrypt file
- `GET /api/files/` - List user's files

### BB84 Protocol
- `POST /api/bb84/initiate/` - Initiate BB84 session
- `POST /api/bb84/<session_id>/accept/` - Accept BB84 request
- `GET /api/bb84/sessions/` - List BB84 sessions
- `POST /api/bb84/<session_id>/complete/` - Complete key exchange

### Groups
- `POST /api/groups/` - Create group
- `GET /api/groups/` - List groups
- `POST /api/groups/<id>/members/` - Add member
- `DELETE /api/groups/<id>/members/<user_id>/` - Remove member

See API documentation at `/api/docs/` (when available) for complete endpoint details.

## Testing

The project includes comprehensive test suites:

### Run specific tests
```bash
python test_bb84_protocol.py          # BB84 protocol tests
python test_crypto_utils.py           # Cryptographic utilities tests
python test_api.py                    # API endpoint tests
python test_download.py               # File download flow tests
```

### Run Django tests
```bash
python manage.py test core
```

### Check BB84 sessions
```bash
python check_sessions.py              # View active BB84 sessions
python check_upload_ready.py          # Check upload readiness
```

## Project Structure

```
quantum_storage/
├── core/                      # Main application
│   ├── bb84_utils.py         # BB84 protocol implementation
│   ├── crypto_utils.py       # Cryptographic utilities
│   ├── models.py             # Database models
│   ├── views.py              # View logic
│   ├── api_views.py          # REST API views
│   ├── eavesdropper_api.py   # Eavesdropping simulation
│   ├── forms.py              # Django forms
│   ├── urls.py               # URL routing
│   ├── templates/            # HTML templates
│   └── migrations/           # Database migrations
├── quantum_storage/           # Project settings
│   ├── settings.py           # Django configuration
│   ├── urls.py               # Root URL configuration
│   └── wsgi.py               # WSGI application
├── media/                     # Uploaded encrypted files
├── static/                    # Static assets (CSS, JS, images)
├── manage.py                  # Django management script
├── requirements.txt           # Python dependencies
└── rough_note.md             # Development notes and enhancements
```

## Security Considerations

### Production Deployment
Before deploying to production:

1. **Change SECRET_KEY** in `settings.py`
2. **Set DEBUG = False**
3. **Configure ALLOWED_HOSTS**
4. **Use HTTPS** (mandatory for security)
5. **Enable secure cookies**:
   ```python
   SESSION_COOKIE_SECURE = True
   CSRF_COOKIE_SECURE = True
   ```
6. **Use PostgreSQL or MySQL** instead of SQLite
7. **Set up proper file permissions** for media directory
8. **Enable rate limiting** on API endpoints
9. **Configure CSP headers** for XSS protection
10. **Regular security audits** of audit logs

### Limitations
- **BB84 Simulation**: This is a **classical simulation** of BB84, not actual quantum hardware
  - No real qubits or quantum channels are used
  - Security relies on computational assumptions and secure classical channels (HTTPS)
  - Provides educational value and prepares codebase for future quantum hardware integration
- **Channel Security**: Assumes secure classical communication channels (HTTPS) for BB84 parameter exchange
  - Alice and Bob must exchange bases and sampled bits over authenticated channel
  - Man-in-the-middle attacks possible without HTTPS/TLS
- **Key Storage**: BB84 shared secrets stored in SQLite/PostgreSQL database
  - Consider Hardware Security Module (HSM) for production
  - Database encryption at rest recommended
- **Eavesdropping Detection**: Probabilistic based on QBER threshold
  - 15% threshold means some eavesdropping may go undetected
  - Perfect eavesdropping detection requires real quantum channels
- **No Forward Secrecy**: BB84 shared keys are reused for multiple files
  - Consider implementing key rotation policy
  - Compromise of BB84 key affects all files wrapped with it

## Future Enhancements

See `rough_note.md` for detailed enhancement roadmap:

- Email notifications for BB84 requests
- Batch key exchange operations
- Advanced audit log filtering and export
- File versioning system
- Mobile-responsive improvements
- API rate limiting
- Content Security Policy headers
- Two-factor authentication
- Hardware security module integration
- Real quantum hardware support

## Contributing

Contributions are welcome. Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-feature`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/new-feature`)
5. Create a Pull Request

## License

This project is licensed under the MIT License. See LICENSE file for details.

## Acknowledgments

- **Open Quantum Safe (OQS)** project for post-quantum cryptography implementations
- **NIST** for standardizing post-quantum cryptographic algorithms
- **Django** framework and community
- **Bootstrap** for UI components

## Contact

- **Repository**: [https://github.com/A-Akhil/QuantumVault](https://github.com/A-Akhil/QuantumVault)
- **Issues**: [GitHub Issues](https://github.com/A-Akhil/QuantumVault/issues)

## Disclaimer

This is an **educational and research project** demonstrating post-quantum cryptography concepts and BB84 quantum key distribution simulation.

**Important Notes:**
- The BB84 implementation is a **classical simulation**, not actual quantum hardware
- It does **NOT** provide the same security guarantees as real quantum key distribution systems
- While it implements NIST-approved post-quantum algorithms (Dilithium3), the overall system should undergo **thorough security review and penetration testing** before use in production environments handling sensitive data
- The simulation assumes secure classical channels (HTTPS) for parameter exchange
- Real-world quantum threats are evolving - consult cryptography experts for production deployments

**Recommended for:**
- Educational purposes and learning quantum cryptography concepts
- Research and development of post-quantum systems
- Proof-of-concept demonstrations
- Testing BB84 protocol mechanics

**NOT recommended for (without security audit):**
- Production systems with sensitive data
- Compliance-regulated environments (HIPAA, PCI-DSS, etc.)
- Mission-critical applications
- Systems requiring certified cryptographic modules
