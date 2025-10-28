# QuantumVault System Architecture

```mermaid
flowchart LR
	subgraph Client Layer
		U["Web Browser\n(Vue/Bootstrap UI)"]
	end

	subgraph Django Platform
		direction TB
		V["Django Views & Templates\n(core/views.py, templates/core)"]
		API["REST API Layer\n(core/api_views.py, DRF)"]
		BB84["Quantum Services\n(core/bb84_utils.py, core/crypto_utils.py)"]
		Auth["Auth & Session Management\n(Django auth, QuantumUser)"]
	end

	subgraph Persistence Layer
		DB[("Relational Database\nSQLite / PostgreSQL\n(core/models.py)")]
		Files[("Encrypted File Storage\nmedia/encrypted_files/")]
		Logs[("Audit Logs\nAuditLog records")]
	end

	subgraph External Interfaces
		OQS["liboqs Library\n(Dilithium3 signatures)"]
		CryptoPy["cryptography Library\n(AES-256-GCM)"]
	end

	U -- HTTPS Requests --> V
	U -- AJAX / REST Calls --> API

	V -- "Render HTML\nHandle forms" --> Auth
	V -- "Trigger BB84 sessions" --> BB84
	API -- "JSON responses" --> Auth
	API -- "Initiate BB84, wrap keys" --> BB84

	Auth -- "CRUD users, permissions" --> DB
	BB84 -- "Persist session keys" --> DB
	BB84 -- "Write ciphertext, signatures" --> Files
	V -- "Log activity" --> Logs
	API -- "Log activity" --> Logs

	BB84 -- "Quantum-safe operations" --> OQS
	BB84 -- "AES-256-GCM" --> CryptoPy
```

## Component Notes

- **Client Layer**: Browser-based UI built with Django templates and Bootstrap. Initiates key exchanges, uploads, and downloads via standard views or AJAX calls.
- **Django Platform**: Core application logic. Views handle HTML workflows; DRF-based API endpoints support asynchronous operations and integrations; BB84 utilities manage quantum key exchange simulation and cryptographic operations; authentication layer extends Django's `AbstractUser` with post-quantum keys.
- **Persistence Layer**: Relational database stores users, sessions, audit logs, and metadata. Encrypted file payloads live under `media/encrypted_files/`. Audit logs capture security-relevant events.
- **External Interfaces**: `liboqs` provides Dilithium3 signatures; `cryptography` library handles AES-256-GCM encryption. These libraries underpin the quantum-safe guarantees.

## Cryptographic Workflow (Algorithm Detail)

```mermaid
flowchart TD
	subgraph Upload Path
		UploadReq["Upload Request\n(user initiates upload)"]
		GenerateAES["Generate AES-256 key & nonce\n(AESGCM.generate_key)"]
		EncryptFile["Encrypt file bytes\nAES-256-GCM"]
		BuildMetadata["Assemble metadata\nfilename | size | recipients"]
		DilithiumSign["Dilithium3 Sign metadata\n(liboqs.Signature)"]
		EnsureBB84{BB84 session exists?}
		RunBB84["Run BB84 protocol\n(core/bb84_utils.py)"]
		DeriveKey["Derive 256-bit shared key\n(privacy amplification)"]
		WrapAES["Wrap AES key per recipient\nAESGCM(shared key)"]
		PersistCiphertext["Store ciphertext\nmedia/encrypted_files/"]
		PersistMetadata["Persist metadata, wrapped keys, signature\nEncryptedFile & BB84Session models"]
	end

	subgraph Download Path
		DownloadReq["Download Request\n(user requests file)"]
		FetchWrapped["Fetch wrapped AES key\nfrom EncryptedFile"]
		RetrieveShared["Retrieve BB84 shared key\nfrom BB84Session"]
		UnwrapAES["Unwrap AES key\nAESGCM(shared key)"]
		LoadCiphertext["Read ciphertext from disk"]
		DecryptFile["Decrypt file\nAES-256-GCM"]
		VerifyMetadata["Rebuild metadata\ncreate_file_metadata_for_signature"]
		DilithiumVerify["Verify Dilithium signature\n(liboqs.Signature.verify)"]
		ReturnFile["Return plaintext to client"]
	end

	UploadReq --> GenerateAES --> EncryptFile --> BuildMetadata --> DilithiumSign --> EnsureBB84
	EnsureBB84 -- "no" --> RunBB84 --> DeriveKey --> WrapAES
	EnsureBB84 -- "yes" --> WrapAES
	WrapAES --> PersistCiphertext --> PersistMetadata

	DownloadReq --> FetchWrapped --> RetrieveShared --> UnwrapAES --> LoadCiphertext --> DecryptFile --> VerifyMetadata --> DilithiumVerify --> ReturnFile
	VerifyMetadata -.-> PersistMetadata
	RetrieveShared -.-> RunBB84
```

**Workflow Highlights**
- BB84 sessions are lazily established: uploads trigger `run_bb84_protocol_with_timeline` only if a completed session is missing.
- AES-256 keys are unique per upload; wrapped copies exist per recipient using their BB84-derived shared secret.
- Dilithium3 signatures cover deterministic metadata, ensuring download-time integrity verification.
- Download vetoes release if Dilithium verification fails or if the wrapped AES key cannot be unwrapped with the stored shared secret.
