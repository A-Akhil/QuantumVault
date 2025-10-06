"""
Quantum-safe cryptographic utilities for the post-quantum file storage system.

This module now focuses on:
- BB84 Quantum Key Distribution (via `core.bb84_utils`)
- Dilithium3 Digital Signatures
- AES-256-GCM Authenticated Encryption
"""

import os
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Tuple, Dict, Any, Optional
import logging

from .bb84_utils import (
    BB84Error,
    EavesdroppingDetected,
    TARGET_KEY_BYTES,
    DEFAULT_KEY_LENGTH,
    DEFAULT_SAMPLE_SIZE,
    run_bb84_protocol,
    wrap_aes_key_with_bb84_key,
    unwrap_aes_key_with_bb84_key,
)

logger = logging.getLogger(__name__)


class QuantumCryptoError(Exception):
    """Base exception for quantum cryptographic operations"""
    pass


class KeyGenerationError(QuantumCryptoError):
    """Raised when key generation fails"""
    pass


class EncryptionError(QuantumCryptoError):
    """Raised when encryption operations fail"""
    pass


class DecryptionError(QuantumCryptoError):
    """Raised when decryption operations fail"""
    pass


class SignatureError(QuantumCryptoError):
    """Raised when signature operations fail"""
    pass


def generate_dilithium3_keypair() -> Tuple[bytes, bytes]:
    """
    Generate a Dilithium3 keypair for Digital Signatures.
    
    Returns:
        Tuple[bytes, bytes]: (public_key, private_key)
    
    Raises:
        KeyGenerationError: If key generation fails
    """
    try:
        sig = oqs.Signature("Dilithium3")
        public_key = sig.generate_keypair()
        private_key = sig.export_secret_key()
        
        logger.info(f"Generated Dilithium3 keypair: pub_key={len(public_key)}B, priv_key={len(private_key)}B")
        return public_key, private_key
        
    except Exception as e:
        logger.error(f"Dilithium3 key generation failed: {e}")
        raise KeyGenerationError(f"Failed to generate Dilithium3 keypair: {e}")


def dilithium_sign(private_key: bytes, message: bytes) -> bytes:
    """
    Sign a message using Dilithium3 private key.
    
    Args:
        private_key: Dilithium3 private key bytes
        message: Message to sign
    
    Returns:
        bytes: Digital signature
    
    Raises:
        SignatureError: If signing fails
    """
    try:
        sig = oqs.Signature("Dilithium3", private_key)
        signature = sig.sign(message)
        
        logger.debug(f"Dilithium3 signature: message={len(message)}B, signature={len(signature)}B")
        return signature
        
    except Exception as e:
        logger.error(f"Dilithium3 signing failed: {e}")
        raise SignatureError(f"Failed to sign with Dilithium3: {e}")


def dilithium_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """
    Verify a Dilithium3 signature.
    
    Args:
        public_key: Dilithium3 public key bytes
        message: Original message
        signature: Digital signature to verify
    
    Returns:
        bool: True if signature is valid, False otherwise
    
    Raises:
        SignatureError: If verification process fails
    """
    try:
        sig = oqs.Signature("Dilithium3")
        is_valid = sig.verify(message, signature, public_key)
        
        logger.debug(f"Dilithium3 verification: valid={is_valid}")
        return is_valid
        
    except Exception as e:
        logger.error(f"Dilithium3 verification failed: {e}")
        raise SignatureError(f"Failed to verify Dilithium3 signature: {e}")


def aes_encrypt_file(file_data: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypt file data using AES-256-GCM.
    
    Args:
        file_data: Raw file bytes to encrypt
    
    Returns:
        Tuple[bytes, bytes, bytes]: (aes_key, nonce, ciphertext)
    
    Raises:
        EncryptionError: If encryption fails
    """
    try:
        # Generate random AES-256 key and nonce
        aes_key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        
        # Encrypt the file data
        aesgcm = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(nonce, file_data, None)
        
        logger.info(f"AES-256-GCM encryption: key={len(aes_key)}B, nonce={len(nonce)}B, "
                   f"plaintext={len(file_data)}B, ciphertext={len(ciphertext)}B")
        return aes_key, nonce, ciphertext
        
    except Exception as e:
        logger.error(f"AES-256-GCM encryption failed: {e}")
        raise EncryptionError(f"Failed to encrypt with AES-256-GCM: {e}")


def aes_decrypt_file(aes_key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt file data using AES-256-GCM.
    
    Args:
        aes_key: AES-256 key
        nonce: 96-bit nonce
        ciphertext: Encrypted file data
    
    Returns:
        bytes: Decrypted file data
    
    Raises:
        DecryptionError: If decryption fails
    """
    try:
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        logger.debug(f"AES-256-GCM decryption: ciphertext={len(ciphertext)}B, plaintext={len(plaintext)}B")
        return plaintext
        
    except Exception as e:
        logger.error(f"AES-256-GCM decryption failed: {e}")
        raise DecryptionError(f"Failed to decrypt with AES-256-GCM: {e}")


def initiate_bb84_session(
    *,
    key_length: int = 1024,
    eavesdropper_present: bool = False,
    eavesdrop_probability: float = 0.0,
    error_threshold: float = 0.15,
    sample_size: int = 50,
) -> Dict[str, Any]:
    """Run the BB84 protocol and return the session artefacts."""

    try:
        result = run_bb84_protocol(
            key_length=key_length,
            eavesdropper_present=eavesdropper_present,
            eavesdrop_probability=eavesdrop_probability,
            error_threshold=error_threshold,
            sample_size=sample_size,
        )
        return result
    except (BB84Error, EavesdroppingDetected) as exc:
        logger.error("BB84 session failed: %s", exc)
        raise EncryptionError(f"BB84 session failed: {exc}") from exc


def wrap_aes_key_with_shared_secret(aes_key: bytes, shared_secret: bytes) -> Tuple[bytes, bytes]:
    """Wrap an AES key using a BB84-derived shared secret."""

    if len(aes_key) != TARGET_KEY_BYTES:
        raise ValueError("aes_key must be 32 bytes (AES-256)")

    try:
        wrapped_key, nonce = wrap_aes_key_with_bb84_key(aes_key, shared_secret)
        logger.debug(
            "AES key wrapped via BB84 shared secret: ciphertext=%dB", len(wrapped_key)
        )
        return wrapped_key, nonce
    except Exception as exc:  # pragma: no cover - defensive
        logger.error("Failed to wrap AES key with BB84 shared secret: %s", exc)
        raise EncryptionError(f"Failed to wrap AES key with BB84 shared secret: {exc}") from exc


def unwrap_aes_key_with_shared_secret(
    wrapped_key: bytes,
    nonce: bytes,
    shared_secret: bytes,
) -> bytes:
    """Unwrap an AES key using a BB84-derived shared secret."""

    try:
        aes_key = unwrap_aes_key_with_bb84_key(wrapped_key, nonce, shared_secret)
        logger.debug("AES key unwrapped via BB84 shared secret: key=%dB", len(aes_key))
        return aes_key
    except Exception as exc:  # pragma: no cover - defensive
        logger.error("Failed to unwrap AES key with BB84 shared secret: %s", exc)
        raise DecryptionError(f"Failed to unwrap AES key with BB84 shared secret: {exc}") from exc


def create_file_metadata_for_signature(filename: str, file_size: int, 
                                     recipients: list, uploader_email: str) -> bytes:
    """
    Create file metadata for digital signature.
    
    Args:
        filename: Name of the file
        file_size: Size of the file in bytes
        recipients: List of recipient email addresses
        uploader_email: Email of the user uploading the file
    
    Returns:
        bytes: Serialized metadata for signing
    """
    metadata = {
        "filename": filename,
        "file_size": file_size,
        "recipients": sorted(recipients),  # Sort for consistency
        "uploader": uploader_email
    }
    
    # Create a deterministic byte representation
    metadata_str = f"{metadata['filename']}|{metadata['file_size']}|{','.join(metadata['recipients'])}|{metadata['uploader']}"
    return metadata_str.encode('utf-8')


def validate_quantum_keys(
    legacy_public: Optional[bytes],
    legacy_private: Optional[bytes],
    dilithium_public: bytes,
    dilithium_private: bytes,
) -> bool:
    """Validate Dilithium credentials and ensure BB84 simulation succeeds.

    The first two parameters are kept for backward compatibility with legacy
    Kyber-based call sites; they are ignored but logged when provided.
    """

    if legacy_public or legacy_private:
        logger.warning(
            "validate_quantum_keys called with legacy Kyber material; ignoring in BB84 mode"
        )

    try:
        test_message = b"test message for key validation"
        signature = dilithium_sign(dilithium_private, test_message)
        if not dilithium_verify(dilithium_public, test_message, signature):
            logger.error("Dilithium3 keypair validation failed: signature verification failed")
            return False

        session = initiate_bb84_session(
            key_length=DEFAULT_KEY_LENGTH,
            sample_size=DEFAULT_SAMPLE_SIZE,
        )
        shared_key = session.get("shared_key")
        if not shared_key or len(shared_key) != TARGET_KEY_BYTES:
            logger.error("BB84 session did not yield expected 256-bit shared key")
            return False

        logger.info("Dilithium keys verified and BB84 session produced a valid shared key")
        return True

    except Exception as exc:  # pragma: no cover - defensive
        logger.error("Quantum material validation failed: %s", exc)
        return False