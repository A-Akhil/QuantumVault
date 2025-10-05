"""
Quantum-safe cryptographic utilities for post-quantum file storage system.

This module provides utility functions for:
- Kyber768 Key Encapsulation Mechanism (KEM)
- Dilithium3 Digital Signatures
- AES-256-GCM Authenticated Encryption
"""

import os
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Tuple, Dict, Any, Optional
import logging

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


def generate_kyber768_keypair() -> Tuple[bytes, bytes]:
    """
    Generate a Kyber768 keypair for Key Encapsulation Mechanism.
    
    Returns:
        Tuple[bytes, bytes]: (public_key, private_key)
    
    Raises:
        KeyGenerationError: If key generation fails
    """
    try:
        kem = oqs.KeyEncapsulation("Kyber768")
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()
        
        logger.info(f"Generated Kyber768 keypair: pub_key={len(public_key)}B, priv_key={len(private_key)}B")
        return public_key, private_key
        
    except Exception as e:
        logger.error(f"Kyber768 key generation failed: {e}")
        raise KeyGenerationError(f"Failed to generate Kyber768 keypair: {e}")


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


def kyber_encapsulate(public_key: bytes) -> Tuple[bytes, bytes]:
    """
    Encapsulate a shared secret using Kyber768 public key.
    
    Args:
        public_key: Kyber768 public key bytes
    
    Returns:
        Tuple[bytes, bytes]: (ciphertext, shared_secret)
    
    Raises:
        EncryptionError: If encapsulation fails
    """
    try:
        kem = oqs.KeyEncapsulation("Kyber768")
        ciphertext, shared_secret = kem.encap_secret(public_key)
        
        logger.debug(f"Kyber768 encapsulation: ciphertext={len(ciphertext)}B, secret={len(shared_secret)}B")
        return ciphertext, shared_secret
        
    except Exception as e:
        logger.error(f"Kyber768 encapsulation failed: {e}")
        raise EncryptionError(f"Failed to encapsulate with Kyber768: {e}")


def kyber_decapsulate(private_key: bytes, ciphertext: bytes) -> bytes:
    """
    Decapsulate shared secret using Kyber768 private key.
    
    Args:
        private_key: Kyber768 private key bytes
        ciphertext: Encapsulated ciphertext
    
    Returns:
        bytes: Shared secret
    
    Raises:
        DecryptionError: If decapsulation fails
    """
    try:
        kem = oqs.KeyEncapsulation("Kyber768", private_key)
        shared_secret = kem.decap_secret(ciphertext)
        
        logger.debug(f"Kyber768 decapsulation: secret={len(shared_secret)}B")
        return shared_secret
        
    except Exception as e:
        logger.error(f"Kyber768 decapsulation failed: {e}")
        raise DecryptionError(f"Failed to decapsulate with Kyber768: {e}")


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


def wrap_aes_key_for_user(aes_key: bytes, user_kyber_public_key: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    Wrap an AES key for a specific user using their Kyber768 public key.
    
    Args:
        aes_key: AES-256 key to wrap
        user_kyber_public_key: User's Kyber768 public key
    
    Returns:
        Tuple[bytes, bytes, bytes]: (kyber_ciphertext, key_nonce, wrapped_aes_key)
    
    Raises:
        EncryptionError: If key wrapping fails
    """
    try:
        # Encapsulate to get shared secret
        kyber_ciphertext, shared_secret = kyber_encapsulate(user_kyber_public_key)
        
        # Use shared secret to encrypt the AES key
        key_nonce = os.urandom(12)
        key_aesgcm = AESGCM(shared_secret[:32])  # Use first 32 bytes as AES key
        wrapped_aes_key = key_aesgcm.encrypt(key_nonce, aes_key, None)
        
        logger.debug(f"AES key wrapping: kyber_ct={len(kyber_ciphertext)}B, "
                    f"wrapped_key={len(wrapped_aes_key)}B")
        return kyber_ciphertext, key_nonce, wrapped_aes_key
        
    except Exception as e:
        logger.error(f"AES key wrapping failed: {e}")
        raise EncryptionError(f"Failed to wrap AES key: {e}")


def unwrap_aes_key_for_user(kyber_ciphertext: bytes, key_nonce: bytes, 
                          wrapped_aes_key: bytes, user_kyber_private_key: bytes) -> bytes:
    """
    Unwrap an AES key for a specific user using their Kyber768 private key.
    
    Args:
        kyber_ciphertext: Kyber768 ciphertext from encapsulation
        key_nonce: Nonce used for AES key encryption
        wrapped_aes_key: Encrypted AES key
        user_kyber_private_key: User's Kyber768 private key
    
    Returns:
        bytes: Unwrapped AES-256 key
    
    Raises:
        DecryptionError: If key unwrapping fails
    """
    try:
        # Decapsulate to get shared secret
        shared_secret = kyber_decapsulate(user_kyber_private_key, kyber_ciphertext)
        
        # Use shared secret to decrypt the AES key
        key_aesgcm = AESGCM(shared_secret[:32])  # Use first 32 bytes as AES key
        aes_key = key_aesgcm.decrypt(key_nonce, wrapped_aes_key, None)
        
        logger.debug(f"AES key unwrapping: wrapped_key={len(wrapped_aes_key)}B, aes_key={len(aes_key)}B")
        return aes_key
        
    except Exception as e:
        logger.error(f"AES key unwrapping failed: {e}")
        raise DecryptionError(f"Failed to unwrap AES key: {e}")


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


def validate_quantum_keys(kyber_public: bytes, kyber_private: bytes,
                         dilithium_public: bytes, dilithium_private: bytes) -> bool:
    """
    Validate that quantum cryptographic keys are well-formed and work together.
    
    Args:
        kyber_public: Kyber768 public key
        kyber_private: Kyber768 private key
        dilithium_public: Dilithium3 public key
        dilithium_private: Dilithium3 private key
    
    Returns:
        bool: True if all keys are valid and functional
    """
    try:
        # Test Kyber768 keypair
        ciphertext, shared_secret1 = kyber_encapsulate(kyber_public)
        shared_secret2 = kyber_decapsulate(kyber_private, ciphertext)
        if shared_secret1 != shared_secret2:
            logger.error("Kyber768 keypair validation failed: shared secrets don't match")
            return False
        
        # Test Dilithium3 keypair
        test_message = b"test message for key validation"
        signature = dilithium_sign(dilithium_private, test_message)
        if not dilithium_verify(dilithium_public, test_message, signature):
            logger.error("Dilithium3 keypair validation failed: signature verification failed")
            return False
        
        logger.info("All quantum keys validated successfully")
        return True
        
    except Exception as e:
        logger.error(f"Quantum key validation failed: {e}")
        return False