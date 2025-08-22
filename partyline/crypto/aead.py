"""
Authenticated Encryption with Associated Data (AEAD) implementations
Supports XChaCha20-Poly1305, AES-256-GCM, and legacy AES-EAX
"""

import hmac
import logging
import secrets
from abc import ABC, abstractmethod
from typing import Optional, Tuple, Union

from partyline.constants import (
    CipherSuite,
    NONCE_LENGTH,
    GCM_NONCE_LENGTH,
    TAG_LENGTH,
)
from partyline.crypto.kdf import zeroize

logger = logging.getLogger(__name__)


class CipherError(Exception):
    """Base exception for cipher operations"""
    pass


class AuthenticationError(CipherError):
    """Raised when message authentication fails"""
    pass


class AEADCipher(ABC):
    """Abstract base class for AEAD ciphers"""
    
    @abstractmethod
    def encrypt(
        self,
        plaintext: bytes,
        associated_data: Optional[bytes] = None
    ) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt plaintext with authentication
        
        Args:
            plaintext: Data to encrypt
            associated_data: Optional additional authenticated data
        
        Returns:
            Tuple of (nonce, ciphertext, tag)
        """
        pass
    
    @abstractmethod
    def decrypt(
        self,
        nonce: bytes,
        ciphertext: bytes,
        tag: bytes,
        associated_data: Optional[bytes] = None
    ) -> bytes:
        """
        Decrypt and verify ciphertext
        
        Args:
            nonce: Nonce used for encryption
            ciphertext: Encrypted data
            tag: Authentication tag
            associated_data: Optional additional authenticated data
        
        Returns:
            Decrypted plaintext
        
        Raises:
            AuthenticationError: If authentication fails
        """
        pass
    
    @property
    @abstractmethod
    def cipher_suite(self) -> CipherSuite:
        """Return the cipher suite identifier"""
        pass


class XChaCha20Poly1305Cipher(AEADCipher):
    """XChaCha20-Poly1305 AEAD cipher (preferred)"""
    
    def __init__(self, key: bytes):
        """
        Initialize XChaCha20-Poly1305 cipher
        
        Args:
            key: 32-byte encryption key
        """
        try:
            import nacl.secret
            import nacl.utils
            self.nacl = nacl
            self.box = nacl.secret.SecretBox(key)
            logger.debug("Initialized XChaCha20-Poly1305 cipher")
        except ImportError:
            raise CipherError("PyNaCl not available for XChaCha20-Poly1305")
        
        if len(key) != 32:
            raise ValueError("XChaCha20-Poly1305 requires 32-byte key")
    
    def encrypt(
        self,
        plaintext: bytes,
        associated_data: Optional[bytes] = None
    ) -> Tuple[bytes, bytes, bytes]:
        """Encrypt with XChaCha20-Poly1305"""
        # PyNaCl's SecretBox includes nonce and tag in the output
        # We need to separate them for our protocol
        nonce = self.nacl.utils.random(NONCE_LENGTH)
        
        # PyNaCl doesn't directly support AAD, so we'll include it in a wrapped format
        if associated_data:
            # Prepend AAD length and AAD to plaintext, will authenticate manually
            wrapped = len(associated_data).to_bytes(4, 'big') + associated_data + plaintext
        else:
            wrapped = b'\x00\x00\x00\x00' + plaintext
        
        # Encrypt (this adds its own nonce internally, but we'll use our own)
        ciphertext = self.box.encrypt(wrapped, nonce)
        
        # Extract components (PyNaCl format: nonce || ciphertext || tag)
        # But we already have the nonce, so skip it
        actual_ciphertext = ciphertext[NONCE_LENGTH:]
        
        # Tag is last 16 bytes
        tag = actual_ciphertext[-16:]
        actual_ciphertext = actual_ciphertext[:-16]
        
        return nonce, actual_ciphertext, tag
    
    def decrypt(
        self,
        nonce: bytes,
        ciphertext: bytes,
        tag: bytes,
        associated_data: Optional[bytes] = None
    ) -> bytes:
        """Decrypt with XChaCha20-Poly1305"""
        # Reconstruct the format PyNaCl expects
        combined = nonce + ciphertext + tag
        
        try:
            wrapped = self.box.decrypt(combined)
        except self.nacl.exceptions.CryptoError as e:
            raise AuthenticationError(f"XChaCha20-Poly1305 authentication failed: {e}")
        
        # Unwrap AAD if present
        aad_len = int.from_bytes(wrapped[:4], 'big')
        if aad_len > 0:
            actual_aad = wrapped[4:4+aad_len]
            if associated_data != actual_aad:
                raise AuthenticationError("Associated data mismatch")
            plaintext = wrapped[4+aad_len:]
        else:
            plaintext = wrapped[4:]
        
        return plaintext
    
    @property
    def cipher_suite(self) -> CipherSuite:
        return CipherSuite.XCHACHA20_POLY1305


class AES256GCMCipher(AEADCipher):
    """AES-256-GCM AEAD cipher (strong default)"""
    
    def __init__(self, key: bytes):
        """
        Initialize AES-256-GCM cipher
        
        Args:
            key: 32-byte encryption key
        """
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            self.cipher = AESGCM(key)
            logger.debug("Initialized AES-256-GCM cipher")
        except ImportError:
            raise CipherError("cryptography library not available for AES-GCM")
        
        if len(key) != 32:
            raise ValueError("AES-256-GCM requires 32-byte key")
    
    def encrypt(
        self,
        plaintext: bytes,
        associated_data: Optional[bytes] = None
    ) -> Tuple[bytes, bytes, bytes]:
        """Encrypt with AES-256-GCM"""
        nonce = secrets.token_bytes(GCM_NONCE_LENGTH)
        
        # Encrypt and authenticate
        ciphertext_and_tag = self.cipher.encrypt(
            nonce,
            plaintext,
            associated_data
        )
        
        # Separate ciphertext and tag
        ciphertext = ciphertext_and_tag[:-16]
        tag = ciphertext_and_tag[-16:]
        
        return nonce, ciphertext, tag
    
    def decrypt(
        self,
        nonce: bytes,
        ciphertext: bytes,
        tag: bytes,
        associated_data: Optional[bytes] = None
    ) -> bytes:
        """Decrypt with AES-256-GCM"""
        # Combine ciphertext and tag for cryptography library
        ciphertext_and_tag = ciphertext + tag
        
        try:
            plaintext = self.cipher.decrypt(
                nonce,
                ciphertext_and_tag,
                associated_data
            )
        except Exception as e:
            raise AuthenticationError(f"AES-256-GCM authentication failed: {e}")
        
        return plaintext
    
    @property
    def cipher_suite(self) -> CipherSuite:
        return CipherSuite.AES_256_GCM


class AES256EAXCipher(AEADCipher):
    """AES-256-EAX cipher (legacy v1 compatibility)"""
    
    def __init__(self, key: bytes):
        """
        Initialize AES-256-EAX cipher
        
        Args:
            key: 32-byte encryption key
        """
        try:
            from Crypto.Cipher import AES
            self.AES = AES
            self.key = key
            logger.debug("Initialized AES-256-EAX cipher (legacy mode)")
        except ImportError:
            raise CipherError("pycryptodome not available for AES-EAX")
        
        if len(key) != 32:
            raise ValueError("AES-256-EAX requires 32-byte key")
    
    def encrypt(
        self,
        plaintext: bytes,
        associated_data: Optional[bytes] = None
    ) -> Tuple[bytes, bytes, bytes]:
        """Encrypt with AES-256-EAX"""
        cipher = self.AES.new(self.key, self.AES.MODE_EAX)
        
        if associated_data:
            cipher.update(associated_data)
        
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        
        return cipher.nonce, ciphertext, tag
    
    def decrypt(
        self,
        nonce: bytes,
        ciphertext: bytes,
        tag: bytes,
        associated_data: Optional[bytes] = None
    ) -> bytes:
        """Decrypt with AES-256-EAX"""
        cipher = self.AES.new(self.key, self.AES.MODE_EAX, nonce=nonce)
        
        if associated_data:
            cipher.update(associated_data)
        
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError as e:
            raise AuthenticationError(f"AES-256-EAX authentication failed: {e}")
        
        return plaintext
    
    @property
    def cipher_suite(self) -> CipherSuite:
        return CipherSuite.AES_256_EAX


class HMACCipher(AEADCipher):
    """Fallback encrypt-then-MAC using AES-CTR + HMAC-SHA256"""
    
    def __init__(self, key: bytes):
        """
        Initialize HMAC cipher
        
        Args:
            key: 32-byte key (will be split for encryption and MAC)
        """
        if len(key) != 32:
            raise ValueError("HMAC cipher requires 32-byte key")
        
        # Split key into encryption and MAC keys
        self.enc_key = key[:16]
        self.mac_key = key[16:]
        
        try:
            from Crypto.Cipher import AES
            from Crypto.Util import Counter
            self.AES = AES
            self.Counter = Counter
            logger.debug("Initialized AES-CTR + HMAC-SHA256 fallback cipher")
        except ImportError:
            raise CipherError("pycryptodome not available for AES-CTR")
    
    def encrypt(
        self,
        plaintext: bytes,
        associated_data: Optional[bytes] = None
    ) -> Tuple[bytes, bytes, bytes]:
        """Encrypt then MAC"""
        # Generate nonce
        nonce = secrets.token_bytes(16)
        
        # Create CTR mode cipher
        ctr = self.Counter.new(128, initial_value=int.from_bytes(nonce, 'big'))
        cipher = self.AES.new(self.enc_key, self.AES.MODE_CTR, counter=ctr)
        
        # Encrypt
        ciphertext = cipher.encrypt(plaintext)
        
        # Compute MAC over nonce || associated_data || ciphertext
        mac_input = nonce
        if associated_data:
            mac_input += associated_data
        mac_input += ciphertext
        
        tag = hmac.new(self.mac_key, mac_input, 'sha256').digest()[:16]
        
        return nonce, ciphertext, tag
    
    def decrypt(
        self,
        nonce: bytes,
        ciphertext: bytes,
        tag: bytes,
        associated_data: Optional[bytes] = None
    ) -> bytes:
        """Verify MAC then decrypt"""
        # Verify MAC first
        mac_input = nonce
        if associated_data:
            mac_input += associated_data
        mac_input += ciphertext
        
        expected_tag = hmac.new(self.mac_key, mac_input, 'sha256').digest()[:16]
        
        # Constant-time comparison
        if not hmac.compare_digest(tag, expected_tag):
            raise AuthenticationError("HMAC verification failed")
        
        # Decrypt
        ctr = self.Counter.new(128, initial_value=int.from_bytes(nonce, 'big'))
        cipher = self.AES.new(self.enc_key, self.AES.MODE_CTR, counter=ctr)
        plaintext = cipher.decrypt(ciphertext)
        
        return plaintext
    
    @property
    def cipher_suite(self) -> CipherSuite:
        return CipherSuite.AES_256_EAX  # Report as EAX for compatibility


def get_cipher(suite: CipherSuite, key: bytes) -> AEADCipher:
    """
    Factory function to get appropriate cipher
    
    Args:
        suite: Cipher suite identifier
        key: Encryption key
    
    Returns:
        Initialized AEAD cipher
    
    Raises:
        CipherError: If cipher suite not supported
    """
    if suite == CipherSuite.XCHACHA20_POLY1305:
        try:
            return XChaCha20Poly1305Cipher(key)
        except CipherError:
            logger.warning("XChaCha20-Poly1305 not available, falling back to AES-GCM")
            return AES256GCMCipher(key)
    
    elif suite == CipherSuite.AES_256_GCM:
        return AES256GCMCipher(key)
    
    elif suite == CipherSuite.AES_256_EAX:
        return AES256EAXCipher(key)
    
    elif suite == CipherSuite.CHACHA20_POLY1305:
        # Could implement standard ChaCha20-Poly1305 here
        logger.warning("ChaCha20-Poly1305 not implemented, using XChaCha20")
        return get_cipher(CipherSuite.XCHACHA20_POLY1305, key)
    
    else:
        raise CipherError(f"Unsupported cipher suite: {suite}")


def get_preferred_cipher(key: bytes) -> AEADCipher:
    """
    Get the best available cipher
    
    Args:
        key: Encryption key
    
    Returns:
        Best available AEAD cipher
    """
    # Try in order of preference
    for suite in [
        CipherSuite.XCHACHA20_POLY1305,
        CipherSuite.AES_256_GCM,
        CipherSuite.AES_256_EAX
    ]:
        try:
            return get_cipher(suite, key)
        except CipherError:
            continue
    
    # Last resort: HMAC fallback
    logger.warning("No AEAD ciphers available, using HMAC fallback")
    return HMACCipher(key)
