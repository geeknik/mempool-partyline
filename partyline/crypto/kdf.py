"""
Key Derivation Functions with secure defaults
Supports Argon2id (preferred) and PBKDF2 (legacy)
"""

import hashlib
import hmac
import logging
import secrets
from typing import Optional, Tuple, Union
from dataclasses import dataclass

from argon2 import PasswordHasher, Type as Argon2Type
from argon2.low_level import hash_secret_raw
from Crypto.Protocol.KDF import PBKDF2
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

from partyline.constants import (
    KDFSuite,
    ARGON2_TIME_COST,
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    DEFAULT_KDF_ITERATIONS,
    MIN_SALT_LENGTH,
    MAX_SALT_LENGTH,
)

logger = logging.getLogger(__name__)


@dataclass
class KDFParams:
    """Parameters for key derivation"""
    kdf_suite: KDFSuite
    salt: bytes
    iterations: Optional[int] = None
    memory_cost: Optional[int] = None
    time_cost: Optional[int] = None
    parallelism: Optional[int] = None
    
    def to_dict(self) -> dict:
        """Serialize to dictionary for encoding"""
        result = {
            'kdf_suite': self.kdf_suite.value,
            'salt': self.salt.hex(),
        }
        if self.iterations:
            result['iterations'] = self.iterations
        if self.memory_cost:
            result['memory_cost'] = self.memory_cost
        if self.time_cost:
            result['time_cost'] = self.time_cost
        if self.parallelism:
            result['parallelism'] = self.parallelism
        return result
    
    @classmethod
    def from_dict(cls, data: dict) -> 'KDFParams':
        """Deserialize from dictionary"""
        return cls(
            kdf_suite=KDFSuite(data['kdf_suite']),
            salt=bytes.fromhex(data['salt']),
            iterations=data.get('iterations'),
            memory_cost=data.get('memory_cost'),
            time_cost=data.get('time_cost'),
            parallelism=data.get('parallelism')
        )


class SecureKDF:
    """Secure key derivation with multiple algorithm support"""
    
    def __init__(self, kdf_suite: KDFSuite = KDFSuite.ARGON2ID):
        self.kdf_suite = kdf_suite
        
        # Initialize Argon2 hasher if needed
        if kdf_suite == KDFSuite.ARGON2ID:
            self.argon2_hasher = PasswordHasher(
                type=Argon2Type.ID,
                time_cost=ARGON2_TIME_COST,
                memory_cost=ARGON2_MEMORY_COST,
                parallelism=ARGON2_PARALLELISM,
                hash_len=32,
                salt_len=16
            )
    
    def generate_salt(self, length: Optional[int] = None) -> bytes:
        """
        Generate cryptographically secure random salt
        
        Args:
            length: Salt length in bytes (defaults to 16-32 random)
        
        Returns:
            Random salt bytes
        """
        if length is None:
            # Random length between MIN and MAX
            length = secrets.randbelow(MAX_SALT_LENGTH - MIN_SALT_LENGTH + 1) + MIN_SALT_LENGTH
        elif not MIN_SALT_LENGTH <= length <= MAX_SALT_LENGTH:
            raise ValueError(f"Salt length must be between {MIN_SALT_LENGTH} and {MAX_SALT_LENGTH}")
        
        return secrets.token_bytes(length)
    
    def derive_key(
        self,
        password: Union[str, bytes],
        salt: Optional[bytes] = None,
        key_length: int = 32,
        **kwargs
    ) -> Tuple[bytes, KDFParams]:
        """
        Derive key from password using configured KDF
        
        Args:
            password: Password string or bytes
            salt: Salt bytes (generated if not provided)
            key_length: Desired key length in bytes
            **kwargs: Additional KDF-specific parameters
        
        Returns:
            Tuple of (derived_key, kdf_params)
        """
        # Ensure password is bytes
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        # Generate salt if not provided
        if salt is None:
            salt = self.generate_salt()
        
        # Derive key based on suite
        if self.kdf_suite == KDFSuite.ARGON2ID:
            key, params = self._argon2_derive(password, salt, key_length, **kwargs)
        elif self.kdf_suite == KDFSuite.PBKDF2_SHA256:
            key, params = self._pbkdf2_derive(password, salt, key_length, **kwargs)
        elif self.kdf_suite == KDFSuite.SCRYPT:
            key, params = self._scrypt_derive(password, salt, key_length, **kwargs)
        else:
            raise ValueError(f"Unsupported KDF suite: {self.kdf_suite}")
        
        # Zeroize password from memory if we converted it
        if isinstance(password, bytearray):
            for i in range(len(password)):
                password[i] = 0
        
        return key, params
    
    def _argon2_derive(
        self,
        password: bytes,
        salt: bytes,
        key_length: int,
        time_cost: Optional[int] = None,
        memory_cost: Optional[int] = None,
        parallelism: Optional[int] = None
    ) -> Tuple[bytes, KDFParams]:
        """Derive key using Argon2id"""
        time_cost = time_cost or ARGON2_TIME_COST
        memory_cost = memory_cost or ARGON2_MEMORY_COST
        parallelism = parallelism or ARGON2_PARALLELISM
        
        # Use low-level API for raw key derivation
        key = hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=key_length,
            type=Argon2Type.ID
        )
        
        params = KDFParams(
            kdf_suite=KDFSuite.ARGON2ID,
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism
        )
        
        logger.debug(f"Derived Argon2id key with t={time_cost}, m={memory_cost}, p={parallelism}")
        return key, params
    
    def _pbkdf2_derive(
        self,
        password: bytes,
        salt: bytes,
        key_length: int,
        iterations: Optional[int] = None
    ) -> Tuple[bytes, KDFParams]:
        """Derive key using PBKDF2-HMAC-SHA256"""
        iterations = iterations or DEFAULT_KDF_ITERATIONS
        
        key = PBKDF2(
            password,
            salt,
            dkLen=key_length,
            count=iterations,
            hmac_hash_module=hashlib.sha256
        )
        
        params = KDFParams(
            kdf_suite=KDFSuite.PBKDF2_SHA256,
            salt=salt,
            iterations=iterations
        )
        
        logger.debug(f"Derived PBKDF2 key with {iterations} iterations")
        return key, params
    
    def _scrypt_derive(
        self,
        password: bytes,
        salt: bytes,
        key_length: int,
        n: int = 16384,  # CPU/memory cost
        r: int = 8,      # Block size
        p: int = 1       # Parallelization
    ) -> Tuple[bytes, KDFParams]:
        """Derive key using Scrypt"""
        kdf = Scrypt(
            salt=salt,
            length=key_length,
            n=n,
            r=r,
            p=p,
            backend=default_backend()
        )
        
        key = kdf.derive(password)
        
        params = KDFParams(
            kdf_suite=KDFSuite.SCRYPT,
            salt=salt,
            iterations=n,  # Store N as iterations
            memory_cost=r,  # Store r as memory_cost
            parallelism=p
        )
        
        logger.debug(f"Derived Scrypt key with n={n}, r={r}, p={p}")
        return key, params
    
    @staticmethod
    def verify_key(
        password: Union[str, bytes],
        params: KDFParams,
        expected_key: bytes
    ) -> bool:
        """
        Verify that password derives to expected key
        
        Args:
            password: Password to verify
            params: KDF parameters used
            expected_key: Expected derived key
        
        Returns:
            True if password derives to expected key
        """
        kdf = SecureKDF(params.kdf_suite)
        
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        # Re-derive with same parameters
        if params.kdf_suite == KDFSuite.ARGON2ID:
            derived_key, _ = kdf._argon2_derive(
                password, 
                params.salt,
                len(expected_key),
                params.time_cost,
                params.memory_cost,
                params.parallelism
            )
        elif params.kdf_suite == KDFSuite.PBKDF2_SHA256:
            derived_key, _ = kdf._pbkdf2_derive(
                password,
                params.salt,
                len(expected_key),
                params.iterations
            )
        elif params.kdf_suite == KDFSuite.SCRYPT:
            derived_key, _ = kdf._scrypt_derive(
                password,
                params.salt,
                len(expected_key),
                params.iterations,  # n
                params.memory_cost,  # r
                params.parallelism  # p
            )
        else:
            return False
        
        # Constant-time comparison
        return hmac.compare_digest(derived_key, expected_key)


def hkdf_derive(
    input_key: bytes,
    length: int = 32,
    salt: Optional[bytes] = None,
    info: Optional[bytes] = None
) -> bytes:
    """
    HKDF key derivation for session keys
    
    Args:
        input_key: Input key material
        length: Desired output length
        salt: Optional salt
        info: Optional context info
    
    Returns:
        Derived key bytes
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    
    if salt is None:
        salt = b''
    if info is None:
        info = b''
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
        backend=default_backend()
    )
    
    return hkdf.derive(input_key)


def zeroize(data: Union[bytes, bytearray]) -> None:
    """
    Best-effort memory zeroization
    
    Args:
        data: Sensitive data to zeroize
    """
    if isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = 0
    elif isinstance(data, bytes):
        # Can't modify bytes directly, log warning
        logger.warning("Cannot zeroize immutable bytes object")
    
    # Try to use sodium_memzero if available
    try:
        import nacl.bindings
        if isinstance(data, (bytes, bytearray)):
            nacl.bindings.sodium_memzero(data)
    except (ImportError, AttributeError):
        pass  # PyNaCl not available or doesn't have memzero
