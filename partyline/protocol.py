"""
Protocol v2 message envelope and serialization
Handles versioning, validation, and backward compatibility
"""

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field, validator

from partyline.constants import (
    PROTOCOL_VERSION,
    MIN_SUPPORTED_VERSION,
    LEGACY_VERSION,
    MessageType,
    CipherSuite,
    KDFSuite,
    MAX_MESSAGE_SIZE,
    MESSAGE_TTL_SECONDS,
    LEGACY_PROTOCOL_WARNING,
)

logger = logging.getLogger(__name__)


class EnvelopeV2(BaseModel):
    """Protocol v2 message envelope with validation"""
    
    version: int = Field(default=PROTOCOL_VERSION, ge=MIN_SUPPORTED_VERSION, le=PROTOCOL_VERSION)
    msg_type: MessageType = Field(default=MessageType.TEXT)
    sender_id: Optional[str] = Field(default=None, max_length=64)  # Hash of identity key
    session_id: str = Field(max_length=32)  # Truncated session identifier
    sequence: int = Field(ge=0)
    timestamp: float = Field(default_factory=time.time)
    
    # Cryptographic parameters
    cipher_suite: CipherSuite
    kdf_suite: KDFSuite
    kdf_params: Dict[str, Any]  # Salt, iterations, etc.
    
    # Encrypted payload and authentication
    nonce: str  # Hex-encoded nonce
    payload: str  # Hex-encoded encrypted data
    tag: str  # Hex-encoded authentication tag
    
    # Optional fields
    ttl: Optional[int] = Field(default=MESSAGE_TTL_SECONDS, ge=0)
    fragment_info: Optional[Dict[str, Any]] = None  # For fragmented messages
    
    @validator('version')
    def validate_version(cls, v):
        """Ensure version is supported"""
        if v < MIN_SUPPORTED_VERSION:
            raise ValueError(f"Unsupported protocol version {v}, minimum is {MIN_SUPPORTED_VERSION}")
        if v > PROTOCOL_VERSION:
            raise ValueError(f"Protocol version {v} is newer than supported {PROTOCOL_VERSION}")
        return v
    
    @validator('timestamp')
    def validate_timestamp(cls, v):
        """Ensure timestamp is reasonable"""
        current = time.time()
        # Allow 5 minutes clock skew
        if v > current + 300:
            raise ValueError("Timestamp is too far in the future")
        # Reject messages older than 24 hours
        if v < current - 86400:
            raise ValueError("Timestamp is too old")
        return v
    
    @validator('payload')
    def validate_payload_size(cls, v):
        """Ensure payload isn't too large"""
        # Hex string is 2x the byte size
        if len(v) > MAX_MESSAGE_SIZE * 2:
            raise ValueError(f"Payload exceeds maximum size of {MAX_MESSAGE_SIZE} bytes")
        return v
    
    @validator('sender_id')
    def validate_sender_id(cls, v):
        """Validate sender ID format if present"""
        if v and not v.replace('-', '').isalnum():
            raise ValueError("Invalid sender_id format")
        return v
    
    def to_bytes(self) -> bytes:
        """Serialize envelope to bytes for transmission"""
        # Use compact JSON without spaces
        return json.dumps(self.dict(exclude_none=True), separators=(',', ':')).encode('utf-8')
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'EnvelopeV2':
        """Deserialize envelope from bytes"""
        try:
            obj = json.loads(data)
            return cls(**obj)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid envelope JSON: {e}")
        except Exception as e:
            raise ValueError(f"Invalid envelope format: {e}")
    
    def get_aad(self) -> bytes:
        """Get additional authenticated data for AEAD"""
        # Include critical fields that must be authenticated
        aad_dict = {
            'version': self.version,
            'msg_type': self.msg_type.value,
            'sender_id': self.sender_id,
            'session_id': self.session_id,
            'sequence': self.sequence,
            'timestamp': self.timestamp,
            'cipher_suite': self.cipher_suite.value,
            'kdf_suite': self.kdf_suite.value,
        }
        return json.dumps(aad_dict, separators=(',', ':')).encode('utf-8')
    
    def is_expired(self) -> bool:
        """Check if message has expired based on TTL"""
        if not self.ttl:
            return False
        age = time.time() - self.timestamp
        return age > self.ttl


class LegacyEnvelope(BaseModel):
    """Legacy v1 envelope for backward compatibility"""
    
    nonce: str
    cipher: str
    tag: str
    sender: Optional[str] = None
    timestamp: Optional[float] = None
    
    @classmethod
    def from_bytes(cls, data: bytes) -> Optional['LegacyEnvelope']:
        """Try to parse as legacy v1 format"""
        try:
            obj = json.loads(data)
            # Check for v1 signature
            if 'nonce' in obj and 'cipher' in obj and 'tag' in obj:
                return cls(**obj)
        except:
            pass
        return None
    
    def to_v2_compat(self) -> EnvelopeV2:
        """Convert legacy envelope to v2 format for processing"""
        # Generate deterministic session ID from content
        session_hash = hashlib.sha256(
            (self.nonce + self.cipher + self.tag).encode()
        ).hexdigest()[:16]
        
        return EnvelopeV2(
            version=LEGACY_VERSION,
            msg_type=MessageType.LEGACY,
            sender_id=hashlib.sha256(
                (self.sender or 'unknown').encode()
            ).hexdigest()[:16] if self.sender else None,
            session_id=session_hash,
            sequence=0,
            timestamp=self.timestamp or time.time(),
            cipher_suite=CipherSuite.AES_256_EAX,
            kdf_suite=KDFSuite.PBKDF2_SHA256,
            kdf_params={
                'salt': 'mempool_partyline_salt',  # Fixed salt in v1
                'iterations': 100000
            },
            nonce=self.nonce,
            payload=self.cipher,
            tag=self.tag
        )


@dataclass
class Message:
    """Decrypted message content"""
    content: str
    timestamp: float
    sender: str = "Unknown"
    msg_type: MessageType = MessageType.TEXT
    session_id: Optional[str] = None
    sequence: Optional[int] = None
    ttl: Optional[int] = None
    
    def formatted(self) -> str:
        """Format message for display"""
        from datetime import datetime
        time_str = datetime.fromtimestamp(self.timestamp).strftime('%H:%M:%S')
        return f"[{time_str}] {self.sender}: {self.content}"
    
    def is_expired(self) -> bool:
        """Check if message has expired"""
        if not self.ttl:
            return False
        age = time.time() - self.timestamp
        return age > self.ttl


class ProtocolNegotiation(BaseModel):
    """Protocol negotiation for handshake"""
    
    supported_versions: List[int] = Field(default=[PROTOCOL_VERSION])
    supported_ciphers: List[CipherSuite] = Field(
        default=[
            CipherSuite.XCHACHA20_POLY1305,
            CipherSuite.AES_256_GCM,
            CipherSuite.AES_256_EAX
        ]
    )
    supported_kdfs: List[KDFSuite] = Field(
        default=[
            KDFSuite.ARGON2ID,
            KDFSuite.PBKDF2_SHA256
        ]
    )
    
    def negotiate_version(self, peer_versions: List[int]) -> int:
        """Negotiate protocol version with peer"""
        common = set(self.supported_versions) & set(peer_versions)
        if not common:
            raise ValueError("No common protocol version")
        return max(common)  # Use highest common version
    
    def negotiate_cipher(self, peer_ciphers: List[CipherSuite]) -> CipherSuite:
        """Negotiate cipher suite with peer"""
        # Use preference order
        for cipher in self.supported_ciphers:
            if cipher in peer_ciphers:
                return cipher
        raise ValueError("No common cipher suite")
    
    def negotiate_kdf(self, peer_kdfs: List[KDFSuite]) -> KDFSuite:
        """Negotiate KDF with peer"""
        # Use preference order
        for kdf in self.supported_kdfs:
            if kdf in peer_kdfs:
                return kdf
        raise ValueError("No common KDF")


def detect_envelope_version(data: bytes) -> int:
    """
    Detect envelope version from raw data
    
    Args:
        data: Raw envelope bytes
    
    Returns:
        Detected protocol version
    """
    try:
        obj = json.loads(data)
        
        # Check for explicit version field
        if 'version' in obj:
            return obj['version']
        
        # Check for v1 signature
        if 'nonce' in obj and 'cipher' in obj and 'tag' in obj and 'version' not in obj:
            logger.warning(LEGACY_PROTOCOL_WARNING)
            return LEGACY_VERSION
        
    except:
        pass
    
    # Default to current version
    return PROTOCOL_VERSION


def parse_envelope(data: bytes) -> Union[EnvelopeV2, LegacyEnvelope]:
    """
    Parse envelope from raw bytes, detecting version
    
    Args:
        data: Raw envelope bytes
    
    Returns:
        Parsed envelope (v2 or legacy)
    
    Raises:
        ValueError: If envelope cannot be parsed
    """
    version = detect_envelope_version(data)
    
    if version == LEGACY_VERSION:
        # Try legacy format
        legacy = LegacyEnvelope.from_bytes(data)
        if legacy:
            logger.warning("Parsed legacy v1 envelope")
            return legacy.to_v2_compat()
        raise ValueError("Failed to parse legacy envelope")
    
    # Parse as v2
    return EnvelopeV2.from_bytes(data)


def validate_envelope_downgrade(
    envelope: EnvelopeV2,
    expected_version: int,
    expected_cipher: CipherSuite,
    expected_kdf: KDFSuite
) -> bool:
    """
    Validate that envelope hasn't been downgraded
    
    Args:
        envelope: Received envelope
        expected_version: Expected protocol version
        expected_cipher: Expected cipher suite
        expected_kdf: Expected KDF suite
    
    Returns:
        True if validation passes
    
    Raises:
        ValueError: If downgrade detected
    """
    if envelope.version < expected_version:
        raise ValueError(f"Protocol downgrade detected: got v{envelope.version}, expected v{expected_version}")
    
    # Check cipher downgrade
    cipher_preference = [
        CipherSuite.XCHACHA20_POLY1305,
        CipherSuite.AES_256_GCM,
        CipherSuite.AES_256_EAX
    ]
    
    expected_idx = cipher_preference.index(expected_cipher)
    actual_idx = cipher_preference.index(envelope.cipher_suite)
    
    if actual_idx > expected_idx:  # Higher index = weaker cipher
        raise ValueError(f"Cipher downgrade detected: got {envelope.cipher_suite}, expected {expected_cipher}")
    
    # Check KDF downgrade
    kdf_preference = [
        KDFSuite.ARGON2ID,
        KDFSuite.SCRYPT,
        KDFSuite.PBKDF2_SHA256
    ]
    
    if expected_kdf in kdf_preference and envelope.kdf_suite in kdf_preference:
        expected_idx = kdf_preference.index(expected_kdf)
        actual_idx = kdf_preference.index(envelope.kdf_suite)
        
        if actual_idx > expected_idx:  # Higher index = weaker KDF
            raise ValueError(f"KDF downgrade detected: got {envelope.kdf_suite}, expected {expected_kdf}")
    
    return True
