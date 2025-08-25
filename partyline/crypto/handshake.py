"""
Handshake protocol for cipher and KDF negotiation
Implements secure parameter negotiation between peers
"""

import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any, List, Tuple
from enum import Enum

import nacl.public
import nacl.signing
import nacl.encoding

from partyline.crypto.aead import get_cipher, CIPHER_REGISTRY
from partyline.crypto.kdf import hkdf_derive, KDF_REGISTRY
from partyline.constants import (
    PROTOCOL_VERSION,
    MessageType,
    SUPPORTED_CIPHERS,
    SUPPORTED_KDF_ALGORITHMS
)
from partyline.security import SecureRandom
from partyline.logging_sec import log_security_event

logger = logging.getLogger(__name__)


class HandshakeState(Enum):
    """Handshake state machine states"""
    INIT = "init"
    HELLO_SENT = "hello_sent"
    HELLO_RECEIVED = "hello_received"
    KEY_EXCHANGE = "key_exchange"
    ESTABLISHED = "established"
    FAILED = "failed"


@dataclass
class CryptoCapabilities:
    """Cryptographic capabilities of a peer"""
    ciphers: List[str]
    kdfs: List[str]
    protocol_versions: List[int]
    features: Dict[str, bool]  # Extension features
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CryptoCapabilities':
        """Create from dictionary"""
        return cls(**data)
    
    @classmethod
    def get_local(cls) -> 'CryptoCapabilities':
        """Get local node capabilities"""
        return cls(
            ciphers=list(CIPHER_REGISTRY.keys()),
            kdfs=list(KDF_REGISTRY.keys()),
            protocol_versions=[1, 2, PROTOCOL_VERSION],
            features={
                "forward_secrecy": True,
                "identity_keys": True,
                "message_padding": True,
                "fragmentation": True,
                "compression": False  # Optional
            }
        )


@dataclass
class HandshakeMessage:
    """Base handshake message"""
    msg_type: str
    timestamp: float
    nonce: bytes
    payload: Dict[str, Any]
    signature: Optional[bytes] = None
    
    def to_bytes(self) -> bytes:
        """Serialize to bytes"""
        data = {
            "type": self.msg_type,
            "timestamp": self.timestamp,
            "nonce": self.nonce.hex(),
            "payload": self.payload
        }
        if self.signature:
            data["signature"] = self.signature.hex()
        
        return json.dumps(data, sort_keys=True).encode()
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'HandshakeMessage':
        """Deserialize from bytes"""
        obj = json.loads(data)
        return cls(
            msg_type=obj["type"],
            timestamp=obj["timestamp"],
            nonce=bytes.fromhex(obj["nonce"]),
            payload=obj["payload"],
            signature=bytes.fromhex(obj["signature"]) if "signature" in obj else None
        )
    
    def verify_freshness(self, max_age_seconds: int = 60) -> bool:
        """Verify message is fresh"""
        age = time.time() - self.timestamp
        return 0 <= age <= max_age_seconds


class HandshakeProtocol:
    """
    Secure handshake protocol implementation
    """
    
    def __init__(self, identity_manager, session_id: Optional[str] = None):
        """
        Initialize handshake protocol
        
        Args:
            identity_manager: Identity manager instance
            session_id: Optional session ID
        """
        self.identity_manager = identity_manager
        self.session_id = session_id or SecureRandom.get_bytes(16).hex()
        self.state = HandshakeState.INIT
        
        # Local capabilities
        self.local_caps = CryptoCapabilities.get_local()
        
        # Negotiated parameters
        self.peer_caps: Optional[CryptoCapabilities] = None
        self.selected_cipher: Optional[str] = None
        self.selected_kdf: Optional[str] = None
        self.selected_version: Optional[int] = None
        
        # Keys
        self.session_keys = None
        self.peer_identity_key: Optional[nacl.public.PublicKey] = None
        self.peer_verify_key: Optional[nacl.signing.VerifyKey] = None
        
        # Anti-replay
        self.seen_nonces = set()
        self.handshake_transcript = []
    
    def create_hello(self) -> bytes:
        """
        Create HELLO message to initiate handshake
        
        Returns:
            Serialized HELLO message
        """
        # Get current identity
        identity = self.identity_manager.get_current_identity()
        if not identity:
            raise ValueError("No identity available for handshake")
        
        # Create ephemeral session keys
        self.session_keys = self.identity_manager.create_session(self.session_id)
        
        # Build HELLO payload
        payload = {
            "session_id": self.session_id,
            "identity_key": identity.public_key.encode(nacl.encoding.Base64Encoder).decode(),
            "verify_key": identity.verify_key.encode(nacl.encoding.Base64Encoder).decode(),
            "ephemeral_key": self.session_keys.ephemeral_public.encode(nacl.encoding.Base64Encoder).decode(),
            "capabilities": self.local_caps.to_dict()
        }
        
        # Create message
        msg = HandshakeMessage(
            msg_type="HELLO",
            timestamp=time.time(),
            nonce=SecureRandom.get_bytes(16),
            payload=payload
        )
        
        # Sign message
        msg_bytes = msg.to_bytes()
        msg.signature = identity.sign(msg_bytes)
        
        # Update state
        self.state = HandshakeState.HELLO_SENT
        self.handshake_transcript.append(msg_bytes)
        
        logger.debug(f"Created HELLO for session {self.session_id[:8]}...")
        return msg.to_bytes()
    
    def process_hello(self, data: bytes) -> Optional[bytes]:
        """
        Process received HELLO message
        
        Args:
            data: Received HELLO message
        
        Returns:
            HELLO_ACK response or None if invalid
        """
        try:
            msg = HandshakeMessage.from_bytes(data)
            
            # Verify freshness
            if not msg.verify_freshness():
                logger.warning("Stale HELLO message")
                return None
            
            # Check nonce replay
            if msg.nonce in self.seen_nonces:
                logger.warning("Replayed HELLO nonce")
                return None
            self.seen_nonces.add(msg.nonce)
            
            # Extract peer keys
            self.peer_verify_key = nacl.signing.VerifyKey(
                msg.payload["verify_key"],
                encoder=nacl.encoding.Base64Encoder
            )
            self.peer_identity_key = nacl.public.PublicKey(
                msg.payload["identity_key"],
                encoder=nacl.encoding.Base64Encoder
            )
            peer_ephemeral = nacl.public.PublicKey(
                msg.payload["ephemeral_key"],
                encoder=nacl.encoding.Base64Encoder
            )
            
            # Verify signature
            msg_bytes = msg.to_bytes()
            try:
                self.peer_verify_key.verify(msg_bytes, msg.signature)
            except Exception:
                logger.warning("Invalid HELLO signature")
                return None
            
            # Store peer capabilities
            self.peer_caps = CryptoCapabilities.from_dict(msg.payload["capabilities"])
            
            # Negotiate parameters
            if not self._negotiate_parameters():
                logger.warning("Parameter negotiation failed")
                return None
            
            # Create our session if not exists
            if not self.session_keys:
                self.session_keys = self.identity_manager.create_session(self.session_id)
            
            # Derive shared secret
            self.session_keys.derive_shared_secret(peer_ephemeral)
            
            # Create HELLO_ACK
            ack = self._create_hello_ack()
            
            # Update state
            self.state = HandshakeState.KEY_EXCHANGE
            self.handshake_transcript.append(msg_bytes)
            self.handshake_transcript.append(ack)
            
            logger.debug(f"Processed HELLO for session {self.session_id[:8]}...")
            return ack
            
        except Exception as e:
            logger.error(f"HELLO processing failed: {e}")
            self.state = HandshakeState.FAILED
            return None
    
    def _create_hello_ack(self) -> bytes:
        """Create HELLO_ACK message"""
        identity = self.identity_manager.get_current_identity()
        
        payload = {
            "session_id": self.session_id,
            "ephemeral_key": self.session_keys.ephemeral_public.encode(nacl.encoding.Base64Encoder).decode(),
            "selected_cipher": self.selected_cipher,
            "selected_kdf": self.selected_kdf,
            "selected_version": self.selected_version,
            "transcript_hash": hashlib.sha256(b"".join(self.handshake_transcript)).hexdigest()
        }
        
        msg = HandshakeMessage(
            msg_type="HELLO_ACK",
            timestamp=time.time(),
            nonce=SecureRandom.get_bytes(16),
            payload=payload
        )
        
        # Sign with identity key
        msg_bytes = msg.to_bytes()
        msg.signature = identity.sign(msg_bytes)
        
        return msg.to_bytes()
    
    def process_hello_ack(self, data: bytes) -> bool:
        """
        Process HELLO_ACK message
        
        Args:
            data: Received HELLO_ACK
        
        Returns:
            True if handshake complete
        """
        try:
            msg = HandshakeMessage.from_bytes(data)
            
            # Verify state
            if self.state != HandshakeState.HELLO_SENT:
                logger.warning("Unexpected HELLO_ACK")
                return False
            
            # Verify freshness and replay
            if not msg.verify_freshness():
                return False
            if msg.nonce in self.seen_nonces:
                return False
            self.seen_nonces.add(msg.nonce)
            
            # Verify signature
            if not self.peer_verify_key:
                return False
            
            msg_bytes = msg.to_bytes()
            try:
                self.peer_verify_key.verify(msg_bytes, msg.signature)
            except Exception:
                logger.warning("Invalid HELLO_ACK signature")
                return False
            
            # Extract ephemeral key
            peer_ephemeral = nacl.public.PublicKey(
                msg.payload["ephemeral_key"],
                encoder=nacl.encoding.Base64Encoder
            )
            
            # Derive shared secret
            self.session_keys.derive_shared_secret(peer_ephemeral)
            
            # Store negotiated parameters
            self.selected_cipher = msg.payload["selected_cipher"]
            self.selected_kdf = msg.payload["selected_kdf"]
            self.selected_version = msg.payload["selected_version"]
            
            # Verify transcript
            self.handshake_transcript.append(msg_bytes)
            expected_hash = hashlib.sha256(b"".join(self.handshake_transcript[:-1])).hexdigest()
            if msg.payload.get("transcript_hash") != expected_hash:
                logger.warning("Transcript hash mismatch")
                return False
            
            # Complete handshake
            self.state = HandshakeState.ESTABLISHED
            self._derive_session_keys()
            
            # Log successful handshake
            log_security_event(
                "handshake_complete",
                {
                    "session_id": self.session_id[:8],
                    "cipher": self.selected_cipher,
                    "kdf": self.selected_kdf,
                    "version": self.selected_version
                }
            )
            
            logger.info(f"Handshake complete: {self.selected_cipher}/{self.selected_kdf}")
            return True
            
        except Exception as e:
            logger.error(f"HELLO_ACK processing failed: {e}")
            self.state = HandshakeState.FAILED
            return False
    
    def _negotiate_parameters(self) -> bool:
        """
        Negotiate cryptographic parameters
        
        Returns:
            True if negotiation successful
        """
        if not self.peer_caps:
            return False
        
        # Select highest common protocol version
        common_versions = set(self.local_caps.protocol_versions) & set(self.peer_caps.protocol_versions)
        if not common_versions:
            logger.warning("No common protocol versions")
            return False
        self.selected_version = max(common_versions)
        
        # Select cipher (prefer XChaCha20-Poly1305)
        cipher_preference = ["xchacha20-poly1305", "aes-256-gcm", "aes-256-eax"]
        common_ciphers = set(self.local_caps.ciphers) & set(self.peer_caps.ciphers)
        
        for cipher in cipher_preference:
            if cipher in common_ciphers:
                self.selected_cipher = cipher
                break
        
        if not self.selected_cipher and common_ciphers:
            self.selected_cipher = sorted(common_ciphers)[0]
        
        if not self.selected_cipher:
            logger.warning("No common ciphers")
            return False
        
        # Select KDF (prefer Argon2id)
        kdf_preference = ["argon2id", "scrypt", "pbkdf2"]
        common_kdfs = set(self.local_caps.kdfs) & set(self.peer_caps.kdfs)
        
        for kdf in kdf_preference:
            if kdf in common_kdfs:
                self.selected_kdf = kdf
                break
        
        if not self.selected_kdf and common_kdfs:
            self.selected_kdf = sorted(common_kdfs)[0]
        
        if not self.selected_kdf:
            logger.warning("No common KDFs")
            return False
        
        logger.debug(f"Negotiated: v{self.selected_version}, {self.selected_cipher}, {self.selected_kdf}")
        return True
    
    def _derive_session_keys(self):
        """Derive final session keys from handshake"""
        if not self.session_keys or not self.session_keys.shared_secret:
            raise ValueError("No shared secret available")
        
        # Derive master key from transcript
        transcript_hash = hashlib.sha256(b"".join(self.handshake_transcript)).digest()
        
        # Mix transcript into session keys
        master_key = hkdf_derive(
            self.session_keys.shared_secret,
            salt=transcript_hash,
            info=b"partyline_master_key"
        )
        
        # Update session keys with master key
        self.session_keys.sending_chain = hkdf_derive(
            master_key,
            info=b"sending_chain"
        )
        self.session_keys.receiving_chain = hkdf_derive(
            master_key,
            info=b"receiving_chain"
        )
    
    def get_negotiated_params(self) -> Optional[Dict[str, Any]]:
        """
        Get negotiated parameters after successful handshake
        
        Returns:
            Dictionary of negotiated parameters or None
        """
        if self.state != HandshakeState.ESTABLISHED:
            return None
        
        return {
            "session_id": self.session_id,
            "cipher": self.selected_cipher,
            "kdf": self.selected_kdf,
            "protocol_version": self.selected_version,
            "peer_identity": self.peer_identity_key.encode(nacl.encoding.Base64Encoder).decode() if self.peer_identity_key else None
        }
    
    def export_session_keys(self) -> Optional[Dict[str, bytes]]:
        """
        Export session keys for message encryption
        
        Returns:
            Session key material or None
        """
        if self.state != HandshakeState.ESTABLISHED or not self.session_keys:
            return None
        
        return {
            "session_id": self.session_id,
            "sending_key": self.session_keys.get_next_message_key("send"),
            "receiving_key": self.session_keys.get_next_message_key("recv"),
            "cipher": self.selected_cipher,
            "kdf": self.selected_kdf
        }
    
    def cleanup(self):
        """Clean up handshake state"""
        if self.session_keys:
            self.session_keys.zeroize()
        
        self.handshake_transcript.clear()
        self.seen_nonces.clear()
        self.state = HandshakeState.INIT


class HandshakeManager:
    """
    Manages multiple concurrent handshakes
    """
    
    def __init__(self, identity_manager):
        """
        Initialize handshake manager
        
        Args:
            identity_manager: Identity manager instance
        """
        self.identity_manager = identity_manager
        self.active_handshakes: Dict[str, HandshakeProtocol] = {}
        self.established_sessions: Dict[str, Dict[str, Any]] = {}
    
    def initiate_handshake(self) -> Tuple[str, bytes]:
        """
        Initiate a new handshake
        
        Returns:
            Tuple of (session_id, hello_message)
        """
        handshake = HandshakeProtocol(self.identity_manager)
        hello = handshake.create_hello()
        
        self.active_handshakes[handshake.session_id] = handshake
        
        return handshake.session_id, hello
    
    def process_message(self, data: bytes) -> Optional[bytes]:
        """
        Process incoming handshake message
        
        Args:
            data: Received message
        
        Returns:
            Response message or None
        """
        try:
            # Parse message type
            msg = HandshakeMessage.from_bytes(data)
            
            if msg.msg_type == "HELLO":
                # New handshake request
                session_id = msg.payload.get("session_id")
                if session_id in self.active_handshakes:
                    # Already have handshake for this session
                    return None
                
                handshake = HandshakeProtocol(self.identity_manager, session_id)
                response = handshake.process_hello(data)
                
                if response:
                    self.active_handshakes[session_id] = handshake
                
                return response
            
            elif msg.msg_type == "HELLO_ACK":
                # Response to our HELLO
                session_id = msg.payload.get("session_id")
                handshake = self.active_handshakes.get(session_id)
                
                if not handshake:
                    logger.warning(f"No handshake for session {session_id[:8]}...")
                    return None
                
                if handshake.process_hello_ack(data):
                    # Handshake complete
                    self.established_sessions[session_id] = handshake.get_negotiated_params()
                    logger.info(f"Session established: {session_id[:8]}...")
                
                return None
            
            else:
                logger.warning(f"Unknown handshake message type: {msg.msg_type}")
                return None
                
        except Exception as e:
            logger.error(f"Handshake message processing failed: {e}")
            return None
    
    def get_session(self, session_id: str) -> Optional[HandshakeProtocol]:
        """Get active handshake by session ID"""
        return self.active_handshakes.get(session_id)
    
    def cleanup_expired(self, max_age_seconds: int = 300):
        """Clean up expired handshakes"""
        current_time = time.time()
        expired = []
        
        for session_id, handshake in self.active_handshakes.items():
            if handshake.state == HandshakeState.FAILED:
                expired.append(session_id)
            elif handshake.state != HandshakeState.ESTABLISHED:
                # Check age of incomplete handshakes
                if hasattr(handshake, 'start_time'):
                    age = current_time - handshake.start_time
                    if age > max_age_seconds:
                        expired.append(session_id)
        
        for session_id in expired:
            handshake = self.active_handshakes.pop(session_id)
            handshake.cleanup()
            logger.debug(f"Cleaned up handshake {session_id[:8]}...")
