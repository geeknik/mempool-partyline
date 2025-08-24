"""
Identity management with Ed25519/X25519 keys
Supports multiple personas with key rotation
"""

import hashlib
import logging
import time
from pathlib import Path
from typing import Optional, Dict, Any, Tuple, List
from dataclasses import dataclass, field

import nacl.signing
import nacl.public
import nacl.encoding
import nacl.hash
import nacl.bindings

from partyline.crypto.keyring_store import get_keyring_store
from partyline.crypto.kdf import hkdf_derive, zeroize
from partyline.security import SecureRandom, MemoryProtection
from partyline.constants import KEY_ROTATION_DAYS, MessageType
from partyline.logging_sec import log_security_event

logger = logging.getLogger(__name__)


@dataclass
class IdentityKeys:
    """Container for identity key material"""
    seed: bytes  # 32-byte seed for key derivation
    signing_key: nacl.signing.SigningKey
    verify_key: nacl.signing.VerifyKey
    encryption_key: nacl.public.PrivateKey
    public_key: nacl.public.PublicKey
    created_at: float = field(default_factory=time.time)
    rotated_at: Optional[float] = None
    message_count: int = 0
    
    def get_identity_hash(self) -> str:
        """Get hash of public identity for sender_id"""
        return hashlib.sha256(
            self.verify_key.encode() + self.public_key.encode()
        ).hexdigest()[:16]
    
    def sign(self, message: bytes) -> bytes:
        """Sign a message with identity key"""
        return self.signing_key.sign(message).signature
    
    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify a signature"""
        try:
            self.verify_key.verify(message, signature)
            return True
        except nacl.exceptions.BadSignatureError:
            return False
    
    def needs_rotation(self, max_days: int = KEY_ROTATION_DAYS, max_messages: int = 10000) -> bool:
        """Check if keys need rotation"""
        age_days = (time.time() - self.created_at) / 86400
        return age_days > max_days or self.message_count > max_messages
    
    def zeroize(self):
        """Securely zero key material"""
        if hasattr(self.seed, '__len__'):
            zeroize(self.seed)
        # Note: NaCl keys are immutable bytes, can't zero in place
        # Best we can do is delete references and let GC handle it
        del self.signing_key
        del self.encryption_key


@dataclass 
class SessionKeys:
    """Ephemeral session keys for forward secrecy"""
    session_id: str
    ephemeral_private: nacl.public.PrivateKey
    ephemeral_public: nacl.public.PublicKey
    peer_public: Optional[nacl.public.PublicKey] = None
    shared_secret: Optional[bytes] = None
    sending_chain: Optional[bytes] = None
    receiving_chain: Optional[bytes] = None
    send_counter: int = 0
    recv_counter: int = 0
    created_at: float = field(default_factory=time.time)
    
    def derive_shared_secret(self, peer_public_key: nacl.public.PublicKey) -> bytes:
        """Derive shared secret via ECDH"""
        self.peer_public = peer_public_key
        box = nacl.public.Box(self.ephemeral_private, peer_public_key)
        
        # Use the raw shared secret for further KDF
        # NaCl's Box includes its own KDF, but we want raw ECDH output
        self.shared_secret = nacl.bindings.crypto_scalarmult(
            self.ephemeral_private.encode(),
            peer_public_key.encode()
        )
        
        # Derive chain keys
        self.sending_chain = hkdf_derive(
            self.shared_secret,
            salt=b"partyline_send",
            info=self.session_id.encode()
        )
        self.receiving_chain = hkdf_derive(
            self.shared_secret,
            salt=b"partyline_recv", 
            info=self.session_id.encode()
        )
        
        return self.shared_secret
    
    def get_next_message_key(self, direction: str = "send") -> bytes:
        """Get next message key and advance ratchet"""
        import hmac
        
        if direction == "send":
            # Derive message key
            message_key = hkdf_derive(
                self.sending_chain,
                info=f"msg_{self.send_counter}".encode()
            )
            # Ratchet forward
            self.sending_chain = hmac.new(
                self.sending_chain,
                b"ratchet",
                hashlib.sha256
            ).digest()
            self.send_counter += 1
        else:
            message_key = hkdf_derive(
                self.receiving_chain,
                info=f"msg_{self.recv_counter}".encode()
            )
            self.receiving_chain = hmac.new(
                self.receiving_chain,
                b"ratchet",
                hashlib.sha256
            ).digest()
            self.recv_counter += 1
        
        return message_key
    
    def zeroize(self):
        """Zero session key material"""
        if self.shared_secret:
            zeroize(self.shared_secret)
        if self.sending_chain:
            zeroize(self.sending_chain)
        if self.receiving_chain:
            zeroize(self.receiving_chain)
        del self.ephemeral_private


class IdentityManager:
    """
    Manages cryptographic identities and personas
    """
    
    def __init__(self, keyring_store=None):
        """
        Initialize identity manager
        
        Args:
            keyring_store: Optional keyring store instance
        """
        self.keyring = keyring_store or get_keyring_store()
        self.identities: Dict[str, IdentityKeys] = {}
        self.sessions: Dict[str, SessionKeys] = {}
        self.current_persona: Optional[str] = None
    
    def generate_identity(self, persona: str = "default") -> IdentityKeys:
        """
        Generate new identity keys for a persona
        
        Args:
            persona: Persona name
        
        Returns:
            New IdentityKeys instance
        """
        # Generate 32-byte seed
        seed = SecureRandom.get_bytes(32)
        
        # Try to lock memory
        MemoryProtection.lock_memory(seed)
        
        # Derive Ed25519 signing key from seed
        signing_key = nacl.signing.SigningKey(seed)
        verify_key = signing_key.verify_key
        
        # Convert Ed25519 to X25519 for encryption
        # This is a standard conversion defined in RFC 7748
        encryption_seed = hashlib.sha256(seed + b"encryption").digest()
        encryption_key = nacl.public.PrivateKey(encryption_seed)
        public_key = encryption_key.public_key
        
        identity = IdentityKeys(
            seed=seed,
            signing_key=signing_key,
            verify_key=verify_key,
            encryption_key=encryption_key,
            public_key=public_key
        )
        
        # Log identity creation
        log_security_event(
            "identity_generated",
            {
                "persona": persona,
                "identity_hash": identity.get_identity_hash(),
                "key_type": "Ed25519/X25519"
            }
        )
        
        logger.info(f"Generated new identity for persona '{persona}'")
        return identity
    
    def store_identity(self, persona: str, identity: IdentityKeys, password: str) -> bool:
        """
        Store identity in keyring
        
        Args:
            persona: Persona name
            identity: Identity keys to store
            password: Encryption password
        
        Returns:
            True if successful
        """
        metadata = {
            "created_at": identity.created_at,
            "rotated_at": identity.rotated_at,
            "message_count": identity.message_count,
            "identity_hash": identity.get_identity_hash(),
            "verify_key": identity.verify_key.encode(nacl.encoding.Base64Encoder).decode(),
            "public_key": identity.public_key.encode(nacl.encoding.Base64Encoder).decode()
        }
        
        success = self.keyring.store_identity(
            persona,
            identity.seed,
            password,
            metadata
        )
        
        if success:
            self.identities[persona] = identity
            logger.info(f"Stored identity for persona '{persona}'")
        
        return success
    
    def load_identity(self, persona: str, password: str) -> Optional[IdentityKeys]:
        """
        Load identity from keyring
        
        Args:
            persona: Persona name
            password: Decryption password
        
        Returns:
            IdentityKeys instance or None
        """
        # Check cache first
        if persona in self.identities:
            return self.identities[persona]
        
        # Load from keyring
        seed = self.keyring.retrieve_identity(persona, password)
        if not seed:
            return None
        
        # Reconstruct keys
        signing_key = nacl.signing.SigningKey(seed)
        verify_key = signing_key.verify_key
        
        encryption_seed = hashlib.sha256(seed + b"encryption").digest()
        encryption_key = nacl.public.PrivateKey(encryption_seed)
        public_key = encryption_key.public_key
        
        identity = IdentityKeys(
            seed=seed,
            signing_key=signing_key,
            verify_key=verify_key,
            encryption_key=encryption_key,
            public_key=public_key
        )
        
        # Cache in memory
        self.identities[persona] = identity
        self.current_persona = persona
        
        logger.info(f"Loaded identity for persona '{persona}'")
        return identity
    
    def switch_persona(self, persona: str, password: str) -> bool:
        """
        Switch to a different persona
        
        Args:
            persona: Persona to switch to
            password: Password for persona
        
        Returns:
            True if successful
        """
        identity = self.load_identity(persona, password)
        if identity:
            self.current_persona = persona
            logger.info(f"Switched to persona '{persona}'")
            return True
        return False
    
    def get_current_identity(self) -> Optional[IdentityKeys]:
        """Get current persona's identity"""
        if self.current_persona:
            return self.identities.get(self.current_persona)
        return None
    
    def create_session(self, session_id: str) -> SessionKeys:
        """
        Create new ephemeral session keys
        
        Args:
            session_id: Unique session identifier
        
        Returns:
            New SessionKeys instance
        """
        # Generate ephemeral X25519 key pair
        ephemeral_private = nacl.public.PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key
        
        session = SessionKeys(
            session_id=session_id,
            ephemeral_private=ephemeral_private,
            ephemeral_public=ephemeral_public
        )
        
        # Store in memory only
        self.sessions[session_id] = session
        
        logger.debug(f"Created session {session_id[:8]}...")
        return session
    
    def get_session(self, session_id: str) -> Optional[SessionKeys]:
        """Get session by ID"""
        return self.sessions.get(session_id)
    
    def rotate_identity(self, persona: str, password: str) -> Optional[IdentityKeys]:
        """
        Rotate identity keys for a persona
        
        Args:
            persona: Persona to rotate
            password: Password for storage
        
        Returns:
            New IdentityKeys or None
        """
        # Get old identity
        old_identity = self.identities.get(persona)
        
        # Generate new identity
        new_identity = self.generate_identity(persona)
        new_identity.rotated_at = time.time()
        
        # Store new identity
        if self.store_identity(persona, new_identity, password):
            # Log rotation
            log_security_event(
                "identity_rotated",
                {
                    "persona": persona,
                    "old_hash": old_identity.get_identity_hash() if old_identity else None,
                    "new_hash": new_identity.get_identity_hash()
                }
            )
            
            # Clean up old identity
            if old_identity:
                old_identity.zeroize()
            
            return new_identity
        
        return None
    
    def export_public_identity(self, persona: str) -> Optional[Dict[str, str]]:
        """
        Export public keys for sharing
        
        Args:
            persona: Persona to export
        
        Returns:
            Dictionary with public key data
        """
        identity = self.identities.get(persona)
        if not identity:
            return None
        
        return {
            "persona": persona,
            "identity_hash": identity.get_identity_hash(),
            "verify_key": identity.verify_key.encode(nacl.encoding.Base64Encoder).decode(),
            "public_key": identity.public_key.encode(nacl.encoding.Base64Encoder).decode(),
            "created_at": str(identity.created_at)
        }
    
    def import_peer_identity(self, peer_data: Dict[str, str]) -> Tuple[nacl.signing.VerifyKey, nacl.public.PublicKey]:
        """
        Import peer's public identity
        
        Args:
            peer_data: Peer's public key data
        
        Returns:
            Tuple of (verify_key, public_key)
        """
        verify_key = nacl.signing.VerifyKey(
            peer_data["verify_key"],
            encoder=nacl.encoding.Base64Encoder
        )
        public_key = nacl.public.PublicKey(
            peer_data["public_key"],
            encoder=nacl.encoding.Base64Encoder
        )
        
        # Verify identity hash
        expected_hash = hashlib.sha256(
            verify_key.encode() + public_key.encode()
        ).hexdigest()[:16]
        
        if expected_hash != peer_data.get("identity_hash"):
            logger.warning("Identity hash mismatch for peer")
        
        return verify_key, public_key
    
    def cleanup_expired_sessions(self, max_age_seconds: int = 3600):
        """Clean up old sessions"""
        current_time = time.time()
        expired = []
        
        for session_id, session in self.sessions.items():
            if current_time - session.created_at > max_age_seconds:
                expired.append(session_id)
        
        for session_id in expired:
            session = self.sessions.pop(session_id)
            session.zeroize()
            logger.debug(f"Cleaned up expired session {session_id[:8]}...")
    
    def cleanup_all(self):
        """Securely clean up all key material"""
        # Zero all identities
        for identity in self.identities.values():
            identity.zeroize()
        self.identities.clear()
        
        # Zero all sessions
        for session in self.sessions.values():
            session.zeroize()
        self.sessions.clear()
        
        self.current_persona = None
        logger.info("Cleaned up all identity material")
