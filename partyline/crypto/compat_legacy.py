"""
Legacy v1 compatibility module
Handles decryption of v1 messages for backward compatibility
"""

import base64
import json
import logging
import time
from typing import Optional, Tuple

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

from partyline.constants import (
    DEFAULT_KDF_ITERATIONS,
    LEGACY_PROTOCOL_WARNING,
)
from partyline.protocol import Message
from partyline.logging_sec import log_security_event

logger = logging.getLogger(__name__)

# Legacy v1 fixed salt - DO NOT USE FOR NEW MESSAGES
LEGACY_SALT = b'mempool_partyline_salt'


class LegacyDecryptor:
    """
    Handles decryption of legacy v1 messages
    
    WARNING: This is for backward compatibility only.
    New messages should NEVER use this format.
    """
    
    def __init__(self, password: str):
        """
        Initialize legacy decryptor
        
        Args:
            password: Shared password for decryption
        """
        self.password = password.encode('utf-8') if isinstance(password, str) else password
        self.key = self._derive_legacy_key(self.password)
        
        # Log that legacy mode is being used
        log_security_event(
            "legacy_decryptor_init",
            {"warning": "Legacy v1 decryptor initialized for backward compatibility"},
            severity="WARNING"
        )
    
    def _derive_legacy_key(self, password: bytes) -> bytes:
        """
        Derive key using legacy PBKDF2 with fixed salt
        
        Args:
            password: Password bytes
        
        Returns:
            32-byte derived key
        """
        logger.warning(LEGACY_PROTOCOL_WARNING)
        
        # Use legacy fixed salt and iteration count
        return PBKDF2(
            password,
            LEGACY_SALT,
            dkLen=32,
            count=DEFAULT_KDF_ITERATIONS,
            hmac_hash_module=SHA256
        )
    
    def decrypt_legacy_message(
        self,
        nonce_hex: str,
        ciphertext_hex: str,
        tag_hex: str,
        sender: Optional[str] = None,
        timestamp: Optional[float] = None
    ) -> Optional[Message]:
        """
        Decrypt a legacy v1 message
        
        Args:
            nonce_hex: Hex-encoded nonce
            ciphertext_hex: Hex-encoded ciphertext
            tag_hex: Hex-encoded authentication tag
            sender: Optional sender name
            timestamp: Optional message timestamp
        
        Returns:
            Decrypted Message object or None if decryption fails
        """
        try:
            # Decode from hex
            nonce = base64.b64decode(nonce_hex) if self._is_base64(nonce_hex) else bytes.fromhex(nonce_hex)
            ciphertext = base64.b64decode(ciphertext_hex) if self._is_base64(ciphertext_hex) else bytes.fromhex(ciphertext_hex)
            tag = base64.b64decode(tag_hex) if self._is_base64(tag_hex) else bytes.fromhex(tag_hex)
            
            # Create AES-EAX cipher
            cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
            
            # Decrypt and verify
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            
            # Try to parse as JSON (v1 format)
            try:
                payload = json.loads(plaintext.decode('utf-8'))
                
                # Extract message fields
                if isinstance(payload, dict):
                    content = payload.get('message', payload.get('content', ''))
                    sender = payload.get('sender', sender or 'Unknown')
                    timestamp = payload.get('timestamp', timestamp or time.time())
                else:
                    # Plain text message
                    content = plaintext.decode('utf-8')
                    sender = sender or 'Unknown'
                    timestamp = timestamp or time.time()
                
            except (json.JSONDecodeError, UnicodeDecodeError):
                # Assume plain text
                content = plaintext.decode('utf-8', errors='replace')
                sender = sender or 'Unknown'
                timestamp = timestamp or time.time()
            
            # Log successful legacy decryption
            log_security_event(
                "legacy_message_decrypted",
                {
                    "sender": sender,
                    "timestamp": timestamp,
                    "warning": "Legacy v1 message decrypted - sender should upgrade"
                },
                severity="WARNING"
            )
            
            return Message(
                content=content,
                timestamp=timestamp,
                sender=f"{sender} (v1)",  # Mark as v1 message
            )
            
        except Exception as e:
            logger.debug(f"Legacy decryption failed: {e}")
            return None
    
    def _is_base64(self, s: str) -> bool:
        """
        Check if string is base64 encoded
        
        Args:
            s: String to check
        
        Returns:
            True if likely base64
        """
        try:
            # Check if it's valid base64
            if len(s) % 4 != 0:
                return False
            base64.b64decode(s, validate=True)
            return True
        except:
            return False


def detect_legacy_format(data: str) -> bool:
    """
    Detect if data is in legacy v1 format
    
    Args:
        data: Raw message data
    
    Returns:
        True if data appears to be v1 format
    """
    try:
        obj = json.loads(data)
        
        # Check for v1 signature fields
        if isinstance(obj, dict):
            # v1 has nonce, cipher, tag but no version
            has_v1_fields = all(k in obj for k in ['nonce', 'cipher', 'tag'])
            has_version = 'version' in obj
            
            if has_v1_fields and not has_version:
                logger.warning("Detected legacy v1 message format")
                return True
                
    except:
        pass
    
    return False


def migrate_legacy_message(legacy_data: dict) -> dict:
    """
    Convert legacy v1 message to v2-compatible format
    
    Args:
        legacy_data: Legacy message dictionary
    
    Returns:
        v2-compatible message dictionary
    """
    import hashlib
    from partyline.constants import CipherSuite, KDFSuite, MessageType
    
    # Generate session ID from content hash
    content_hash = hashlib.sha256(
        json.dumps(legacy_data, sort_keys=True).encode()
    ).hexdigest()[:16]
    
    return {
        'version': 1,  # Mark as v1 for processing
        'msg_type': MessageType.LEGACY.value,
        'sender_id': hashlib.sha256(
            (legacy_data.get('sender', 'unknown')).encode()
        ).hexdigest()[:16],
        'session_id': content_hash,
        'sequence': 0,
        'timestamp': legacy_data.get('timestamp', time.time()),
        'cipher_suite': CipherSuite.AES_256_EAX.value,
        'kdf_suite': KDFSuite.PBKDF2_SHA256.value,
        'kdf_params': {
            'salt': LEGACY_SALT.hex(),
            'iterations': DEFAULT_KDF_ITERATIONS
        },
        'nonce': legacy_data['nonce'],
        'payload': legacy_data['cipher'],
        'tag': legacy_data['tag']
    }


class LegacyBridge:
    """
    Bridge between v1 and v2 protocols
    Allows v2 clients to receive v1 messages
    """
    
    def __init__(self, password: str):
        """
        Initialize legacy bridge
        
        Args:
            password: Shared password for v1 compatibility
        """
        self.decryptor = LegacyDecryptor(password)
        self.v1_message_count = 0
        self.last_v1_warning = 0
    
    def process_legacy_envelope(self, data: dict) -> Optional[Message]:
        """
        Process a legacy v1 envelope
        
        Args:
            data: Legacy envelope dictionary
        
        Returns:
            Decrypted Message or None
        """
        self.v1_message_count += 1
        
        # Rate-limit warnings (once per minute)
        current_time = time.time()
        if current_time - self.last_v1_warning > 60:
            logger.warning(
                f"Processed {self.v1_message_count} legacy v1 messages. "
                "Please encourage senders to upgrade to v2."
            )
            self.last_v1_warning = current_time
        
        return self.decryptor.decrypt_legacy_message(
            nonce_hex=data.get('nonce', ''),
            ciphertext_hex=data.get('cipher', ''),
            tag_hex=data.get('tag', ''),
            sender=data.get('sender'),
            timestamp=data.get('timestamp')
        )
    
    def should_warn_sender(self) -> bool:
        """
        Check if we should warn about v1 usage
        
        Returns:
            True if warning should be shown
        """
        # Warn every 10 v1 messages
        return self.v1_message_count % 10 == 0


# Compatibility export for existing code
def decrypt_v1_message(
    password: str,
    nonce: str,
    ciphertext: str,
    tag: str,
    **kwargs
) -> Optional[Message]:
    """
    Convenience function to decrypt a single v1 message
    
    Args:
        password: Shared password
        nonce: Hex or base64 encoded nonce
        ciphertext: Hex or base64 encoded ciphertext
        tag: Hex or base64 encoded tag
        **kwargs: Additional message metadata
    
    Returns:
        Decrypted Message or None
    """
    decryptor = LegacyDecryptor(password)
    return decryptor.decrypt_legacy_message(
        nonce_hex=nonce,
        ciphertext_hex=ciphertext,
        tag_hex=tag,
        **kwargs
    )
