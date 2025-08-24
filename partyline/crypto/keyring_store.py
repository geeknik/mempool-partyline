"""
Secure key storage using OS keyring
Manages identity keys with encryption and backup support
"""

import json
import logging
import keyring
import base64
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass, field

from partyline.crypto.kdf import SecureKDF, KDFParams, zeroize
from partyline.crypto.aead import get_preferred_cipher
from partyline.security import SecureRandom, secure_delete_file
from partyline.constants import CipherSuite, KDFSuite

logger = logging.getLogger(__name__)

# Keyring service name
KEYRING_SERVICE = "mempool_partyline"
KEYRING_NAMESPACE = "identity"


@dataclass
class KeyBundle:
    """Encrypted key bundle for storage"""
    version: int = 2
    persona: str = "default"
    cipher_suite: CipherSuite = CipherSuite.AES_256_GCM
    kdf_params: Dict[str, Any] = field(default_factory=dict)
    nonce: str = ""  # Base64
    ciphertext: str = ""  # Base64
    tag: str = ""  # Base64
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_json(self) -> str:
        """Serialize to JSON for storage"""
        return json.dumps({
            'version': self.version,
            'persona': self.persona,
            'cipher_suite': self.cipher_suite.value,
            'kdf_params': self.kdf_params,
            'nonce': self.nonce,
            'ciphertext': self.ciphertext,
            'tag': self.tag,
            'metadata': self.metadata
        })
    
    @classmethod
    def from_json(cls, data: str) -> 'KeyBundle':
        """Deserialize from JSON"""
        obj = json.loads(data)
        return cls(
            version=obj['version'],
            persona=obj['persona'],
            cipher_suite=CipherSuite(obj['cipher_suite']),
            kdf_params=obj['kdf_params'],
            nonce=obj['nonce'],
            ciphertext=obj['ciphertext'],
            tag=obj['tag'],
            metadata=obj.get('metadata', {})
        )


class KeyringStore:
    """
    Secure key storage using OS keyring
    
    Stores encrypted identity keys in the OS keyring (macOS Keychain,
    Windows Credential Manager, Linux Secret Service)
    """
    
    def __init__(self, app_id: str = KEYRING_SERVICE):
        """
        Initialize keyring store
        
        Args:
            app_id: Application identifier for keyring
        """
        self.app_id = app_id
        self._check_keyring_availability()
    
    def _check_keyring_availability(self) -> None:
        """Check if keyring is available and working"""
        try:
            # Test keyring access
            test_key = f"{self.app_id}_test"
            keyring.set_password(self.app_id, test_key, "test")
            keyring.delete_password(self.app_id, test_key)
            logger.debug(f"Keyring backend: {keyring.get_keyring()}")
        except Exception as e:
            logger.warning(f"Keyring not available: {e}")
            logger.info("Keys will be stored in encrypted files instead")
    
    def store_identity(
        self,
        persona: str,
        identity_seed: bytes,
        password: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Store encrypted identity seed in keyring
        
        Args:
            persona: Persona name (key identifier)
            identity_seed: Raw identity seed bytes
            password: Encryption password
            metadata: Optional metadata to store
        
        Returns:
            True if successful
        """
        try:
            # Derive encryption key
            kdf = SecureKDF(KDFSuite.ARGON2ID)
            key, kdf_params = kdf.derive_key(password)
            
            # Encrypt identity seed
            cipher = get_preferred_cipher(key)
            nonce, ciphertext, tag = cipher.encrypt(
                identity_seed,
                persona.encode('utf-8')  # Use persona as AAD
            )
            
            # Create key bundle
            bundle = KeyBundle(
                persona=persona,
                cipher_suite=cipher.cipher_suite,
                kdf_params=kdf_params.to_dict(),
                nonce=base64.b64encode(nonce).decode(),
                ciphertext=base64.b64encode(ciphertext).decode(),
                tag=base64.b64encode(tag).decode(),
                metadata=metadata or {}
            )
            
            # Store in keyring
            key_id = f"{KEYRING_NAMESPACE}_{persona}"
            keyring.set_password(self.app_id, key_id, bundle.to_json())
            
            # Zeroize sensitive data
            zeroize(key)
            zeroize(identity_seed)
            
            logger.info(f"Stored identity for persona '{persona}'")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store identity: {e}")
            return False
    
    def retrieve_identity(
        self,
        persona: str,
        password: str
    ) -> Optional[bytes]:
        """
        Retrieve and decrypt identity seed from keyring
        
        Args:
            persona: Persona name
            password: Decryption password
        
        Returns:
            Identity seed bytes or None if not found/failed
        """
        try:
            # Retrieve from keyring
            key_id = f"{KEYRING_NAMESPACE}_{persona}"
            bundle_json = keyring.get_password(self.app_id, key_id)
            
            if not bundle_json:
                logger.warning(f"No identity found for persona '{persona}'")
                return None
            
            # Parse bundle
            bundle = KeyBundle.from_json(bundle_json)
            
            # Derive decryption key
            kdf_params = KDFParams.from_dict(bundle.kdf_params)
            kdf = SecureKDF(kdf_params.kdf_suite)
            key, _ = kdf.derive_key(password, kdf_params.salt)
            
            # Decrypt identity seed
            from partyline.crypto.aead import get_cipher
            cipher = get_cipher(bundle.cipher_suite, key)
            
            identity_seed = cipher.decrypt(
                base64.b64decode(bundle.nonce),
                base64.b64decode(bundle.ciphertext),
                base64.b64decode(bundle.tag),
                persona.encode('utf-8')  # AAD
            )
            
            # Zeroize key
            zeroize(key)
            
            logger.info(f"Retrieved identity for persona '{persona}'")
            return identity_seed
            
        except Exception as e:
            logger.error(f"Failed to retrieve identity: {e}")
            return None
    
    def delete_identity(self, persona: str) -> bool:
        """
        Delete identity from keyring
        
        Args:
            persona: Persona to delete
        
        Returns:
            True if successful
        """
        try:
            key_id = f"{KEYRING_NAMESPACE}_{persona}"
            keyring.delete_password(self.app_id, key_id)
            logger.info(f"Deleted identity for persona '{persona}'")
            return True
        except Exception as e:
            logger.error(f"Failed to delete identity: {e}")
            return False
    
    def list_personas(self) -> list[str]:
        """
        List all stored personas
        
        Returns:
            List of persona names
        """
        # This is backend-specific and may not work on all platforms
        # Fallback to file-based listing if needed
        personas = []
        try:
            # Try to enumerate (not supported by all backends)
            import keyring.backends
            kr = keyring.get_keyring()
            
            # This is a hack and may not work on all platforms
            # Better to maintain a separate index
            logger.debug("Persona enumeration not fully supported by keyring")
            
        except Exception as e:
            logger.debug(f"Cannot enumerate keyring: {e}")
        
        return personas
    
    def export_bundle(
        self,
        persona: str,
        password: str,
        export_path: Path
    ) -> bool:
        """
        Export encrypted key bundle to file
        
        Args:
            persona: Persona to export
            password: Current password (for verification)
            export_path: Path to export file
        
        Returns:
            True if successful
        """
        try:
            # Retrieve bundle
            key_id = f"{KEYRING_NAMESPACE}_{persona}"
            bundle_json = keyring.get_password(self.app_id, key_id)
            
            if not bundle_json:
                logger.error(f"No identity found for persona '{persona}'")
                return False
            
            # Verify password by attempting decrypt
            identity = self.retrieve_identity(persona, password)
            if not identity:
                logger.error("Invalid password")
                return False
            
            # Zeroize retrieved identity
            zeroize(identity)
            
            # Write encrypted bundle to file
            export_path.parent.mkdir(parents=True, exist_ok=True)
            with open(export_path, 'w') as f:
                f.write(bundle_json)
            
            # Set secure permissions
            import os
            os.chmod(export_path, 0o600)
            
            logger.info(f"Exported identity bundle to {export_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export bundle: {e}")
            return False
    
    def import_bundle(
        self,
        import_path: Path,
        password: str,
        new_persona: Optional[str] = None
    ) -> bool:
        """
        Import encrypted key bundle from file
        
        Args:
            import_path: Path to bundle file
            password: Password to verify bundle
            new_persona: Optional new persona name
        
        Returns:
            True if successful
        """
        try:
            # Read bundle
            with open(import_path, 'r') as f:
                bundle_json = f.read()
            
            # Parse and validate
            bundle = KeyBundle.from_json(bundle_json)
            
            # Use new persona name if provided
            if new_persona:
                bundle.persona = new_persona
            
            # Verify by attempting decrypt
            kdf_params = KDFParams.from_dict(bundle.kdf_params)
            kdf = SecureKDF(kdf_params.kdf_suite)
            key, _ = kdf.derive_key(password, kdf_params.salt)
            
            from partyline.crypto.aead import get_cipher
            cipher = get_cipher(bundle.cipher_suite, key)
            
            # Try to decrypt (will raise if invalid)
            identity_seed = cipher.decrypt(
                base64.b64decode(bundle.nonce),
                base64.b64decode(bundle.ciphertext),
                base64.b64decode(bundle.tag),
                bundle.persona.encode('utf-8')
            )
            
            # Zeroize after verification
            zeroize(key)
            zeroize(identity_seed)
            
            # Store in keyring
            key_id = f"{KEYRING_NAMESPACE}_{bundle.persona}"
            keyring.set_password(self.app_id, key_id, bundle.to_json())
            
            logger.info(f"Imported identity bundle for persona '{bundle.persona}'")
            return True
            
        except Exception as e:
            logger.error(f"Failed to import bundle: {e}")
            return False


class FileBackedStore(KeyringStore):
    """
    File-based fallback when OS keyring is not available
    Uses encrypted files with secure permissions
    """
    
    def __init__(self, storage_dir: Optional[Path] = None):
        """
        Initialize file-backed store
        
        Args:
            storage_dir: Directory for key storage
        """
        self.storage_dir = storage_dir or (
            Path.home() / ".config" / "mempool_partyline" / "keys"
        )
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        # Set secure permissions
        import os
        os.chmod(self.storage_dir, 0o700)
        
        logger.info(f"Using file-backed key storage at {self.storage_dir}")
    
    def _get_key_path(self, persona: str) -> Path:
        """Get path for persona key file"""
        # Sanitize persona name for filesystem
        import re
        safe_name = re.sub(r'[^\w\-_]', '_', persona)
        return self.storage_dir / f"{safe_name}.key"
    
    def store_identity(
        self,
        persona: str,
        identity_seed: bytes,
        password: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Store encrypted identity in file"""
        try:
            # Use parent class logic for encryption
            # Create the bundle
            kdf = SecureKDF(KDFSuite.ARGON2ID)
            key, kdf_params = kdf.derive_key(password)
            
            cipher = get_preferred_cipher(key)
            nonce, ciphertext, tag = cipher.encrypt(
                identity_seed,
                persona.encode('utf-8')
            )
            
            bundle = KeyBundle(
                persona=persona,
                cipher_suite=cipher.cipher_suite,
                kdf_params=kdf_params.to_dict(),
                nonce=base64.b64encode(nonce).decode(),
                ciphertext=base64.b64encode(ciphertext).decode(),
                tag=base64.b64encode(tag).decode(),
                metadata=metadata or {}
            )
            
            # Write to file
            key_path = self._get_key_path(persona)
            with open(key_path, 'w') as f:
                f.write(bundle.to_json())
            
            # Set secure permissions
            import os
            os.chmod(key_path, 0o600)
            
            # Zeroize sensitive data
            zeroize(key)
            zeroize(identity_seed)
            
            logger.info(f"Stored identity for persona '{persona}' in file")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store identity in file: {e}")
            return False
    
    def retrieve_identity(self, persona: str, password: str) -> Optional[bytes]:
        """Retrieve identity from file"""
        try:
            key_path = self._get_key_path(persona)
            
            if not key_path.exists():
                logger.warning(f"No identity file found for persona '{persona}'")
                return None
            
            # Read bundle
            with open(key_path, 'r') as f:
                bundle_json = f.read()
            
            bundle = KeyBundle.from_json(bundle_json)
            
            # Decrypt
            kdf_params = KDFParams.from_dict(bundle.kdf_params)
            kdf = SecureKDF(kdf_params.kdf_suite)
            key, _ = kdf.derive_key(password, kdf_params.salt)
            
            from partyline.crypto.aead import get_cipher
            cipher = get_cipher(bundle.cipher_suite, key)
            
            identity_seed = cipher.decrypt(
                base64.b64decode(bundle.nonce),
                base64.b64decode(bundle.ciphertext),
                base64.b64decode(bundle.tag),
                persona.encode('utf-8')
            )
            
            zeroize(key)
            
            logger.info(f"Retrieved identity for persona '{persona}' from file")
            return identity_seed
            
        except Exception as e:
            logger.error(f"Failed to retrieve identity from file: {e}")
            return None
    
    def delete_identity(self, persona: str) -> bool:
        """Delete identity file"""
        try:
            key_path = self._get_key_path(persona)
            if key_path.exists():
                secure_delete_file(key_path)
                logger.info(f"Deleted identity file for persona '{persona}'")
            return True
        except Exception as e:
            logger.error(f"Failed to delete identity file: {e}")
            return False
    
    def list_personas(self) -> list[str]:
        """List personas from files"""
        personas = []
        for key_file in self.storage_dir.glob("*.key"):
            try:
                with open(key_file, 'r') as f:
                    bundle = KeyBundle.from_json(f.read())
                    personas.append(bundle.persona)
            except:
                continue
        return personas


def get_keyring_store() -> KeyringStore:
    """
    Get appropriate keyring store for platform
    
    Returns:
        KeyringStore instance (OS keyring or file-backed)
    """
    try:
        # Try OS keyring first
        store = KeyringStore()
        # Test if it works
        test_key = "test_availability"
        keyring.set_password(KEYRING_SERVICE, test_key, "test")
        keyring.delete_password(KEYRING_SERVICE, test_key)
        logger.info("Using OS keyring for key storage")
        return store
    except Exception as e:
        logger.warning(f"OS keyring not available: {e}")
        logger.info("Falling back to encrypted file storage")
        return FileBackedStore()
