"""
Secure configuration management with validation and sanitization
"""

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional, List, Union
import configparser
import yaml

from partyline.crypto.keyring_store import get_keyring_store
from partyline.crypto.kdf import hkdf_derive, zeroize
from partyline.security import SecureRandom
from partyline.constants import (
    MIN_PASSWORD_LENGTH,
    SUPPORTED_CIPHERS,
    SUPPORTED_KDF_ALGORITHMS
)
from partyline.logging_sec import log_security_event

logger = logging.getLogger(__name__)


class ConfigValidator:
    """Validates and sanitizes configuration values"""
    
    @staticmethod
    def validate_string(value: Any, min_length: int = 0, max_length: int = 1024, 
                       allowed_chars: Optional[str] = None) -> str:
        """
        Validate a string value
        
        Args:
            value: Value to validate
            min_length: Minimum allowed length
            max_length: Maximum allowed length
            allowed_chars: Optional string of allowed characters
        
        Returns:
            Validated string
        
        Raises:
            ValueError: If validation fails
        """
        if not isinstance(value, str):
            raise ValueError(f"Expected string, got {type(value)}")
        
        if len(value) < min_length:
            raise ValueError(f"String too short (min {min_length})")
        
        if len(value) > max_length:
            raise ValueError(f"String too long (max {max_length})")
        
        if allowed_chars:
            for char in value:
                if char not in allowed_chars:
                    raise ValueError(f"Invalid character: {char}")
        
        return value
    
    @staticmethod
    def validate_int(value: Any, min_val: Optional[int] = None, 
                    max_val: Optional[int] = None) -> int:
        """Validate an integer value"""
        try:
            int_val = int(value)
        except (TypeError, ValueError):
            raise ValueError(f"Invalid integer: {value}")
        
        if min_val is not None and int_val < min_val:
            raise ValueError(f"Value {int_val} below minimum {min_val}")
        
        if max_val is not None and int_val > max_val:
            raise ValueError(f"Value {int_val} above maximum {max_val}")
        
        return int_val
    
    @staticmethod
    def validate_bool(value: Any) -> bool:
        """Validate a boolean value"""
        if isinstance(value, bool):
            return value
        
        if isinstance(value, str):
            if value.lower() in ("true", "yes", "1", "on"):
                return True
            elif value.lower() in ("false", "no", "0", "off"):
                return False
        
        raise ValueError(f"Invalid boolean: {value}")
    
    @staticmethod
    def validate_choice(value: Any, choices: List[Any]) -> Any:
        """Validate value is in allowed choices"""
        if value not in choices:
            raise ValueError(f"Invalid choice: {value}. Must be one of {choices}")
        return value
    
    @staticmethod
    def validate_path(value: Any, must_exist: bool = False, 
                     must_be_file: bool = False, must_be_dir: bool = False) -> Path:
        """Validate a file system path"""
        try:
            path = Path(value).expanduser().resolve()
        except Exception as e:
            raise ValueError(f"Invalid path: {e}")
        
        if must_exist and not path.exists():
            raise ValueError(f"Path does not exist: {path}")
        
        if must_be_file and not path.is_file():
            raise ValueError(f"Not a file: {path}")
        
        if must_be_dir and not path.is_dir():
            raise ValueError(f"Not a directory: {path}")
        
        return path
    
    @staticmethod
    def validate_url(value: Any) -> str:
        """Validate a URL"""
        from urllib.parse import urlparse
        
        if not isinstance(value, str):
            raise ValueError(f"URL must be string, got {type(value)}")
        
        try:
            result = urlparse(value)
            if not all([result.scheme, result.netloc]):
                raise ValueError("Invalid URL structure")
            
            # Only allow specific schemes
            allowed_schemes = ["http", "https", "socks5", "socks5h"]
            if result.scheme not in allowed_schemes:
                raise ValueError(f"URL scheme must be one of {allowed_schemes}")
            
            return value
        except Exception as e:
            raise ValueError(f"Invalid URL: {e}")
    
    @staticmethod
    def sanitize_log_value(value: Any) -> str:
        """Sanitize a value for logging (redact sensitive data)"""
        str_val = str(value)
        
        # Redact anything that looks like a password or key
        sensitive_keys = ["password", "key", "secret", "token", "seed", "private"]
        for key in sensitive_keys:
            if key in str_val.lower():
                return "[REDACTED]"
        
        # Truncate long values
        if len(str_val) > 100:
            return str_val[:100] + "..."
        
        return str_val


class SecureConfig:
    """
    Secure configuration management with encryption support
    """
    
    # Configuration schema defining valid keys and their validation rules
    SCHEMA = {
        # Network settings
        "network.bitcoin_rpc_url": {
            "type": "url",
            "default": "http://localhost:8332",
            "description": "Bitcoin RPC endpoint"
        },
        "network.bitcoin_rpc_user": {
            "type": "string",
            "default": "",
            "sensitive": True,
            "description": "Bitcoin RPC username"
        },
        "network.bitcoin_rpc_password": {
            "type": "string",
            "default": "",
            "sensitive": True,
            "description": "Bitcoin RPC password"
        },
        "network.use_tor": {
            "type": "bool",
            "default": False,
            "description": "Route traffic through Tor"
        },
        "network.tor_proxy": {
            "type": "url",
            "default": "socks5h://127.0.0.1:9050",
            "description": "Tor SOCKS proxy address"
        },
        "network.zmq_endpoint": {
            "type": "string",
            "default": "tcp://127.0.0.1:28332",
            "description": "ZMQ endpoint for mempool monitoring"
        },
        
        # Cryptography settings
        "crypto.default_cipher": {
            "type": "choice",
            "choices": list(SUPPORTED_CIPHERS.keys()),
            "default": "xchacha20-poly1305",
            "description": "Default encryption cipher"
        },
        "crypto.default_kdf": {
            "type": "choice",
            "choices": list(SUPPORTED_KDF_ALGORITHMS.keys()),
            "default": "argon2id",
            "description": "Default key derivation function"
        },
        "crypto.kdf_iterations": {
            "type": "int",
            "min": 1,
            "max": 1000000,
            "default": 3,
            "description": "KDF iteration count"
        },
        "crypto.kdf_memory_kb": {
            "type": "int",
            "min": 1024,
            "max": 1048576,
            "default": 65536,
            "description": "KDF memory usage in KB"
        },
        
        # Security settings
        "security.min_password_length": {
            "type": "int",
            "min": 8,
            "max": 256,
            "default": MIN_PASSWORD_LENGTH,
            "description": "Minimum password length"
        },
        "security.key_rotation_days": {
            "type": "int",
            "min": 1,
            "max": 365,
            "default": 30,
            "description": "Days between key rotations"
        },
        "security.enable_memory_protection": {
            "type": "bool",
            "default": True,
            "description": "Enable memory locking for sensitive data"
        },
        "security.enable_process_hardening": {
            "type": "bool",
            "default": True,
            "description": "Enable process security hardening"
        },
        
        # Message settings
        "message.max_size_bytes": {
            "type": "int",
            "min": 80,
            "max": 80,  # Bitcoin OP_RETURN limit
            "default": 80,
            "description": "Maximum message size"
        },
        "message.enable_padding": {
            "type": "bool",
            "default": True,
            "description": "Enable message padding"
        },
        "message.enable_decoy_traffic": {
            "type": "bool",
            "default": False,
            "description": "Enable decoy message generation"
        },
        "message.decoy_probability": {
            "type": "float",
            "min": 0.0,
            "max": 1.0,
            "default": 0.1,
            "description": "Probability of sending decoy message"
        },
        
        # Operational settings
        "operation.data_dir": {
            "type": "path",
            "default": "~/.partyline",
            "description": "Data directory for keys and cache"
        },
        "operation.log_level": {
            "type": "choice",
            "choices": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
            "default": "INFO",
            "description": "Logging level"
        },
        "operation.enable_auto_cleanup": {
            "type": "bool",
            "default": True,
            "description": "Automatically clean up old sessions"
        },
        "operation.session_timeout_seconds": {
            "type": "int",
            "min": 60,
            "max": 86400,
            "default": 3600,
            "description": "Session timeout in seconds"
        }
    }
    
    def __init__(self, config_file: Optional[Path] = None, encrypted: bool = False):
        """
        Initialize secure configuration
        
        Args:
            config_file: Path to configuration file
            encrypted: Whether to encrypt configuration
        """
        self.config_file = config_file
        self.encrypted = encrypted
        self.config: Dict[str, Any] = {}
        self.keyring = None
        
        if encrypted:
            self.keyring = get_keyring_store()
        
        # Load defaults
        self._load_defaults()
        
        # Load from file if provided
        if config_file and config_file.exists():
            self.load()
    
    def _load_defaults(self):
        """Load default values from schema"""
        for key, spec in self.SCHEMA.items():
            if "default" in spec:
                self.config[key] = spec["default"]
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value
        
        Args:
            key: Configuration key
            default: Default value if key not found
        
        Returns:
            Configuration value
        """
        # Check environment variable override
        env_key = f"PARTYLINE_{key.upper().replace('.', '_')}"
        if env_key in os.environ:
            return self._parse_env_value(os.environ[env_key], key)
        
        return self.config.get(key, default)
    
    def set(self, key: str, value: Any):
        """
        Set configuration value
        
        Args:
            key: Configuration key
            value: Value to set
        
        Raises:
            ValueError: If key or value is invalid
        """
        # Validate key exists in schema
        if key not in self.SCHEMA:
            raise ValueError(f"Unknown configuration key: {key}")
        
        # Validate value
        validated = self._validate_value(key, value)
        
        # Store value
        self.config[key] = validated
        
        # Log change (sanitized)
        if self.SCHEMA[key].get("sensitive"):
            log_value = "[REDACTED]"
        else:
            log_value = ConfigValidator.sanitize_log_value(validated)
        
        logger.info(f"Configuration updated: {key} = {log_value}")
        log_security_event("config_changed", {"key": key})
    
    def _validate_value(self, key: str, value: Any) -> Any:
        """Validate a configuration value against schema"""
        spec = self.SCHEMA[key]
        val_type = spec["type"]
        
        if val_type == "string":
            return ConfigValidator.validate_string(
                value,
                min_length=spec.get("min_length", 0),
                max_length=spec.get("max_length", 1024)
            )
        elif val_type == "int":
            return ConfigValidator.validate_int(
                value,
                min_val=spec.get("min"),
                max_val=spec.get("max")
            )
        elif val_type == "float":
            float_val = float(value)
            if "min" in spec and float_val < spec["min"]:
                raise ValueError(f"Value below minimum: {spec['min']}")
            if "max" in spec and float_val > spec["max"]:
                raise ValueError(f"Value above maximum: {spec['max']}")
            return float_val
        elif val_type == "bool":
            return ConfigValidator.validate_bool(value)
        elif val_type == "choice":
            return ConfigValidator.validate_choice(value, spec["choices"])
        elif val_type == "path":
            return str(ConfigValidator.validate_path(value))
        elif val_type == "url":
            return ConfigValidator.validate_url(value)
        else:
            raise ValueError(f"Unknown type: {val_type}")
    
    def _parse_env_value(self, value: str, key: str) -> Any:
        """Parse environment variable value according to type"""
        spec = self.SCHEMA.get(key)
        if not spec:
            return value
        
        val_type = spec["type"]
        
        if val_type == "int":
            return int(value)
        elif val_type == "float":
            return float(value)
        elif val_type == "bool":
            return value.lower() in ("true", "yes", "1", "on")
        else:
            return value
    
    def load(self, password: Optional[str] = None):
        """
        Load configuration from file
        
        Args:
            password: Password for encrypted config
        """
        if not self.config_file or not self.config_file.exists():
            logger.warning(f"Config file not found: {self.config_file}")
            return
        
        try:
            # Read file content
            content = self.config_file.read_bytes()
            
            # Decrypt if needed
            if self.encrypted:
                if not password:
                    raise ValueError("Password required for encrypted config")
                content = self._decrypt_config(content, password)
            
            # Parse based on file extension
            if self.config_file.suffix == ".json":
                data = json.loads(content)
            elif self.config_file.suffix in (".yaml", ".yml"):
                data = yaml.safe_load(content)
            elif self.config_file.suffix in (".ini", ".conf"):
                parser = configparser.ConfigParser()
                parser.read_string(content.decode())
                data = self._flatten_ini(parser)
            else:
                # Default to JSON
                data = json.loads(content)
            
            # Validate and load each value
            for key, value in data.items():
                if key in self.SCHEMA:
                    self.set(key, value)
                else:
                    logger.warning(f"Unknown config key ignored: {key}")
            
            logger.info(f"Loaded configuration from {self.config_file}")
            
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            raise
    
    def save(self, password: Optional[str] = None):
        """
        Save configuration to file
        
        Args:
            password: Password for encrypted config
        """
        if not self.config_file:
            raise ValueError("No config file specified")
        
        try:
            # Ensure directory exists
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Filter out sensitive values if not encrypted
            data = {}
            for key, value in self.config.items():
                if not self.encrypted and self.SCHEMA[key].get("sensitive"):
                    # Skip sensitive values in plaintext configs
                    continue
                data[key] = value
            
            # Serialize based on file extension
            if self.config_file.suffix == ".json":
                content = json.dumps(data, indent=2).encode()
            elif self.config_file.suffix in (".yaml", ".yml"):
                content = yaml.dump(data, default_flow_style=False).encode()
            else:
                # Default to JSON
                content = json.dumps(data, indent=2).encode()
            
            # Encrypt if needed
            if self.encrypted:
                if not password:
                    raise ValueError("Password required for encrypted config")
                content = self._encrypt_config(content, password)
            
            # Write to file with restricted permissions
            self.config_file.write_bytes(content)
            self.config_file.chmod(0o600)
            
            logger.info(f"Saved configuration to {self.config_file}")
            
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
            raise
    
    def _encrypt_config(self, data: bytes, password: str) -> bytes:
        """Encrypt configuration data"""
        from partyline.crypto.aead import get_cipher
        
        # Derive key from password
        salt = SecureRandom.get_bytes(16)
        key = hkdf_derive(password.encode(), salt=salt)
        
        # Encrypt with default cipher
        cipher = get_cipher(self.get("crypto.default_cipher"))
        nonce = SecureRandom.get_bytes(cipher.nonce_size)
        ciphertext = cipher.encrypt(data, key, nonce, aad=b"config")
        
        # Pack: salt || nonce || ciphertext
        return salt + nonce + ciphertext
    
    def _decrypt_config(self, data: bytes, password: str) -> bytes:
        """Decrypt configuration data"""
        from partyline.crypto.aead import get_cipher
        
        cipher = get_cipher(self.get("crypto.default_cipher"))
        
        # Unpack: salt || nonce || ciphertext
        salt = data[:16]
        nonce = data[16:16 + cipher.nonce_size]
        ciphertext = data[16 + cipher.nonce_size:]
        
        # Derive key
        key = hkdf_derive(password.encode(), salt=salt)
        
        # Decrypt
        plaintext = cipher.decrypt(ciphertext, key, nonce, aad=b"config")
        return plaintext
    
    def _flatten_ini(self, parser: configparser.ConfigParser) -> Dict[str, Any]:
        """Flatten INI sections into dotted keys"""
        result = {}
        for section in parser.sections():
            for key, value in parser.items(section):
                full_key = f"{section}.{key}"
                result[full_key] = value
        return result
    
    def validate_all(self) -> List[str]:
        """
        Validate entire configuration
        
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        
        for key, spec in self.SCHEMA.items():
            # Check required keys
            if spec.get("required") and key not in self.config:
                errors.append(f"Missing required key: {key}")
                continue
            
            # Validate existing values
            if key in self.config:
                try:
                    self._validate_value(key, self.config[key])
                except ValueError as e:
                    errors.append(f"Invalid {key}: {e}")
        
        return errors
    
    def get_section(self, section: str) -> Dict[str, Any]:
        """Get all values in a configuration section"""
        result = {}
        prefix = f"{section}."
        
        for key, value in self.config.items():
            if key.startswith(prefix):
                short_key = key[len(prefix):]
                result[short_key] = value
        
        return result
    
    def reset_to_defaults(self):
        """Reset configuration to default values"""
        self.config.clear()
        self._load_defaults()
        logger.info("Configuration reset to defaults")
