"""
Secure configuration management with validation and versioning
"""

import os
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from enum import Enum

from pydantic import BaseModel, Field, validator, SecretStr
from pydantic import IPvAnyAddress, AnyUrl
from dotenv import load_dotenv

from partyline.constants import (
    Network,
    CipherSuite,
    KDFSuite,
    CONFIG_FILE_MODE,
    DEFAULT_TESTNET_PORT,
    DEFAULT_MAINNET_PORT,
    DEFAULT_ZMQ_PORT,
    POLL_INTERVAL_SECONDS,
    RATE_LIMIT_MESSAGES_PER_MINUTE,
    RATE_LIMIT_BURST,
)

logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

CONFIG_VERSION = 2


class ProxyType(str, Enum):
    """Supported proxy types"""
    NONE = "none"
    SOCKS5 = "socks5"
    SOCKS5H = "socks5h"  # DNS resolution via proxy
    HTTP = "http"
    TOR = "tor"


class NodeConfig(BaseModel):
    """Bitcoin node configuration"""
    
    host: IPvAnyAddress = Field(default="127.0.0.1")
    port: int = Field(default=DEFAULT_TESTNET_PORT, ge=1, le=65535)
    rpc_user: str = Field(min_length=1, max_length=100)
    rpc_password: SecretStr = Field(min_length=8)
    
    # Optional settings
    network: Network = Field(default=Network.TESTNET)
    wallet: Optional[str] = Field(default=None, max_length=100)
    timeout: int = Field(default=30, ge=5, le=300)
    
    # ZMQ settings
    zmq_enabled: bool = Field(default=False)
    zmq_host: IPvAnyAddress = Field(default="127.0.0.1")
    zmq_port: int = Field(default=DEFAULT_ZMQ_PORT, ge=1, le=65535)
    
    @validator('port')
    def validate_port_for_network(cls, v, values):
        """Validate port matches network"""
        network = values.get('network', Network.TESTNET)
        if network == Network.MAINNET and v == DEFAULT_TESTNET_PORT:
            logger.warning(f"Using testnet port {v} for mainnet, expected {DEFAULT_MAINNET_PORT}")
        return v
    
    @validator('host')
    def warn_remote_host(cls, v):
        """Warn about remote RPC connections"""
        if str(v) not in ['127.0.0.1', 'localhost', '::1']:
            logger.warning(f"Remote RPC host configured: {v} - ensure connection is encrypted!")
        return v
    
    def get_rpc_url(self) -> str:
        """Get RPC connection URL"""
        return f"http://{self.rpc_user}:{self.rpc_password.get_secret_value()}@{self.host}:{self.port}"
    
    def get_zmq_endpoint(self) -> str:
        """Get ZMQ endpoint URL"""
        return f"tcp://{self.zmq_host}:{self.zmq_port}"


class ProxyConfig(BaseModel):
    """Proxy configuration for Tor/SOCKS5"""
    
    enabled: bool = Field(default=False)
    type: ProxyType = Field(default=ProxyType.NONE)
    host: IPvAnyAddress = Field(default="127.0.0.1")
    port: int = Field(default=9050, ge=1, le=65535)  # Default Tor SOCKS port
    username: Optional[str] = Field(default=None, max_length=100)
    password: Optional[SecretStr] = Field(default=None)
    
    # Tor-specific
    use_tor_dns: bool = Field(default=True)  # Use .onion resolution
    tor_control_port: Optional[int] = Field(default=9051, ge=1, le=65535)
    
    @validator('type')
    def validate_proxy_enabled(cls, v, values):
        """Ensure proxy type matches enabled state"""
        if values.get('enabled') and v == ProxyType.NONE:
            return ProxyType.SOCKS5H  # Default to SOCKS5H for Tor
        return v
    
    def get_proxy_url(self) -> Optional[str]:
        """Get proxy URL for requests"""
        if not self.enabled:
            return None
        
        auth = ""
        if self.username and self.password:
            auth = f"{self.username}:{self.password.get_secret_value()}@"
        
        return f"{self.type}://{auth}{self.host}:{self.port}"


class SecurityConfig(BaseModel):
    """Security and privacy settings"""
    
    # Protocol settings
    protocol_version: int = Field(default=2, ge=1, le=2)
    allow_legacy_v1: bool = Field(default=True)  # Allow receiving v1 messages
    warn_legacy_senders: bool = Field(default=True)
    
    # Cryptography
    cipher_suite: CipherSuite = Field(default=CipherSuite.XCHACHA20_POLY1305)
    kdf_suite: KDFSuite = Field(default=KDFSuite.ARGON2ID)
    
    # Privacy features
    enable_padding: bool = Field(default=True)
    enable_decoy_traffic: bool = Field(default=False)  # Off by default for safety
    decoy_rate_per_hour: int = Field(default=2, ge=0, le=10)
    
    # Rate limiting
    rate_limit_enabled: bool = Field(default=True)
    rate_limit_messages: int = Field(default=RATE_LIMIT_MESSAGES_PER_MINUTE, ge=1, le=100)
    rate_limit_burst: int = Field(default=RATE_LIMIT_BURST, ge=1, le=100)
    
    # OpSec
    disable_core_dumps: bool = Field(default=True)
    secure_delete: bool = Field(default=True)
    memory_lock: bool = Field(default=True)  # Best-effort mlock
    clear_clipboard: bool = Field(default=True)
    
    @validator('enable_decoy_traffic')
    def warn_decoy_traffic(cls, v):
        """Warn about decoy traffic costs"""
        if v:
            logger.warning("Decoy traffic enabled - this will incur transaction fees!")
        return v


class AppConfig(BaseModel):
    """Main application configuration"""
    
    version: int = Field(default=CONFIG_VERSION)
    
    # User settings
    nickname: str = Field(default="anonymous", min_length=1, max_length=32)
    locale: str = Field(default="en_US", regex=r'^[a-z]{2}_[A-Z]{2}$')
    
    # Network
    nodes: List[NodeConfig] = Field(min_items=1)
    primary_node_index: int = Field(default=0, ge=0)
    
    # Proxy
    proxy: ProxyConfig = Field(default_factory=ProxyConfig)
    
    # Security
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    
    # Paths
    data_dir: Path = Field(default_factory=lambda: Path.home() / ".config" / "mempool_partyline")
    log_file: Optional[Path] = Field(default=None)
    
    # Behavior
    poll_interval: int = Field(default=POLL_INTERVAL_SECONDS, ge=5, le=300)
    auto_connect: bool = Field(default=True)
    
    @validator('nickname')
    def sanitize_nickname(cls, v):
        """Sanitize nickname for safety"""
        # Remove control characters and limit charset
        import re
        cleaned = re.sub(r'[^\w\s\-_.]', '', v)
        return cleaned[:32]  # Enforce max length
    
    @validator('primary_node_index')
    def validate_node_index(cls, v, values):
        """Ensure primary node index is valid"""
        nodes = values.get('nodes', [])
        if v >= len(nodes):
            raise ValueError(f"Invalid primary_node_index {v}, only {len(nodes)} nodes configured")
        return v
    
    @validator('data_dir')
    def ensure_data_dir(cls, v):
        """Ensure data directory exists with proper permissions"""
        v = Path(v)
        if not v.exists():
            v.mkdir(parents=True, mode=0o700)
        elif not v.is_dir():
            raise ValueError(f"Data dir {v} exists but is not a directory")
        
        # Check permissions on Unix
        if hasattr(os, 'chmod'):
            os.chmod(v, 0o700)
        
        return v
    
    def get_primary_node(self) -> NodeConfig:
        """Get primary node configuration"""
        return self.nodes[self.primary_node_index]
    
    @classmethod
    def from_env(cls) -> 'AppConfig':
        """Load configuration from environment variables"""
        # Build node config from env
        node = NodeConfig(
            host=os.getenv('BITCOIN_RPC_HOST', '127.0.0.1'),
            port=int(os.getenv('BITCOIN_RPC_PORT', DEFAULT_TESTNET_PORT)),
            rpc_user=os.getenv('BITCOIN_RPC_USER', 'bitcoinrpc'),
            rpc_password=os.getenv('BITCOIN_RPC_PASSWORD', 'changeme'),
            network=Network(os.getenv('BITCOIN_NETWORK', 'testnet')),
            zmq_enabled=os.getenv('ZMQ_ENABLED', 'false').lower() == 'true',
            zmq_port=int(os.getenv('ZMQ_PORT', DEFAULT_ZMQ_PORT)),
        )
        
        # Build proxy config
        proxy = ProxyConfig(
            enabled=os.getenv('PROXY_ENABLED', 'false').lower() == 'true',
            type=ProxyType(os.getenv('PROXY_TYPE', 'socks5h')),
            host=os.getenv('PROXY_HOST', '127.0.0.1'),
            port=int(os.getenv('PROXY_PORT', 9050)),
        )
        
        # Build main config
        return cls(
            nickname=os.getenv('PARTYLINE_NICKNAME', 'anonymous'),
            nodes=[node],
            proxy=proxy,
            data_dir=Path(os.getenv('PARTYLINE_DATA_DIR', Path.home() / ".config" / "mempool_partyline")),
        )
    
    @classmethod
    def load(cls, config_path: Optional[Path] = None) -> 'AppConfig':
        """Load configuration from file or create default"""
        if config_path is None:
            config_path = Path.home() / ".config" / "mempool_partyline" / "config.json"
        
        # Try environment first
        if os.getenv('PARTYLINE_USE_ENV', '').lower() == 'true':
            logger.info("Loading configuration from environment variables")
            return cls.from_env()
        
        # Load from file
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    data = json.load(f)
                    
                # Check version and migrate if needed
                if data.get('version', 1) < CONFIG_VERSION:
                    logger.warning(f"Migrating config from v{data.get('version', 1)} to v{CONFIG_VERSION}")
                    data = migrate_config(data)
                
                return cls(**data)
            except Exception as e:
                logger.error(f"Failed to load config from {config_path}: {e}")
                logger.info("Creating default configuration")
        
        # Create default
        return cls.create_default()
    
    @classmethod
    def create_default(cls) -> 'AppConfig':
        """Create default configuration"""
        # Default to testnet for safety
        node = NodeConfig(
            rpc_user="bitcoinrpc",
            rpc_password="changeme",
            network=Network.TESTNET,
        )
        
        return cls(
            nodes=[node],
            nickname="anonymous",
        )
    
    def save(self, config_path: Optional[Path] = None) -> None:
        """Save configuration to file with secure permissions"""
        if config_path is None:
            config_path = self.data_dir / "config.json"
        
        # Ensure directory exists
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Convert to dict, excluding secrets
        data = self.dict(exclude={'nodes': {'__all__': {'rpc_password'}}})
        
        # Save with restrictive permissions
        with open(config_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        # Set secure permissions
        os.chmod(config_path, CONFIG_FILE_MODE)
        
        logger.info(f"Configuration saved to {config_path}")


def migrate_config(old_config: Dict[str, Any]) -> Dict[str, Any]:
    """Migrate old configuration format to current version"""
    version = old_config.get('version', 1)
    
    if version == 1:
        # Migrate v1 to v2
        logger.info("Migrating v1 config to v2")
        
        # Convert flat structure to nested
        node = NodeConfig(
            host=old_config.get('rpc_host', '127.0.0.1'),
            port=int(old_config.get('rpc_port', DEFAULT_TESTNET_PORT)),
            rpc_user=old_config.get('rpc_user', 'bitcoinrpc'),
            rpc_password=old_config.get('rpc_password', 'changeme'),
            zmq_enabled='zmq_tx_endpoint' in old_config,
            zmq_port=DEFAULT_ZMQ_PORT,
        )
        
        new_config = {
            'version': 2,
            'nickname': old_config.get('nickname', 'anonymous'),
            'nodes': [node.dict()],
            'poll_interval': old_config.get('poll_interval', POLL_INTERVAL_SECONDS),
        }
        
        return new_config
    
    return old_config
