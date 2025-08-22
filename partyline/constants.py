"""
Protocol constants and security defaults for Mempool Partyline
"""

from enum import IntEnum, Enum
from typing import Final

# Protocol versioning
PROTOCOL_VERSION: Final[int] = 2
MIN_SUPPORTED_VERSION: Final[int] = 1
LEGACY_VERSION: Final[int] = 1

# Security constants
DEFAULT_KDF_ITERATIONS: Final[int] = 100_000  # PBKDF2 legacy
ARGON2_TIME_COST: Final[int] = 3
ARGON2_MEMORY_COST: Final[int] = 65536  # 64 MB
ARGON2_PARALLELISM: Final[int] = 4
MIN_SALT_LENGTH: Final[int] = 16
MAX_SALT_LENGTH: Final[int] = 32
NONCE_LENGTH: Final[int] = 24  # For XChaCha20
GCM_NONCE_LENGTH: Final[int] = 12  # For AES-GCM
TAG_LENGTH: Final[int] = 16

# Message size constraints
MAX_OP_RETURN_SIZE: Final[int] = 80  # Standard OP_RETURN limit
MAX_MESSAGE_SIZE: Final[int] = 4096  # Before fragmentation
PADDING_BUCKETS: Final[list[int]] = [64, 80, 128, 256, 512]
MAX_FRAGMENTS: Final[int] = 16

# Timing and rate limits
MESSAGE_TTL_SECONDS: Final[int] = 3600  # 1 hour default
RATCHET_ROTATION_MESSAGES: Final[int] = 100
KEY_ROTATION_DAYS: Final[int] = 30
RATE_LIMIT_MESSAGES_PER_MINUTE: Final[int] = 10
RATE_LIMIT_BURST: Final[int] = 20

# Network defaults
DEFAULT_TESTNET_PORT: Final[int] = 18332
DEFAULT_MAINNET_PORT: Final[int] = 8332
DEFAULT_ZMQ_PORT: Final[int] = 28332
POLL_INTERVAL_SECONDS: Final[int] = 30
CONNECTION_TIMEOUT: Final[int] = 10

# File permissions (octal)
CONFIG_FILE_MODE: Final[int] = 0o600  # rw-------
LOG_FILE_MODE: Final[int] = 0o640    # rw-r-----
KEY_FILE_MODE: Final[int] = 0o600    # rw-------


class MessageType(IntEnum):
    """Protocol message types"""
    HANDSHAKE_INIT = 1
    HANDSHAKE_RESP = 2
    KEY_UPDATE = 3
    TEXT = 4
    FRAGMENT = 5
    DECOY = 6
    CONTROL = 7
    LEGACY = 99  # For v1 compatibility


class CipherSuite(IntEnum):
    """Supported cipher suites in preference order"""
    XCHACHA20_POLY1305 = 1  # Preferred
    AES_256_GCM = 2         # Strong default
    AES_256_EAX = 3         # Legacy v1
    CHACHA20_POLY1305 = 4   # Alternative


class KDFSuite(IntEnum):
    """Key derivation functions"""
    ARGON2ID = 1    # Preferred
    PBKDF2_SHA256 = 2  # Legacy
    SCRYPT = 3      # Alternative


class Network(Enum):
    """Bitcoin networks"""
    MAINNET = "mainnet"
    TESTNET = "testnet"
    SIGNET = "signet"
    REGTEST = "regtest"


# Security warnings
MAINNET_WARNING = """
⚠️  WARNING: You are about to use Mempool Partyline on Bitcoin MAINNET.
This will cost real money in transaction fees. 
Consider using testnet or signet for testing.
"""

REMOTE_RPC_WARNING = """
⚠️  WARNING: Connecting to remote Bitcoin RPC without encryption.
This is insecure and may expose your credentials.
Consider using SSH tunneling or Tor.
"""

LEGACY_PROTOCOL_WARNING = """
⚠️  WARNING: Using legacy protocol v1 with known security limitations:
- Fixed salt (no per-message randomness)
- Weaker KDF (PBKDF2 vs Argon2id)
- No forward secrecy
- No identity management
Please upgrade to protocol v2 for improved security.
"""
