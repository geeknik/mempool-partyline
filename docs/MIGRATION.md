# Migration Guide: v1 to v2

## Overview

Mempool Partyline v2 introduces significant security improvements while maintaining backward compatibility with v1 clients. This guide helps you migrate from v1 to v2.

## Key Changes in v2

### Security Improvements
- **Random Salts**: Every message now uses a unique random salt (16-32 bytes)
- **Modern KDF**: Argon2id replaces PBKDF2 for better security
- **AEAD Encryption**: XChaCha20-Poly1305 or AES-256-GCM with authentication
- **Protocol Versioning**: Future-proof design with version negotiation
- **Memory Protection**: Keys are zeroized after use, core dumps disabled

### New Features
- **Forward Secrecy**: Session keys with ratcheting (coming soon)
- **Identity Management**: Multiple personas with key rotation
- **Tor Support**: Built-in SOCKS5/Tor proxy support
- **Message TTL**: Automatic message expiration
- **Decoy Traffic**: Optional cover traffic for enhanced privacy

## Migration Steps

### 1. Backup Your Data

```bash
# Backup existing configuration
cp -r ~/.config/mempool_partyline ~/.config/mempool_partyline.v1.backup

# Archive old code
cp mempool_partyline.py mempool_partyline_v1.py.backup
```

### 2. Install v2 Dependencies

```bash
# Upgrade pip
python -m pip install --upgrade pip

# Install new requirements
pip install -r requirements.txt
```

### 3. Update Configuration

The v2 configuration format has changed. Your v1 config will be automatically migrated on first run, but you can also manually update:

**v1 Config (flat structure):**
```json
{
  "rpc_user": "bitcoinrpc",
  "rpc_password": "password",
  "rpc_host": "127.0.0.1",
  "rpc_port": "18443",
  "nickname": "alice"
}
```

**v2 Config (nested structure):**
```json
{
  "version": 2,
  "nickname": "alice",
  "nodes": [{
    "host": "127.0.0.1",
    "port": 18443,
    "rpc_user": "bitcoinrpc",
    "rpc_password": "password",
    "network": "testnet"
  }],
  "security": {
    "protocol_version": 2,
    "cipher_suite": 1,
    "kdf_suite": 1
  }
}
```

### 4. Environment Variables (Optional)

v2 supports configuration via environment variables:

```bash
export PARTYLINE_USE_ENV=true
export BITCOIN_RPC_USER=bitcoinrpc
export BITCOIN_RPC_PASSWORD=yourpassword
export BITCOIN_NETWORK=testnet
export PARTYLINE_NICKNAME=alice
```

### 5. Code Migration

If you have custom code using the v1 API, here are the key changes:

**v1 Encryption:**
```python
# Old v1 code
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_EAX)
ciphertext, tag = cipher.encrypt_and_digest(plaintext)
```

**v2 Encryption:**
```python
# New v2 code
from partyline.crypto import get_preferred_cipher, SecureKDF

# Derive key with Argon2id
kdf = SecureKDF()
key, params = kdf.derive_key(password)

# Use AEAD cipher
cipher = get_preferred_cipher(key)
nonce, ciphertext, tag = cipher.encrypt(plaintext)
```

## Compatibility Mode

### Receiving v1 Messages

v2 clients can receive v1 messages by default. You'll see warnings in the logs:

```
WARNING: Processed 10 legacy v1 messages. Please encourage senders to upgrade to v2.
```

Messages from v1 clients will be marked with "(v1)" in the UI.

### Disabling v1 Support

To disable v1 compatibility (recommended after all peers upgrade):

```python
# In config.json
{
  "security": {
    "allow_legacy_v1": false
  }
}
```

## Security Considerations

### Password Changes

v2 uses stronger key derivation. Your existing password will work, but consider:

1. **Increasing password complexity** for v2's enhanced security
2. **Using a password manager** to generate strong passwords
3. **Enabling Tor** for additional privacy

### Key Storage

v2 stores keys differently:

- **v1**: Keys derived from password each time
- **v2**: Identity keys stored in OS keyring (when available)

### Network Security

v2 adds warnings for insecure configurations:

- Remote RPC connections without encryption
- Mainnet usage (transaction fee warnings)
- Weak cipher suites

## Testing Your Migration

### 1. Test v2 Installation

```bash
# Test the new v2 module
python -c "from partyline import PROTOCOL_VERSION; print(f'Protocol v{PROTOCOL_VERSION}')"
```

### 2. Test Backward Compatibility

```bash
# Start v2 client
python mempool_partyline.py --setup

# From another terminal with v1
python mempool_partyline_v1.py  # Should still work
```

### 3. Verify Security Hardening

Check the logs for security measures:

```
INFO: Applied hardening: no_core_dumps, memlock_ready, umask_0o077
```

## Rollback Plan

If you need to rollback to v1:

```bash
# Restore v1 code
cp legacy/mempool_partyline_v1.py.bak mempool_partyline.py

# Restore v1 config
cp -r ~/.config/mempool_partyline.v1.backup ~/.config/mempool_partyline

# Reinstall v1 dependencies
pip install pycryptodome python-bitcoinrpc pyzmq
```

## Getting Help

- **Issues**: Report bugs at https://github.com/geeknik/mempool-partyline/issues
- **Security**: Report vulnerabilities to geeknik@protonmail.ch (PGP preferred)
- **Documentation**: See `/docs` for protocol specs and security details

## Timeline

- **Phase 1** (Current): v2 available with v1 compatibility
- **Phase 2** (3 months): v2 default, v1 deprecated with warnings
- **Phase 3** (6 months): v1 support removed

## FAQ

**Q: Will v2 work with my existing Bitcoin node?**
A: Yes, v2 uses the same Bitcoin RPC interface as v1.

**Q: Can v1 and v2 clients communicate?**
A: Yes, v2 can receive v1 messages. v1 clients cannot read v2 messages.

**Q: Do I need to change my password?**
A: No, but consider upgrading to a stronger password for better security.

**Q: Will my message history be preserved?**
A: No, messages are ephemeral and exist only in the mempool.

**Q: Is v2 more expensive (transaction fees)?**
A: No, message sizes are similar. Padding may add ~10% overhead.

---

*Last updated: 2024*
