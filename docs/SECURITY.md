# Mempool Partyline Security Architecture

## Overview

Mempool Partyline v2 implements defense-in-depth security through multiple layers of cryptographic protection, operational security features, and privacy-preserving techniques. This document describes the security architecture, threat model, and mitigation strategies.

## Threat Model

### Adversary Capabilities

We assume adversaries with the following capabilities:

1. **Network Observation**: Can monitor Bitcoin network traffic and mempool contents
2. **Transaction Analysis**: Can perform blockchain analysis and timing correlation
3. **Computational Resources**: Can attempt brute-force attacks on weak cryptography
4. **Node Operation**: May run malicious Bitcoin nodes to collect mempool data
5. **Traffic Analysis**: Can observe network patterns and message sizes

### Security Goals

1. **Confidentiality**: Messages remain encrypted and unreadable to unauthorized parties
2. **Integrity**: Messages cannot be tampered with without detection
3. **Authentication**: Optional verification of sender identity
4. **Forward Secrecy**: Compromise of long-term keys doesn't reveal past messages
5. **Plausible Deniability**: Ability to deny participation in communications
6. **Metadata Protection**: Minimize observable patterns and correlations

## Cryptographic Architecture

### Protocol v2 Features

#### Key Derivation (KDF)
- **Primary**: Argon2id with configurable parameters
  - Time cost: 3 iterations
  - Memory cost: 64 MB
  - Parallelism: 4 threads
  - Random salt: 16-32 bytes per message
- **Legacy**: PBKDF2-HMAC-SHA256 with 100,000+ iterations
- **Session Keys**: HKDF-SHA256 for key expansion

#### Authenticated Encryption (AEAD)
- **Preferred**: XChaCha20-Poly1305 (if available)
- **Default**: AES-256-GCM 
- **Legacy**: AES-256-EAX (decrypt only)
- All modes provide authentication and integrity

#### Identity & Session Management
- **Long-term Keys**: Ed25519 signing keys
- **Session Keys**: X25519 ephemeral keys
- **Key Exchange**: ECDH with forward secrecy
- **Ratcheting**: Symmetric ratchet for per-message keys

### Message Envelope Structure

```json
{
  "version": 2,
  "msg_type": "TEXT",
  "sender_id": "hash_of_identity_key",
  "session_id": "unique_session_identifier",
  "sequence": 42,
  "timestamp": 1234567890,
  "cipher_suite": "XCHACHA20_POLY1305",
  "kdf_suite": "ARGON2ID",
  "kdf_params": {
    "salt": "hex_encoded_salt",
    "time_cost": 3,
    "memory_cost": 65536,
    "parallelism": 4
  },
  "nonce": "hex_encoded_nonce",
  "payload": "encrypted_and_authenticated_data",
  "tag": "authentication_tag"
}
```

## Privacy Features

### Traffic Analysis Resistance
- **Message Padding**: Bucketized sizes (64, 80, 128, 256, 512 bytes)
- **Decoy Traffic**: Optional automated cover traffic generation
- **Timing Jitter**: Random delays in message sending
- **Fee Randomization**: Vary transaction fees within acceptable bands

### Metadata Minimization
- **No Plaintext Headers**: All metadata encrypted except version
- **Session IDs**: Use truncated hashes for correlation resistance
- **Address Rotation**: Avoid address reuse in transactions
- **Ephemeral Storage**: Messages expire after TTL

### Plausible Deniability
- **Optional Signatures**: Identity verification is opt-in
- **Decoy Messages**: Indistinguishable from real messages
- **Key Separation**: Different keys for different personas
- **Burn After Reading**: Messages can self-destruct

## Operational Security

### Key Management
- **OS Keyring Integration**: Secure storage of identity keys
- **Memory Protection**: Best-effort key zeroization
- **Key Rotation**: Automatic rotation after time/message thresholds
- **Backup/Recovery**: Encrypted key bundle export/import

### Process Hardening
- **Core Dump Prevention**: Disabled on Unix systems
- **Secure File Permissions**: 0600 for sensitive files
- **Logging Sanitization**: Automatic redaction of secrets
- **Error Handling**: No sensitive data in error messages

### Network Security
- **Tor Support**: Optional SOCKS5 proxy for all connections
- **Multi-Node Support**: Distribute trust across nodes
- **RPC Validation**: Verify node network and version
- **Local-Only Binding**: Default to loopback interfaces

## Implementation Security

### Input Validation
- **Pydantic Models**: Type-safe configuration and messages
- **Size Limits**: Maximum message and fragment sizes
- **Character Filtering**: Sanitize user-provided strings
- **Fee Validation**: Min/max transaction fee limits

### Secure Coding Practices
- **Constant-Time Operations**: For cryptographic comparisons
- **Secure Randomness**: Using `secrets` module only
- **No Eval/Exec**: No dynamic code execution
- **Dependency Scanning**: Regular security audits

### Testing & Verification
- **Unit Tests**: Cryptographic primitives with test vectors
- **Property Testing**: Hypothesis-based fuzzing
- **Integration Tests**: End-to-end on regtest network
- **Static Analysis**: Bandit security scanning

## Known Limitations

1. **Blockchain Permanence**: Encrypted messages visible on blockchain
2. **Transaction Fees**: Cost of sending messages
3. **Message Size**: Limited by OP_RETURN constraints
4. **Network Delays**: Subject to Bitcoin confirmation times
5. **Quantum Resistance**: Current algorithms not quantum-safe

## Security Checklist

### Before First Use
- [ ] Generate strong encryption password
- [ ] Verify Bitcoin node connection security
- [ ] Configure appropriate network (testnet/mainnet)
- [ ] Review and understand fee settings
- [ ] Set up key backup procedures

### Operational Security
- [ ] Use Tor for enhanced privacy
- [ ] Rotate keys periodically
- [ ] Monitor audit logs for anomalies
- [ ] Keep software updated
- [ ] Verify message authenticity when required

### Emergency Procedures
- [ ] Key compromise: Rotate immediately and notify contacts
- [ ] Suspected surveillance: Enable maximum privacy settings
- [ ] Data breach: Use secure deletion tools
- [ ] System compromise: Reinstall from verified sources

## Reporting Security Issues

Please report security vulnerabilities to geeknik@protonmail.ch using PGP encryption. Do not disclose vulnerabilities publicly until patched.

## References

- [Argon2 Specification](https://github.com/P-H-C/phc-winner-argon2)
- [XChaCha20-Poly1305](https://tools.ietf.org/html/draft-irtf-cfrg-xchacha)
- [Signal Protocol](https://signal.org/docs/)
- [Bitcoin OP_RETURN](https://en.bitcoin.it/wiki/OP_RETURN)

---

*Last Updated: 2025*
*Version: 2.0.0*
