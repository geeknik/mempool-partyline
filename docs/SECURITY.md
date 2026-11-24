# Mempool Partyline Security Architecture

## Overview

Mempool Partyline implements defense-in-depth security for ephemeral messaging via the Bitcoin mempool. Messages are encrypted, embedded in OP_RETURN transactions, and exist only until confirmed — leaving minimal permanent trace.

## Cryptographic Architecture

- **Encryption**: XChaCha20-Poly1305 (preferred) or AES-256-GCM (default), both AEAD
- **Key Derivation**: Argon2id (64MB memory, 3 iterations, 4 parallelism)
- **Identity Keys**: Ed25519 signing keys
- **Session Keys**: X25519 ephemeral keys via ECDH for forward secrecy
- **Legacy**: PBKDF2-HMAC-SHA256 and AES-256-EAX (decrypt only)

## Privacy Features

- **Traffic Analysis Resistance**: Message padding to bucketized sizes (64–512 bytes)
- **Metadata Minimization**: No plaintext headers except version field
- **Plausible Deniability**: Signatures are opt-in; different keys per persona

## Operational Security

- **Key Management**: OS keyring integration with encrypted file fallback
- **Memory Protection**: Best-effort key zeroization after use
- **Process Hardening**: Core dump prevention, memory locking, restricted file permissions (0o600)
- **Logging Sanitization**: Automatic redaction of secrets and sensitive data

## Known Limitations

1. **Blockchain Permanence**: Encrypted messages visible on blockchain (OP_RETURN)
2. **Transaction Fees**: Each message requires a Bitcoin transaction
3. **Message Size**: Limited by OP_RETURN constraints (~80 bytes)
4. **Network Delays**: Subject to Bitcoin confirmation times
5. **Quantum Resistance**: Current algorithms not quantum-safe

## Reporting Security Issues

Please report security vulnerabilities privately via GitHub Security Advisories. Do not disclose vulnerabilities publicly until patched.

## References

- [Argon2 Specification](https://github.com/P-H-C/phc-winner-argon2)
- [XChaCha20-Poly1305](https://tools.ietf.org/html/draft-irtf-cfrg-xchacha)
- [Bitcoin OP_RETURN](https://en.bitcoin.it/wiki/OP_RETURN)