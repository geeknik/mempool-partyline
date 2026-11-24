# Mempool Partyline

An anarcho-ephemeral mempool messaging system with a curses-based TUI.

## Overview

Mempool Partyline enables secure, anonymous messaging by embedding encrypted messages within the Bitcoin mempool using OP_RETURN transactions. Messages exist only temporarily in the mempool until transactions are confirmed, providing an ephemeral communication channel that leaves minimal permanent traces.

## Features

- **End-to-end encryption** using XChaCha20-Poly1305 or AES-256-GCM with AES-256-GCM as strong default
- **Forward secrecy** via ephemeral X25519 key exchange and symmetric ratcheting
- **Ephemeral messaging** - messages exist only in the mempool
- **Anonymous communication** - no account registration required
- **Multiple interfaces**:
  - Console-based UI for simple usage
  - Curses-based TUI with enhanced features
  - Daemon mode for background monitoring
- **Flexible message monitoring**:
  - ZMQ-based real-time notification (preferred)
  - Polling-based fallback for nodes without ZMQ
- **User-friendly features**:
  - Message history with timestamps
  - Custom nicknames
  - Config file management
  - Interactive setup wizard

## Requirements

- Python 3.7+
- Bitcoin Core node with JSON-RPC and (optionally) ZMQ enabled
- Some bitcoin testnet coins for sending messages

### Python Dependencies

- `cryptography` - For AES-GCM and modern KDFs
- `PyNaCl` - For XChaCha20-Poly1305
- `argon2-cffi` - For Argon2id key derivation
- `keyring` - For secure key storage
- `python-dotenv` - For environment configuration
- `pyyaml` - For YAML config support
- `pyzmq` - ZeroMQ for real-time mempool monitoring
- `pycryptodome` - For legacy AES-EAX compatibility
- `python-bitcoinrpc` - For Bitcoin Core RPC communication
- `curses` - For the TUI interface (included in Python standard library)

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/geeknik/mempool-partyline.git
   cd mempool-partyline
   ```

2. Install dependencies:
   ```
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. Run the setup wizard:
   ```
   python mempool_partyline.py --setup
   ```

## Bitcoin Node Configuration

Mempool Partyline requires a Bitcoin Core node with JSON-RPC enabled. For optimal performance, ZMQ should also be enabled.

Add the following to your `bitcoin.conf` file:

```
# JSON-RPC Configuration
server=1
rpcuser=yourrpcuser  # Choose a secure username
rpcpassword=yourrpcpass  # Choose a secure password
rpcallowip=127.0.0.1

# ZMQ Configuration (Optional but recommended)
zmqpubrawtx=tcp://127.0.0.1:28332
```

### Running on Testnet

For testing, it's recommended to use Bitcoin's testnet:

```
testnet=1
```

## Usage

### First-Time Setup

The first time you run Mempool Partyline, it will guide you through configuration:

```
python mempool_partyline.py --setup
```

### Running the Application

#### Console UI

```
python mempool_partyline.py --console
```

#### Text User Interface (TUI)

```
python mempool_partyline.py --tui
```

#### Daemon Mode (Just listen for messages)

```
python mempool_partyline.py --listen
```

### Sending Messages

In the console or TUI, type your message and press Enter to send. The application will create a Bitcoin transaction with your encrypted message and broadcast it to the network.

The message will be visible to any other Mempool Partyline users who share the same encryption password.

## Configuration

Configuration is stored in `~/.config/mempool_partyline/config.json` and includes:

- Bitcoin Core RPC credentials
- ZMQ endpoint information
- User nickname
- Logging settings

You can modify this file directly or run the setup wizard again.

## Security Considerations

- **Encryption Password**: All users must share the same encryption password to communicate
- **Transaction Costs**: Each message may require a small Bitcoin transaction fee
- **Privacy**: While messages are encrypted, the fact that you're sending/receiving data via OP_RETURN is visible on the blockchain
- **Ephemeral**: Messages only exist in the mempool until the transaction is confirmed
- **Forward Secrecy**: Ephemeral session keys provide forward secrecy for v2 messages
- **Memory Protection**: Keys are securely zeroized after use
- **Process Hardening**: Core dumps are disabled and ptrace is restricted

## Security Architecture

For detailed information about the security architecture, threat model, and implementation details, see [docs/SECURITY.md](docs/SECURITY.md).

### Cryptographic Features

- **Key Derivation**: Argon2id with 64MB memory, 3 iterations, 4 parallelism; PBKDF2-SHA256 (legacy)
- **Encryption**: XChaCha20-Poly1305 (preferred) or AES-256-GCM (strong default) with AEAD
- **Identity**: Ed25519 signing keys with X25519 ephemeral encryption keys
- **Forward Secrecy**: X25519 ECDH + HKDF + symmetric ratcheting
- **Key Rotation**: Automatic rotation after time/message thresholds
- **Message Padding**: Bucketized sizes for traffic analysis resistance

### Operational Security

- **Secure Logging**: Automatic redaction of secrets and sensitive data
- **File Permissions**: Sensitive files use 0600 permissions
- **Key Storage**: OS keyring integration with encrypted file fallback
- **Memory Protection**: Best-effort key zeroization and memory locking

## Advanced Usage

### Creating a Closed Group

For private group communication, all participants should:

1. Use the same encryption password
2. Configure their Bitcoin nodes to connect directly to each other (using `addnode=`)
3. Potentially run with `blocksonly=1` to prevent your messages from being relayed outside your private network

### Custom Network Configuration

For completely private communication, you can:

1. Run a private Bitcoin regtest network
2. Configure all participants to connect only to this network
3. Use Mempool Partyline as normal

## Troubleshooting

### Common Issues

#### "No UTXOs available for transaction"

You need testnet coins to send messages. Get some from a testnet faucet.

#### "Failed to connect to Bitcoin node"

Check your Bitcoin Core is running and RPC credentials are correct.

#### "ZMQ listener failed, falling back to polling"

Your Bitcoin Core may not have ZMQ enabled. Add the ZMQ configuration in bitcoin.conf and restart.

## Logs

Logs are stored in `~/.config/mempool_partyline/partyline.log` and can help diagnose issues.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This software is provided for educational and research purposes only. Using this software may require compliance with local regulations regarding encryption and privacy. Users are responsible for their own compliance with applicable laws.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.