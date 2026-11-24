"""
Message transport: encrypt, wrap in OP_RETURN, broadcast via Bitcoin RPC.

Supports:
- JSON-RPC (python-bitcoinrpc) for transaction creation/signing/broadcast
- Subprocess fallback to `bitcoin-cli` for environments without RPC auth
"""

import logging
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Any

from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException

from partyline.constants import (
    MAX_OP_RETURN_SIZE,
    PROTOCOL_VERSION,
    CipherSuite,
    KDFSuite,
    MessageType,
)
from partyline.crypto.aead import get_cipher
from partyline.protocol import EnvelopeV2

logger = logging.getLogger(__name__)


class SendError(Exception):
    """Raised when message sending fails."""


@dataclass
class SendResult:
    """Result of a send attempt."""
    txid: str | None
    error: str | None


class MessageSender:
    """
    Encrypts messages and broadcasts them as OP_RETURN transactions.
    """

    def __init__(
        self,
        rpc_url: str = "http://localhost:8332",
        rpc_user: str | None = None,
        rpc_password: str | None = None,
        fee_rate: int = 1,  # sat/vB
        change_address: str | None = None,
    ):
        """
        Initialize the message sender.

        Args:
            rpc_url: Bitcoin Core RPC endpoint
            rpc_user: RPC username (optional if cookie auth)
            rpc_password: RPC password (optional if cookie auth)
            fee_rate: Fee rate in sat/vB
            change_address: Address for change output (auto if None)
        """
        self.rpc_url = rpc_url
        self.rpc_user = rpc_user
        self.rpc_password = rpc_password
        self.fee_rate = fee_rate
        self.change_address = change_address
        self._rpc: AuthServiceProxy | None = None

    @property
    def rpc(self) -> AuthServiceProxy:
        """Lazy-initialize RPC connection."""
        if self._rpc is None:
            auth = ""
            if self.rpc_user and self.rpc_password:
                auth = f"{self.rpc_user}:{self.rpc_password}@"
            url = self.rpc_url.replace("http://", f"http://{auth}")
            self._rpc = AuthServiceProxy(url, timeout=30)
        return self._rpc

    def encrypt_message(
        self,
        plaintext: str,
        shared_key: bytes,
        cipher_suite: CipherSuite = CipherSuite.XCHACHA20_POLY1305,
    ) -> bytes:
        """
        Encrypt a message for embedding in OP_RETURN.

        Returns:
            nonce || ciphertext || tag
        """
        cipher = get_cipher(cipher_suite, shared_key)
        nonce, ciphertext, tag = cipher.encrypt(plaintext.encode())
        return nonce + ciphertext + tag

    def build_envelope(
        self,
        plaintext: str,
        shared_key: bytes,
        sender_id: str | None = None,
        session_id: str = "default",
        sequence: int = 0,
        cipher_suite: CipherSuite = CipherSuite.XCHACHA20_POLY1305,
        kdf_suite: KDFSuite = KDFSuite.ARGON2ID,
    ) -> EnvelopeV2:
        """
        Build a protocol v2 envelope with encrypted payload.
        """
        encrypted = self.encrypt_message(plaintext, shared_key, cipher_suite)

        # Build envelope
        envelope = EnvelopeV2(
            version=PROTOCOL_VERSION,
            msg_type=MessageType.TEXT,
            sender_id=sender_id,
            session_id=session_id[:32],
            sequence=sequence,
            cipher_suite=cipher_suite,
            kdf_suite=kdf_suite,
            kdf_params={},  # Not needed for session-based encryption
            nonce=encrypted[:24].hex(),
            payload=encrypted[24:-16].hex(),
            tag=encrypted[-16:].hex(),
        )
        return envelope

    def build_op_return_script(self, data: bytes) -> bytes:
        """Build an OP_RETURN script: OP_RETURN <push data>."""
        if len(data) > MAX_OP_RETURN_SIZE:
            raise SendError(f"Data too large for OP_RETURN: {len(data)} > {MAX_OP_RETURN_SIZE}")
        # OP_RETURN (0x6a) + push length + data
        return bytes([0x6a, len(data)]) + data

    def get_utxos(self, min_amount: float = 0.00001) -> list[dict[str, Any]]:
        """Get spendable UTXOs from the wallet."""
        try:
            utxos = self.rpc.listunspent(1, 9999999, [], True, {"minimumAmount": min_amount})
            return [u for u in utxos if u.get("spendable", True)]
        except JSONRPCException as e:
            raise SendError(f"RPC listunspent failed: {e.message}")

    def create_raw_transaction(
        self,
        utxos: list[dict[str, Any]],
        op_return_script: bytes,
        change_address: str | None = None,
    ) -> str:
        """
        Create a raw transaction with OP_RETURN output.

        Returns:
            Hex-encoded raw transaction
        """
        inputs = []
        total_in = 0
        for utxo in utxos:
            inputs.append({"txid": utxo["txid"], "vout": utxo["vout"]})
            total_in += utxo["amount"]
            # Stop when we have enough for fee + change
            if total_in > 0.0001:
                break

        if not inputs:
            raise SendError("No spendable UTXOs available")

        outputs: dict[str, Any] = {
            "data": op_return_script.hex(),  # OP_RETURN output
        }

        # Add change output if we have an address
        if change_address and total_in > 0.0001:
            outputs[change_address] = total_in - 0.0001

        try:
            raw_tx = self.rpc.createrawtransaction(inputs, outputs)
            return raw_tx
        except JSONRPCException as e:
            raise SendError(f"RPC createrawtransaction failed: {e.message}")

    def fund_and_sign(self, raw_tx_hex: str) -> str:
        """Fund, sign, and return complete transaction hex."""
        try:
            options = {"feeRate": self.fee_rate}
            funded = self.rpc.fundrawtransaction(raw_tx_hex, options)
            signed = self.rpc.signrawtransactionwithwallet(funded["hex"])
            if not signed["complete"]:
                raise SendError("Transaction signing incomplete")
            return signed["hex"]
        except JSONRPCException as e:
            raise SendError(f"RPC fund/sign failed: {e.message}")

    def broadcast(self, signed_tx_hex: str) -> str:
        """Broadcast a signed transaction and return TXID."""
        try:
            txid = self.rpc.sendrawtransaction(signed_tx_hex)
            return txid
        except JSONRPCException as e:
            raise SendError(f"RPC sendrawtransaction failed: {e.message}")

    def send(
        self,
        message: str,
        shared_key: bytes,
        sender_id: str | None = None,
        session_id: str = "default",
        sequence: int = 0,
        cipher_suite: CipherSuite = CipherSuite.XCHACHA20_POLY1305,
        kdf_suite: KDFSuite = KDFSuite.ARGON2ID,
    ) -> SendResult:
        """
        Encrypt message, wrap in OP_RETURN, broadcast to Bitcoin network.

        Args:
            message: Plaintext message to send
            shared_key: 32-byte shared encryption key
            sender_id: Optional sender identifier
            session_id: Session identifier
            sequence: Message sequence number
            cipher_suite: Encryption cipher to use
            kdf_suite: Key derivation function name

        Returns:
            SendResult with txid on success, error on failure
        """
        try:
            # 1. Build encrypted envelope
            envelope = self.build_envelope(
                plaintext=message,
                shared_key=shared_key,
                sender_id=sender_id,
                session_id=session_id,
                sequence=sequence,
                cipher_suite=cipher_suite,
                kdf_suite=kdf_suite,
            )

            # 2. Serialize envelope to bytes (compact JSON)
            envelope_bytes = envelope.to_bytes()

            # 3. Check size - envelope must fit in OP_RETURN
            if len(envelope_bytes) > MAX_OP_RETURN_SIZE:
                return SendResult(
                    None,
                    f"Envelope too large for OP_RETURN: {len(envelope_bytes)} > {MAX_OP_RETURN_SIZE}",
                )

            # 4. Build OP_RETURN script
            op_return_script = self.build_op_return_script(envelope_bytes)

            # 5. Get UTXOs
            utxos = self.get_utxos()

            # 6. Get or use change address
            change_addr = self.change_address
            if not change_addr:
                try:
                    change_addr = self.rpc.getrawchangeaddress()
                except JSONRPCException:
                    # No change address available, send without change
                    change_addr = None

            # 7. Create raw transaction
            raw_tx = self.create_raw_transaction(utxos, op_return_script, change_addr)

            # 8. Fund and sign
            signed_tx = self.fund_and_sign(raw_tx)

            # 9. Broadcast
            txid = self.broadcast(signed_tx)

            logger.info(f"Message sent successfully: {txid}")
            return SendResult(txid=txid, error=None)

        except SendError:
            raise
        except (JSONRPCException, ConnectionError, TimeoutError) as e:
            logger.error("Send failed: %s", e)
            return SendResult(None, str(e))

    def send_via_cli(
        self,
        message: str,
        shared_key: bytes,
        sender_id: str | None = None,
        session_id: str = "default",
        sequence: int = 0,
        cipher_suite: CipherSuite = CipherSuite.XCHACHA20_POLY1305,
        kdf_suite: KDFSuite = KDFSuite.ARGON2ID,
    ) -> SendResult:
        """
        Fallback: send via bitcoin-cli subprocess.
        Useful when RPC auth is not configured but bitcoin-cli works.
        """
        try:
            # Build envelope
            envelope = self.build_envelope(
                plaintext=message,
                shared_key=shared_key,
                sender_id=sender_id,
                session_id=session_id,
                sequence=sequence,
                cipher_suite=cipher_suite,
                kdf_suite=kdf_suite,
            )
            envelope_bytes = envelope.to_bytes()

            if len(envelope_bytes) > MAX_OP_RETURN_SIZE:
                return SendResult(
                    None,
                    f"Envelope too large: {len(envelope_bytes)} > {MAX_OP_RETURN_SIZE}",
                )

            op_return_script = self.build_op_return_script(envelope_bytes)

            # Use bitcoin-cli to create, fund, sign, send
            # We'll write the raw tx to a temp file and pipe through bitcoin-cli
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False):
                # Create raw transaction
                utxos_json = subprocess.run(
                    ["bitcoin-cli", "listunspent", "1", "9999999", "[]", "true"],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                import json
                utxos = json.loads(utxos_json.stdout)
                utxos = [u for u in utxos if u.get("spendable", True)]

                if not utxos:
                    return SendResult(None, "No spendable UTXOs")

                inputs = [{"txid": u["txid"], "vout": u["vout"]} for u in utxos[:1]]
                outputs = {"data": op_return_script.hex()}

                raw_tx_json = subprocess.run(
                    ["bitcoin-cli", "createrawtransaction"],
                    input=json.dumps([inputs, outputs]),
                    capture_output=True,
                    text=True,
                    check=True,
                )
                raw_tx = raw_tx_json.stdout.strip()

                # Fund
                funded_json = subprocess.run(
                    ["bitcoin-cli", "fundrawtransaction", raw_tx, json.dumps({"feeRate": self.fee_rate})],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                funded = json.loads(funded_json.stdout)

                # Sign
                signed_json = subprocess.run(
                    ["bitcoin-cli", "signrawtransactionwithwallet", funded["hex"]],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                signed = json.loads(signed_json.stdout)

                if not signed.get("complete"):
                    return SendResult(None, "Signing incomplete")

                # Send
                txid_json = subprocess.run(
                    ["bitcoin-cli", "sendrawtransaction", signed["hex"]],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                txid = txid_json.stdout.strip()

                return SendResult(txid=txid, error=None)

        except subprocess.CalledProcessError as e:
            error = e.stderr.strip() if e.stderr else str(e)
            return SendResult(None, f"bitcoin-cli failed: {error}")
        except (OSError, ValueError) as e:
            return SendResult(None, str(e))