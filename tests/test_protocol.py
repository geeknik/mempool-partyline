"""
Tests for protocol v2 envelope handling
"""

import json
import unittest

from partyline.protocol import (
    EnvelopeV2,
    MessageType,
    CipherSuite,
    KDFSuite,
    Message,
    validate_envelope_downgrade,
    parse_envelope,
    detect_envelope_version,
)
from partyline.constants import PROTOCOL_VERSION, MIN_SUPPORTED_VERSION


class TestEnvelopeV2(unittest.TestCase):
    def test_default_creation(self):
        """Test default envelope creation"""
        env = EnvelopeV2(
            session_id="abc123",
            sequence=0,
            cipher_suite=CipherSuite.XCHACHA20_POLY1305,
            kdf_suite=KDFSuite.ARGON2ID,
            kdf_params={"salt": "abc", "time_cost": 3},
            nonce="nonce",
            payload="payload",
            tag="tag",
        )
        self.assertEqual(env.version, PROTOCOL_VERSION)
        self.assertEqual(env.msg_type, MessageType.TEXT)
        self.assertEqual(env.session_id, "abc123")

    def test_validation_future_timestamp(self):
        """Test that future timestamps are rejected"""
        with self.assertRaises(ValueError):
            EnvelopeV2(
                session_id="abc",
                sequence=0,
                cipher_suite=CipherSuite.XCHACHA20_POLY1305,
                kdf_suite=KDFSuite.ARGON2ID,
                kdf_params={},
                nonce="nonce",
                payload="payload",
                tag="tag",
                timestamp=9999999999999,
            )

    def test_validation_old_timestamp(self):
        """Test that very old timestamps are rejected"""
        with self.assertRaises(ValueError):
            EnvelopeV2(
                session_id="abc",
                sequence=0,
                cipher_suite=CipherSuite.XCHACHA20_POLY1305,
                kdf_suite=KDFSuite.ARGON2ID,
                kdf_params={},
                nonce="nonce",
                payload="payload",
                tag="tag",
                timestamp=1000,
            )

    def test_payload_size_limit(self):
        """Test that oversized payloads are rejected"""
        big_payload = "A" * (5000 * 2)  # 5000 bytes as hex
        with self.assertRaises(ValueError):
            EnvelopeV2(
                session_id="abc",
                sequence=0,
                cipher_suite=CipherSuite.XCHACHA20_POLY1305,
                kdf_suite=KDFSuite.ARGON2ID,
                kdf_params={},
                nonce="nonce",
                payload=big_payload,
                tag="tag",
            )

    def test_serialization(self):
        """Test envelope serialization"""
        env = EnvelopeV2(
            session_id="abc123",
            sequence=0,
            cipher_suite=CipherSuite.XCHACHA20_POLY1305,
            kdf_suite=KDFSuite.ARGON2ID,
            kdf_params={"salt": "abc", "time_cost": 3},
            nonce="nonce",
            payload="payload",
            tag="tag",
        )
        data = env.to_bytes()
        parsed = json.loads(data)
        self.assertEqual(parsed["session_id"], "abc123")
        self.assertEqual(parsed["version"], PROTOCOL_VERSION)


class TestMessage(unittest.TestCase):
    def test_formatted(self):
        """Test message formatting"""
        msg = Message(content="hello", timestamp=1234567890, sender="alice")
        formatted = msg.formatted()
        self.assertIn("alice", formatted)
        self.assertIn("hello", formatted)

    def test_is_expired(self):
        """Test message expiration"""
        import time
        msg = Message(
            content="test",
            timestamp=time.time() - 7200,  # 2 hours ago
            ttl=3600,  # 1 hour TTL
        )
        self.assertTrue(msg.is_expired())

        msg2 = Message(
            content="test",
            timestamp=time.time(),
            ttl=3600,
        )
        self.assertFalse(msg2.is_expired())


class TestProtocolDowngrade(unittest.TestCase):
    def test_no_downgrade(self):
        """Test that equal version is not flagged as downgrade"""
        env = EnvelopeV2(
            session_id="abc",
            sequence=0,
            cipher_suite=CipherSuite.XCHACHA20_POLY1305,
            kdf_suite=KDFSuite.ARGON2ID,
            kdf_params={},
            nonce="nonce",
            payload="payload",
            tag="tag",
            version=2,
        )
        result = validate_envelope_downgrade(
            env, expected_version=2,
            expected_cipher=CipherSuite.XCHACHA20_POLY1305,
            expected_kdf=KDFSuite.ARGON2ID,
        )
        self.assertTrue(result)

    def test_version_downgrade(self):
        """Test that version downgrade is detected"""
        env = EnvelopeV2(
            session_id="abc",
            sequence=0,
            cipher_suite=CipherSuite.XCHACHA20_POLY1305,
            kdf_suite=KDFSuite.ARGON2ID,
            kdf_params={},
            nonce="nonce",
            payload="payload",
            tag="tag",
            version=1,
        )
        with self.assertRaises(ValueError):
            validate_envelope_downgrade(
                env, expected_version=2,
                expected_cipher=CipherSuite.XCHACHA20_POLY1305,
                expected_kdf=KDFSuite.ARGON2ID,
            )


if __name__ == '__main__':
    unittest.main()