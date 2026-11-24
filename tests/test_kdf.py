"""
Tests for Mempool Partyline core functionality
"""

import os
import unittest
from unittest.mock import Mock, patch

from partyline.crypto.kdf import SecureKDF, KDFParams, zeroize
from partyline.constants import KDFSuite, DEFAULT_KDF_ITERATIONS


class TestKDF(unittest.TestCase):
    def test_kdf_params_default(self):
        """Test default KDF parameters"""
        params = KDFParams(kdf_suite=KDFSuite.ARGON2ID, salt=b"default_salt")
        self.assertEqual(params.kdf_suite, KDFSuite.ARGON2ID)
        self.assertEqual(params.iterations, None)  # Optional, defaults to None
        self.assertEqual(params.memory_cost, None)  # Optional, defaults to None
        self.assertEqual(params.parallelism, None)  # Optional, defaults to None
        self.assertEqual(params.salt, b"default_salt")

    def test_kdf_derive_key(self):
        """Test key derivation"""
        kdf = SecureKDF(KDFSuite.ARGON2ID)
        password = b"test_password"
        salt = b"test_salt"
        key, params = kdf.derive_key(password, salt=salt, key_length=32)
        
        # Verify key is 32 bytes
        self.assertEqual(len(key), 32)
        
        # Verify params are preserved
        self.assertEqual(params.kdf_suite, KDFSuite.ARGON2ID)
        self.assertEqual(params.salt, salt)

    def test_zeroize(self):
        """Test zeroization"""
        data = bytearray(b'secret')
        zeroize(data)
        for byte in data:
            self.assertEqual(byte, 0)


if __name__ == '__main__':
    unittest.main()