#!/usr/bin/env python3

"""Tests for the package."""

# pylint: disable=line-too-long

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.abspath(__file__), "..", "..")))
import keyper


class KeyperPasswordTests(unittest.TestCase):
    """Test passwords."""

    SAMPLE_PASSWORDS = [
        "",
        "password",
        "p@ssw0rd",
        'Hello "World"',
        "Hello 'World'",
        "Line\nBreak",
        "!@£$%^&*()_+-=[]{};'\\:\"|<>?,./`~§±",
        "This is a rather long passphrase but it should still be totally fine",
        "パスワード",
        "👍",
    ]

    def test_password_write_read(self):
        """Test that passwords written to a keychain can be read back."""

        with keyper.TemporaryKeychain() as keychain:
            for index, password in enumerate(KeyperPasswordTests.SAMPLE_PASSWORDS):
                keyper.set_password(
                    password,
                    account=f"account_{index}",
                    service=f"service_{index}",
                    keychain=keychain,
                )
                returned_password = keyper.get_password(
                    account=f"account_{index}", service=f"service_{index}", keychain=keychain
                )
                self.assertEqual(password, returned_password)


if __name__ == "__main__":
    unittest.main(verbosity=2)
