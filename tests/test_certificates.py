#!/usr/bin/env python3

"""Tests for the package."""

# pylint: disable=line-too-long

import os
import subprocess
import sys
import tempfile
import unittest


sys.path.insert(0, os.path.abspath(os.path.join(os.path.abspath(__file__), "..", "..")))

import keyper


class KeyperCertificateTests(unittest.TestCase):
    """Test certificates."""

    TEST_CERT_PATH = os.path.join(os.path.dirname(__file__), "TestCert_CodeSign.p12")
    TEST_CERT_PASSWORD = "testcertificatepassword"

    def test_creating_cert(self):
        """Test creating a certificate."""

        certificate = keyper.Certificate(
            KeyperCertificateTests.TEST_CERT_PATH,
            password=KeyperCertificateTests.TEST_CERT_PASSWORD,
        )
        self.assertEqual(
            certificate.sha1, "2B:7F:C0:ED:58:4C:69:E7:62:A9:F1:10:3B:FE:F6:16:38:A8:35:B8"
        )
        self.assertEqual(certificate.common_name, "TestCertificate")
        self.assertEqual(certificate.private_key_name, "TestCertificate")

    def test_adding_cert(self):
        """Test that we can add a cert to the keychain."""

        with keyper.TemporaryKeychain() as keychain:
            certificate = keyper.Certificate(
                KeyperCertificateTests.TEST_CERT_PATH,
                password=KeyperCertificateTests.TEST_CERT_PASSWORD,
            )
            self.assertEqual(certificate.path, KeyperCertificateTests.TEST_CERT_PATH)
            self.assertEqual(certificate.password, KeyperCertificateTests.TEST_CERT_PASSWORD)
            keychain.install_cert(certificate)

    def test_using_codesign(self):
        """Test that an added cert works with codesign."""

        with keyper.TemporaryKeychain() as keychain:
            certificate = keyper.Certificate(
                KeyperCertificateTests.TEST_CERT_PATH,
                password=KeyperCertificateTests.TEST_CERT_PASSWORD,
            )
            keychain.install_cert(certificate)

            temp_file_path = tempfile.mktemp()

            with open(temp_file_path, "w", encoding="utf-8") as temp_file:
                temp_file.write("Test")

            try:
                subprocess.run(
                    [
                        "codesign",
                        "-s",
                        "TestCertificate",
                        "--keychain",
                        keychain.path,
                        temp_file_path,
                    ],
                    check=True,
                )
            except subprocess.CalledProcessError as ex:
                self.fail(f"Failed to use codesign: {ex}")
            finally:
                if os.path.exists(temp_file_path):
                    os.remove(temp_file_path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
