#!/usr/bin/env python3

"""A utility for dealing with the macOS keychain."""

import logging
import re
import subprocess

from .exceptions import KeyperException

log = logging.getLogger("keyper")  # pylint: disable=invalid-name

# pylint: disable=too-many-arguments


class Certificate:
    """Represents a p12 certificate."""

    path: str
    password: str
    sha1: str
    common_name: str | None
    private_key_name: str | None

    def __init__(self, path: str, *, password: str | None = None) -> None:
        self.path = path
        self.password = password if password is not None else ""

        self.sha1 = self._get_p12_sha1_hash()
        self.common_name = self._get_common_name()
        self.private_key_name = self._get_private_key_name()

    def _get_value(self, value_name: str) -> str | None:
        log.debug("Getting certificate value: %s", value_name)

        get_cert_command = [
            "openssl",
            "pkcs12",
            "-in",
            self.path,
            "-nokeys",
            "-passin",
            f"pass:{self.password}",
        ]

        try:
            with subprocess.Popen(
                get_cert_command,
                universal_newlines=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ) as get_cert:
                openssl_command = ["openssl", "x509", "-noout", f"-{value_name}"]

                with subprocess.Popen(
                    openssl_command,
                    universal_newlines=True,
                    stdin=get_cert.stdout,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ) as openssl:
                    if openssl.stdout is None:
                        raise subprocess.CalledProcessError(1, openssl_command, None, None)

                    value = openssl.stdout.read()

        except subprocess.CalledProcessError as ex:
            log.error("Failed to get value: %s", ex)
            return None

        value = value.strip()

        log.debug("Full value: %s", value)

        return value

    def _get_common_name(self) -> str | None:
        log.debug("Getting certificate common name")

        subject = self._get_value("subject")

        if subject is None:
            log.error("Failed to get common name due to lack of subject")
            return None

        match = re.search(r"subject=.*/CN=(.*).*/.*", subject)

        if match:
            common_name = match.group(1)
        else:
            log.error("Failed to get common name from subject: %s", subject)
            return None

        return common_name

    def _get_p12_sha1_hash(self) -> str:
        log.debug("Getting certificate SHA1 hash")

        fingerprint = self._get_value("fingerprint")

        if fingerprint is None:
            raise KeyperException("Failed to get fingerprint")

        fingerprint = fingerprint.replace("SHA1 Fingerprint=", "")

        return fingerprint

    def _get_private_key_name(self) -> str | None:
        log.debug("Getting certificate private key name")

        command = [
            "openssl",
            "pkcs12",
            "-in",
            self.path,
            "-nocerts",
            "-passin",
            f"pass:{self.password}",
            "-passout",
            f"pass:{self.password}",
        ]

        try:
            lines = subprocess.run(
                command,
                universal_newlines=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                encoding="utf-8",
            ).stdout.split("\n")
        except subprocess.CalledProcessError as ex:
            log.error("Failed to get private key name: %s", ex)
            return None

        key = "friendlyName: "
        lines = [line.strip() for line in lines]
        friendly_names = [line for line in lines if line.startswith(key)]

        if len(friendly_names) != 1:
            log.error(f"Failed to get friendly name: {friendly_names}")
            return None

        value = friendly_names[0][len(key) :]

        log.debug("Friendly name: %s", value)

        return value
