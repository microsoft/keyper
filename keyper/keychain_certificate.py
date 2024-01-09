"""Handling code for keychain certificates."""

import re
import subprocess
from typing import Any


ATTRIBUTE_PATTERN = re.compile(r'"(.*)"<(.*)>=(.*)')


class KeychainCertificate:
    """Represents a certificate in the keychain."""

    keychain: str
    version: int
    klass: int
    attributes: dict[str, Any]

    def __init__(self, **kwargs: Any) -> None:
        self.keychain = kwargs["keychain"][1:-1]
        self.version = int(kwargs["version"])
        self.klass = int(kwargs["class"], 16)
        self.attributes = kwargs["attributes"]


def _parse_blob(blob: str) -> str | bytes | None:
    """Parse the given blob.

    :param blob: The blob to parse

    :returns: The parsed blob
    """

    if blob.startswith('"'):
        return blob[1:-1]

    if blob == "<NULL>":
        return None

    if blob.startswith("0x"):
        return bytes.fromhex(blob[2:].split(" ")[0])

    raise ValueError("Unexpected blob format")


def _parse_attribute(attribute: str) -> tuple[str, Any]:
    """Parse the given attribute.

    :param attribute: The attribute to parse

    :returns: The key and value
    """

    match = ATTRIBUTE_PATTERN.match(attribute)

    if not match:
        raise ValueError(f"Failed to parse attribute: {attribute}")

    match match.group(2):
        case "blob":
            return match.group(1), _parse_blob(match.group(3))
        case "uint32":
            return match.group(1), int(match.group(3), 16)
        case _:
            raise ValueError(f"Unexpected attribute type: {match.group(2)}")


def _parse_attributes(attributes: list[str]) -> dict[str, Any]:
    """Parse the attributes from the given output.

    :param attributes: The attributes to parse

    :returns: The parsed attributes
    """

    output = {}
    for attribute in attributes:
        k, v = _parse_attribute(attribute)
        output[k] = v
    return output


def _parse_certificate(certificate: list[str]) -> KeychainCertificate:
    """Parse a certificate

    :param certificate: The raw certificate to parse.

    :returns: The parsed certificate
    """

    cert: dict[str, Any] = {}
    current_key = None
    output = []

    for line in certificate:
        if len(line) == 0:
            continue

        if line.startswith(" "):
            output.append(line.strip())
            continue

        k, v = line.split(":", 1)

        if v:
            if output:
                assert current_key is not None
                cert[current_key] = output
                output = []
            cert[k] = v.strip()
        else:
            current_key = k

    if output:
        assert current_key is not None
        cert[current_key] = output

    cert["attributes"] = _parse_attributes(cert["attributes"])

    return KeychainCertificate(**cert)


def _parse_certificates(output: list[str]) -> list[KeychainCertificate]:
    """Parse the certificates from the given output.

    :param output: The output to parse

    :returns: The certificates
    """

    certificates = []
    certificate: list[str] = []

    for line in output:
        if line.startswith("keychain: "):
            if len(certificate) > 0:
                certificates.append(_parse_certificate(certificate))
                certificate = []
        certificate.append(line)

    if len(certificate) > 0:
        certificates.append(_parse_certificate(certificate))

    return certificates


def load_all_certificates(keychain: str | None) -> list[KeychainCertificate]:
    """Load all certificates from the given keychain.

    If the keychain isn't specified, it will load from all accessible keychains.

    :param keychain: The keychain to load from

    :returns: The certificates found in the keychain(s)
    """

    command = ["security", "find-certificate", "-a"]

    if keychain:
        command += [keychain]

    result = subprocess.run(
        command,
        check=True,
        stdout=subprocess.PIPE,
    )

    output = result.stdout.decode("utf-8").split("\n")
    return _parse_certificates(output)
