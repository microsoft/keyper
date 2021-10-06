#!/usr/bin/env python3

"""A utility for dealing with the macOS keychain."""

from distutils.version import StrictVersion
import logging
import os
import platform
import re
import secrets
import shlex
from string import ascii_letters, digits
import subprocess
import tempfile
from types import TracebackType
from typing import List, Literal, Optional, Type
import uuid

log = logging.getLogger("keyper")  # pylint: disable=invalid-name

_PASSWORD_ALPHABET = ascii_letters + digits + "!@£$%^&*()_+-={}[]:|;<>?,./~`"

if platform.system() != "Darwin":
    raise Exception("This tool is only supported on macOS")

if StrictVersion(platform.mac_ver()[0]) < StrictVersion("10.13.0"):
    raise Exception("This tool is only supported on macOS 10.13.0 or higher")


class Certificate:
    """Represents a p12 certificate."""

    path: str
    password: str
    sha1: str
    common_name: Optional[str]
    private_key_name: Optional[str]

    def __init__(self, path: str, *, password: Optional[str] = None) -> None:
        self.path = path
        self.password = password if password is not None else ""

        self.sha1 = self._get_p12_sha1_hash()
        self.common_name = self._get_common_name()
        self.private_key_name = self._get_private_key_name()

    def _get_value(self, value_name: str) -> Optional[str]:

        log.debug("Getting certificate value: %s", value_name)

        command = f"openssl pkcs12 -in {shlex.quote(self.path)} -nokeys -passin pass:{shlex.quote(self.password)}"
        command += f" | openssl x509 -noout -{value_name}"

        try:
            value = subprocess.run(
                command,
                universal_newlines=True,
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).stdout
        except subprocess.CalledProcessError as ex:
            log.error("Failed to get value: %s", ex)
            return None

        value = value.strip()

        log.debug("Full value: %s", value)

        return value

    def _get_common_name(self) -> Optional[str]:

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
            raise Exception("Failed to get fingerprint")

        fingerprint = fingerprint.replace("SHA1 Fingerprint=", "")

        return fingerprint

    def _get_private_key_name(self) -> Optional[str]:

        log.debug("Getting certificate private key name")

        command = (
            f"openssl pkcs12 -in {shlex.quote(self.path)} "
            "-nocerts "
            f"-passin pass:{shlex.quote(self.password)} "
            f"-passout pass:{shlex.quote(self.password)} "
            '| grep "friendlyName"'
        )

        try:
            value = subprocess.run(
                command,
                universal_newlines=True,
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).stdout
        except subprocess.CalledProcessError as ex:
            log.error("Failed to get private key name: %s", ex)
            return None

        value = value.strip()

        log.debug("Friendly name: %s", value)

        private_key_name = value.replace("friendlyName: ", "")

        return private_key_name


class Keychain:
    """Represents an actual keychain in the system."""

    path: str
    password: str
    is_temporary: bool

    def __init__(self, path: str, password: str, *, is_temporary: bool = False) -> None:
        log.debug("Creating new keychain: %s (is_temporary=%s)", path, str(is_temporary))
        self.path = path
        self.password = password
        self.is_temporary = is_temporary

    def delete_temporary(self) -> None:
        """Delete the keychain if it is a temporary one."""

        if not self.is_temporary:
            log.debug("Skipping deletion due to being a non-temporary")
            return

        self.delete()

    def delete(self) -> None:
        """Deletes the keychain."""

        log.info("Deleting keychain: %s", self.path)

        try:
            subprocess.run(
                f"security delete-keychain {shlex.quote(self.path)}",
                shell=True,
                check=True,
            )
        except subprocess.CalledProcessError as ex:
            log.error("Failed to delete keychain: %s", ex)

        if os.path.exists(self.path):
            os.remove(self.path)

    def unlock(self) -> None:
        """Unlock the keychain."""

        log.info("Unlocking keychain: %s", self.path)

        try:
            subprocess.run(
                f"security unlock-keychain -p {shlex.quote(self.password)} {shlex.quote(self.path)}",
                shell=True,
                check=True,
            )
        except subprocess.CalledProcessError as ex:
            log.error("Failed to set unlock keychain: %s", ex)
            raise

    def set_key_partition_list(self, certificate: Certificate) -> None:
        """Set the key partition list for the keychain.

        This avoids the prompt to enter the password when using a certificate
        via codesign for the first time.

        The logic for this is based on the answer to this SO question:
        https://stackoverflow.com/questions/39868578/

        :param Certificate certificate: The certificate to use the private key name from.
        """

        log.debug("Setting partition list for: %s", certificate.private_key_name)

        if certificate.private_key_name is None:
            log.warning("Skipping due to certificate not having a private key")
            return

        if self.is_temporary:
            log.debug("Skipping due to being temporary")
            return

        try:
            subprocess.run(
                (
                    "security set-key-partition-list "
                    "-S apple-tool:,apple: -s "
                    f"-l {shlex.quote(certificate.private_key_name)} "
                    f"-k {shlex.quote(self.password)} {shlex.quote(self.path)}"
                ),
                shell=True,
                check=True,
            )
        except subprocess.CalledProcessError as ex:
            log.error("Failed to set key partition list: %s", ex)
            raise

    def add_to_user_search_list(self) -> None:
        """Add the keychain to the user domain keychain search list."""

        log.debug("Adding keychain to user search list: %s", self.path)

        # There is no "add" operation, only a "set" one, so we need to get the
        # existing ones so that we can set those along with our new one.

        previous_keychains = Keychain.list_keychains(domain="user")

        if self.path in previous_keychains:
            return

        command = "security list-keychains -d user -s "

        command += shlex.quote(self.path) + " "

        # Our new keychain needs to be at the start of the list so that it is
        # searched before the others are (otherwise they'll prompt for
        # passwords)
        for path in previous_keychains:
            command += shlex.quote(path) + " "

        try:
            subprocess.run(
                command,
                universal_newlines=True,
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).stdout
        except subprocess.CalledProcessError as ex:
            log.error("Failed to get keychains: %s", ex)
            raise

        # Validate that the new keychain is there

        new_keychains = Keychain.list_keychains(domain="user")

        for path in previous_keychains:
            if path not in new_keychains:
                raise Exception("Previous keychain missing when checking keychains: " + path)

        new_path_exists = False

        # /var and /private/var are the same, but we don't know which macOS is
        # going to send back, so we have to normalize out the symlinks to do
        # the comparisons
        for new_path in new_keychains:
            if os.path.realpath(new_path) == os.path.realpath(self.path):
                new_path_exists = True
                break

        if not new_path_exists:
            raise Exception("New keychain missing when checking keychains: " + self.path)

    def install_cert(self, certificate: Certificate) -> None:
        """Install the supplied certificate to the keychain.

        If this is a temporary keychain, the search list will be modified so that
        we can use it in other applications such as using the codesign binary.

        NOTE: The certificate (and private key) is set to allow any program on the
        system to access it. Be sure that this is what you want.

        :param Certificate certificate: The certificate to be installed.
        """

        # The keychain must be unlocked before we can do anything further
        self.unlock()

        # Import the certificate into the keychain
        import_command = (
            f"security import {shlex.quote(certificate.path)} "
            f"-P {shlex.quote(certificate.password)} "
            f"-A -t cert -f pkcs12 -k {shlex.quote(self.path)}"
        )

        try:
            subprocess.run(import_command, shell=True, check=True)
        except subprocess.CalledProcessError as ex:
            log.error("Failed to get import certificate: %s", ex)
            raise

        # Give everything access to the keychain so that it is actually useful
        self.set_key_partition_list(certificate)

        # Add the keychain to the search list so that we can just search across all
        # keychains
        self.add_to_user_search_list()

    @staticmethod
    def list_keychains(*, domain: Optional[str] = None) -> List[str]:
        """Get the list of the current keychains.

        :param domain: The domain to list the keychains for. If left as None, all will be searched.
        """

        log.debug("Listing the current keychains")

        command = "security list-keychains"

        if domain is not None:
            if domain not in ["user", "system", "common", "dynamic"]:
                raise Exception("Invalid domain: " + domain)

            command += f" -d {shlex.quote(domain)}"

        try:
            keychain_command_output = subprocess.run(
                command,
                universal_newlines=True,
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).stdout
        except subprocess.CalledProcessError as ex:
            log.error("Failed to get keychains: %s", ex)
            raise

        # Cleanup the output format into a regular Python list of strings
        keychains = []
        for keychain in keychain_command_output.split("\n"):
            # Remove surrounding whitespace and then surrounding quotes
            current = keychain.strip()[1:-1]
            if current:
                keychains.append(current)

        log.debug("Current keychains: %s", str(keychains))

        return keychains

    @staticmethod
    def create_temporary() -> "Keychain":
        """Create a new temporary keychain."""

        keychain_name = str(uuid.uuid4()) + ".keychain"
        keychain_path = os.path.join(tempfile.gettempdir(), keychain_name)
        keychain_password = "".join(secrets.choice(_PASSWORD_ALPHABET) for _ in range(50))

        if os.path.exists(keychain_path):
            raise Exception(
                "Cannot create temporary keychain. Path already exists: " + keychain_path
            )

        keychain = Keychain(keychain_path, keychain_password, is_temporary=True)

        # We have a reference, but now we need to create the keychain with the
        # system.
        Keychain._create_keychain(keychain_path, keychain_password)

        log.info("Created temporary keychain: %s", keychain_path)

        return keychain

    @staticmethod
    def default(password: str) -> "Keychain":
        """Get the default keychain for the current user."""

        log.debug("Getting default keychain")

        try:
            default_keychain_path = subprocess.run(
                "security default-keychain",
                universal_newlines=True,
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).stdout
        except subprocess.CalledProcessError as ex:
            log.error(f"Failed to get default keychain: {ex}")
            raise

        # The output format looks like this:
        #     "/Users/dalemy/Library/Keychains/login.keychain-db"

        # Remove whitespace
        default_keychain_path = default_keychain_path.strip()

        # Remove quotes
        default_keychain_path = default_keychain_path[1:]
        default_keychain_path = default_keychain_path[:-1]

        return Keychain(default_keychain_path, password)

    @staticmethod
    def _create_keychain(
        keychain_path: str,
        keychain_password: str,
        *,
        lock_on_sleep: bool = True,
        lock_on_timeout: bool = True,
        timeout: int = 60 * 6,
    ):
        """Create a new keychain."""

        try:
            subprocess.run(
                f"security create-keychain -p {shlex.quote(keychain_password)} {shlex.quote(keychain_path)}",
                shell=True,
                check=True,
            )
        except subprocess.CalledProcessError as ex:
            log.error("Failed to create keychain: %s", ex)
            raise

        settings_command = "security set-keychain-settings -"

        if lock_on_sleep:
            settings_command += "l"

        if lock_on_timeout:
            settings_command += "u"

        settings_command += f"t {timeout} {shlex.quote(keychain_path)}"

        try:
            subprocess.run(settings_command, shell=True, check=True)
        except subprocess.CalledProcessError as ex:
            log.error("Failed to set keychain settings: %s", ex)
            raise


class TemporaryKeychain:
    """Context object for working with a temporary keychain."""

    keychain: Optional[Keychain]

    def __init__(self) -> None:
        self.keychain = None

    def __enter__(self) -> "Keychain":
        """Enter the context

        :returns: A reference to self
        """
        self.keychain = Keychain.create_temporary()
        return self.keychain

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[Exception],
        exc_tb: Optional[TracebackType],
    ) -> Literal[False]:
        if self.keychain:
            self.keychain.delete_temporary()
            self.keychain = None
        return False


def get_password(
    *,
    label: Optional[str] = None,
    account: Optional[str] = None,
    creator: Optional[str] = None,
    type_code: Optional[str] = None,
    kind: Optional[str] = None,
    value: Optional[str] = None,
    comment: Optional[str] = None,
    service: Optional[str] = None,
    keychain: Optional[Keychain] = None,
) -> Optional[str]:
    """Read a password from the system keychain for a given item.

    Any of the supplied arguments can be used to search for the password.

    :param str label: Match on the label of the password. This is the normal one to use.
    :param str account: Match on the account of the password.
    :param str creator: Match on the creator of the password.
    :param str type_code: Match on the type of the password.
    :param str kind: Match on the kind of the password.
    :param str value: Match on the value of the password (this is a generic attribute).
    :param str comment: Match on the comment of the password.
    :param str service: Match on the service of the password.
    :param Keychain keychain: If supplied, only search this keychain, otherwise search all.
    """

    # pylint: disable=too-many-locals

    log.debug(
        "Fetching item from keychain: %s, %s, %s, %s, %s, %s, %s, %s, %s",
        label,
        account,
        creator,
        type_code,
        kind,
        value,
        comment,
        service,
        keychain,
    )

    command = "security find-generic-password"

    flags = {
        "-l": label,
        "-a": account,
        "-c": creator,
        "-C": type_code,
        "-D": kind,
        "-G": value,
        "-j": comment,
        "-s": service,
    }

    for flag, item in flags.items():
        if item is not None:
            command += f" {flag} {shlex.quote(item)}"

    command += " -g"

    if keychain is not None:
        command += " " + keychain.path

    try:
        output = subprocess.run(
            command,
            universal_newlines=True,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stderr
    except subprocess.CalledProcessError:
        return None

    # The output is somewhat complex. We are looking for the line starting "password:"
    password_lines = [line for line in output.split("\n") if line.startswith("password: ")]

    if len(password_lines) != 1:
        raise Exception("Failed to get password from security output")

    password_line = password_lines[0]

    complex_pattern_match = re.match(r"^password: 0x([0-9A-F]*) .*$", password_line)
    simple_pattern_match = re.match(r'^password: "(.*)"$', password_line)

    password = None

    if complex_pattern_match:
        hex_value = complex_pattern_match.group(1)
        password = bytes.fromhex(hex_value).decode("utf-8")

    elif simple_pattern_match:
        password = simple_pattern_match.group(1)

    else:
        password = ""

    return password


def set_password(
    password: str,
    *,
    account: str,
    service: str,
    label: Optional[str] = None,
    creator: Optional[str] = None,
    type_code: Optional[str] = None,
    kind: Optional[str] = None,
    attribute: Optional[str] = None,
    comment: Optional[str] = None,
    allow_any_app_access: bool = False,
    apps_with_access: Optional[List[str]] = None,
    update_if_exists: bool = False,
    keychain: Optional[Keychain] = None,
) -> None:
    """Read a password from the system keychain for a given item.

    Any of the supplied arguments can be used to search for the password.

    :param str password: The password to set
    :param str account: The name of the account
    :param str service: The service name
    :param Optional[str] label: The label (uses service name if not specified)
    :param Optional[str] creator: The creator (a 4 character code)
    :param Optional[str] type_code: The item type (a 4 character code)
    :param Optional[str] kind: The item kind. Defaults to "application password"
    :param Optional[str] attribute: Any generic attribute
    :param Optional[str] comment: The comment
    :param bool allow_any_app_access: Set to True to allow any app to access the item without warning
    :param Optional[List[str]] apps_with_access: A list of apps with access to the item (the app binary paths)
    :param bool update_if_exists: Update the existing item if it already exists
    :param Keychain keychain: If supplied, add to that keychain, otherwise use the default.
    """

    # pylint: disable=too-many-locals

    log.debug(
        "Setting item from keychain: %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s",
        account,
        service,
        label,
        creator,
        type_code,
        kind,
        attribute,
        comment,
        allow_any_app_access,
        apps_with_access,
        update_if_exists,
        keychain,
    )

    command = "security add-generic-password"

    flags = {
        "-a": account,
        "-c": creator,
        "-C": type_code,
        "-D": kind,
        "-G": attribute,
        "-j": comment,
        "-l": label,
        "-s": service,
        "-w": password,
    }

    for flag, item in flags.items():
        if item is not None:
            command += f" {flag} {shlex.quote(item)}"

    if allow_any_app_access:
        command += " -A"

    if update_if_exists:
        command += " -U"

    if apps_with_access is not None:
        for app_path in apps_with_access:
            if not os.path.exists(app_path):
                raise FileNotFoundError(f"The following app does not exist at: {app_path}")

            command += f" -T {shlex.quote(app_path)}"

    if keychain is not None:
        command += " " + keychain.path

    # Let the exception bubble up
    _ = subprocess.run(
        command,
        universal_newlines=True,
        shell=True,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout


def delete_password(
    *,
    account: str,
    service: str,
    label: Optional[str] = None,
    creator: Optional[str] = None,
    type_code: Optional[str] = None,
    kind: Optional[str] = None,
    attribute: Optional[str] = None,
    comment: Optional[str] = None,
    keychain: Optional[Keychain] = None,
) -> None:
    """Delete a password from the system keychain for a given item.

    Any of the supplied arguments can be used to search for the password.

    :param str account: The name of the account
    :param str service: The service name
    :param Optional[str] label: The label (uses service name if not specified)
    :param Optional[str] creator: The creator (a 4 character code)
    :param Optional[str] type_code: The item type (a 4 character code)
    :param Optional[str] kind: The item kind. Defaults to "application password"
    :param Optional[str] attribute: Any generic attribute
    :param Optional[str] comment: The comment
    :param Keychain keychain: If supplied, delete from that keychain, otherwise use the default.
    """

    # pylint: disable=too-many-locals

    log.debug(
        "Deleting item from keychain: %s, %s, %s, %s, %s, %s, %s, %s, %s",
        account,
        service,
        label,
        creator,
        type_code,
        kind,
        attribute,
        comment,
        keychain,
    )

    command = "security delete-generic-password"

    flags = {
        "-a": account,
        "-c": creator,
        "-C": type_code,
        "-D": kind,
        "-G": attribute,
        "-j": comment,
        "-l": label,
        "-s": service,
    }

    for flag, item in flags.items():
        if item is not None:
            command += f" {flag} {shlex.quote(item)}"

    if keychain is not None:
        command += " " + keychain.path

    # Let the exception bubble up
    _ = subprocess.run(
        command,
        universal_newlines=True,
        shell=True,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout
