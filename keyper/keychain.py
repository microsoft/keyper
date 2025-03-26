"""A utility for dealing with the macOS keychain."""

import logging
import os
import re
import secrets
from string import ascii_letters, digits
import subprocess
import tempfile
from typing import List, Optional
import uuid

from .certificate import Certificate
from .exceptions import KeyperException

log = logging.getLogger("keyper")  # pylint: disable=invalid-name

_PASSWORD_ALPHABET = ascii_letters + digits + "!@£$%^&*()_+-={}[]:|;<>?,./~`"


# pylint: disable=too-many-arguments


class Keychain:
    """Represents an actual keychain in the system."""

    path: str
    password: str
    is_temporary: bool

    def __init__(self, path: str, password: str, *, is_temporary: bool = False) -> None:
        log.debug("Creating new keychain: %s (is_temporary=%s)", path, str(is_temporary))
        self.path = os.path.realpath(path)
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
                ["security", "delete-keychain", self.path],
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
                ["security", "unlock-keychain", "-p", self.password, self.path],
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
                [
                    "security",
                    "set-key-partition-list",
                    "-S",
                    "apple-tool:,apple:",
                    "-s",
                    "-l",
                    certificate.private_key_name,
                    "-k",
                    self.password,
                    self.path,
                ],
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

        command = ["security", "list-keychains", "-d", "user", "-s", self.path]

        # Our new keychain needs to be at the start of the list so that it is
        # searched before the others are (otherwise they'll prompt for
        # passwords)
        for path in previous_keychains:
            command.append(path)

        try:
            subprocess.run(
                command,
                universal_newlines=True,
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
                raise KeyperException("Previous keychain missing when checking keychains: " + path)

        new_path_exists = False

        # /var and /private/var are the same, but we don't know which macOS is
        # going to send back, so we have to normalize out the symlinks to do
        # the comparisons
        for new_path in new_keychains:
            if os.path.realpath(new_path) == os.path.realpath(self.path):
                new_path_exists = True
                break

        if not new_path_exists:
            raise KeyperException("New keychain missing when checking keychains: " + self.path)

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
        import_command = [
            "security",
            "import",
            certificate.path,
            "-P",
            certificate.password,
            "-A",
            "-t",
            "cert",
            "-f",
            "pkcs12",
            "-k",
            self.path,
        ]

        try:
            subprocess.run(import_command, check=True)
        except subprocess.CalledProcessError as ex:
            log.error("Failed to get import certificate: %s", ex)
            raise

        # Give everything access to the keychain so that it is actually useful
        self.set_key_partition_list(certificate)

        # Add the keychain to the search list so that we can just search across all
        # keychains
        self.add_to_user_search_list()

    def get_password(
        self,
        *,
        label: Optional[str] = None,
        account: Optional[str] = None,
        creator: Optional[str] = None,
        type_code: Optional[str] = None,
        kind: Optional[str] = None,
        value: Optional[str] = None,
        comment: Optional[str] = None,
        service: Optional[str] = None,
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
        """

        return get_password(
            label=label,
            account=account,
            creator=creator,
            type_code=type_code,
            kind=kind,
            value=value,
            comment=comment,
            service=service,
            keychain=self,
        )

    def set_password(
        self,
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
    ) -> None:
        """Read a password from the keychain for a given item.

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
        """
        return set_password(
            password,
            label=label,
            account=account,
            creator=creator,
            type_code=type_code,
            kind=kind,
            attribute=attribute,
            comment=comment,
            service=service,
            allow_any_app_access=allow_any_app_access,
            apps_with_access=apps_with_access,
            update_if_exists=update_if_exists,
            keychain=self,
        )

    def delete_password(
        self,
        *,
        account: str,
        service: str,
        label: Optional[str] = None,
        creator: Optional[str] = None,
        type_code: Optional[str] = None,
        kind: Optional[str] = None,
        attribute: Optional[str] = None,
        comment: Optional[str] = None,
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
        """

        return delete_password(
            label=label,
            account=account,
            creator=creator,
            type_code=type_code,
            kind=kind,
            attribute=attribute,
            comment=comment,
            service=service,
            keychain=self,
        )

    @staticmethod
    def list_keychains(*, domain: Optional[str] = None) -> List[str]:
        """Get the list of the current keychains.

        :param domain: The domain to list the keychains for. If left as None, all will be searched.
        """

        log.debug("Listing the current keychains")

        command = ["security", "list-keychains"]

        if domain is not None:
            if domain not in ["user", "system", "common", "dynamic"]:
                raise KeyperException("Invalid domain: " + domain)

            command += ["-d", domain]

        try:
            keychain_command_output = subprocess.run(
                command,
                universal_newlines=True,
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
            if not current:
                continue
            current = os.path.realpath(current)
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
            raise KeyperException(
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
                ["security", "default-keychain"],
                universal_newlines=True,
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
                ["security", "create-keychain", "-p", keychain_password, keychain_path],
                check=True,
            )
        except subprocess.CalledProcessError as ex:
            log.error("Failed to create keychain: %s", ex)
            raise

        settings_command = ["security", "set-keychain-settings"]

        if lock_on_sleep:
            settings_command += ["-l"]

        if lock_on_timeout:
            settings_command += ["-u"]

        settings_command += ["-t", str(timeout), keychain_path]

        try:
            subprocess.run(settings_command, check=True)
        except subprocess.CalledProcessError as ex:
            log.error("Failed to set keychain settings: %s", ex)
            raise


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
    keychain: Optional["Keychain"] = None,
    skip_decode: Optional[bool] = None
) -> Optional[str|bytearray]:
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
    :param bool skip_decode: Indicates to skip trying to interpret the password as a UTF-8 string, instead returning the password as a `bytearray`. Useful for system passwords

    :returns: The found password as a `utf-8` string, unless `skip_decode` is set to `True`, in which case the password will be returned as a `bytearray`
    :rtype: str|bytearray|None
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

    command = ["security", "find-generic-password"]

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
            command += [flag, item]

    command += ["-g"]

    if keychain is not None:
        command += [keychain.path]

    try:
        output = subprocess.run(
            command,
            universal_newlines=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stderr
    except subprocess.CalledProcessError:
        return None

    # The output is somewhat complex. We are looking for the line starting "password:"
    password_lines = [line for line in output.split("\n") if line.startswith("password: ")]

    if len(password_lines) != 1:
        raise KeyperException("Failed to get password from security output")

    password_line = password_lines[0]

    complex_pattern_match = re.match(r"^password: 0x([0-9A-F]*) .*$", password_line)
    simple_pattern_match = re.match(r'^password: "(.*)"$', password_line)

    password = None

    if complex_pattern_match:
        hex_value = complex_pattern_match.group(1)
        password = bytes.fromhex(hex_value)
        if not skip_decode:
            password = password.decode("utf-8")

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
    keychain: Optional["Keychain"] = None,
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

    command = ["security", "add-generic-password"]

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
            command += [flag, item]

    if allow_any_app_access:
        command += ["-A"]

    if update_if_exists:
        command += ["-U"]

    if apps_with_access is not None:
        for app_path in apps_with_access:
            if not os.path.exists(app_path):
                raise FileNotFoundError(f"The following app does not exist at: {app_path}")

            command += ["-T", app_path]

    if keychain is not None:
        command += [keychain.path]

    # Let the exception bubble up
    _ = subprocess.run(
        command,
        universal_newlines=True,
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
    keychain: Optional["Keychain"] = None,
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

    command = ["security", "delete-generic-password"]

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
            command += [flag, item]

    if keychain is not None:
        command += [keychain.path]

    # Let the exception bubble up
    _ = subprocess.run(
        command,
        universal_newlines=True,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout
