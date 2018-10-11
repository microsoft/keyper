#!/usr/bin/env python3

"""A utility for dealing with the macOS keychain."""

#pylint: disable=line-too-long

from distutils.version import StrictVersion
import logging
import os
import platform
import re
import secrets
import shlex
import subprocess
import tempfile
import uuid

__version__ = '0.3'

#pylint: disable=invalid-name
log = logging.getLogger("mackey")
#pylint: enable=invalid-name

_PASSWORD_ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@£$%^&*()_+-={}[]:|;<>?,./~`'

if platform.system() != "Darwin":
    raise Exception("This tool is only supported on macOS")

if StrictVersion(platform.mac_ver()[0]) < StrictVersion("10.13.0"):
    raise Exception("This tool is only supported on macOS 10.13.0 or higher")


class Certificate():
    """Represents a p12 certificate."""

    def __init__(self, path, *, password=None):
        self.path = path
        self.password = password if password is not None else ""

        self.sha1 = self._get_p12_sha1_hash()
        self.common_name = self._get_common_name()
        self.private_key_name = self._get_private_key_name()

    def _get_value(self, value_name):

        log.debug(f"Getting certificate value: {value_name}")

        command = f'openssl pkcs12 -in {shlex.quote(self.path)} -nokeys -passin pass:{shlex.quote(self.password)}'
        command += f' | openssl x509 -noout -{value_name}'

        try:
            value = subprocess.run(
                command,
                universal_newlines=True,
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            ).stdout
        except subprocess.CalledProcessError as ex:
            log.error(f"Failed to get value {ex}")
            return None

        value = value.strip()

        log.debug(f"Full value: {value}")

        return value


    def _get_common_name(self):

        log.debug("Getting certificate common name")

        subject = self._get_value("subject")
        match = re.search(r'subject=.*/CN=(.*).*/.*', subject)

        if match:
            common_name = match.group(1)
        else:
            log.error(f"Failed to get common name from subject: {subject}")
            return None

        return common_name

    def _get_p12_sha1_hash(self):

        log.debug("Getting certificate SHA1 hash")

        fingerprint = self._get_value("fingerprint")
        fingerprint = fingerprint.replace("SHA1 Fingerprint=", "")

        return fingerprint

    def _get_private_key_name(self):

        log.debug("Getting certificate private key name")

        command = f'openssl pkcs12 -in {shlex.quote(self.path)} -nocerts -passin pass:{shlex.quote(self.password)} -passout pass:{shlex.quote(self.password)} | grep "friendlyName"'

        try:
            value = subprocess.run(
                command,
                universal_newlines=True,
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            ).stdout
        except subprocess.CalledProcessError as ex:
            log.error(f"Failed to get private key name {ex}")
            return None

        value = value.strip()

        log.debug(f"Friendly name: {value}")

        private_key_name = value.replace("friendlyName: ", "")

        return private_key_name


class Keychain():
    """Represents an actual keychain in the system."""

    def __init__(self, path: str, password: str, *, is_temporary: bool = False):
        log.debug(f"Creating new keychain {path} (is_temporary={is_temporary})")
        self.path = path
        self.password = password
        self.is_temporary = is_temporary

    def delete_temporary(self):
        """Delete the keychain if it is a temporary one."""

        if not self.is_temporary:
            log.debug("Skipping deletion due to being a non-temporary")
            return

        self.delete()

    def delete(self):
        """Deletes the keychain."""

        log.info(f"Deleting keychain: {self.path}")

        try:
            subprocess.run(
                f'security delete-keychain {shlex.quote(self.path)}',
                shell=True,
                check=True
            )
        except subprocess.CalledProcessError as ex:
            log.error(f"Failed to delete keychain: {ex}")

        if os.path.exists(self.path):
            os.remove(self.path)

    def unlock(self):
        """Unlock the keychain."""

        log.info(f"Unlocking keychain: {self.path}")

        try:
            subprocess.run(
                f'security unlock-keychain -p {shlex.quote(self.password)} {shlex.quote(self.path)}',
                shell=True,
                check=True,
            )
        except subprocess.CalledProcessError as ex:
            log.error(f"Failed to set unlock keychain: {ex}")
            raise

    def set_key_partition_list(self, certificate: Certificate):
        """Set the key partition list for the keychain.

        This avoids the prompt to enter the password when using a certificate
        via codesign for the first time.

        The logic for this is based on the answer to this SO question:
        https://stackoverflow.com/questions/39868578/security-codesign-in-sierra-keychain-ignores-access-control-settings-and-ui-p

        :param Certificate certificate: The certificate to use the private key name from.
        """

        log.debug(f"Setting partition list for: {certificate.private_key_name}")

        if self.is_temporary:
            log.debug("Skipping due to being temporary")
            return

        try:
            subprocess.run(
                f'security set-key-partition-list -S apple-tool:,apple: -s -l {shlex.quote(certificate.private_key_name)} -k {shlex.quote(self.password)} {shlex.quote(self.path)}',
                shell=True,
                check=True
            )
        except subprocess.CalledProcessError as ex:
            log.error(f"Failed to set key parition list: {ex}")
            raise

    def add_to_user_search_list(self):
        """Add the keychain to the user domain keychain search list."""

        log.debug(f"Adding keychain to user search list: {self.path}")

        # There is no "add" operation, only a "set" one, so we need to get the
        # existing ones so that we can set those along with our new one.

        previous_keychains = Keychain.list_keychains(domain="user")

        if self.path in previous_keychains:
            return

        command = 'security list-keychains -d user -s '

        command += shlex.quote(self.path) + ' '

        # Our new keychain needs to be at the start of the list so that it is
        # searched before the others are (otherwise they'll prompt for
        # passwords)
        for path in previous_keychains:
            command += shlex.quote(path) + ' '

        try:
            subprocess.run(
                command,
                universal_newlines=True,
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            ).stdout
        except subprocess.CalledProcessError as ex:
            log.error(f"Failed to get keychains: {ex}")
            raise

        # Validate that the new keychain is there

        new_keychains = Keychain.list_keychains(domain="user")

        for path in previous_keychains:
            if path not in new_keychains:
                raise Exception(f"Previous keychain missing when checking keychains: {path}")

        new_path_exists = False

        # /var and /private/var are the same, but we don't know which macOS is
        # going to send back, so we have to normalize out the symlinks to do
        # the comparisons
        for new_path in new_keychains:
            if os.path.realpath(new_path) == os.path.realpath(self.path):
                new_path_exists = True
                break

        if not new_path_exists:
            raise Exception(f"New keychain missing when checking keychains: {self.path}")

    def install_cert(self, certificate: Certificate):
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
        import_command = f'security import {shlex.quote(certificate.path)} -P {shlex.quote(certificate.password)} -A -t cert -f pkcs12 -k {shlex.quote(self.path)}'

        try:
            subprocess.run(
                import_command,
                shell=True,
                check=True
            )
        except subprocess.CalledProcessError as ex:
            log.error(f"Failed to get import certificate: {ex}")
            raise

        # Give everything access to the keychain so that it is actually useful
        self.set_key_partition_list(certificate)

        # Add the keychain to the search list so that we can just search across all
        # keychains
        self.add_to_user_search_list()

    @staticmethod
    def list_keychains(*, domain=None):
        """Get the list of the current keychains.

        :param str domain: The domain to list the keycahins for. If left as None, all will be searched.
        """

        log.debug("Listing the current keychains")

        command = 'security list-keychains'

        if domain is not None:
            if domain not in ["user", "system", "common", "dynamic"]:
                raise Exception(f"Invalid domain: {domain}")

            command += f' -d {shlex.quote(domain)}'

        try:
            keychains = subprocess.run(
                command,
                universal_newlines=True,
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            ).stdout
        except subprocess.CalledProcessError as ex:
            log.error(f"Failed to get keychains: {ex}")
            raise

        keychains = keychains.split("\n")

        # Cleanup the output format into a regular Python list of strings
        keychains = [keychain.strip() for keychain in keychains]
        keychains = [keychain for keychain in keychains if len(keychain) > 0]
        keychains = [keychain[1:] for keychain in keychains]
        keychains = [keychain[:-1] for keychain in keychains]

        log.debug(f"Current keychains: {keychains}")

        return keychains

    @staticmethod
    def create_temporary():
        """Create a new temporary keychain."""

        keychain_name = f"{uuid.uuid4()}.keychain"
        keychain_path = os.path.join(tempfile.gettempdir(), keychain_name)
        keychain_password = ''.join(secrets.choice(_PASSWORD_ALPHABET) for _ in range(50))

        if os.path.exists(keychain_path):
            raise Exception(f"Cannot create temporary keychain. Path already exists: {keychain_path}")

        keychain = Keychain(keychain_path, keychain_password, is_temporary=True)

        # We have a reference, but now we need to create the keychain with the
        # system.
        Keychain._create_keychain(keychain_path, keychain_password)

        log.info(f"Created temporary keychain: {keychain_path}")

        return keychain

    @staticmethod
    def default(password):
        """Get the default keychain for the current user."""

        log.debug("Getting default keychain")

        try:
            default_keychain_path = subprocess.run(
                'security default-keychain',
                universal_newlines=True,
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            ).stdout
        except subprocess.CalledProcessError:
            return None

        # The output format looks like this:
        #     "/Users/dalemy/Library/Keychains/login.keychain-db"

        # Remove whitespace
        default_keychain_path = default_keychain_path.strip()

        # Remove quotes
        default_keychain_path = default_keychain_path[1:]
        default_keychain_path = default_keychain_path[:-1]

        return Keychain(default_keychain_path, password)

    @staticmethod
    def _create_keychain(keychain_path, keychain_password, *, lock_on_sleep=True, lock_on_timeout=True, timeout=60*6):
        try:
            subprocess.run(
                f'security create-keychain -p {shlex.quote(keychain_password)} {shlex.quote(keychain_path)}',
                shell=True,
                check=True
            )
        except subprocess.CalledProcessError as ex:
            log.error(f"Failed to create keychain: {ex}")
            raise

        settings_command = 'security set-keychain-settings -'

        if lock_on_sleep:
            settings_command += 'l'

        if lock_on_timeout:
            settings_command += 'u'

        settings_command += f't {timeout} {shlex.quote(keychain_path)}'

        try:
            subprocess.run(
                settings_command,
                shell=True,
                check=True
            )
        except subprocess.CalledProcessError as ex:
            log.error(f"Failed to set keychain settings: {ex}")
            raise


class TemporaryKeychain():
    """Context object for working with a temporary keychain."""

    def __init__(self):
        self.keychain = None

    def __enter__(self):
        self.keychain = Keychain.create_temporary()
        return self.keychain

    def __exit__(self, *args):
        self.keychain.delete_temporary()
        self.keychain = None


def get_password(*, label: str = None, account: str = None, creator: str = None, type_code: str = None, kind: str = None, value: str = None, comment: str = None, service: str = None, keychain: Keychain = None) -> str:
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

    log.debug(
        "Fetching item from keychain: "
        f"{label}, {account}, {creator}, {type_code}, "
        f"{kind}, {value}, {comment}, {service}, {keychain}"
    )

    command = 'security find-generic-password'

    if label is not None:
        command += f' -l {shlex.quote(label)}'

    if account is not None:
        command += f' -a {shlex.quote(account)}'

    if creator is not None:
        command += f' -c {shlex.quote(creator)}'

    if type_code is not None:
        command += f' -C {shlex.quote(type_code)}'

    if kind is not None:
        command += f' -D {shlex.quote(kind)}'

    if value is not None:
        command += f' -G {shlex.quote(value)}'

    if comment is not None:
        command += f' -j {shlex.quote(comment)}'

    if service is not None:
        command += f' -s {shlex.quote(service)}'

    command += ' -w'

    if keychain is not None:
        command += ' ' + keychain.path

    try:
        password = subprocess.run(
            command,
            universal_newlines=True,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        ).stdout
    except subprocess.CalledProcessError:
        return None

    # It has a new line since we are running a command, so we need to drop it.
    assert password[-1] == "\n"
    password = password[:-1]

    return password
