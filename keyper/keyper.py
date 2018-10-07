import logging
import os
import re
import secrets
import shlex
import subprocess
import tempfile
import uuid
from keyper.const import _PASSWORD_ALPHABET
from typing import List

log = logging.getLogger("mackey")


class Certificate:
    """Represents a p12 certificate."""

    def __init__(self, path: str, password: str = None):
        self.path = path
        self.password = password if password is not None else str()
        self.sha1 = self._get_p12_sha1_hash()
        self.common_name = self._get_common_name()
        self.private_key_name = self._get_private_key_name()

    def _get_value(self, value_name: str) -> str:
        log.debug(f'Getting certificate value: {value_name}')

        command = ' '.join([
            f'openssl pkcs12 -in {shlex.quote(self.path)}',
            f'-nokeys -passin pass:{shlex.quote(self.password)}',
            f'| openssl x509 -noout -{value_name}'
        ])

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
            log.error(f'Failed to get value: {ex}')
            raise

        value = value.strip()
        log.debug(f'Full value: {value}')
        return value

    def _get_common_name(self) -> str:
        log.debug("Getting certificate common name")
        subject = self._get_value("subject")
        match = re.search(r'subject=.*/CN=(.*).*/.*', subject)

        if match:
            return match.group(1)

        err_msg = f'Failed to get common name from subject: {subject}'
        log.error(err_msg)
        raise ValueError(err_msg)

    def _get_p12_sha1_hash(self) -> str:
        log.debug("Getting certificate SHA1 hash")
        fingerprint = self._get_value("fingerprint").replace("SHA1 Fingerprint=", "")
        return fingerprint

    def _get_private_key_name(self) -> str:
        log.debug("Getting certificate private key name")

        command = ' '.join(
            [
                f'openssl pkcs12 -in {shlex.quote(self.path)}',
                f'-nocerts -passin pass:{shlex.quote(self.password)}',
                f'-passout pass:{shlex.quote(self.password)} | grep "friendlyName"'
            ]
        )

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
            log.error(f'Failed to get private key name: {ex}')
            raise

        value = value.strip()
        log.debug(f'Friendly name: {value}')
        private_key_name = value.replace("friendlyName: ", "")
        return private_key_name


class Keychain:
    """Represents an actual keychain in the system."""

    def __init__(self, path: str, password: str, is_temporary: bool = False):
        log.debug(f'Creating new keychain: {path} (is_temporary={str(is_temporary)})')
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

        log.info(f'Deleting keychain: {self.path}')

        try:
            subprocess.run(
                f'security delete-keychain {shlex.quote(self.path)}',
                shell=True,
                check=True
            )
        except subprocess.CalledProcessError as ex:
            log.error(f'Failed to delete keychain: {ex}')
            raise

        if os.path.exists(self.path):
            os.remove(self.path)

    def unlock(self) -> None:
        """Unlock the keychain."""

        log.info(f'Unlocking keychain: {self.path}')

        try:
            subprocess.run(
                f'security unlock-keychain -p {shlex.quote(self.password)} {shlex.quote(self.path)}',
                shell=True,
                check=True,
            )
        except subprocess.CalledProcessError as ex:
            log.error(f'Failed to set unlock keychain: {ex}')
            raise

    def set_key_partition_list(self, certificate: Certificate) -> None:
        """Set the key partition list for the keychain.

        This avoids the prompt to enter the password when using a certificate
        via codesign for the first time.

        The logic for this is based on the answer to this SO question:
        https://stackoverflow.com/questions/39868578

        :param Certificate certificate: The certificate to use the private key name from.
        """

        log.debug(f'Setting partition list for: {certificate.private_key_name}')

        if self.is_temporary:
            log.debug("Skipping due to being temporary")
            return

        command = ' '.join(
            [
                f'security set-key-partition-list -S apple-tool:,apple: -s -l',
                f'{shlex.quote(certificate.private_key_name)} -k {shlex.quote(self.password)}',
                f'{shlex.quote(self.path)}'
            ]
        )

        try:
            subprocess.run(
                command,
                shell=True,
                check=True
            )
        except subprocess.CalledProcessError as ex:
            log.error(f'Failed to set key parition list: {ex}')
            raise

    def add_to_user_search_list(self) -> None:
        """Add the keychain to the user domain keychain search list."""

        log.debug(f'Adding keychain to user search list: {self.path}')

        # There is no "add" operation, only a "set" one, so we need to get the
        # existing ones so that we can set those along with our new one.
        previous_keychains = Keychain.list_keychains(domain="user")
        if self.path in previous_keychains:
            return

        command = f'security list-keychains -d user -s {shlex.quote(self.path)} '

        # Our new keychain needs to be at the start of the list so that it is
        # searched before the others are (otherwise they'll prompt for
        # passwords)
        for path in previous_keychains:
            command = f'{command} {shlex.quote(path)}'

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
            log.error(f'Failed to get keychains: {ex}')
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

        import_command = ' '.join(
            [
                f'security import {shlex.quote(certificate.path)}',
                f'-P {shlex.quote(certificate.password)} -A',
                f'-t cert -f pkcs12 -k {shlex.quote(self.path)}',
            ]
        )

        try:
            subprocess.run(
                import_command,
                shell=True,
                check=True
            )
        except subprocess.CalledProcessError as ex:
            log.error(f'Failed to get import certificate: {ex}')
            raise

        # Give everything access to the keychain so that it is actually useful
        self.set_key_partition_list(certificate)

        # Add the keychain to the search list so that we can just search across all
        # keychains
        self.add_to_user_search_list()

    @staticmethod
    def list_keychains(domain=None) -> List[str]:
        """Get the list of the current keychains.

        :param str domain: The domain to list the keycahins for. If left as None, all will be searched.
        """

        log.debug("Listing the current keychains")

        command = 'security list-keychains'

        if domain is not None:
            if domain not in ("user", "system", "common", "dynamic"):
                raise Exception("Invalid domain: " + domain)

            command = f'{command} -d {shlex.quote(domain)}'

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
            log.error(f'Failed to get keychains: {ex}')
            raise

        keychains = keychains.split("\n")

        # Cleanup the output format into a regular Python list of strings
        keychains = [keychain.strip() for keychain in keychains]
        keychains = [keychain for keychain in keychains if len(keychain) > 0]
        keychains = [keychain[1:] for keychain in keychains]
        keychains = [keychain[:-1] for keychain in keychains]

        log.debug(f'Current keychains: {str(keychains)}', )

        return keychains

    @staticmethod
    def _create_keychain(keychain_path: str, keychain_password: str, lock_on_sleep: bool = True,
                         lock_on_timeout: bool = True, timeout: int = 60 * 6) -> None:
        try:
            subprocess.run(
                f'security create-keychain -p {shlex.quote(keychain_password)} {shlex.quote(keychain_path)}',
                shell=True,
                check=True
            )
        except subprocess.CalledProcessError as ex:
            log.error(f'Failed to create keychain: {ex}')
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
            log.error(f'Failed to set keychain settings: {ex}')
            raise


class TemporaryKeychain:
    """Context object for working with a temporary keychain."""

    def __init__(self):
        self.keychain = None

    def __enter__(self):
        self.keychain = create_temporary()
        return self.keychain

    def __exit__(self, *args):
        self.keychain.delete_temporary()
        self.keychain = None


def create_temporary() -> Keychain:
    """Create a new temporary keychain."""

    keychain_name = str(uuid.uuid4()) + ".keychain"
    keychain_path = os.path.join(tempfile.gettempdir(), keychain_name)
    keychain_password = ''.join(secrets.choice(_PASSWORD_ALPHABET) for _ in range(50))

    if os.path.exists(keychain_path):
        raise Exception("Cannot create temporary keychain. Path already exists: " + keychain_path)

    keychain = Keychain(keychain_path, keychain_password, is_temporary=True)

    # We have a reference, but now we need to create the keychain with the
    # system.
    Keychain._create_keychain(keychain_path, keychain_password)

    log.info(f'Created temporary keychain: {keychain_path}')

    return keychain


def get_password(*, label: str = None, account: str = None, creator: str = None, type_code: str = None,
                 kind: str = None, value: str = None, comment: str = None, service: str = None,
                 keychain: Keychain = None) -> str:
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
        f'Fetching item from keychain: {label}, {account}, {creator}, {type_code},'
        f'{kind}, {value}, {comment}, {service}, {keychain}'
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
        raise

    # It has a new line since we are running a command, so we need to drop it.
    assert password[-1] == "\n"
    password = password[:-1]

    return password
