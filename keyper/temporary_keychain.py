"""A utility for dealing with the macOS keychain."""

import logging
from types import TracebackType
from typing import Literal, Optional, Type

from .keychain import Keychain

log = logging.getLogger("keyper")  # pylint: disable=invalid-name


# pylint: disable=too-many-arguments


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
