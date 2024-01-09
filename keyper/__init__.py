#!/usr/bin/env python3

"""A utility for dealing with the macOS keychain."""

import platform

from .certificate import Certificate
from .keychain import Keychain, get_password, set_password, delete_password
from .temporary_keychain import TemporaryKeychain
from .exceptions import KeyperException


if platform.system() != "Darwin":
    raise KeyperException("This tool is only supported on macOS")

if tuple(map(int, platform.mac_ver()[0].split("."))) < (10, 13):
    raise KeyperException("This tool is only supported on macOS 10.13.0 or higher")
