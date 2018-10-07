import platform
from distutils.version import StrictVersion

from .keyper import Certificate, Keychain, TemporaryKeychain, get_password, create_temporary

if platform.system() != "Darwin":
    raise Exception("This tool is only supported on macOS")

if StrictVersion(platform.mac_ver()[0]) < StrictVersion("10.13.0"):
    raise Exception("This tool is only supported on macOS 10.13.0 or higher")