# keyper 

[![PyPi Version](https://img.shields.io/pypi/v/keyper.svg)](https://pypi.org/project/keyper/)
[![License](https://img.shields.io/pypi/l/keyper.svg)](https://github.com/Microsoft/keyper/blob/master/LICENSE)

A Python 3 library for dealing with the macOS Keychain

### Installation

    pip install keyper

### Examples:
```python
import keyper

# Get a password from the keychain
password = keyper.get_password(label="my_keychain_password")

# Create a temporary keychain and install the certificate:

with keyper.TemporaryKeychain() as keychain:
    certificate = keyper.Certificate("/path/to/cert", password="password")
    keychain.install_cert(certificate)
    # Use codesign or similar here
```
    


# Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
