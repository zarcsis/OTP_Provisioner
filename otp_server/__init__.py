"""OTP_Provisioner server: provisions Raspberry Pi 5 boards over WebUSB from a local web page.

The package is split into small modules:

* :mod:`otp_server.config`      -- YAML configuration (``load_config``)
* :mod:`otp_server.secrets_gen` -- per-board secrets (RSA boot key, device secret, LUKS passphrases)
* :mod:`otp_server.storage`     -- module registry backends (local JSON, Google Sheets, Google Drive)
* :mod:`otp_server.modules`     -- ``ModuleService``: board lifecycle on top of a store

Importing the package itself is cheap: no third-party library is imported here.
"""

from __future__ import annotations

__version__ = "0.2.0"

__all__ = ["__version__"]
