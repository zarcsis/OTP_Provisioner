#!/usr/bin/env python3
"""OTP_Provisioner launcher.

    python server.py [--config PATH] [--host H] [--port N] [--no-browser] [--no-auto-build]

Loads the configuration, starts the web server on http://127.0.0.1:8765/ (by default), prints the URL
and opens the page in Chrome (Edge on Windows when Chrome is missing). Other commands are available
through ``python -m otp_server`` (build, modules, status, login).
"""

from __future__ import annotations

import sys
from pathlib import Path

if sys.version_info < (3, 11):
    sys.exit("OTP_Provisioner needs Python 3.11 or newer")

# The repository has no .gitignore on purpose: do not leave __pycache__ directories in the tree.
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from otp_server.__main__ import main
except ImportError as exc:  # most likely the requirements are not installed
    sys.exit(f"ERROR: {exc}\nInstall the requirements first:  python -m pip install -r requirements.txt")


if __name__ == "__main__":
    args = sys.argv[1:]
    if args and args[0] == "serve":
        args = args[1:]
    if any(a in ("build", "modules", "status", "login") for a in args):
        sys.exit("server.py only runs the server; use  python -m otp_server build|modules|status|login")
    sys.exit(main(["serve", *args], prog="python server.py"))
