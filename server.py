#!/usr/bin/env python3
"""OTP_Provisioner launcher.

    uv run server.py [--host H] [--port N] [--browser EXE] [--no-browser] [--no-auto-build] [--work DIR]

Starts the web server on http://127.0.0.1:8765/ (by default), prints the URL and opens the page in
Chrome (Edge on Windows when Chrome is missing). There is no config file: sign in to Google on the
page; the settings and the board registry live in the station spreadsheet. Other commands are available
through ``uv run -m otp_server`` (login, build, modules, status).
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
except ImportError as exc:  # most likely a Python without the locked packages, not the one uv manages
    sys.exit(f"ERROR: {exc}\nStart the server with uv, which installs them into .venv:  uv run server.py")


if __name__ == "__main__":
    args = sys.argv[1:]
    if args and args[0] == "serve":
        args = args[1:]
    if any(a in ("build", "modules", "status", "login") for a in args):
        sys.exit("server.py only runs the server; use  uv run -m otp_server build|modules|status|login")
    sys.exit(main(["serve", *args], prog="uv run server.py"))
