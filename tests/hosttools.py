"""The host's shell tools, for the tests that run the station's shell code outside its Debian containers.

That code is written for Debian trixie (GNU coreutils and sed, bash 5). Windows has them in Git's usr/bin, Linux
has them anyway; macOS ships BSD stat and sed and bash 3.2 in /bin. A test that needs one of them skips with the
reason (and how to get it) instead of failing on the host's dialect.
"""
from __future__ import annotations

import functools
import shutil
import subprocess
from pathlib import Path

#: Where Homebrew puts bash (Apple Silicon, Intel): macOS's own /bin/bash is 3.2.
EXTRA_BASH = ("/opt/homebrew/bin/bash", "/usr/local/bin/bash")


@functools.lru_cache(maxsize=None)
def bash4() -> str | None:
    """The first bash on PATH (then Homebrew's) whose major version is at least 4 (``mapfile``, ``declare -A``)."""
    for cand in (shutil.which("bash"), *EXTRA_BASH):
        if not cand or not Path(cand).is_file() or cand.lower().endswith(r"system32\bash.exe"):
            continue
        try:
            r = subprocess.run([cand, "-c", 'echo "${BASH_VERSINFO[0]}"'], capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            continue
        if r.returncode == 0 and r.stdout.strip().isdigit() and int(r.stdout.strip()) >= 4:
            return cand
    return None


@functools.lru_cache(maxsize=None)
def is_gnu(tool: str, shell: str | None = None) -> bool:
    """``tool`` is the GNU one (``--version`` says so): BSD stat and sed take other options. With ``shell``, the
    ``tool`` that shell finds (Git for Windows' bash puts its own usr/bin first, whatever this process's PATH)."""
    argv = [shell, "-c", f"{tool} --version"] if shell else [shutil.which(tool) or tool, "--version"]
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0 and "GNU" in r.stdout


GNU_HINT = "macOS: brew install coreutils gnu-sed and put their gnubin directories first on PATH"
BASH_HINT = "no bash >= 4 (macOS: brew install bash)"
