"""docker/gadget-helpers/otp-keyexport/otp-keyexport: the gadget side of the OTP device key export.

The script runs under busybox sh on the gadget. Here it runs under every POSIX shell found on PATH
(``sh``; also ``dash`` and ``busybox sh`` when present: they are closer to busybox ash than bash in
POSIX mode) against a fake ``rpi-fw-crypto`` placed first in PATH. The fake keeps the OTP key slot in
files under ``$FAKE_FW_STATE``:

* ``slot``           ``blank`` | ``present`` | ``locked`` (READ_LOCKED, the lock rpi-fastbootd sets)
* ``key.der``        what ``privkey`` writes (``genkey`` creates it from ``genkey.der``)
* ``fail-<command>`` when it exists, ``<command>`` prints the file to stderr and exits 1
* ``calls``          one line per invocation (its arguments)

``OTP_KEYEXPORT_DIR`` points the script at a temporary export dir, ``OTP_KEYEXPORT_MBOX`` at an existing
file (the firmware mailbox device it waits for) or, for the timeout test, a missing one with a fake
``sleep`` that returns at once.
"""
from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
PKG = REPO / "docker" / "gadget-helpers" / "otp-keyexport"
SCRIPT = PKG / "otp-keyexport"
LOCKED_MSG = "the key is READ-locked in this boot; boot the gadget again (stage 2) to export it"


def _shells() -> list[tuple[str, list[str]]]:
    """[(id, argv prefix)] of the POSIX shells that actually run here, each real executable once."""
    candidates = [("sh", ["sh"]), ("dash", ["dash"])]
    if os.name != "nt":                      # busybox-w32 is not the gadget's busybox
        candidates.append(("busybox", ["busybox", "sh"]))
    found: list[tuple[str, list[str]]] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()
    for name, argv in candidates:
        exe = shutil.which(argv[0])
        if not exe:
            continue
        key = (os.path.normcase(os.path.realpath(exe)), tuple(argv[1:]))
        if key in seen:
            continue
        try:
            r = subprocess.run([exe, *argv[1:], "-c", "echo ok"], capture_output=True, timeout=30)
            ok = r.returncode == 0 and r.stdout.strip() == b"ok"
        except (OSError, subprocess.SubprocessError):
            ok = False
        if ok:
            seen.add(key)
            found.append((name, [exe, *argv[1:]]))
    return found


SHELLS = _shells()
pytestmark = pytest.mark.skipif(not any(name == "sh" for name, _ in SHELLS),
                                reason="no runnable POSIX sh on PATH (on Windows Git Bash provides one)")

FAKE_FW_CRYPTO = r"""#!/bin/sh
# Fake rpi-fw-crypto (tests/test_keyexport_script.py): the CLI as otp-keyexport uses it.
S="${FAKE_FW_STATE:?FAKE_FW_STATE is not set}"
printf '%s\n' "$*" >> "$S/calls"
cmd="${1:-}"
[ $# -gt 0 ] && shift
slot=$(cat "$S/slot" 2>/dev/null) || slot=blank
if [ -f "$S/fail-$cmd" ]; then
    cat "$S/fail-$cmd" >&2
    exit 1
fi
out=""
pos=""
while [ $# -gt 0 ]; do
    case "$1" in
        --out) out="$2"; shift 2 ;;
        --key-id|--alg) shift 2 ;;
        *) pos="$pos $1"; shift ;;
    esac
done
case "$cmd" in
    get-key-status)
        if [ "$slot" = locked ]; then echo "key 1 status 0x00000001 READ_LOCKED"; else echo "key 1 status 0x00000000"; fi
        ;;
    pubkey)
        if [ "$slot" = blank ]; then echo "Error: key slot 1 is blank" >&2; exit 1; fi
        printf '%s\n' "-----BEGIN PUBLIC KEY-----" "ZmFrZQ==" "-----END PUBLIC KEY-----" > "$out"
        ;;
    genkey)
        if [ "$slot" != blank ]; then echo "Error: Key slot is not blank" >&2; exit 1; fi
        cat "$S/genkey.der" > "$S/key.der"
        echo present > "$S/slot"
        echo "generated an ec key in slot 1"
        ;;
    privkey)
        case "$slot" in
            blank) echo "Error: key slot 1 is blank" >&2; exit 1 ;;
            locked) echo "Error: Key is locked" >&2; exit 1 ;;
        esac
        cat "$S/key.der" > "$out"
        ;;
    set-key-status)
        case "$pos" in
            *READ_LOCKED*) echo locked > "$S/slot" ;;
        esac
        ;;
    *)
        echo "fake rpi-fw-crypto: unknown command $cmd" >&2
        exit 2
        ;;
esac
exit 0
"""

FAKE_SLEEP = """#!/bin/sh
printf '%s\\n' "$*" >> "${FAKE_FW_STATE:?}/sleeps"
"""


def _der(d_bytes: bytes) -> bytes:
    """SEC1 DER of the P-256 key with scalar ``d_bytes`` (what the server's parser takes)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.derive_private_key(int.from_bytes(d_bytes, "big"), ec.SECP256R1())
    return key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.TraditionalOpenSSL,
                             serialization.NoEncryption())


# CR, LF, NUL and ^Z inside the scalar: the export must be byte-exact
KEY_D = bytes([0x0D, 0x0A, 0x00, 0x1A]) + bytes(range(1, 29))
KEY_DER = _der(KEY_D)
GEN_D = bytes(range(0x21, 0x41))
GEN_DER = _der(GEN_D)


def posix(p: Path) -> str:
    """Path as the shell sees it (forward slashes; MSYS takes C:/... as is)."""
    return Path(p).as_posix()


def write_exec(path: Path, text: str) -> None:
    path.write_bytes(text.encode("ascii"))          # LF only, also on Windows
    path.chmod(0o755)


class Gadget:
    """The gadget's view: an OTP key slot behind the fake rpi-fw-crypto, the export dir, the mailbox."""

    def __init__(self, tmp_path: Path, shell: list[str], *, slot: str = "blank", key: bytes = KEY_DER,
                 tool: bool = True, cmdline: str = "rootwait console=tty1 root=/dev/ram0 quiet"):
        self.shell = shell
        self.cmdline = tmp_path / "cmdline"
        self.cmdline.write_bytes(cmdline.encode("ascii") + b"\n")        # /proc/cmdline: one line
        self.state = tmp_path / "fw"
        self.state.mkdir()
        self.bin = tmp_path / "bin"
        self.bin.mkdir()
        self.dir = tmp_path / "run" / "otp-keyexport"
        self.mbox = tmp_path / "dev" / "vcio_crypto"
        self.mbox.parent.mkdir()
        self.mbox.write_bytes(b"")
        write_exec(self.bin / "sleep", FAKE_SLEEP)
        if tool:
            write_exec(self.bin / "rpi-fw-crypto", FAKE_FW_CRYPTO)
        (self.state / "slot").write_bytes(slot.encode("ascii") + b"\n")
        (self.state / "genkey.der").write_bytes(GEN_DER)
        if slot != "blank":
            (self.state / "key.der").write_bytes(key)

    def fail(self, command: str, message: str) -> None:
        (self.state / f"fail-{command}").write_bytes(message.encode("ascii") + b"\n")

    def request_file(self) -> Path:
        """The station's request (fastboot "oem download-file .../request"); the path unit fires on it."""
        self.dir.mkdir(parents=True, exist_ok=True)
        req = self.dir / "request"
        req.write_bytes(b"export\n")
        return req

    def run(self, *mode: str, mailbox: bool = True) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        env["PATH"] = os.pathsep.join([str(self.bin), os.path.dirname(self.shell[0]), env.get("PATH", "")])
        env["OTP_KEYEXPORT_DIR"] = posix(self.dir)
        env["OTP_KEYEXPORT_MBOX"] = posix(self.mbox if mailbox else self.mbox.with_name("no-such-mailbox"))
        env["FAKE_FW_STATE"] = posix(self.state)
        env["OTP_KEYEXPORT_CMDLINE"] = posix(self.cmdline)
        return subprocess.run([*self.shell, posix(SCRIPT), *mode], env=env, capture_output=True, timeout=120)

    @property
    def status(self) -> str:
        raw = (self.dir / "status").read_bytes()
        assert raw.endswith(b"\n") and raw.count(b"\n") == 1 and b"\r" not in raw, raw
        return raw.decode("utf-8")[:-1]

    @property
    def calls(self) -> list[str]:
        p = self.state / "calls"
        return p.read_text(encoding="utf-8").splitlines() if p.is_file() else []

    @property
    def key(self) -> Path:
        return self.dir / "key.der"

    @property
    def slot(self) -> str:
        return (self.state / "slot").read_text(encoding="ascii").strip()

    def leftovers(self) -> list[str]:
        return sorted(p.name for p in self.dir.iterdir() if p.name.endswith(".tmp")) if self.dir.is_dir() else []

    def privkey_call(self) -> str:
        return f"privkey --key-id 1 --out {posix(self.dir)}/key.der.tmp"


STATUS_CALLS = ["get-key-status 1", "pubkey --key-id 1 --out /dev/null"]
LOCK_CALL = "set-key-status 1 READ_LOCKED"
GENKEY_CALL = "genkey --key-id 1 --alg ec"


@pytest.fixture(params=[argv for _name, argv in SHELLS], ids=[name for name, _argv in SHELLS])
def shell(request) -> list[str]:
    return request.param


def explain(r: subprocess.CompletedProcess) -> str:
    return f"rc={r.returncode}\nstdout={r.stdout.decode(errors='replace')}\nstderr={r.stderr.decode(errors='replace')}"


# ---------------------------------------------------------------------- the files themselves
def test_helper_files_are_lf_only():
    files = sorted(p for p in PKG.parent.rglob("*") if p.is_file())
    assert SCRIPT in files and len(files) >= 8
    for p in files:
        data = p.read_bytes()
        assert b"\r" not in data, f"{p.relative_to(REPO)} has CR line endings"
        assert data.endswith(b"\n"), f"{p.relative_to(REPO)} does not end with a newline"
    assert SCRIPT.read_bytes().startswith(b"#!/bin/sh\n")


# Constructs bash / ksh accept and busybox ash (or dash) rejects or reads differently.
BASHISMS = [
    (r"\[\[", "[[ ]] test"),
    (r"(?<!\$)\(\(", "(( )) arithmetic command"),
    (r"\bfunction\s+\w+", "function keyword"),
    (r"<<<", "here-string"),
    (r"&>|>&\s*[^\d\s-]", "&> redirection"),
    (r"\|&", "|& pipe"),
    (r"\$'", "$'...' quoting"),
    (r"\$\"", "$\"...\" locale quoting"),
    (r"\b\w+=\(", "array assignment"),
    (r"\$\{[#!]?\w+\[", "array expansion"),
    (r"\$\{!\w", "indirect expansion"),
    (r"\$\{\w+:(\d|\s+-)", "substring expansion"),
    (r"\$\{\w+(//?|\^\^?|,,?)", "pattern substitution / case modification"),
    (r"\[\s[^]]*\s==\s", "== inside [ ]"),
    (r"^\s*(source|declare|typeset|let|shopt|pushd|popd|disown|select)\b", "bash builtin"),
    (r"\becho\s+-[neE]+\b", "echo with options"),
    (r"\bread\s+-[a-zA-Z]*[pasnNdtu]", "read options beyond -r"),
    (r"\$(RANDOM|BASH\w*|PIPESTATUS|FUNCNAME|EPOCH\w+|SECONDS|HOSTNAME|UID|EUID)\b", "bash variable"),
    (r"\$\{(RANDOM|BASH\w*|PIPESTATUS|FUNCNAME)\b", "bash variable"),
    (r"\btrap\s+\S+\s+(ERR|DEBUG|RETURN)\b", "bash trap"),
    (r"\bset\s+-o\s+pipefail\b", "pipefail"),
]


def test_script_has_no_bashisms():
    code = []
    for n, line in enumerate(SCRIPT.read_text(encoding="ascii").splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        code.append((n, re.sub(r"\s+#.*$", "", line)))      # trailing comments
    assert code
    problems = [f"line {n}: {what}: {text.strip()}" for n, text in code for pat, what in BASHISMS
                if re.search(pat, text)]
    assert problems == []


@pytest.mark.parametrize("argv", [argv for _n, argv in SHELLS], ids=[n for n, _a in SHELLS])
def test_script_parses(argv):
    r = subprocess.run([*argv, "-n", posix(SCRIPT)], capture_output=True, timeout=60)
    assert r.returncode == 0 and r.stderr == b"", explain(r)


# ---------------------------------------------------------------------- boot
def test_boot_on_a_blank_slot_never_generates(tmp_path, shell):
    g = Gadget(tmp_path, shell, slot="blank")
    r = g.run("boot")
    assert r.returncode == 0, explain(r)
    assert g.status.startswith("blank ") and "the station generates the key on request" in g.status
    assert not g.key.exists() and g.leftovers() == []
    assert g.calls == STATUS_CALLS                         # no genkey, no privkey
    assert g.slot == "blank"


def test_boot_exports_an_existing_key(tmp_path, shell):
    from otp_server.secrets_gen import parse_device_private_key

    g = Gadget(tmp_path, shell, slot="present")
    r = g.run("boot")
    assert r.returncode == 0, explain(r)
    assert g.status == "exported key.der"
    assert g.key.read_bytes() == KEY_DER                   # byte-exact (the scalar holds CR, LF, NUL, ^Z)
    assert g.calls == [*STATUS_CALLS, g.privkey_call(), LOCK_CALL]
    assert g.slot == "locked"                              # READ-locked for the rest of the boot
    assert g.leftovers() == []
    assert parse_device_private_key(g.key.read_bytes())[0] == int.from_bytes(KEY_D, "big")   # what the server takes


def test_default_mode_is_boot(tmp_path, shell):
    g = Gadget(tmp_path, shell, slot="present")
    r = g.run()
    assert r.returncode == 0, explain(r)
    assert g.status == "exported key.der" and g.key.read_bytes() == KEY_DER
    assert GENKEY_CALL not in g.calls


def test_boot_with_a_read_locked_key(tmp_path, shell):
    g = Gadget(tmp_path, shell, slot="locked")
    r = g.run("boot")
    assert r.returncode == 0, explain(r)
    assert g.status == f"locked {LOCKED_MSG}"
    assert g.calls == STATUS_CALLS                         # privkey would only fail
    assert not g.key.exists()


def test_boot_get_key_status_failure_is_an_error(tmp_path, shell):
    g = Gadget(tmp_path, shell, slot="present")
    g.fail("get-key-status", "vcio: mailbox call failed")
    r = g.run("boot")
    assert r.returncode == 0, explain(r)
    assert g.status == "error get-key-status: vcio: mailbox call failed"
    assert g.calls == ["get-key-status 1"] and not g.key.exists()


# ---------------------------------------------------------------------- request
def test_request_on_a_blank_slot_generates_then_exports(tmp_path, shell):
    from otp_server.secrets_gen import parse_device_private_key

    g = Gadget(tmp_path, shell, slot="blank")
    req = g.request_file()
    r = g.run("request")
    assert r.returncode == 0, explain(r)
    assert not req.exists()                                # the request is consumed
    assert g.status == "exported key.der"
    assert g.calls == [*STATUS_CALLS, GENKEY_CALL, g.privkey_call(), LOCK_CALL]
    assert g.key.read_bytes() == GEN_DER
    assert parse_device_private_key(g.key.read_bytes())[0] == int.from_bytes(GEN_D, "big")
    assert g.slot == "locked" and g.leftovers() == []


def test_request_on_a_present_key_exports_without_genkey(tmp_path, shell):
    g = Gadget(tmp_path, shell, slot="present")
    req = g.request_file()
    r = g.run("request")
    assert r.returncode == 0, explain(r)
    assert not req.exists() and g.status == "exported key.der" and g.key.read_bytes() == KEY_DER
    assert g.calls == [*STATUS_CALLS, g.privkey_call(), LOCK_CALL]


def test_request_after_a_boot_export_changes_nothing(tmp_path, shell):
    g = Gadget(tmp_path, shell, slot="present")
    assert g.run("boot").returncode == 0
    calls = g.calls
    req = g.request_file()
    r = g.run("request")
    assert r.returncode == 0, explain(r)
    assert not req.exists()
    assert g.calls == calls                                # no new rpi-fw-crypto call at all
    assert g.status == "exported key.der" and g.key.read_bytes() == KEY_DER


def test_request_when_genkey_says_not_blank_still_exports(tmp_path, shell):
    # the public key cannot be derived (the slot looks blank) but the slot holds a key: never overwritten
    g = Gadget(tmp_path, shell, slot="present")
    g.fail("pubkey", "Error: cannot derive the public key")
    g.request_file()
    r = g.run("request")
    assert r.returncode == 0, explain(r)
    assert g.calls == [*STATUS_CALLS, GENKEY_CALL, g.privkey_call(), LOCK_CALL]
    assert g.status == "exported key.der" and g.key.read_bytes() == KEY_DER
    assert "not blank" in r.stdout.decode()


def test_request_genkey_failure_is_an_error(tmp_path, shell):
    g = Gadget(tmp_path, shell, slot="blank")
    g.fail("genkey", "vcio: OTP write failed")
    req = g.request_file()
    r = g.run("request")
    assert r.returncode == 1, explain(r)
    assert not req.exists()
    assert g.status == "error genkey: vcio: OTP write failed"
    assert g.calls == [*STATUS_CALLS, GENKEY_CALL] and not g.key.exists()


def test_request_on_a_read_locked_key(tmp_path, shell):
    g = Gadget(tmp_path, shell, slot="locked")
    g.request_file()
    r = g.run("request")
    assert r.returncode == 1, explain(r)
    assert g.status == f"locked {LOCKED_MSG}"
    assert g.calls == STATUS_CALLS and not g.key.exists()


def test_request_get_key_status_failure_is_an_error(tmp_path, shell):
    g = Gadget(tmp_path, shell, slot="blank")
    g.fail("get-key-status", "vcio: mailbox call failed")
    g.request_file()
    r = g.run("request")
    assert r.returncode == 1, explain(r)
    assert g.status == "error get-key-status: vcio: mailbox call failed"
    assert g.calls == ["get-key-status 1"]                 # never genkey on an unknown slot state
    assert g.slot == "blank" and not g.key.exists()


# ---------------------------------------------------------------------- privkey / set-key-status failures
@pytest.mark.parametrize("mode,rc", [("boot", 0), ("request", 1)])
def test_privkey_key_is_locked(tmp_path, shell, mode, rc):
    g = Gadget(tmp_path, shell, slot="present")
    g.fail("privkey", "Error: Key is locked")
    r = g.run(mode)
    assert r.returncode == rc, explain(r)
    assert g.status == f"locked {LOCKED_MSG}"
    assert not g.key.exists() and g.leftovers() == []
    assert LOCK_CALL not in g.calls


@pytest.mark.parametrize("mode,rc", [("boot", 0), ("request", 1)])
def test_privkey_other_failure(tmp_path, shell, mode, rc):
    g = Gadget(tmp_path, shell, slot="present")
    g.fail("privkey", "vcio: Operation not permitted")
    r = g.run(mode)
    assert r.returncode == rc, explain(r)
    assert g.status == "error privkey: vcio: Operation not permitted"
    assert not g.key.exists() and g.leftovers() == []
    assert LOCK_CALL not in g.calls


def test_privkey_writing_nothing_is_an_error(tmp_path, shell):
    g = Gadget(tmp_path, shell, slot="present", key=b"")
    r = g.run("request")
    assert r.returncode == 1, explain(r)
    assert g.status == "error privkey wrote nothing"
    assert not g.key.exists() and g.leftovers() == []


def test_a_stale_key_is_never_served_after_a_failed_export(tmp_path, shell):
    # boot: a key.der left from an earlier attempt must not survive a failing export
    g = Gadget(tmp_path, shell, slot="present")
    g.dir.mkdir(parents=True)
    g.key.write_bytes(b"stale")
    g.fail("privkey", "vcio: Operation not permitted")
    r = g.run("boot")
    assert r.returncode == 0, explain(r)
    assert g.status.startswith("error privkey:") and not g.key.exists()


def test_set_key_status_failure_still_exports(tmp_path, shell):
    g = Gadget(tmp_path, shell, slot="present")
    g.fail("set-key-status", "vcio: lock failed")
    r = g.run("boot")
    assert r.returncode == 0, explain(r)
    assert g.status == "exported key.der" and g.key.read_bytes() == KEY_DER
    assert "could not READ-lock the key" in r.stdout.decode()


# ---------------------------------------------------------------------- environment problems
@pytest.mark.parametrize("mode", ["boot", "request"])
def test_missing_rpi_fw_crypto(tmp_path, shell, mode):
    g = Gadget(tmp_path, shell, slot="present", tool=False)
    paths = os.pathsep.join([str(g.bin), os.path.dirname(shell[0]), os.environ.get("PATH", "")])
    if shutil.which("rpi-fw-crypto", path=paths):
        pytest.skip("a real rpi-fw-crypto is installed on this machine")
    if mode == "request":
        g.request_file()
    r = g.run(mode)
    assert r.returncode == 1, explain(r)
    assert g.status == "error rpi-fw-crypto is not installed in this gadget"
    assert not g.key.exists() and g.calls == []
    # the request is consumed even then: the .path unit would otherwise restart the service in a loop
    assert not (g.dir / "request").exists()


@pytest.mark.skipif(os.path.exists("/dev/vcio"), reason="this machine has a VideoCore mailbox device")
@pytest.mark.parametrize("mode", ["boot", "request"])
def test_no_firmware_mailbox(tmp_path, shell, mode):
    g = Gadget(tmp_path, shell, slot="present")
    r = g.run(mode, mailbox=False)
    assert r.returncode == 1, explain(r)
    assert g.status == "error no firmware mailbox device (/dev/vcio_crypto, /dev/vcio)"
    assert g.calls == [] and not g.key.exists()
    if "busybox" not in os.path.basename(shell[0]).lower():   # busybox may run its own sleep applet
        sleeps = (g.state / "sleeps").read_text(encoding="ascii").split()
        assert sleeps and set(sleeps) == {"1"} and len(sleeps) <= 15  # it waited, a bounded number of seconds


def test_mailbox_present_means_no_waiting(tmp_path, shell):
    g = Gadget(tmp_path, shell, slot="present")
    assert g.run("boot").returncode == 0
    assert not (g.state / "sleeps").exists()


def test_unknown_mode(tmp_path, shell):
    g = Gadget(tmp_path, shell, slot="present")
    r = g.run("export")
    assert r.returncode == 2, explain(r)
    assert b"usage: otp-keyexport boot|request" in r.stderr
    assert g.calls == [] and not (g.dir / "status").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_export_dir_and_files_are_private(tmp_path, shell):
    g = Gadget(tmp_path, shell, slot="present")
    assert g.run("boot").returncode == 0
    assert stat.S_IMODE(g.dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(g.key.stat().st_mode) == 0o600
    assert stat.S_IMODE((g.dir / "status").stat().st_mode) == 0o600


# ------------------------------------------------------------------ otp_keyexport=off (the station holds the key)
OFF = "rootwait console=tty1 root=/dev/ram0 quiet otp_keyexport=off"


def test_disabled_boot_never_reads_the_key(tmp_path, shell):
    g = Gadget(tmp_path, shell, slot="present", cmdline=OFF)
    g.dir.mkdir(parents=True)
    g.key.write_bytes(b"stale")                            # whatever an earlier boot left: gone
    r = g.run("boot")
    assert r.returncode == 0, explain(r)
    assert g.status.startswith("disabled ") and "already holds this board's device key" in g.status
    assert not g.key.exists() and g.calls == [] and g.slot == "present"


def test_disabled_request_neither_generates_nor_exports(tmp_path, shell):
    g = Gadget(tmp_path, shell, slot="blank", cmdline=OFF)
    req = g.request_file()
    r = g.run("request")
    assert r.returncode == 1 and not req.exists()          # the request is consumed: no path-unit loop
    assert g.status.startswith("disabled ") and g.calls == [] and g.slot == "blank" and not g.key.exists()


@pytest.mark.parametrize("cmdline", ["quiet otp_keyexport=offx", "quiet xotp_keyexport=off", "quiet otp_keyexport=on"])
def test_only_the_exact_word_disables(tmp_path, shell, cmdline):
    g = Gadget(tmp_path, shell, slot="present", cmdline=cmdline)
    r = g.run("boot")
    assert r.returncode == 0, explain(r)
    assert g.status == "exported key.der" and g.key.read_bytes() == KEY_DER


def test_disabled_as_the_first_or_only_word(tmp_path, shell):
    g = Gadget(tmp_path, shell, slot="present", cmdline="otp_keyexport=off")
    assert g.run("boot").returncode == 0 and g.status.startswith("disabled ") and g.calls == []
