"""Stage 1: rpiboot directory that flashes the EEPROM (and, signed, burns the key hash into OTP).

Files served: ``bootcode5.bin`` (rpi-eeprom recovery.bin, counter-signed when the board is already
locked to our key), ``pieeprom.bin`` + ``pieeprom.sig`` (newest pieeprom of the firmware channel with
our boot.conf applied, signed with the board key in signed mode) and ``config.txt``. The binaries are
produced by ``docker/scripts/stage1.sh`` in the tools image.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..docker import Mount
from ..secrets_gen import customer_key_hash
from .common import (NotReady, StageFile, TempKeys, commit_partial, content_hash, file_url, fingerprint,
                     fresh_partial, is_complete, read_json, require_quick_build, sha256_file, write_text)

PIEEPROM_SIZE = 2 * 1024 * 1024
_PIEEPROM_RE = re.compile(r"^pieeprom-(\d{4}-\d{2}-\d{2})\.bin$")
OUTPUTS = ("bootcode5.bin", "pieeprom.bin", "pieeprom.sig", "config.txt")

WHY_PUBKEY = ("burns sha256 of this board's public key into OTP: the SoC will only run firmware signed with "
              "this key, forever")
WHY_JTAG = "permanently disables VideoCore JTAG"


def _mismatch(stored: str, computed: str) -> str:
    return (f"the board record's customer_key_hash {stored or '(empty)'} does not match its RSA key "
            f"(sha256 of the key blob is {computed}); signing with this key would lock or boot the board "
            "against a hash the server does not expect - fix the record in storage first")


@dataclass
class Stage1Plan:
    signed: bool
    program_pubkey: bool
    jtag_lock: bool
    sign_recovery: bool
    channel: str
    pieeprom: Path
    recovery: Path
    boot_conf: str
    config_txt: str
    customer_key_hash: str
    fp: str = ""
    dir: Path = field(default_factory=Path)
    # customer_key_hash was computed from the record's own PEM (signed plans); when False, ensure()
    # checks it against the key from secrets_fn before anything is served.
    key_checked: bool = False
    warnings: list[str] = field(default_factory=list)

    @property
    def mode(self) -> str:
        return "signed" if self.signed else "unsigned"


def config_txt(program_pubkey: bool, jtag_lock: bool) -> str:
    """Stage-1 config.txt (SPEC §10.2 order)."""
    lines = ["uart_2ndstage=1", "set_reboot_order=0x3", "recovery_reboot=1"]
    if program_pubkey:
        lines.append("program_pubkey=1")
    if jtag_lock:
        lines.append("program_jtag_lock=1")
    return "\n".join(lines) + "\n"


_SECTION_RE = re.compile(r"^\s*\[([^\]]*)\]")


def _key_occurrences(lines: list[str], key: str) -> list[tuple[int, str, str, str]]:
    """``(line index, section, key as spelled, value)`` of every assignment of ``key`` (any case).

    Text before the first ``[section]`` header belongs to the implicit ``[all]`` section, as in the
    bootloader's own parser; section names are compared in lower case.
    """
    pat = re.compile(rf"^\s*({re.escape(key)})\s*=(.*)$", re.IGNORECASE)
    section = "all"
    out = []
    for i, ln in enumerate(lines):
        m = _SECTION_RE.match(ln)
        if m:
            section = m.group(1).strip().lower()
            continue
        m = pat.match(ln)
        if m:
            out.append((i, section, m.group(1), m.group(2).strip()))
    return out


def signed_boot_conf(boot_conf: str) -> str:
    """boot.conf for a signed EEPROM: ensure ``ENABLE_SELF_UPDATE=0`` and ``SIGNED_BOOT=1`` under ``[all]``.

    A key counts as set only when every assignment of it sits in an ``[all]`` section (or before the
    first header) with exactly the wanted value; one under a model filter such as ``[cm5]`` does not
    apply to every board. Otherwise every assignment of the key, in any section, is removed and the
    wanted value is appended under a trailing ``[all]``, which is the last word for every model
    (``rpi-sb-provisioner``'s ``enforceSecureBootloaderConfig`` does the same without the sections).
    """
    lines = boot_conf.replace("\r\n", "\n").split("\n")
    missing: list[str] = []
    for key, value in (("ENABLE_SELF_UPDATE", "0"), ("SIGNED_BOOT", "1")):
        occ = _key_occurrences(lines, key)
        if occ and all(sec == "all" and spelled == key and val == value for _i, sec, spelled, val in occ):
            continue
        drop = {i for i, *_rest in occ}
        lines = [ln for i, ln in enumerate(lines) if i not in drop]
        missing.append(f"{key}={value}")
    out = "\n".join(lines).rstrip("\n") + "\n"
    if missing:
        out += "[all]\n" + "\n".join(missing) + "\n"
    return out


def unsigned_boot_conf(boot_conf: str) -> tuple[str, list[str]]:
    """boot.conf for an unsigned EEPROM and the lines removed from it.

    ``SIGNED_BOOT`` set to anything but ``0`` (in any section) is removed: an unsigned EEPROM has no
    embedded public key and no ``bootconf.sig``, so it must never ask the bootloader for signed boot.
    """
    lines = boot_conf.replace("\r\n", "\n").split("\n")
    drop = {i for i, _sec, _k, val in _key_occurrences(lines, "SIGNED_BOOT") if val != "0"}
    removed = [lines[i].strip() for i in sorted(drop)]
    kept = [ln for i, ln in enumerate(lines) if i not in drop]
    return "\n".join(kept), removed


def newest_pieeprom(channel_dir: Path) -> Path | None:
    best: tuple[str, Path] | None = None
    if not channel_dir.is_dir():
        return None
    for p in channel_dir.iterdir():
        m = _PIEEPROM_RE.match(p.name)
        if m and p.is_file() and p.stat().st_size == PIEEPROM_SIZE:
            if best is None or m.group(1) > best[0]:
                best = (m.group(1), p)
    return best[1] if best else None


class Stage1Builder:
    """Plans, builds (through the jobs queue) and describes stage-1 directories."""

    def __init__(self, cfg: Any, docker: Any, jobs: Any, tools: Any, hashes: Any):
        self.cfg = cfg
        self.docker = docker
        self.jobs = jobs
        self.tools = tools
        self.hashes = hashes

    def channel_dir(self, channel: str) -> Path:
        return Path(self.cfg.repo_root) / "external" / "usbboot" / "rpi-eeprom" / "firmware-2712" / channel

    def _eeprom_tools_hash(self) -> str:
        """Content hash of the rpi-eeprom / usbboot tools stage1.sh runs (they shape the EEPROM image)."""
        ext = Path(self.cfg.repo_root) / "external" / "usbboot"
        eeprom = ext / "rpi-eeprom"
        return content_hash([eeprom / "rpi-eeprom-config", eeprom / "rpi-eeprom-digest",
                             eeprom / "tools" / "rpi-sign-bootcode", ext / "tools" / "update-pieeprom.sh"])

    @staticmethod
    def _key_hash(record: dict) -> tuple[str, bool]:
        """``(customer_key_hash, computed_from_the_key)`` for a signed plan.

        The hash is recomputed from the record's PEM (the key stage1.sh will be given); a record whose
        stored ``customer_key_hash`` disagrees is refused, because that stored value is what the page is
        told to expect from OTP and what later decides whether the board counts as locked to our key.
        Without a PEM in the record the stored value is returned unchecked (ensure() checks it).
        """
        stored = str(record.get("customer_key_hash") or "").strip().lower()
        pem = str(record.get("rsa_public_pem") or record.get("rsa_private_pem") or "")
        if not pem:
            return stored, False
        try:
            computed = customer_key_hash(pem)
        except ValueError as exc:
            raise NotReady(f"the board's RSA key is unusable ({exc}); fix the record in storage") from None
        if stored and stored != computed:
            raise NotReady(_mismatch(stored, computed))
        return computed, bool(stored)

    def plan(self, record: dict, *, locked_to_ours: bool, secure: bool) -> Stage1Plan:
        """Decide mode and inputs for a board (see SPEC §10 signing rules); ``secure`` = the board's scenario."""
        prov = self.cfg.provisioning
        channel = prov.firmware_channel
        cdir = self.channel_dir(channel)
        pie = newest_pieeprom(cdir)
        rec = cdir / "recovery.bin"
        if pie is None or not rec.is_file():
            raise NotReady(f"rpi-eeprom firmware-2712/{channel} has no pieeprom-*.bin / recovery.bin "
                           f"(is the external/usbboot submodule checked out with rpi-eeprom?)")
        secure = bool(secure)
        signed = secure or locked_to_ours
        program_pubkey = secure and not locked_to_ours
        jtag = bool(prov.jtag_lock) and secure
        sign_recovery = locked_to_ours
        khash, key_checked = self._key_hash(record) if signed else ("", False)
        warnings: list[str] = []
        if signed:
            boot_conf = signed_boot_conf(prov.boot_conf)
        else:
            boot_conf, removed = unsigned_boot_conf(prov.boot_conf)
            if removed:
                warnings.append(f"provisioning.boot_conf sets {', '.join(removed)}, but this EEPROM is unsigned "
                                "(no customer key): the line was removed; SIGNED_BOOT belongs to the secure scenario")
        if prov.jtag_lock and not secure:
            warnings.append("provisioning.jtag_lock only applies to the secure scenario")
        cfgtxt = config_txt(program_pubkey, jtag)
        plan = Stage1Plan(signed=signed, program_pubkey=program_pubkey, jtag_lock=jtag,
                          sign_recovery=sign_recovery, channel=channel, pieeprom=pie, recovery=rec,
                          boot_conf=boot_conf, config_txt=cfgtxt, customer_key_hash=khash,
                          key_checked=key_checked, warnings=warnings)
        plan.fp = fingerprint("stage1", plan.mode, channel, pie.name, self.hashes.sha256(pie),
                              self.hashes.sha256(rec), self._eeprom_tools_hash(),
                              boot_conf, cfgtxt, sign_recovery, khash if signed else None,
                              self.tools.hash(), self.tools.script_hash("stage1.sh"))
        work = Path(self.cfg.work_dir)
        serial = str(record.get("serial") or "")
        if signed:
            plan.dir = work / "modules" / serial / "stage1" / plan.fp
        else:
            plan.dir = work / "artifacts" / "stage1" / plan.fp
        return plan

    def complete(self, plan: Stage1Plan) -> bool:
        if not (is_complete(plan.dir) and all((plan.dir / n).is_file() for n in OUTPUTS)):
            return False
        if plan.signed:
            # the key the EEPROM was really signed with (stage1.sh records it) must be the expected one
            try:
                info = read_json(plan.dir / "build-info.json")
            except (OSError, ValueError):
                return False
            return isinstance(info, dict) and info.get("customer_key_hash") == plan.customer_key_hash
        return True

    @staticmethod
    def check_key(plan: Stage1Plan, secrets: dict | None) -> None:
        """Refuse (NotReady) unless the public key that will be mounted hashes to the plan's key hash."""
        pub = str((secrets or {}).get("rsa_public_pem") or "")
        if not pub or not (secrets or {}).get("rsa_private_pem"):
            raise NotReady("signed stage 1 needs the board's RSA key, but the record has none")
        try:
            computed = customer_key_hash(pub)
        except ValueError as exc:
            raise NotReady(f"the board's RSA public key is unusable ({exc}); fix the record in storage") from None
        stored = str((secrets or {}).get("customer_key_hash") or "").strip().lower()
        if not plan.customer_key_hash:
            raise NotReady("the board's key was only just created; request stage 1 again")
        if computed != plan.customer_key_hash or (stored and stored != computed):
            raise NotReady(_mismatch(stored or plan.customer_key_hash, computed))

    def build(self, job: Any, plan: Stage1Plan, secrets: dict | None) -> None:
        """Job body: write boot.conf/config.txt, run stage1.sh, verify, mark complete."""
        if self.complete(plan):
            job.log(f"==> stage-1 dir already complete: {plan.dir}")
            return
        if plan.signed:
            self.check_key(plan, secrets)
        self.tools.ensure(job.log)
        part = fresh_partial(plan.dir)
        write_text(part / "boot.conf", plan.boot_conf)
        write_text(part / "config.txt", plan.config_txt)
        env = {"MODE": plan.mode, "CHANNEL": plan.channel, "SIGN_RECOVERY": "1" if plan.sign_recovery else "0"}
        mounts = [Mount.bind(part, "/out")]
        job.log(f"==> stage 1 ({plan.mode}, channel {plan.channel}, {plan.pieeprom.name}) -> {plan.dir}")
        for w in plan.warnings:
            job.log(f"WARNING: {w}")
        if plan.signed:
            # stage1.sh dies unless public.pem and the key embedded in pieeprom.bin hash to this value
            env["EXPECT_CKH"] = plan.customer_key_hash
            with TempKeys(self.cfg.work_dir, secrets["rsa_private_pem"], secrets["rsa_public_pem"]) as kdir:
                self.tools.run_script("stage1.sh", mounts=[*mounts, Mount.bind(kdir, "/keys", readonly=True)],
                                      env=env, log=job.log)
        else:
            self.tools.run_script("stage1.sh", mounts=mounts, env=env, log=job.log)
        self._verify(part, plan)
        info = read_json(part / "build-info.json")
        commit_partial(part, plan.dir, {"stage": 1, "mode": plan.mode, "fp": plan.fp, "build_info": info})
        job.log(f"==> stage-1 dir ready: {plan.dir}")

    @staticmethod
    def _verify(part: Path, plan: Stage1Plan) -> None:
        for n in ("bootcode5.bin", "pieeprom.bin", "pieeprom.sig", "build-info.json"):
            p = part / n
            if not p.is_file() or p.stat().st_size == 0:
                raise RuntimeError(f"stage1.sh did not produce {n}")
        if (part / "pieeprom.bin").stat().st_size != PIEEPROM_SIZE:
            raise RuntimeError(f"pieeprom.bin has {(part / 'pieeprom.bin').stat().st_size} bytes, "
                               f"expected {PIEEPROM_SIZE}")
        if (part / "config.txt").read_text(encoding="utf-8") != plan.config_txt:
            raise RuntimeError("stage1.sh modified config.txt")
        # pieeprom.sig is sha256 + ts only, in both modes: the signed EEPROM carries its signature
        # inside the image (bootconf.sig + pubkey), which stage1.sh self-checks.
        sig = (part / "pieeprom.sig").read_text(encoding="ascii", errors="replace")
        first = sig.splitlines()[0].strip() if sig else ""
        if not re.fullmatch(r"[0-9a-f]{64}", first):
            raise RuntimeError("pieeprom.sig does not start with a sha256 line")
        if first != sha256_file(part / "pieeprom.bin"):
            raise RuntimeError("pieeprom.sig does not match pieeprom.bin")
        try:
            info = read_json(part / "build-info.json")
        except (OSError, ValueError) as exc:
            raise RuntimeError(f"stage1.sh wrote an unreadable build-info.json ({exc})") from None
        if not isinstance(info, dict) or info.get("mode") != plan.mode:
            raise RuntimeError(f"build-info.json mode is {info.get('mode') if isinstance(info, dict) else None!r}, "
                               f"expected {plan.mode!r}")
        want = plan.customer_key_hash if plan.signed else None
        if info.get("customer_key_hash") != want:
            raise RuntimeError(f"build-info.json customer_key_hash is {info.get('customer_key_hash')!r}, "
                               f"expected {want!r}: the EEPROM was not built with the board's key")

    def ensure(self, plan: Stage1Plan, serial: str, secrets_fn) -> None:
        """Make the plan's directory complete (quick build via jobs.run_sync, ≤ 5 min).

        A signed plan is checked against the key (NotReady on a mismatch) before anything is served,
        also when its directory is already complete.
        """
        secrets = None
        if plan.signed and not plan.key_checked:
            secrets = secrets_fn()
            self.check_key(plan, secrets)
        if self.complete(plan):
            return
        self.tools.require(self.jobs)
        if plan.signed:
            target, title = f"stage1:{serial}", f"Stage 1 files for {serial} (signed)"
            if secrets is None:
                secrets = secrets_fn()
            self.check_key(plan, secrets)
        else:
            target, title = "stage1", "Stage 1 files (unsigned)"
        require_quick_build(self.jobs, target, title, lambda job: self.build(job, plan, secrets),
                            lambda: self.complete(plan), "stage 1 files")

    def files(self, plan: Stage1Plan) -> list[StageFile]:
        rel = f"rpi-eeprom firmware-2712/{plan.channel}"
        rec_origin = f"{rel}/recovery.bin" + (" (counter-signed with the board key)" if plan.sign_recovery else "")
        pie_origin = f"{rel}/{plan.pieeprom.name} + boot.conf" + (" (signed)" if plan.signed else "")
        return [
            self.hashes.stage_file("bootcode5.bin", plan.dir / "bootcode5.bin", rec_origin),
            self.hashes.stage_file("pieeprom.bin", plan.dir / "pieeprom.bin", pie_origin),
            self.hashes.stage_file("pieeprom.sig", plan.dir / "pieeprom.sig",
                                   "rpi-eeprom-digest" + (" -k <board key>" if plan.signed else "")),
            self.hashes.stage_file("config.txt", plan.dir / "config.txt", "generated"),
        ]

    def manifest(self, plan: Stage1Plan, record: dict, files: list[StageFile], base_url: str,
                 assumed_lock: str = "") -> dict:
        serial = str(record.get("serial") or "")
        irreversible = []
        if plan.program_pubkey:
            irreversible.append({"key": "program_pubkey", "value": "1", "why": WHY_PUBKEY})
        if plan.jtag_lock:
            irreversible.append({"key": "program_jtag_lock", "value": "1", "why": WHY_JTAG})
        notes = []
        if not plan.signed:
            notes.append("unsigned EEPROM update; OTP is not changed in this stage")
        elif plan.program_pubkey:
            notes.append("signed EEPROM; program_pubkey=1 locks this board to its key (IRREVERSIBLE)")
        elif assumed_lock:
            notes.append(f"the board's OTP probably holds our key hash already ({assumed_lock}): signed EEPROM and "
                         "counter-signed recovery; if the boot ROM refuses it, the next run sends the plain one")
        else:
            notes.append("board OTP is already locked to our key: signed EEPROM and counter-signed recovery")
        notes.extend(plan.warnings)
        return {
            "stage": 1,
            "kind": "rpiboot",
            "title": "EEPROM & OTP",
            "ready": True,
            "mode": plan.mode,
            # which second stage bootcode5.bin is (the page reports it back when the boot ROM refuses it)
            "recovery": "countersigned" if plan.sign_recovery else "plain",
            "files": [f.to_dict(file_url(base_url, serial, 1, f.name)) for f in files],
            "config_txt": plan.config_txt,
            "irreversible": irreversible,
            "expect": {"secure_boot_provision": plan.program_pubkey,
                       "customer_key_hash": plan.customer_key_hash if plan.program_pubkey else None},
            "notes": notes,
            "source": {"channel": plan.channel, "pieeprom": plan.pieeprom.name},
        }
