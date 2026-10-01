"""Server configuration (SPEC section 4). There is no configuration file.

Two sources, merged over :data:`DEFAULTS`:

* **Settings** -- everything under ``provisioning``, ``builds``, ``docker`` and ``paths.droneos`` -- live in
  the ``settings`` worksheet of the station spreadsheet (:mod:`otp_server.settings`); the server reads them
  after the operator has signed in to Google and re-reads them while it runs, so a change in the sheet
  needs no restart.
* **Bootstrap** -- what the server needs before anyone has signed in: ``server.*`` (listen address,
  browser) and ``paths.work`` -- come from the command line, the environment (``OTP_WORK_DIR``,
  ``OTP_PORT``) and the defaults.

:func:`load_config` merges defaults, ``settings`` (a nested dict, as decoded from the sheet), the
environment and finally ``overrides`` (CLI flags, tests). Retired keys are dropped with a warning:
``provisioning.secure_boot``/``mode`` (the scenario is chosen per board; see
``provisioning.default_mode``), ``storage.*`` (Google Sheets is the only store, configured by signing in)
and ``builds.gadget.source`` (the gadget is always built here).

Relative paths are resolved against the repository root; ``builds.image.config`` is resolved against the
droneos checkout (see :attr:`ImageBuildCfg.config`). ``~`` and environment variables are expanded.
"""

from __future__ import annotations

import copy
import logging
import os
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping

from . import __version__

log = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent

FIRMWARE_CHANNELS = ("default", "latest")
#: Provisioning scenarios, chosen per board on the page (both are always available):
#: ``open`` = unsigned bootloader + clear image, OTP untouched;
#: ``secure`` = signed bootloader (program_pubkey) + LUKS-encrypted image + OTP device key export.
PROVISIONING_MODES = ("open", "secure")
#: rpi-image-gen provisioning map of the image each scenario flashes (``IGconf_image_pmap``).
IMAGE_PMAP = {"open": "clear", "secure": "crypt"}

DEFAULT_BOOT_CONF = "[all]\nBOOT_UART=1\nPOWER_OFF_ON_HALT=1\nBOOT_ORDER=0xf2461\n"

#: The complete default configuration tree (the YAML schema).
DEFAULTS: dict[str, Any] = {
    "server": {"host": "127.0.0.1", "port": 8765, "open_browser": True, "browser": None},
    "paths": {"work": None, "droneos": "external/droneos"},
    "provisioning": {
        "default_mode": "open",
        "jtag_lock": False,
        "recovery_passphrase": False,
        "confirm_irreversible": True,
        "erase_storage": True,
        "firmware_channel": "default",
        "max_piece_size": 268435456,
        "boot_conf": DEFAULT_BOOT_CONF,
    },
    "builds": {
        "auto": True,
        "tools": {"image_tag": "otp-tools:latest"},
        "gadget": {
            "targets": "pi5-family",
            "image_tag": "otp-gadget-builder:trixie",
            "volume": "otp-pgm-work",
        },
        "image": {
            "config": "droneos.yaml",
            "overrides": [],
            "builder_tag": "droneos-builder:trixie",
            "volume": "otp-droneos-work",
            "keep_raw_image": False,
        },
    },
    "docker": {"binary": "docker", "start_desktop": True, "desktop_path": None, "idle_timeout": 1800},
}


# --------------------------------------------------------------------------------------------------
# Dataclasses (other modules rely on exactly these names)
# --------------------------------------------------------------------------------------------------


@dataclass
class ServerCfg:
    host: str
    port: int
    open_browser: bool
    #: Browser executable to open the page in (Chrome/Edge); None = the standard install locations.
    browser: Path | None = None


@dataclass
class ProvisioningCfg:
    """``default_mode`` is the scenario the page preselects (:data:`PROVISIONING_MODES`); the operator
    picks the scenario per board. ``jtag_lock`` and ``recovery_passphrase`` only apply to ``secure``."""

    default_mode: str
    jtag_lock: bool
    recovery_passphrase: bool
    confirm_irreversible: bool
    erase_storage: bool
    firmware_channel: str
    max_piece_size: int
    boot_conf: str


@dataclass
class GadgetBuildCfg:
    targets: str
    image_tag: str
    volume: str


@dataclass
class ImageBuildCfg:
    """droneos image build settings.

    ``config`` is the rpi-image-gen config file. When it lies inside the droneos checkout it is kept
    *relative to the checkout* in POSIX form (e.g. ``"droneos.yaml"`` or ``"configs/x.yaml"``), so
    both ``cfg.droneos_dir / config`` and ``"/src/" + config`` work. When it lies outside the checkout
    it is an absolute path string. :attr:`Config.image_config_path` always gives the absolute path.
    """

    config: str
    overrides: list[str]
    builder_tag: str
    volume: str
    keep_raw_image: bool


@dataclass
class ToolsBuildCfg:
    image_tag: str


@dataclass
class BuildsCfg:
    auto: bool
    tools: ToolsBuildCfg
    gadget: GadgetBuildCfg
    image: ImageBuildCfg


@dataclass
class DockerCfg:
    binary: str
    start_desktop: bool
    desktop_path: Path | None
    idle_timeout: int = 1800   # seconds without output before a streamed docker build/run is stopped; 0 = off


@dataclass
class Config:
    """The resolved server configuration. All paths are absolute."""

    repo_root: Path
    work_dir: Path
    droneos_dir: Path
    server: ServerCfg
    provisioning: ProvisioningCfg
    builds: BuildsCfg
    docker: DockerCfg
    #: Keys found in the settings/overrides that the schema does not know (typos); reported, not fatal.
    unknown_keys: list[str] = field(default_factory=list)
    #: The command-line overrides this config was loaded with (they stay on top of the sheet settings).
    bootstrap: dict = field(default_factory=dict)

    def apply_settings(self, other: "Config") -> None:
        """Take over the sheet-backed parts of ``other`` in place (the services keep this object)."""
        self.droneos_dir = other.droneos_dir
        self.provisioning = other.provisioning
        self.builds = other.builds
        self.docker = other.docker
        self.unknown_keys = list(other.unknown_keys)

    @property
    def external_dir(self) -> Path:
        """``<repo>/external`` (the usbboot / pi-gen-micro / droneos submodules)."""
        return self.repo_root / "external"

    @property
    def web_dir(self) -> Path:
        """Directory holding ``index.html``, ``css/`` and ``js/`` (the repository root)."""
        return self.repo_root

    @property
    def image_config_path(self) -> Path:
        """Absolute path of the droneos image config (``builds.image.config``)."""
        p = Path(self.builds.image.config)
        return p if p.is_absolute() else (self.droneos_dir / p)

    def ensure_dirs(self) -> None:
        """Create the runtime directory tree under ``work_dir`` (idempotent)."""
        dirs = [
            self.work_dir,
            self.work_dir / "google",
            self.work_dir / "modules",
            self.work_dir / "artifacts",
            self.work_dir / "artifacts" / "stage1",
            self.work_dir / "artifacts" / "stage2",
            self.work_dir / "artifacts" / "gadget",
            self.work_dir / "artifacts" / "image",
            self.work_dir / "artifacts" / "image" / "staging",
            self.work_dir / "jobs",
            self.work_dir / "tmp",
        ]
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)

    def summary(self) -> dict:
        """JSON-safe overview for ``/api/status``.

        Contains paths (including credential/token file paths) but never the content of any
        credential file or any per-board secret.
        """

        return {
            "version": __version__,
            "repo_root": str(self.repo_root),
            "work_dir": str(self.work_dir),
            "droneos_dir": str(self.droneos_dir),
            "settings": "Google Sheets (worksheet settings)",
            "server": {**asdict(self.server), "browser": _pstr(self.server.browser)},
            "provisioning": {**asdict(self.provisioning), "modes": list(PROVISIONING_MODES)},
            "builds": {
                "auto": self.builds.auto,
                "tools": asdict(self.builds.tools),
                "gadget": asdict(self.builds.gadget),
                "image": {**asdict(self.builds.image), "config_path": str(self.image_config_path)},
            },
            "docker": {
                "binary": self.docker.binary,
                "start_desktop": self.docker.start_desktop,
                "desktop_path": _pstr(self.docker.desktop_path),
                "idle_timeout": self.docker.idle_timeout,
            },
            "unknown_keys": list(self.unknown_keys),
        }


# --------------------------------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------------------------------


def default_work_dir() -> Path:
    """Platform default for ``work_dir`` (ignores ``OTP_WORK_DIR`` and the config file).

    Windows: ``%LOCALAPPDATA%\\OTP_Provisioner``; elsewhere ``$XDG_DATA_HOME/otp-provisioner`` or
    ``~/.local/share/otp-provisioner``.
    """
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA")
        root = Path(base) if base else Path.home() / "AppData" / "Local"
        return root / "OTP_Provisioner"
    xdg = os.environ.get("XDG_DATA_HOME")
    root = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return root / "otp-provisioner"


def load_config(
    *,
    overrides: dict | None = None,
    repo_root: Path | None = None,
    settings: dict | None = None,
) -> Config:
    """Merge and validate the configuration.

    :param overrides: nested dict merged last (CLI flags, tests), e.g. ``{"server": {"port": 9000}}``.
    :param repo_root: repository root (default: the directory containing ``otp_server``).
    :param settings: nested dict of the sheet-backed settings (values may be text, as read from cells).
    :raises ValueError: an invalid value (enum, type).
    """
    root = Path(repo_root).resolve() if repo_root is not None else REPO_ROOT

    env_tree: dict[str, Any] = {}
    env_work = os.environ.get("OTP_WORK_DIR")
    if env_work:
        # Relative env paths are relative to the current directory, not the repo root.
        env_tree.setdefault("paths", {})["work"] = str(Path(_expand(env_work)).resolve())
    env_port = os.environ.get("OTP_PORT")
    if env_port:
        try:
            env_tree.setdefault("server", {})["port"] = int(env_port.strip())
        except ValueError:
            raise ValueError(f"OTP_PORT must be an integer, got {env_port!r}") from None

    tree = copy.deepcopy(DEFAULTS)
    unknown: list[str] = []
    layers = []
    for name, layer in (("settings", settings), ("overrides", overrides)):
        if not layer:
            continue
        layer = copy.deepcopy(layer)
        _retired_keys(layer, name)
        found: list[str] = []
        _collect_unknown(layer, DEFAULTS, "", found)
        for u in found:
            log.warning("config %s: unknown key %r ignored", name, u)
        unknown.extend(found)
        layers.append((name, layer))
    for name, layer in layers:
        if name == "settings":
            _deep_merge(tree, layer)
    _deep_merge(tree, env_tree)
    for name, layer in layers:
        if name == "overrides":
            _deep_merge(tree, layer)
    return _build(tree, root, unknown)


# --------------------------------------------------------------------------------------------------
# Internals
# --------------------------------------------------------------------------------------------------


def _pstr(p: Path | None) -> str | None:
    return str(p) if p is not None else None


def _expand(s: str) -> str:
    return os.path.expanduser(os.path.expandvars(s))


def _resolve_path(value: Any, base: Path) -> Path:
    p = Path(_expand(str(value)))
    if not p.is_absolute():
        p = base / p
    return Path(os.path.normpath(p))


def _opt_path(value: Any, base: Path, key: str) -> Path | None:
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    if not isinstance(value, (str, os.PathLike)):
        raise ValueError(f"config {key}: expected a path string, got {type(value).__name__}")
    return _resolve_path(value, base)


def _peek(tree: Mapping | None, *keys: str) -> Any:
    cur: Any = tree
    for k in keys:
        if not isinstance(cur, Mapping) or k not in cur:
            return None
        cur = cur[k]
    return cur


def _retired_keys(tree: Any, where: str) -> None:
    """Drop (or translate) retired keys in place, with a warning instead of an "unknown key".

    * ``provisioning.secure_boot`` / ``provisioning.mode`` -> ``provisioning.default_mode`` (the scenario
      is chosen per board now; the flag only says which one the page preselects);
    * the whole ``storage`` section: the registry is the station's Google spreadsheet, set up by signing in;
    * ``builds.gadget.source``: the fastboot gadget is always built by this server.
    """
    if not isinstance(tree, dict):
        return
    prov = tree.get("provisioning")
    if isinstance(prov, dict):
        for old in ("mode", "secure_boot"):
            if old not in prov:
                continue
            value = prov.pop(old)
            if "default_mode" in prov:
                log.warning("config %s: provisioning.%s is retired and ignored (provisioning.default_mode is set)",
                            where, old)
                continue
            if old == "mode":
                prov["default_mode"] = value
            else:
                try:
                    prov["default_mode"] = "secure" if _bool(value, "provisioning.secure_boot") else "open"
                except ValueError:
                    raise ValueError("config provisioning.secure_boot is retired: use "
                                     "provisioning.default_mode: open | secure") from None
            log.warning("config %s: provisioning.%s is retired; read as provisioning.default_mode: %s "
                        "(the scenario is chosen per board on the page)", where, old, prov["default_mode"])
    if "storage" in tree:
        tree.pop("storage")
        log.warning("config %s: the storage section is retired and ignored: the registry is the station's "
                    "Google spreadsheet, set up by signing in to Google on the page", where)
    gadget = (tree.get("builds") or {}).get("gadget") if isinstance(tree.get("builds"), dict) else None
    if isinstance(gadget, dict) and "source" in gadget:
        gadget.pop("source")
        log.warning("config %s: builds.gadget.source is retired: the gadget is always built here", where)


def _deep_merge(dst: dict, src: Mapping) -> dict:
    """Merge ``src`` into ``dst`` in place. Mappings merge recursively, ``None`` for a section
    (``storage:`` with nothing under it) leaves the defaults alone, everything else replaces."""
    for k, v in src.items():
        if isinstance(v, Mapping):
            cur = dst.get(k)
            if isinstance(cur, dict):
                _deep_merge(cur, v)
            else:
                dst[k] = copy.deepcopy(dict(v))
        elif v is None and isinstance(dst.get(k), dict):
            continue
        else:
            dst[k] = copy.deepcopy(v)
    return dst


def _collect_unknown(tree: Any, schema: Any, prefix: str, out: list[str]) -> None:
    if not isinstance(tree, Mapping) or not isinstance(schema, Mapping):
        return
    for k, v in tree.items():
        key = f"{prefix}{k}"
        if k not in schema:
            out.append(key)
        elif isinstance(schema[k], Mapping):
            _collect_unknown(v, schema[k], key + ".", out)


_TRUE = {"1", "true", "yes", "on", "y"}
_FALSE = {"0", "false", "no", "off", "n", ""}


def _bool(v: Any, key: str) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, int) and v in (0, 1):
        return bool(v)
    if isinstance(v, str) and v.strip().lower() in _TRUE | _FALSE:
        return v.strip().lower() in _TRUE
    raise ValueError(f"config {key}: expected true/false, got {v!r}")


def _int(v: Any, key: str, *, lo: int | None = None, hi: int | None = None) -> int:
    if isinstance(v, bool):
        raise ValueError(f"config {key}: expected an integer, got {v!r}")
    try:
        n = int(str(v).strip(), 0) if isinstance(v, str) else int(v)
    except (TypeError, ValueError):
        raise ValueError(f"config {key}: expected an integer, got {v!r}") from None
    if (lo is not None and n < lo) or (hi is not None and n > hi):
        raise ValueError(f"config {key}: {n} is out of range [{lo}, {hi}]")
    return n


def _str(v: Any, key: str, *, allow_none: bool = False) -> str | None:
    if v is None:
        if allow_none:
            return None
        raise ValueError(f"config {key}: a value is required")
    if isinstance(v, (dict, list)):
        raise ValueError(f"config {key}: expected a string, got {type(v).__name__}")
    s = str(v).strip()
    if not s and allow_none:
        return None
    return s


def _enum(v: Any, key: str, allowed: tuple[str, ...]) -> str:
    s = str(v).strip().lower() if v is not None else ""
    if s not in allowed:
        raise ValueError(f"config {key}: {v!r} is not one of {', '.join(allowed)}")
    return s


def _image_config(value: Any, droneos: Path) -> str:
    s = _str(value, "builds.image.config")
    if not s:
        raise ValueError("config builds.image.config: a value is required")
    p = _resolve_path(s, droneos)
    try:
        return p.relative_to(droneos).as_posix()
    except ValueError:
        return str(p)


def _default_desktop_path() -> Path | None:
    if sys.platform != "win32":
        return None
    base = os.environ.get("ProgramFiles") or r"C:\Program Files"
    return Path(base) / "Docker" / "Docker" / "Docker Desktop.exe"


def _build(tree: dict, root: Path, unknown: list[str]) -> Config:
    srv, pth = tree["server"], tree["paths"]
    prov, bld, dck = tree["provisioning"], tree["builds"], tree["docker"]

    work = _opt_path(pth.get("work"), root, "paths.work") or default_work_dir()
    droneos = _opt_path(pth.get("droneos"), root, "paths.droneos")
    if droneos is None:
        raise ValueError("config paths.droneos: a value is required")

    server = ServerCfg(
        host=_str(srv.get("host"), "server.host") or "127.0.0.1",
        port=_int(srv.get("port"), "server.port", lo=1, hi=65535),
        open_browser=_bool(srv.get("open_browser"), "server.open_browser"),
        browser=_opt_path(srv.get("browser"), root, "server.browser"),
    )

    boot_conf = prov.get("boot_conf")
    if not isinstance(boot_conf, str) or not boot_conf.strip():
        raise ValueError("config provisioning.boot_conf: a non-empty text block is required")
    boot_conf = boot_conf.replace("\r\n", "\n")
    if not boot_conf.endswith("\n"):
        boot_conf += "\n"
    provisioning = ProvisioningCfg(
        default_mode=_enum(prov.get("default_mode"), "provisioning.default_mode", PROVISIONING_MODES),
        jtag_lock=_bool(prov.get("jtag_lock"), "provisioning.jtag_lock"),
        recovery_passphrase=_bool(prov.get("recovery_passphrase"), "provisioning.recovery_passphrase"),
        confirm_irreversible=_bool(prov.get("confirm_irreversible"), "provisioning.confirm_irreversible"),
        erase_storage=_bool(prov.get("erase_storage"), "provisioning.erase_storage"),
        firmware_channel=_enum(prov.get("firmware_channel"), "provisioning.firmware_channel", FIRMWARE_CHANNELS),
        max_piece_size=_int(prov.get("max_piece_size"), "provisioning.max_piece_size", lo=1 << 20),
        boot_conf=boot_conf,
    )

    tools = bld.get("tools") or {}
    gadget = bld.get("gadget") or {}
    image = bld.get("image") or {}
    ovr = image.get("overrides")
    if ovr is None:
        ovr = []
    if isinstance(ovr, str):
        ovr = [ovr]
    if not isinstance(ovr, list) or not all(isinstance(o, (str, int, float)) for o in ovr):
        raise ValueError("config builds.image.overrides: expected a list of KEY=VALUE strings")
    for o in ovr:
        if str(o).strip().startswith("IGconf_image_pmap="):
            raise ValueError("config builds.image.overrides: IGconf_image_pmap is set per scenario "
                             "(open = clear, secure = crypt; both images are built); remove it")
    builds = BuildsCfg(
        auto=_bool(bld.get("auto"), "builds.auto"),
        tools=ToolsBuildCfg(image_tag=_str(tools.get("image_tag"), "builds.tools.image_tag") or ""),
        gadget=GadgetBuildCfg(
            targets=_str(gadget.get("targets"), "builds.gadget.targets") or "pi5-family",
            image_tag=_str(gadget.get("image_tag"), "builds.gadget.image_tag") or "",
            volume=_str(gadget.get("volume"), "builds.gadget.volume") or "",
        ),
        image=ImageBuildCfg(
            config=_image_config(image.get("config"), droneos),
            overrides=[str(o).strip() for o in ovr if str(o).strip()],
            builder_tag=_str(image.get("builder_tag"), "builds.image.builder_tag") or "",
            volume=_str(image.get("volume"), "builds.image.volume") or "",
            keep_raw_image=_bool(image.get("keep_raw_image"), "builds.image.keep_raw_image"),
        ),
    )

    docker = DockerCfg(
        binary=_str(dck.get("binary"), "docker.binary") or "docker",
        start_desktop=_bool(dck.get("start_desktop"), "docker.start_desktop"),
        desktop_path=_opt_path(dck.get("desktop_path"), root, "docker.desktop_path") or _default_desktop_path(),
        idle_timeout=_int(dck.get("idle_timeout"), "docker.idle_timeout", lo=0),
    )

    return Config(
        repo_root=root,
        work_dir=work,
        droneos_dir=droneos,
        server=server,
        provisioning=provisioning,
        builds=builds,
        docker=docker,
        unknown_keys=unknown,
    )
