"""Server configuration (SPEC section 4).

The configuration is a YAML file in which every key is optional; missing keys take the defaults in
:data:`DEFAULTS`. The file is searched in this order (first existing one wins):

1. the ``path`` argument of :func:`load_config` (the ``--config`` CLI flag),
2. the ``OTP_CONFIG`` environment variable,
3. ``<repo>/config.yaml``,
4. ``<work>/config.yaml``.

An explicit path (1 or 2) that does not exist is an error; 3 and 4 are optional. After the file, the
environment overrides ``OTP_WORK_DIR`` (``paths.work``), ``OTP_STORAGE`` (``storage.backend``) and
``OTP_PORT`` (``server.port``) are applied, and finally the ``overrides`` dict (CLI flags, tests).

Relative paths inside the YAML tree (and in ``overrides``) are resolved against the repository root;
``builds.image.config`` is resolved against the droneos checkout (see :attr:`ImageBuildCfg.config`).
``~`` and environment variables (``%LOCALAPPDATA%``, ``$HOME``) are expanded in every path.
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

STORAGE_BACKENDS = ("local", "gsheets", "gdrive")
GOOGLE_AUTH_MODES = ("service_account", "oauth")
GADGET_SOURCES = ("build", "prebuilt", "auto")
FIRMWARE_CHANNELS = ("default", "latest")

DEFAULT_BOOT_CONF = "[all]\nBOOT_UART=1\nPOWER_OFF_ON_HALT=1\nBOOT_ORDER=0xf2461\n"

#: The complete default configuration tree (the YAML schema).
DEFAULTS: dict[str, Any] = {
    "server": {"host": "127.0.0.1", "port": 8765, "open_browser": True},
    "paths": {"work": None, "droneos": "external/droneos"},
    "storage": {
        "backend": "local",
        "local": {"dir": None},
        "gsheets": {
            "auth": "service_account",
            "credentials": None,
            "token": None,
            "spreadsheet": None,
            "worksheet": "modules",
        },
        "gdrive": {
            "auth": "service_account",
            "credentials": None,
            "token": None,
            "folder_id": None,
        },
    },
    "provisioning": {
        "secure_boot": False,
        "jtag_lock": False,
        "recovery_passphrase": True,
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
            "source": "auto",
            "targets": "pi5-family",
            "image_tag": "otp-gadget-builder:trixie",
            "volume": "otp-pgm-work",
        },
        "image": {
            "config": "droneos.yaml",
            "overrides": ["IGconf_image_pmap=crypt"],
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


@dataclass
class GoogleCfg:
    """Settings of one Google backend (``storage.gsheets`` or ``storage.gdrive``).

    ``credentials`` is the service-account JSON key (``auth: service_account``) or the OAuth
    "Desktop app" client JSON (``auth: oauth``). ``token`` is the OAuth authorized-user cache
    (always filled with a default under ``<work>/google/``; unused for service accounts).
    ``spreadsheet``/``worksheet`` are used by Sheets only, ``folder_id`` by Drive only.
    """

    auth: str
    credentials: Path | None
    token: Path | None
    spreadsheet: str | None
    worksheet: str
    folder_id: str | None


@dataclass
class StorageCfg:
    backend: str
    local_dir: Path
    gsheets: GoogleCfg
    gdrive: GoogleCfg


@dataclass
class ProvisioningCfg:
    secure_boot: bool
    jtag_lock: bool
    recovery_passphrase: bool
    confirm_irreversible: bool
    erase_storage: bool
    firmware_channel: str
    max_piece_size: int
    boot_conf: str


@dataclass
class GadgetBuildCfg:
    source: str
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
    config_path: Path | None
    server: ServerCfg
    storage: StorageCfg
    provisioning: ProvisioningCfg
    builds: BuildsCfg
    docker: DockerCfg
    #: Keys found in the YAML file that the schema does not know (typos); reported, not fatal.
    unknown_keys: list[str] = field(default_factory=list)

    @property
    def external_dir(self) -> Path:
        """``<repo>/external`` (the usbboot / rpi-sb-provisioner / pi-gen-micro submodules)."""
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
            self.storage.local_dir,
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

        def g(c: GoogleCfg) -> dict:
            return {
                "auth": c.auth,
                "credentials": _pstr(c.credentials),
                "credentials_exists": bool(c.credentials and c.credentials.is_file()),
                "token": _pstr(c.token),
                "spreadsheet": c.spreadsheet,
                "worksheet": c.worksheet,
                "folder_id": c.folder_id,
            }

        return {
            "version": __version__,
            "repo_root": str(self.repo_root),
            "work_dir": str(self.work_dir),
            "droneos_dir": str(self.droneos_dir),
            "config_path": _pstr(self.config_path),
            "server": asdict(self.server),
            "storage": {
                "backend": self.storage.backend,
                "local_dir": str(self.storage.local_dir),
                "gsheets": g(self.storage.gsheets),
                "gdrive": g(self.storage.gdrive),
            },
            "provisioning": asdict(self.provisioning),
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
    path: str | Path | None = None,
    *,
    overrides: dict | None = None,
    repo_root: Path | None = None,
) -> Config:
    """Load, merge and validate the configuration.

    :param path: explicit config file (``--config``); must exist when given.
    :param overrides: nested dict merged last, e.g. ``{"server": {"port": 9000}}``.
    :param repo_root: repository root (default: the directory containing ``otp_server``).
    :raises FileNotFoundError: an explicit config file (argument or ``OTP_CONFIG``) is missing.
    :raises ValueError: invalid YAML or an invalid value (enum, type).
    """
    root = Path(repo_root).resolve() if repo_root is not None else REPO_ROOT

    # Environment overrides (applied after the file, before ``overrides``).
    env_tree: dict[str, Any] = {}
    env_work = os.environ.get("OTP_WORK_DIR")
    if env_work:
        # Relative env paths are relative to the current directory, not the repo root.
        env_tree.setdefault("paths", {})["work"] = str(Path(_expand(env_work)).resolve())
    env_backend = os.environ.get("OTP_STORAGE")
    if env_backend:
        env_tree.setdefault("storage", {})["backend"] = env_backend.strip()
    env_port = os.environ.get("OTP_PORT")
    if env_port:
        try:
            env_tree.setdefault("server", {})["port"] = int(env_port.strip())
        except ValueError:
            raise ValueError(f"OTP_PORT must be an integer, got {env_port!r}") from None

    # The work dir used to look for <work>/config.yaml: env / overrides beat the platform default
    # (a paths.work inside that very file cannot be used to find it).
    search_work = _peek(overrides, "paths", "work") or env_tree.get("paths", {}).get("work")
    search_work_dir = _resolve_path(search_work, root) if search_work else default_work_dir()

    config_path = _find_config(path, root, search_work_dir)
    file_tree: dict[str, Any] = {}
    if config_path is not None:
        file_tree = _read_yaml(config_path)

    tree = copy.deepcopy(DEFAULTS)
    unknown: list[str] = []
    _collect_unknown(file_tree, DEFAULTS, "", unknown)
    for u in unknown:
        log.warning("config %s: unknown key %r ignored", config_path, u)
    _deep_merge(tree, file_tree)
    _deep_merge(tree, env_tree)
    if overrides:
        _deep_merge(tree, overrides)

    return _build(tree, root, config_path, unknown)


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


def _find_config(path: str | Path | None, root: Path, work: Path) -> Path | None:
    if path is not None and str(path).strip():
        p = _resolve_path(path, Path.cwd())
        if not p.is_file():
            raise FileNotFoundError(f"config file not found: {p}")
        return p
    env = os.environ.get("OTP_CONFIG")
    if env and env.strip():
        p = _resolve_path(env.strip(), Path.cwd())
        if not p.is_file():
            raise FileNotFoundError(f"OTP_CONFIG points to a missing file: {p}")
        return p
    for cand in (root / "config.yaml", work / "config.yaml"):
        if cand.is_file():
            return cand
    return None


def _read_yaml(p: Path) -> dict:
    import yaml  # PyYAML; imported here so importing this module stays cheap

    try:
        with open(p, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise ValueError(f"config file {p} is not valid YAML: {exc}") from None
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"config file {p}: top level must be a mapping, got {type(data).__name__}")
    return data


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


def _google(tree: Mapping, key: str, root: Path, work: Path, token_name: str) -> GoogleCfg:
    token = _opt_path(tree.get("token"), root, f"{key}.token")
    return GoogleCfg(
        auth=_enum(tree.get("auth"), f"{key}.auth", GOOGLE_AUTH_MODES),
        credentials=_opt_path(tree.get("credentials"), root, f"{key}.credentials"),
        token=token if token is not None else work / "google" / token_name,
        spreadsheet=_str(tree.get("spreadsheet"), f"{key}.spreadsheet", allow_none=True),
        worksheet=_str(tree.get("worksheet") or "modules", f"{key}.worksheet") or "modules",
        folder_id=_str(tree.get("folder_id"), f"{key}.folder_id", allow_none=True),
    )


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


def _build(tree: dict, root: Path, config_path: Path | None, unknown: list[str]) -> Config:
    srv, pth, sto = tree["server"], tree["paths"], tree["storage"]
    prov, bld, dck = tree["provisioning"], tree["builds"], tree["docker"]

    work = _opt_path(pth.get("work"), root, "paths.work") or default_work_dir()
    droneos = _opt_path(pth.get("droneos"), root, "paths.droneos")
    if droneos is None:
        raise ValueError("config paths.droneos: a value is required")

    server = ServerCfg(
        host=_str(srv.get("host"), "server.host") or "127.0.0.1",
        port=_int(srv.get("port"), "server.port", lo=1, hi=65535),
        open_browser=_bool(srv.get("open_browser"), "server.open_browser"),
    )

    local = sto.get("local") or {}
    storage = StorageCfg(
        backend=_enum(sto.get("backend"), "storage.backend", STORAGE_BACKENDS),
        local_dir=_opt_path(local.get("dir"), root, "storage.local.dir") or work / "registry",
        gsheets=_google(sto.get("gsheets") or {}, "storage.gsheets", root, work, "gsheets-token.json"),
        gdrive=_google(sto.get("gdrive") or {}, "storage.gdrive", root, work, "gdrive-token.json"),
    )

    boot_conf = prov.get("boot_conf")
    if not isinstance(boot_conf, str) or not boot_conf.strip():
        raise ValueError("config provisioning.boot_conf: a non-empty text block is required")
    boot_conf = boot_conf.replace("\r\n", "\n")
    if not boot_conf.endswith("\n"):
        boot_conf += "\n"
    provisioning = ProvisioningCfg(
        secure_boot=_bool(prov.get("secure_boot"), "provisioning.secure_boot"),
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
    builds = BuildsCfg(
        auto=_bool(bld.get("auto"), "builds.auto"),
        tools=ToolsBuildCfg(image_tag=_str(tools.get("image_tag"), "builds.tools.image_tag") or ""),
        gadget=GadgetBuildCfg(
            source=_enum(gadget.get("source"), "builds.gadget.source", GADGET_SOURCES),
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
        config_path=config_path,
        server=server,
        storage=storage,
        provisioning=provisioning,
        builds=builds,
        docker=docker,
        unknown_keys=unknown,
    )
