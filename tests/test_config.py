from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from otp_server import __version__
from otp_server.config import DEFAULT_BOOT_CONF, REPO_ROOT, default_work_dir, load_config

ENV = ("OTP_CONFIG", "OTP_WORK_DIR", "OTP_STORAGE", "OTP_PORT")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for n in ENV:
        monkeypatch.delenv(n, raising=False)


def write(p: Path, text: str) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def test_defaults(tmp_path):
    cfg = load_config(write(tmp_path / "c.yaml", ""), overrides={"paths": {"work": str(tmp_path / "w")}})
    assert cfg.repo_root == REPO_ROOT
    assert cfg.work_dir == tmp_path / "w"
    assert cfg.droneos_dir == (REPO_ROOT / "external" / "droneos")
    assert cfg.config_path == tmp_path / "c.yaml"
    assert (cfg.server.host, cfg.server.port, cfg.server.open_browser) == ("127.0.0.1", 8765, True)
    assert cfg.storage.backend == "local"
    assert cfg.storage.local_dir == tmp_path / "w" / "registry"
    assert cfg.storage.gsheets.auth == "service_account"
    assert cfg.storage.gsheets.worksheet == "modules"
    assert cfg.storage.gsheets.token == tmp_path / "w" / "google" / "gsheets-token.json"
    assert cfg.storage.gdrive.token == tmp_path / "w" / "google" / "gdrive-token.json"
    assert cfg.storage.gsheets.credentials is None and cfg.storage.gdrive.folder_id is None
    p = cfg.provisioning
    assert (p.secure_boot, p.jtag_lock, p.recovery_passphrase, p.confirm_irreversible, p.erase_storage) == (
        False, False, True, True, True)
    assert p.firmware_channel == "default"
    assert p.max_piece_size == 268435456
    assert p.boot_conf == DEFAULT_BOOT_CONF
    assert "BOOT_ORDER=0xf2461" in p.boot_conf
    b = cfg.builds
    assert b.auto is True and b.tools.image_tag == "otp-tools:latest"
    assert (b.gadget.source, b.gadget.targets, b.gadget.image_tag, b.gadget.volume) == (
        "auto", "pi5-family", "otp-gadget-builder:trixie", "otp-pgm-work")
    assert b.image.config == "droneos.yaml"
    assert b.image.overrides == ["IGconf_image_pmap=crypt"]
    assert (b.image.builder_tag, b.image.volume, b.image.keep_raw_image) == (
        "droneos-builder:trixie", "otp-droneos-work", False)
    assert cfg.image_config_path == cfg.droneos_dir / "droneos.yaml"
    assert cfg.docker.binary == "docker" and cfg.docker.start_desktop is True
    if sys.platform == "win32":
        assert cfg.docker.desktop_path is not None and cfg.docker.desktop_path.name == "Docker Desktop.exe"
    assert cfg.external_dir == REPO_ROOT / "external"
    assert cfg.web_dir == REPO_ROOT
    assert cfg.unknown_keys == []


def test_default_work_dir(monkeypatch, tmp_path):
    if sys.platform == "win32":
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        assert default_work_dir() == tmp_path / "OTP_Provisioner"
    else:
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
        assert default_work_dir() == tmp_path / "otp-provisioner"
        monkeypatch.delenv("XDG_DATA_HOME")
        assert default_work_dir() == Path.home() / ".local" / "share" / "otp-provisioner"


def test_yaml_values_and_relative_paths(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    cfgfile = write(
        tmp_path / "cfg.yaml",
        """
server: {host: 0.0.0.0, port: 9000, open_browser: false}
paths: {work: state, droneos: ../dos}
storage:
  backend: gsheets
  local: {dir: reg}
  gsheets: {auth: oauth, credentials: google/client.json, spreadsheet: "https://docs.google.com/spreadsheets/d/abc/edit", worksheet: boards}
  gdrive: {credentials: sa.json, token: tok.json, folder_id: F123}
provisioning:
  secure_boot: true
  jtag_lock: true
  firmware_channel: latest
  max_piece_size: 0x8000000
  boot_conf: |
    [all]
    BOOT_ORDER=0xf1
builds:
  auto: false
  gadget: {source: build}
  image: {config: configs/x.yaml, overrides: [A=1, B=2], keep_raw_image: true}
docker: {binary: podman, start_desktop: no, desktop_path: D/docker.exe}
""",
    )
    cfg = load_config(cfgfile, repo_root=repo)
    assert cfg.repo_root == repo.resolve()
    r = cfg.repo_root
    assert cfg.work_dir == r / "state"
    assert cfg.droneos_dir == tmp_path.resolve() / "dos"
    assert (cfg.server.host, cfg.server.port, cfg.server.open_browser) == ("0.0.0.0", 9000, False)
    assert cfg.storage.backend == "gsheets"
    assert cfg.storage.local_dir == r / "reg"
    g = cfg.storage.gsheets
    assert g.auth == "oauth" and g.credentials == r / "google" / "client.json"
    assert g.spreadsheet.startswith("https://") and g.worksheet == "boards"
    assert g.token == r / "state" / "google" / "gsheets-token.json"
    d = cfg.storage.gdrive
    assert d.credentials == r / "sa.json" and d.token == r / "tok.json" and d.folder_id == "F123"
    assert cfg.provisioning.secure_boot and cfg.provisioning.jtag_lock
    assert cfg.provisioning.firmware_channel == "latest"
    assert cfg.provisioning.max_piece_size == 0x8000000
    assert cfg.provisioning.boot_conf == "[all]\nBOOT_ORDER=0xf1\n"
    assert cfg.builds.auto is False and cfg.builds.gadget.source == "build"
    assert cfg.builds.gadget.targets == "pi5-family"  # untouched default in a partial section
    assert cfg.builds.image.config == "configs/x.yaml"
    assert cfg.image_config_path == cfg.droneos_dir / "configs" / "x.yaml"
    assert cfg.builds.image.overrides == ["A=1", "B=2"]
    assert cfg.builds.image.keep_raw_image is True
    assert cfg.docker.binary == "podman" and cfg.docker.start_desktop is False
    assert cfg.docker.desktop_path == r / "D" / "docker.exe"


def test_image_config_outside_droneos_is_absolute(tmp_path):
    outside = tmp_path / "elsewhere" / "img.yaml"
    cfg = load_config(
        write(tmp_path / "c.yaml", ""),
        overrides={"paths": {"work": str(tmp_path / "w"), "droneos": str(tmp_path / "dos")},
                   "builds": {"image": {"config": str(outside)}}},
    )
    assert Path(cfg.builds.image.config).is_absolute()
    assert cfg.image_config_path == outside
    assert cfg.droneos_dir / cfg.builds.image.config == outside


def test_search_order_env_and_overrides(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    work = tmp_path / "work"
    write(repo / "config.yaml", "server: {port: 1111}\n")
    write(work / "config.yaml", "server: {port: 2222}\n")
    envfile = write(tmp_path / "env.yaml", "server: {port: 3333}\n")
    explicit = write(tmp_path / "explicit.yaml", "server: {port: 4444}\n")
    monkeypatch.setenv("OTP_WORK_DIR", str(work))

    assert load_config(repo_root=repo).server.port == 1111
    (repo / "config.yaml").unlink()
    cfg = load_config(repo_root=repo)
    assert cfg.server.port == 2222 and cfg.config_path == work / "config.yaml"
    assert cfg.work_dir == work
    monkeypatch.setenv("OTP_CONFIG", str(envfile))
    assert load_config(repo_root=repo).server.port == 3333
    assert load_config(explicit, repo_root=repo).server.port == 4444
    # env overrides beat the file, overrides beat env
    monkeypatch.setenv("OTP_PORT", "5555")
    monkeypatch.setenv("OTP_STORAGE", "gdrive")
    cfg = load_config(explicit, repo_root=repo)
    assert cfg.server.port == 5555 and cfg.storage.backend == "gdrive"
    cfg = load_config(explicit, repo_root=repo, overrides={"server": {"port": 6666}, "storage": {"backend": "local"}})
    assert cfg.server.port == 6666 and cfg.storage.backend == "local"


def test_no_config_file_at_all(tmp_path, monkeypatch):
    monkeypatch.setenv("OTP_WORK_DIR", str(tmp_path / "w"))
    cfg = load_config(repo_root=tmp_path / "emptyrepo")
    assert cfg.config_path is None
    assert cfg.work_dir == tmp_path / "w"
    assert cfg.server.port == 8765


def test_missing_explicit_file(tmp_path, monkeypatch):
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "nope.yaml")
    monkeypatch.setenv("OTP_CONFIG", str(tmp_path / "nope2.yaml"))
    with pytest.raises(FileNotFoundError):
        load_config(repo_root=tmp_path)


@pytest.mark.parametrize(
    "yaml_text, needle",
    [
        ("storage: {backend: s3}", "storage.backend"),
        ("storage: {gsheets: {auth: apikey}}", "storage.gsheets.auth"),
        ("storage: {gdrive: {auth: x}}", "storage.gdrive.auth"),
        ("builds: {gadget: {source: maybe}}", "builds.gadget.source"),
        ("provisioning: {firmware_channel: beta}", "provisioning.firmware_channel"),
        ("server: {port: 70000}", "server.port"),
        ("server: {port: abc}", "server.port"),
        ("provisioning: {secure_boot: perhaps}", "provisioning.secure_boot"),
        ("provisioning: {boot_conf: ''}", "provisioning.boot_conf"),
        ("builds: {image: {overrides: {a: 1}}}", "builds.image.overrides"),
        ("- just a list", "top level"),
        ("server: {port: [1", "not valid YAML"),
    ],
)
def test_validation_errors(tmp_path, yaml_text, needle):
    f = write(tmp_path / "bad.yaml", yaml_text + "\n")
    with pytest.raises(ValueError) as ei:
        load_config(f, overrides={"paths": {"work": str(tmp_path / "w")}})
    assert needle in str(ei.value)


def test_bad_env_port(tmp_path, monkeypatch):
    monkeypatch.setenv("OTP_PORT", "http")
    with pytest.raises(ValueError, match="OTP_PORT"):
        load_config(write(tmp_path / "c.yaml", ""))


def test_enum_case_insensitive_and_empty_sections(tmp_path):
    f = write(tmp_path / "c.yaml", "storage:\n  backend: GSheets\nserver:\nbuilds:\n  image:\n")
    cfg = load_config(f, overrides={"paths": {"work": str(tmp_path / "w")}})
    assert cfg.storage.backend == "gsheets"
    assert cfg.server.port == 8765
    assert cfg.builds.image.config == "droneos.yaml"


def test_unknown_keys_are_reported_not_fatal(tmp_path, caplog):
    f = write(tmp_path / "c.yaml", "sever: {port: 1}\nprovisioning: {secureboot: true}\n")
    cfg = load_config(f, overrides={"paths": {"work": str(tmp_path / "w")}})
    assert set(cfg.unknown_keys) == {"sever", "provisioning.secureboot"}
    assert cfg.provisioning.secure_boot is False


def test_env_vars_expanded_in_paths(tmp_path, monkeypatch):
    monkeypatch.setenv("OTP_TEST_BASE", str(tmp_path / "base"))
    f = write(tmp_path / "c.yaml", "paths: {work: $OTP_TEST_BASE/w}\n")
    cfg = load_config(f)
    assert cfg.work_dir == tmp_path / "base" / "w"


def test_ensure_dirs_and_summary(make_cfg, tmp_path):
    secret = "SUPER-SECRET-SA-CONTENT"
    cred = write(tmp_path / "sa.json", json.dumps({"private_key": secret}))
    cfg = make_cfg(tmp_path, storage={"gsheets": {"credentials": str(cred), "spreadsheet": "KEY"}})
    for sub in ("registry", "google", "modules", "artifacts/stage1", "artifacts/stage2", "artifacts/gadget",
                "artifacts/image/staging", "jobs", "tmp"):
        assert (cfg.work_dir / sub).is_dir(), sub
    s = cfg.summary()
    text = json.dumps(s)  # JSON-safe
    assert secret not in text
    assert s["version"] == __version__
    assert s["storage"]["gsheets"]["credentials"] == str(cred)
    assert s["storage"]["gsheets"]["credentials_exists"] is True
    assert s["server"]["open_browser"] is False
    assert s["provisioning"]["max_piece_size"] == 268435456
    assert s["builds"]["image"]["config"] == "droneos.yaml"


def test_make_cfg_fixture_is_isolated(make_cfg, tmp_path, monkeypatch):
    cfg = make_cfg(tmp_path, provisioning={"secure_boot": True}, storage={"backend": "local"})
    assert cfg.work_dir == tmp_path / "work"
    assert cfg.work_dir.is_relative_to(tmp_path)
    assert cfg.provisioning.secure_boot is True
    assert cfg.config_path == tmp_path / "otp-test-config.yaml"
    assert cfg.builds.auto is False and cfg.server.open_browser is False


def test_docker_idle_timeout(make_cfg, tmp_path):
    """docker.idle_timeout: default 30 min, configurable, 0 disables, negative rejected; DockerRunner uses it."""
    from otp_server.docker import DockerRunner

    cfg = make_cfg(tmp_path / "a")
    assert cfg.docker.idle_timeout == 1800
    assert cfg.summary()["docker"]["idle_timeout"] == 1800
    assert DockerRunner(cfg).idle_timeout == 1800.0

    cfg = make_cfg(tmp_path / "b", docker={"idle_timeout": 0})
    assert cfg.docker.idle_timeout == 0 and DockerRunner(cfg).idle_timeout == 0.0

    with pytest.raises(ValueError, match="docker.idle_timeout"):
        make_cfg(tmp_path / "c", docker={"idle_timeout": -5})


def test_example_config_matches_defaults():
    """config.example.yaml documents exactly the real defaults."""
    import yaml

    from otp_server.config import DEFAULTS

    example = yaml.safe_load((REPO_ROOT / "config.example.yaml").read_text(encoding="utf-8"))
    assert example == DEFAULTS
