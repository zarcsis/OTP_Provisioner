"""otp_server.config: the loader without a configuration file.

Sources, in order of precedence (lowest first): DEFAULTS < ``settings`` (the settings worksheet, values
as cell text) < environment (``OTP_WORK_DIR``, ``OTP_PORT``) < ``overrides`` (CLI flags, tests).
"""

from __future__ import annotations

import copy
import json
import logging
import sys
from pathlib import Path

import pytest

from otp_server import __version__
from otp_server.config import (
    DEFAULT_BOOT_CONF,
    DEFAULTS,
    PROVISIONING_MODES,
    REPO_ROOT,
    default_work_dir,
    load_config,
)

ENV = ("OTP_WORK_DIR", "OTP_PORT")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for n in ENV:
        monkeypatch.delenv(n, raising=False)


def write(p: Path, text: str) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def load(tmp_path: Path, *, settings: dict | None = None, repo_root: Path | None = None, **overrides):
    """``load_config`` with ``paths.work`` under ``tmp_path`` (unless the overrides say otherwise)."""
    tree = {"paths": {"work": str(tmp_path / "w")}}
    for k, v in overrides.items():
        if isinstance(v, dict) and isinstance(tree.get(k), dict):
            tree[k] = {**tree[k], **v}
        else:
            tree[k] = v
    return load_config(overrides=tree, settings=settings, repo_root=repo_root)


def warnings_of(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.name == "otp_server.config" and r.levelno >= logging.WARNING]


# --------------------------------------------------------------------------------------------------
# Defaults
# --------------------------------------------------------------------------------------------------


def test_defaults(tmp_path):
    cfg = load(tmp_path)
    assert cfg.repo_root == REPO_ROOT
    assert cfg.work_dir == tmp_path / "w"
    assert cfg.image_dir == REPO_ROOT / "image"
    s = cfg.server
    assert (s.host, s.port, s.open_browser, s.browser) == ("127.0.0.1", 8765, True, None)
    p = cfg.provisioning
    assert p.default_mode == "open"
    assert (p.jtag_lock, p.recovery_passphrase, p.confirm_irreversible, p.erase_storage) == (False, False, True, True)
    assert p.firmware_channel == "default"
    assert p.max_piece_size == 268435456
    assert p.boot_conf == DEFAULT_BOOT_CONF
    assert "BOOT_ORDER=0xf2461" in p.boot_conf
    b = cfg.builds
    assert b.auto is True and b.tools.image_tag == "otp-tools:latest"
    assert (b.gadget.targets, b.gadget.image_tag, b.gadget.volume) == (
        "pi5-family", "otp-gadget-builder:trixie", "otp-pgm-work")
    assert b.image.overrides == []          # IGconf_image_pmap is set per scenario, not here
    assert (b.image.builder_tag, b.image.volume, b.image.keep_raw_image) == (
        "otp-image-builder:trixie", "otp-image-work", False)
    i = cfg.image
    assert (i.name, i.hostname, i.timezone, i.user, i.password_hash) == (
        "rpios-trixie-arm64-lite", "pi5-{serial}", "Europe/Kyiv", "pi", "")
    assert i.keyboard == "us"
    assert (i.ssh, i.ssh_password_login, i.ssh_authorized_keys) == (False, True, [])
    assert (i.wifi_ssid, i.wifi_password, i.wifi_country, i.wifi_hidden) == ("", "", "UA", False)
    assert cfg.docker.binary == "docker" and cfg.docker.start_desktop is True
    assert cfg.docker.idle_timeout == 1800
    if sys.platform == "win32":
        assert cfg.docker.desktop_path is not None and cfg.docker.desktop_path.name == "Docker Desktop.exe"
    else:
        assert cfg.docker.desktop_path is None
    assert cfg.external_dir == REPO_ROOT / "external"
    assert cfg.web_dir == REPO_ROOT
    assert cfg.unknown_keys == []
    assert cfg.bootstrap == {}


def test_retired_attributes_are_gone(tmp_path):
    cfg = load(tmp_path)
    assert not hasattr(cfg, "storage")
    assert not hasattr(cfg, "config_path")
    assert not hasattr(cfg, "droneos_dir") and not hasattr(cfg, "image_config_path")
    assert not hasattr(cfg.builds.image, "config")
    assert "droneos" not in DEFAULTS["paths"] and "config" not in DEFAULTS["builds"]["image"]
    assert not hasattr(cfg.provisioning, "secure_boot")
    assert not hasattr(cfg.provisioning, "mode")
    assert not hasattr(cfg.builds.gadget, "source")
    assert "storage" not in DEFAULTS
    assert "source" not in DEFAULTS["builds"]["gadget"]
    assert not {"secure_boot", "mode"} & set(DEFAULTS["provisioning"])


def test_default_work_dir(monkeypatch, tmp_path):
    if sys.platform == "win32":
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        assert default_work_dir() == tmp_path / "OTP_Provisioner"
    else:
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
        assert default_work_dir() == tmp_path / "otp-provisioner"
        monkeypatch.delenv("XDG_DATA_HOME")
        assert default_work_dir() == Path.home() / ".local" / "share" / "otp-provisioner"


def test_no_arguments_uses_the_platform_work_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALAPPDATA" if sys.platform == "win32" else "XDG_DATA_HOME", str(tmp_path))
    cfg = load_config()
    assert cfg.work_dir == default_work_dir()
    assert cfg.work_dir.is_relative_to(tmp_path)
    assert not cfg.work_dir.exists()        # loading creates nothing; ensure_dirs() does


def test_no_config_file_is_read(tmp_path, monkeypatch):
    """There is no configuration file: config.yaml files and the retired OTP_CONFIG/OTP_STORAGE are ignored."""
    repo, work = tmp_path / "repo", tmp_path / "work"
    yaml_text = "server: {port: 1111}\nprovisioning: {default_mode: secure}\n"
    write(repo / "config.yaml", yaml_text)
    write(work / "config.yaml", yaml_text)
    monkeypatch.setenv("OTP_CONFIG", str(repo / "config.yaml"))
    monkeypatch.setenv("OTP_STORAGE", "gdrive")
    monkeypatch.setenv("OTP_WORK_DIR", str(work))
    cfg = load_config(repo_root=repo)
    assert cfg.work_dir == work
    assert cfg.server.port == 8765 and cfg.provisioning.default_mode == "open"
    assert cfg.unknown_keys == []
    with pytest.raises(TypeError):
        load_config(repo / "config.yaml")   # no positional path argument any more


def test_loading_does_not_touch_inputs_or_defaults(tmp_path):
    overrides = {"paths": {"work": str(tmp_path / "w")},
                 "provisioning": {"secure_boot": True},
                 "builds": {"gadget": {"source": "build"}, "image": {"overrides": ["A=1"]}}}
    settings = {"provisioning": {"mode": "secure"}, "storage": {"backend": "local"}}
    ov_before, st_before = copy.deepcopy(overrides), copy.deepcopy(settings)
    defaults_before = copy.deepcopy(DEFAULTS)
    cfg = load_config(overrides=overrides, settings=settings)
    assert overrides == ov_before and settings == st_before    # retired keys are dropped from a copy
    cfg.builds.image.overrides.append("B=2")
    cfg2 = load(tmp_path)
    assert cfg2.builds.image.overrides == []
    assert DEFAULTS == defaults_before


# --------------------------------------------------------------------------------------------------
# Environment
# --------------------------------------------------------------------------------------------------


def test_env_work_dir_and_port(tmp_path, monkeypatch):
    monkeypatch.setenv("OTP_WORK_DIR", str(tmp_path / "envwork"))
    monkeypatch.setenv("OTP_PORT", " 9100 ")
    cfg = load_config(repo_root=tmp_path / "repo")
    assert cfg.work_dir == tmp_path / "envwork"
    assert cfg.server.port == 9100


def test_relative_env_work_dir_is_relative_to_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("OTP_WORK_DIR", "rel/w")
    cfg = load_config(repo_root=tmp_path / "repo")
    assert cfg.work_dir == (tmp_path / "rel" / "w").resolve()
    assert not cfg.work_dir.is_relative_to(tmp_path / "repo")


def test_env_vars_and_home_expanded_in_paths(tmp_path, monkeypatch):
    monkeypatch.setenv("OTP_TEST_BASE", str(tmp_path / "base"))
    cfg = load_config(overrides={"paths": {"work": "$OTP_TEST_BASE/w"}})
    assert cfg.work_dir == tmp_path / "base" / "w"
    monkeypatch.setenv("OTP_WORK_DIR", "$OTP_TEST_BASE/envw")
    assert load_config().work_dir == (tmp_path / "base" / "envw").resolve()
    monkeypatch.delenv("OTP_WORK_DIR")
    cfg = load_config(overrides={"paths": {"work": "~/otp-test-w"}})
    assert cfg.work_dir == Path.home() / "otp-test-w"


@pytest.mark.parametrize("value", ["http", "80.5", ""])
def test_bad_env_port(value, monkeypatch):
    monkeypatch.setenv("OTP_PORT", value)
    if value == "":
        assert load_config().server.port == 8765      # an empty variable is "not set"
        return
    with pytest.raises(ValueError, match="OTP_PORT"):
        load_config()


def test_env_port_is_range_checked(monkeypatch):
    monkeypatch.setenv("OTP_PORT", "70000")
    with pytest.raises(ValueError, match="server.port"):
        load_config()


# --------------------------------------------------------------------------------------------------
# Precedence: defaults < settings < environment < overrides
# --------------------------------------------------------------------------------------------------


def test_overrides_beat_settings(tmp_path):
    settings = {"provisioning": {"default_mode": "secure", "firmware_channel": "latest", "jtag_lock": "true"},
                "builds": {"image": {"overrides": ["A=1"], "keep_raw_image": "true"}}}
    cfg = load(tmp_path, settings=settings)
    assert cfg.provisioning.default_mode == "secure" and cfg.provisioning.jtag_lock is True
    assert cfg.builds.image.overrides == ["A=1"] and cfg.builds.image.keep_raw_image is True
    cfg = load(tmp_path, settings=settings, provisioning={"default_mode": "open"}, builds={"auto": False})
    assert cfg.provisioning.default_mode == "open"            # override wins
    assert cfg.provisioning.firmware_channel == "latest"      # the rest of the sheet still applies
    assert cfg.provisioning.jtag_lock is True
    assert cfg.builds.auto is False
    assert cfg.builds.image.overrides == ["A=1"] and cfg.builds.image.keep_raw_image is True
    assert cfg.builds.image.builder_tag == "otp-image-builder:trixie"   # untouched default in a partial section


def test_env_beats_settings_and_overrides_beat_env(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    settings = {"server": {"port": "1111", "host": "10.0.0.1"},
                "paths": {"work": str(tmp_path / "sheetwork")},
                "provisioning": {"default_mode": "secure"}}
    cfg = load_config(settings=settings, repo_root=repo)
    assert cfg.server.port == 1111 and cfg.work_dir == tmp_path / "sheetwork"

    monkeypatch.setenv("OTP_WORK_DIR", str(tmp_path / "envwork"))
    monkeypatch.setenv("OTP_PORT", "2222")
    cfg = load_config(settings=settings, repo_root=repo)
    assert cfg.server.port == 2222 and cfg.work_dir == tmp_path / "envwork"
    assert cfg.server.host == "10.0.0.1"                      # the environment says nothing about it
    assert cfg.image_dir == repo.resolve() / "image"
    assert cfg.provisioning.default_mode == "secure"

    cfg = load_config(settings=settings, repo_root=repo,
                      overrides={"server": {"port": 3333}, "paths": {"work": str(tmp_path / "cli")}})
    assert cfg.server.port == 3333 and cfg.work_dir == tmp_path / "cli"
    assert cfg.provisioning.default_mode == "secure"


def test_empty_sections_keep_defaults(tmp_path):
    cfg = load(tmp_path, settings={"server": None, "builds": {"image": None}, "docker": {}, "image": None},
               provisioning=None)
    assert cfg.server.port == 8765
    assert cfg.builds.image.builder_tag == "otp-image-builder:trixie" and cfg.image.hostname == "pi5-{serial}"
    assert cfg.provisioning.default_mode == "open"
    assert cfg.docker.binary == "docker"
    assert cfg.unknown_keys == []


# --------------------------------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------------------------------


def test_relative_paths_are_repo_relative(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    cfg = load_config(
        repo_root=repo,
        overrides={"paths": {"work": "state"}, "server": {"browser": "tools/chrome.exe"}},
        settings={"docker": {"desktop_path": "D/docker.exe"}},
    )
    r = repo.resolve()
    assert cfg.repo_root == r
    assert cfg.work_dir == r / "state"
    assert cfg.server.browser == r / "tools" / "chrome.exe"
    assert cfg.docker.desktop_path == r / "D" / "docker.exe"
    assert cfg.external_dir == r / "external" and cfg.web_dir == r and cfg.image_dir == r / "image"


@pytest.mark.parametrize("layer", ["settings", "overrides"])
def test_retired_droneos_keys_are_dropped(tmp_path, caplog, layer):
    tree = {"paths": {"droneos": "external/droneos"}, "builds": {"image": {"config": "droneos.yaml"}}}
    cfg = load(tmp_path, settings=tree) if layer == "settings" else load(tmp_path, **tree)
    assert cfg.unknown_keys == [] and not hasattr(cfg, "droneos_dir")
    msgs = [r.getMessage() for r in caplog.records]
    assert any(f"config {layer}: paths.droneos is retired" in m for m in msgs)
    assert any(f"config {layer}: builds.image.config is retired" in m for m in msgs)


def test_server_browser_path(tmp_path):
    assert load(tmp_path).server.browser is None
    assert load(tmp_path, server={"browser": ""}).server.browser is None
    assert load(tmp_path, server={"browser": "   "}).server.browser is None
    exe = tmp_path / "Chrome" / "chrome.exe"
    cfg = load(tmp_path, server={"browser": str(exe)})
    assert cfg.server.browser == exe
    assert cfg.summary()["server"]["browser"] == str(exe)
    cfg = load(tmp_path, repo_root=tmp_path / "repo", server={"browser": "bin/../chrome.exe"})
    assert cfg.server.browser == (tmp_path / "repo").resolve() / "chrome.exe"
    with pytest.raises(ValueError, match="server.browser"):
        load(tmp_path, server={"browser": 5})


def test_empty_desktop_path_means_standard_location(tmp_path):
    cfg = load(tmp_path, settings={"docker": {"desktop_path": ""}})
    assert cfg.docker.desktop_path == load(tmp_path).docker.desktop_path


# --------------------------------------------------------------------------------------------------
# Values given as text (settings cells) and validation
# --------------------------------------------------------------------------------------------------


def test_text_values_from_cells(tmp_path):
    settings = {
        "provisioning": {"default_mode": " SECURE ", "jtag_lock": "TRUE", "recovery_passphrase": "yes",
                         "confirm_irreversible": "off", "erase_storage": "0", "firmware_channel": "Latest",
                         "max_piece_size": "0x8000000", "boot_conf": "[all]\r\nBOOT_ORDER=0xf1"},
        "builds": {"auto": "no", "image": {"overrides": ["A=1", " ", "B=2 "], "keep_raw_image": "y"}},
        "docker": {"start_desktop": "n", "idle_timeout": " 60 "},
    }
    cfg = load(tmp_path, settings=settings, server={"port": " 9000 ", "open_browser": "false"})
    p = cfg.provisioning
    assert p.default_mode == "secure" and p.firmware_channel == "latest"
    assert (p.jtag_lock, p.recovery_passphrase, p.confirm_irreversible, p.erase_storage) == (True, True, False, False)
    assert p.max_piece_size == 0x8000000
    assert p.boot_conf == "[all]\nBOOT_ORDER=0xf1\n"            # CRLF -> LF, trailing newline added
    assert cfg.builds.auto is False and cfg.builds.image.keep_raw_image is True
    assert cfg.builds.image.overrides == ["A=1", "B=2"]
    assert cfg.docker.start_desktop is False and cfg.docker.idle_timeout == 60
    assert cfg.server.port == 9000 and cfg.server.open_browser is False


BOOL_KEYS = [("server", "open_browser"), ("provisioning", "jtag_lock"), ("provisioning", "recovery_passphrase"),
             ("provisioning", "confirm_irreversible"), ("provisioning", "erase_storage"), ("builds", "auto"),
             ("builds.image", "keep_raw_image"), ("docker", "start_desktop")]


def _nested(section: str, key: str, value) -> dict:
    tree: dict = {key: value}
    for part in reversed(section.split(".")):
        tree = {part: tree}
    return tree


def _get(cfg, section: str, key: str):
    obj = cfg
    for part in section.split("."):
        obj = getattr(obj, part)
    return getattr(obj, key)


@pytest.mark.parametrize("section, key", BOOL_KEYS)
@pytest.mark.parametrize("text, expected", [
    ("true", True), ("TRUE", True), (" Yes ", True), ("on", True), ("1", True), ("y", True),
    ("false", False), ("FALSE", False), ("no", False), ("Off", False), ("0", False), ("n", False),
])
def test_bools_given_as_text(tmp_path, section, key, text, expected):
    cfg = load(tmp_path, settings=_nested(section, key, text))
    assert _get(cfg, section, key) is expected


@pytest.mark.parametrize("section, key", BOOL_KEYS)
@pytest.mark.parametrize("value", ["perhaps", "2", 2, "tru"])
def test_bad_bools(tmp_path, section, key, value):
    with pytest.raises(ValueError) as ei:
        load(tmp_path, settings=_nested(section, key, value))
    assert f"{section}.{key}" in str(ei.value)


@pytest.mark.parametrize("section, key, text, expected", [
    ("provisioning", "max_piece_size", "268435456", 268435456),
    ("provisioning", "max_piece_size", " 0x10000000 ", 0x10000000),
    ("provisioning", "max_piece_size", "1048576", 1 << 20),
    ("docker", "idle_timeout", "0", 0),
    ("docker", "idle_timeout", "3600", 3600),
    ("server", "port", "9000", 9000),
])
def test_ints_given_as_text(tmp_path, section, key, text, expected):
    assert _get(load(tmp_path, settings=_nested(section, key, text)), section, key) == expected


@pytest.mark.parametrize(
    "tree, needle",
    [
        ({"provisioning": {"default_mode": "paranoid"}}, "provisioning.default_mode"),
        ({"provisioning": {"default_mode": ""}}, "provisioning.default_mode"),
        ({"provisioning": {"default_mode": None}}, "provisioning.default_mode"),
        ({"provisioning": {"firmware_channel": "beta"}}, "provisioning.firmware_channel"),
        ({"provisioning": {"max_piece_size": "abc"}}, "provisioning.max_piece_size"),
        ({"provisioning": {"max_piece_size": "1.5"}}, "provisioning.max_piece_size"),
        ({"provisioning": {"max_piece_size": "1048575"}}, "provisioning.max_piece_size"),   # < 1 MiB
        ({"provisioning": {"max_piece_size": ""}}, "provisioning.max_piece_size"),
        ({"provisioning": {"boot_conf": ""}}, "provisioning.boot_conf"),
        ({"provisioning": {"boot_conf": "  \n "}}, "provisioning.boot_conf"),
        ({"provisioning": {"boot_conf": ["[all]"]}}, "provisioning.boot_conf"),
        ({"server": {"port": 70000}}, "server.port"),
        ({"server": {"port": "0"}}, "server.port"),
        ({"server": {"port": "abc"}}, "server.port"),
        ({"server": {"port": True}}, "server.port"),
        ({"docker": {"idle_timeout": -5}}, "docker.idle_timeout"),
        ({"docker": {"idle_timeout": "-1"}}, "docker.idle_timeout"),
        ({"builds": {"image": {"overrides": {"a": 1}}}}, "builds.image.overrides"),
        ({"builds": {"image": {"overrides": [{"a": 1}]}}}, "builds.image.overrides"),
        ({"builds": {"tools": {"image_tag": ["x"]}}}, "builds.tools.image_tag"),
        ({"image": {"hostname": "bad_host"}}, "image.hostname"),
        ({"image": {"hostname": "-x"}}, "image.hostname"),
        ({"image": {"hostname": ""}}, "image.hostname"),
        ({"image": {"user": "root"}}, "image.user"),
        ({"image": {"user": "Pi"}}, "image.user"),
        ({"image": {"timezone": "Kyiv time"}}, "image.timezone"),
        ({"image": {"password_hash": "plain-password"}}, "image.password_hash"),
        ({"image": {"password_hash": "$6$a b$c"}}, "image.password_hash"),
        ({"image": {"ssh": "maybe"}}, "image.ssh"),
        ({"image": {"ssh_authorized_keys": ["not a key"]}}, "image.ssh_authorized_keys"),
        ({"image": {"wifi_ssid": "x" * 33}}, "image.wifi_ssid"),
        ({"image": {"wifi_ssid": " lead"}}, "image.wifi_ssid"),
        ({"image": {"wifi_password": "short"}}, "image.wifi_password"),
        ({"image": {"wifi_password": "x" * 64}}, "image.wifi_password"),
        ({"image": {"wifi_password": "naïve-pass"}}, "image.wifi_password"),
        ({"image": {"wifi_country": "Ukraine"}}, "image.wifi_country"),
        ({"image": {"name": "bad name"}}, "image.name"),
        ({"provisioning": {"secure_boot": "perhaps"}}, "provisioning.secure_boot"),
    ],
)
@pytest.mark.parametrize("layer", ["settings", "overrides"])
def test_validation_errors(tmp_path, tree, needle, layer):
    with pytest.raises(ValueError) as ei:
        if layer == "settings":
            load(tmp_path, settings=tree)
        else:
            load(tmp_path, **tree)
    assert needle in str(ei.value)


def test_image_overrides_shapes(tmp_path):
    assert load(tmp_path, builds={"image": {"overrides": "A=1"}}).builds.image.overrides == ["A=1"]
    assert load(tmp_path, builds={"image": {"overrides": None}}).builds.image.overrides == []
    assert load(tmp_path, builds={"image": {"overrides": [" A=1 ", "", 7]}}).builds.image.overrides == ["A=1", "7"]


@pytest.mark.parametrize("ovr", [["IGconf_image_pmap=crypt"], ["A=1", "  IGconf_image_pmap=clear"],
                                 "IGconf_image_pmap=clear"])
@pytest.mark.parametrize("layer", ["settings", "overrides"])
def test_image_pmap_override_rejected(tmp_path, ovr, layer):
    tree = {"builds": {"image": {"overrides": ovr}}}
    with pytest.raises(ValueError) as ei:
        load(tmp_path, settings=tree) if layer == "settings" else load(tmp_path, **tree)
    assert "IGconf_image_pmap" in str(ei.value) and "builds.image.overrides" in str(ei.value)
    # other IGconf_ overrides are fine
    cfg = load(tmp_path, builds={"image": {"overrides": ["IGconf_image_pmapx=1", "IGconf_device_hostname=d"]}})
    assert cfg.builds.image.overrides == ["IGconf_image_pmapx=1", "IGconf_device_hostname=d"]


def test_docker_idle_timeout(make_cfg, tmp_path):
    """docker.idle_timeout: default 30 min, configurable (also as text), 0 disables, negative rejected;
    DockerRunner uses it."""
    from otp_server.docker import DockerRunner

    cfg = make_cfg(tmp_path / "a")
    assert cfg.docker.idle_timeout == 1800
    assert cfg.summary()["docker"]["idle_timeout"] == 1800
    assert DockerRunner(cfg).idle_timeout == 1800.0

    cfg = make_cfg(tmp_path / "b", docker={"idle_timeout": 0})
    assert cfg.docker.idle_timeout == 0 and DockerRunner(cfg).idle_timeout == 0.0

    cfg = make_cfg(tmp_path / "c", docker={"idle_timeout": "90"})
    assert cfg.docker.idle_timeout == 90 and DockerRunner(cfg).idle_timeout == 90.0

    with pytest.raises(ValueError, match="docker.idle_timeout"):
        make_cfg(tmp_path / "d", docker={"idle_timeout": -5})


def test_text_fallbacks_for_empty_strings(tmp_path):
    cfg = load(tmp_path, server={"host": " "}, docker={"binary": ""}, builds={"gadget": {"targets": ""}})
    assert cfg.server.host == "127.0.0.1"
    assert cfg.docker.binary == "docker"
    assert cfg.builds.gadget.targets == "pi5-family"


# --------------------------------------------------------------------------------------------------
# Retired and unknown keys
# --------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("value, mode", [(True, "secure"), (False, "open"), ("true", "secure"), ("no", "open"),
                                         ("1", "secure"), (0, "open")])
@pytest.mark.parametrize("layer", ["settings", "overrides"])
def test_retired_secure_boot_becomes_default_mode(tmp_path, caplog, value, mode, layer):
    caplog.set_level(logging.WARNING, logger="otp_server.config")
    tree = {"provisioning": {"secure_boot": value}}
    cfg = load(tmp_path, settings=tree) if layer == "settings" else load(tmp_path, **tree)
    assert cfg.provisioning.default_mode == mode
    assert cfg.unknown_keys == []
    msgs = warnings_of(caplog)
    assert any(f"config {layer}: provisioning.secure_boot is retired" in m and f"default_mode: {mode}" in m
               for m in msgs), msgs


@pytest.mark.parametrize("layer", ["settings", "overrides"])
def test_retired_mode_becomes_default_mode(tmp_path, caplog, layer):
    caplog.set_level(logging.WARNING, logger="otp_server.config")
    tree = {"provisioning": {"mode": "secure"}}
    cfg = load(tmp_path, settings=tree) if layer == "settings" else load(tmp_path, **tree)
    assert cfg.provisioning.default_mode == "secure"
    assert cfg.unknown_keys == []
    assert any(f"config {layer}: provisioning.mode is retired" in m for m in warnings_of(caplog))


def test_retired_mode_value_is_still_validated(tmp_path):
    with pytest.raises(ValueError, match="provisioning.default_mode"):
        load(tmp_path, provisioning={"mode": "paranoid"})


@pytest.mark.parametrize("old, value", [("mode", "secure"), ("secure_boot", True), ("secure_boot", "perhaps")])
def test_retired_keys_ignored_when_default_mode_is_set(tmp_path, caplog, old, value):
    caplog.set_level(logging.WARNING, logger="otp_server.config")
    cfg = load(tmp_path, settings={"provisioning": {"default_mode": "open", old: value}})
    assert cfg.provisioning.default_mode == "open"
    assert cfg.unknown_keys == []
    assert any(f"provisioning.{old} is retired and ignored (provisioning.default_mode is set)" in m
               for m in warnings_of(caplog))


def test_retired_mode_wins_over_retired_secure_boot(tmp_path, caplog):
    caplog.set_level(logging.WARNING, logger="otp_server.config")
    cfg = load(tmp_path, provisioning={"mode": "open", "secure_boot": True})
    assert cfg.provisioning.default_mode == "open"
    msgs = warnings_of(caplog)
    assert any("provisioning.mode is retired; read as provisioning.default_mode: open" in m for m in msgs)
    assert any("provisioning.secure_boot is retired and ignored" in m for m in msgs)


def test_retired_mode_in_settings_and_default_mode_in_overrides(tmp_path):
    """Each layer is translated on its own; the overrides still win."""
    cfg = load(tmp_path, settings={"provisioning": {"secure_boot": True}}, provisioning={"default_mode": "open"})
    assert cfg.provisioning.default_mode == "open"
    cfg = load(tmp_path, settings={"provisioning": {"default_mode": "open"}}, provisioning={"mode": "secure"})
    assert cfg.provisioning.default_mode == "secure"


@pytest.mark.parametrize("layer", ["settings", "overrides"])
def test_retired_gadget_source_dropped(tmp_path, caplog, layer):
    caplog.set_level(logging.WARNING, logger="otp_server.config")
    tree = {"builds": {"gadget": {"source": "prebuilt", "targets": "pi5"}}}
    cfg = load(tmp_path, settings=tree) if layer == "settings" else load(tmp_path, **tree)
    assert cfg.builds.gadget.targets == "pi5"
    assert not hasattr(cfg.builds.gadget, "source")
    assert cfg.unknown_keys == []
    assert any(f"config {layer}: builds.gadget.source is retired" in m for m in warnings_of(caplog))


@pytest.mark.parametrize("layer", ["settings", "overrides"])
def test_retired_storage_keys_warn_and_are_not_fatal(tmp_path, caplog, layer):
    caplog.set_level(logging.WARNING, logger="otp_server.config")
    tree = {"storage": {"backend": "local", "local": {"dir": "reg"}, "gdrive": {"folder_id": "F123"}}}
    cfg = load(tmp_path, settings=tree) if layer == "settings" else load(tmp_path, **tree)
    assert not hasattr(cfg, "storage")
    assert "storage" not in cfg.summary()
    msgs = warnings_of(caplog)
    assert any(f"config {layer}: the storage section is retired and ignored" in m for m in msgs), msgs
    assert cfg.unknown_keys == []


@pytest.mark.parametrize("tree", [
    {"storage": {"backend": "local"}},
    {"storage": {"backend": "gsheets", "gsheets": {"spreadsheet": "KEY", "worksheet": "boards"}}},
])
def test_retired_storage_section_is_dropped_not_unknown(tmp_path, caplog, tree):
    caplog.set_level(logging.WARNING, logger="otp_server.config")
    cfg = load(tmp_path, settings=tree)
    assert cfg.unknown_keys == []
    assert not any("unknown key" in m for m in warnings_of(caplog))
    assert any("storage" in m and "retired" in m for m in warnings_of(caplog))


def test_unknown_keys_are_reported_not_fatal(tmp_path, caplog):
    caplog.set_level(logging.WARNING, logger="otp_server.config")
    cfg = load(tmp_path,
               settings={"sever": {"port": 1}, "builds": {"image": {"colour": "red"}}},
               provisioning={"secureboot": True, "default_mode": "secure"})
    assert cfg.unknown_keys == ["sever", "builds.image.colour", "provisioning.secureboot"]
    assert cfg.provisioning.default_mode == "secure"
    assert cfg.server.port == 8765
    msgs = warnings_of(caplog)
    assert "config settings: unknown key 'sever' ignored" in msgs
    assert "config settings: unknown key 'builds.image.colour' ignored" in msgs
    assert "config overrides: unknown key 'provisioning.secureboot' ignored" in msgs
    assert cfg.summary()["unknown_keys"] == cfg.unknown_keys


# --------------------------------------------------------------------------------------------------
# Config methods
# --------------------------------------------------------------------------------------------------


def test_ensure_dirs(tmp_path):
    cfg = load(tmp_path)
    assert not cfg.work_dir.exists()
    cfg.ensure_dirs()
    cfg.ensure_dirs()      # idempotent
    for sub in ("google", "modules", "artifacts/stage1", "artifacts/stage2", "artifacts/gadget",
                "artifacts/image/staging", "jobs", "tmp"):
        assert (cfg.work_dir / sub).is_dir(), sub
    assert not (cfg.work_dir / "registry").exists()     # the local JSON registry is gone


def test_summary(make_cfg, tmp_path):
    cfg = make_cfg(tmp_path, provisioning={"default_mode": "secure"}, server={"browser": str(tmp_path / "chrome.exe")})
    secret = "SUPER-SECRET-REFRESH-TOKEN"
    (cfg.work_dir / "google" / "token.json").write_text(json.dumps({"refresh_token": secret}), encoding="utf-8")
    s = cfg.summary()
    text = json.dumps(s)     # JSON-safe
    assert secret not in text
    assert set(s) == {"version", "repo_root", "work_dir", "image_dir", "settings", "server", "provisioning",
                      "image", "builds", "docker", "unknown_keys"}
    assert s["version"] == __version__
    assert s["repo_root"] == str(cfg.repo_root) and s["work_dir"] == str(cfg.work_dir)
    assert s["image_dir"] == str(cfg.image_dir)
    assert s["image"]["hostname"] == "pi5-{serial}" and s["image"]["password_set"] is False
    assert "password_hash" not in s["image"] and "wifi_password" not in s["image"]
    assert s["settings"] == "Google Sheets (worksheet settings)"
    assert s["server"] == {"host": "127.0.0.1", "port": 8765, "open_browser": False,
                           "browser": str(tmp_path / "chrome.exe")}
    prov = s["provisioning"]
    assert prov["modes"] == list(PROVISIONING_MODES) == ["open", "secure"]
    assert prov["default_mode"] == "secure"
    assert prov["recovery_passphrase"] is False and prov["max_piece_size"] == 268435456
    assert prov["boot_conf"] == DEFAULT_BOOT_CONF
    assert "secure_boot" not in prov and "mode" not in prov
    assert s["builds"]["auto"] is False
    assert s["builds"]["tools"] == {"image_tag": "otp-tools:latest"}
    assert s["builds"]["gadget"] == {"targets": "pi5-family", "image_tag": "otp-gadget-builder:trixie",
                                     "volume": "otp-pgm-work"}
    assert s["builds"]["image"] == {"overrides": [], "builder_tag": "otp-image-builder:trixie",
                                    "volume": "otp-image-work", "keep_raw_image": False}
    d = s["docker"]
    assert set(d) == {"binary", "start_desktop", "desktop_path", "idle_timeout"}
    assert d["desktop_path"] == (str(cfg.docker.desktop_path) if cfg.docker.desktop_path else None)
    assert s["unknown_keys"] == []


def test_summary_browser_none(make_cfg, tmp_path):
    assert make_cfg(tmp_path).summary()["server"]["browser"] is None


def test_apply_settings_replaces_sheet_backed_parts_only(tmp_path):
    repo = tmp_path / "repo"
    cfg = load_config(repo_root=repo, overrides={
        "paths": {"work": str(tmp_path / "w")},
        "server": {"host": "0.0.0.0", "port": 9001, "open_browser": False, "browser": "b/chrome.exe"},
    })
    cfg.bootstrap = {"server": {"port": 9001}}
    server_before = copy.deepcopy(cfg.server)
    new = load_config(
        repo_root=repo,
        settings={"provisioning": {"default_mode": "secure", "jtag_lock": "true", "firmware_channel": "latest"},
                  "image": {"hostname": "drone9", "wifi_ssid": "Field"},
                  "builds": {"auto": "false", "image": {"overrides": ["A=1"]}},
                  "docker": {"binary": "podman", "idle_timeout": "5"},
                  "typo": "1"},
        overrides={"paths": {"work": str(tmp_path / "other")}, "server": {"port": 1234, "host": "10.1.1.1"}},
    )
    cfg_id = id(cfg)
    cfg.apply_settings(new)
    assert id(cfg) == cfg_id
    assert cfg.image == new.image and cfg.image.hostname == "drone9" and cfg.image.wifi_ssid == "Field"
    assert cfg.provisioning == new.provisioning and cfg.provisioning.default_mode == "secure"
    assert cfg.provisioning.jtag_lock is True and cfg.provisioning.firmware_channel == "latest"
    assert cfg.builds == new.builds and cfg.builds.auto is False and cfg.builds.image.overrides == ["A=1"]
    assert cfg.docker == new.docker and cfg.docker.binary == "podman" and cfg.docker.idle_timeout == 5
    assert cfg.unknown_keys == ["typo"] and cfg.unknown_keys is not new.unknown_keys
    # bootstrap parts stay
    assert cfg.server == server_before and cfg.server.port == 9001 and cfg.server.host == "0.0.0.0"
    assert cfg.work_dir == tmp_path / "w"
    assert cfg.repo_root == repo.resolve()
    assert cfg.bootstrap == {"server": {"port": 9001}}
    assert cfg.summary()["provisioning"]["default_mode"] == "secure"
    # a later clean sheet clears the reported unknown keys again
    cfg.apply_settings(load_config(repo_root=repo, overrides={"paths": {"work": str(tmp_path / "w")}}))
    assert cfg.unknown_keys == [] and cfg.provisioning.default_mode == "open"
    assert cfg.image.hostname == "pi5-{serial}"


def test_make_cfg_fixture_is_isolated(make_cfg, tmp_path):
    cfg = make_cfg(tmp_path, provisioning={"default_mode": "secure"})
    assert cfg.work_dir == tmp_path / "work"
    assert cfg.work_dir.is_relative_to(tmp_path)
    assert (cfg.work_dir / "google").is_dir()
    assert cfg.provisioning.default_mode == "secure"
    assert cfg.builds.auto is False and cfg.server.open_browser is False
    assert cfg.bootstrap == {} and cfg.unknown_keys == []


# --------------------------------------------------------------------------------------------------
# image.* (what goes into the OS image)
# --------------------------------------------------------------------------------------------------


def test_image_settings_are_normalised(tmp_path):
    key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGabcdefghijklmnopqrstuvwxyz0123456789ABCD op@station"
    cfg = load(tmp_path, settings={"image": {
        "hostname": " Drone-7 ", "user": "ops", "timezone": "UTC", "ssh": "yes", "ssh_password_login": "no",
        "ssh_authorized_keys": f"{key}\r\n\n  ", "wifi_ssid": "Field Net", "wifi_password": "  spaced pass  ",
        "wifi_country": "pl", "wifi_hidden": "true", "password_hash": " $6$salt$abc ", "name": "fleet-img.v2"}})
    i = cfg.image
    assert (i.hostname, i.user, i.timezone, i.name) == ("drone-7", "ops", "UTC", "fleet-img.v2")
    assert i.ssh is True and i.ssh_password_login is False and i.ssh_authorized_keys == [key]
    assert i.wifi_ssid == "Field Net" and i.wifi_password == "  spaced pass  "    # spaces belong to a passphrase
    assert i.wifi_country == "PL" and i.wifi_hidden is True and i.password_hash == "$6$salt$abc"


def test_image_wifi_password_forms(tmp_path):
    hexkey = "AB" * 32
    assert load(tmp_path, image={"wifi_password": hexkey}).image.wifi_password == hexkey.lower()
    assert load(tmp_path, image={"wifi_password": "x" * 63}).image.wifi_password == "x" * 63
    assert load(tmp_path, image={"wifi_password": None}).image.wifi_password == ""
    assert load(tmp_path, image={"wifi_country": "00"}).image.wifi_country == "00"


def test_image_section_is_a_setting(tmp_path):
    cfg = load(tmp_path, settings={"image": {"hostname": "a1"}}, image={"user": "b1"})
    assert cfg.image.hostname == "a1" and cfg.image.user == "b1"      # sheet and overrides merge per key
