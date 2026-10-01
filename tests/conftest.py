"""Shared pytest fixtures for the OTP_Provisioner server tests.

* Puts the repository root on ``sys.path`` so ``import otp_server`` works from any cwd.
* ``make_cfg`` -- factory fixture building an isolated :class:`otp_server.config.Config`::

      def test_x(make_cfg, tmp_path):
          cfg = make_cfg(tmp_path)                                    # defaults, local store
          cfg = make_cfg(tmp_path, provisioning={"secure_boot": True})  # nested overrides
          cfg = make_cfg(tmp_path, repo_root=fake_repo, paths={"droneos": str(tmp_path / "droneos")})

  Signature: ``make_cfg(tmp_path, *, repo_root=None, ensure_dirs=True, **overrides) -> Config``.

  - ``work_dir`` is ``tmp_path / "work"`` (override with ``paths={"work": ...}``);
  - the config file is an empty ``tmp_path / "otp-test-config.yaml"``, so no user config
    (``<repo>/config.yaml``, ``<work>/config.yaml``, ``OTP_CONFIG``) can leak in; the ``OTP_*``
    environment variables are removed for the test;
  - ``server.open_browser`` and ``builds.auto`` default to ``False``;
  - ``overrides`` are nested dicts per top-level YAML section (``server``, ``paths``, ``storage``,
    ``provisioning``, ``builds``, ``docker``) merged over those test defaults;
  - ``repo_root`` defaults to the real repository (``external/`` submodules available);
  - the work directory tree is created (``cfg.ensure_dirs()``) unless ``ensure_dirs=False``.

* ``cfg``            -- ``make_cfg(tmp_path)``.
* ``store``          -- a :class:`~otp_server.storage.local.LocalJsonStore` on ``cfg``.
* ``module_service`` -- a :class:`~otp_server.modules.ModuleService` on ``cfg`` + ``store``.
"""

from __future__ import annotations

import copy
import shutil
import sys
from pathlib import Path

import pytest

# The repository has no .gitignore on purpose: keep bytecode out of the tree (pytest.ini also
# disables the cache provider). Only this conftest's own rewritten .pyc can be written before
# this line runs; pytest_sessionfinish removes it.
sys.dont_write_bytecode = True

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def pytest_sessionfinish(session, exitstatus):  # noqa: ARG001 - pytest hook signature
    shutil.rmtree(Path(__file__).resolve().parent / "__pycache__", ignore_errors=True)

from otp_server.config import Config, load_config  # noqa: E402

_OTP_ENV = ("OTP_CONFIG", "OTP_WORK_DIR", "OTP_STORAGE", "OTP_PORT")


def _merge(dst: dict, src: dict) -> dict:
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            _merge(dst[k], v)
        else:
            dst[k] = copy.deepcopy(v)
    return dst


@pytest.fixture
def make_cfg(monkeypatch):
    """Factory: ``make_cfg(tmp_path, *, repo_root=None, ensure_dirs=True, **overrides) -> Config``."""
    for name in _OTP_ENV:
        monkeypatch.delenv(name, raising=False)

    def _make(tmp_path: Path, *, repo_root: Path | None = None, ensure_dirs: bool = True, **overrides) -> Config:
        tmp_path = Path(tmp_path)
        tmp_path.mkdir(parents=True, exist_ok=True)
        cfg_file = tmp_path / "otp-test-config.yaml"
        if not cfg_file.exists():
            cfg_file.write_text("{}\n", encoding="utf-8")
        tree: dict = {
            "paths": {"work": str(tmp_path / "work")},
            "server": {"open_browser": False},
            "builds": {"auto": False},
        }
        _merge(tree, overrides)
        cfg = load_config(cfg_file, overrides=tree, repo_root=repo_root)
        if ensure_dirs:
            cfg.ensure_dirs()
        return cfg

    return _make


@pytest.fixture
def cfg(make_cfg, tmp_path) -> Config:
    return make_cfg(tmp_path)


@pytest.fixture
def store(cfg):
    from otp_server.storage.local import LocalJsonStore

    return LocalJsonStore(cfg.storage.local_dir)


@pytest.fixture
def module_service(cfg, store):
    from otp_server.modules import ModuleService

    return ModuleService(cfg, store)
