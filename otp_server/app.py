"""FastAPI application factory and the service container shared by the API and the CLI.

``create_app(cfg)`` builds every service eagerly (Google account, store, module registry, docker runner,
job manager, artifacts) so the app can be driven directly with ``httpx.ASGITransport`` in tests. Nothing
here may prevent the server from starting:

* signing in to Google is required: until the operator has signed in (``/api/google/login``) and the
  settings worksheet has been read, the module, stage and build endpoints answer HTTP 401 and the page
  shows only the sign-in. The settings are re-read from the sheet while the server runs
  (:meth:`Services.refresh_settings`), so changing them needs no restart;
* an unreachable store (``StoreError``) is reported in ``/api/status`` and turns the module endpoints
  into HTTP 503;
* Docker being down is only reported (``/api/status`` -> ``docker.ok = false``); builds fail as jobs;
* the optional auto-build (``builds.auto``) runs in a background thread after startup.

Every request passes :class:`HostOriginGuard` first: the API has no authentication and hands out
per-board signing files and LUKS passphrases, so a request is served only when its ``Host`` names
this machine (loopback, or the configured listen address), and a state-changing request only when it
carries no foreign ``Origin``/``Referer``. That closes DNS rebinding and cross-site POSTs.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import socket
import threading
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI

from . import __version__

log = logging.getLogger(__name__)


@dataclass
class Services:
    """Everything the HTTP API and the CLI need. ``store``/``modules`` are ``None`` when the store
    could not be created (``store_error`` says why); ``artifacts`` is ``None`` when the artifacts
    facade could not be created (``artifacts_error``)."""

    cfg: Any
    store: Any = None
    modules: Any = None
    docker: Any = None
    jobs: Any = None
    artifacts: Any = None
    store_error: str = ""
    artifacts_error: str = ""
    auto_build_error: str = ""
    extra: dict = field(default_factory=dict)
    #: The Google login and the settings worksheet (None in tests that inject their own store).
    account: Any = None
    settings: Any = None
    #: CLI flags / test overrides applied on top of the sheet settings (``load_config(overrides=...)``).
    bootstrap: dict = field(default_factory=dict)
    settings_error: str = ""
    settings_unknown: list = field(default_factory=list)
    settings_loaded_at: float | None = None
    settings_checked_at: float = float("-inf")
    auto_build: bool | None = None
    auto_build_done: bool = False
    _settings_lock: Any = field(default_factory=threading.RLock, repr=False)

    SETTINGS_TTL = 15.0

    # ------------------------------------------------------------------ Google + settings
    def refresh_settings(self, force: bool = False) -> bool:
        """Read the settings worksheet (at most every :attr:`SETTINGS_TTL` s unless ``force``) and apply it
        to ``cfg`` in place. Returns whether settings from the sheet are in effect. A broken sheet keeps
        the last good settings and reports why (``settings_error``)."""
        if self.account is None or self.settings is None:
            return True
        with self._settings_lock:
            now = time.monotonic()
            loaded = self.settings_loaded_at is not None
            if not force and now - self.settings_checked_at < self.SETTINGS_TTL:
                return loaded
            self.settings_checked_at = now
            if not self.account.has_token():
                self.settings_error = "not signed in to Google"
                return loaded
            from .config import load_config
            from .google_account import NotSignedIn
            from .settings import decode_rows
            from .storage.base import StoreError

            try:
                rows = self.settings.read()
                tree, unknown = decode_rows(rows)
                new = load_config(overrides=self.bootstrap or None, repo_root=self.cfg.repo_root, settings=tree)
            except NotSignedIn as exc:
                # Google rejected the login (revoked / expired): the station is signed out again, so the
                # page shows its sign-in gate instead of failing module calls with 503
                self.settings_error = str(exc)
                self.settings_loaded_at = None
                return False
            except StoreError as exc:
                self.settings_error = str(exc)
                return loaded
            except ValueError as exc:
                self.settings_error = f"invalid value in the settings sheet: {exc}"
                return loaded
            self.cfg.apply_settings(new)
            self.settings_unknown = list(unknown)
            self.settings_error = ""
            self.settings_loaded_at = now
            return True

    def google_ready(self) -> bool:
        """Signed in and the settings sheet read (always true when no Google account is wired: tests)."""
        if self.account is None:
            return True
        return self.account.has_token() and self.refresh_settings()

    def google_problem(self) -> str:
        if self.account is None:
            return ""
        if not self.account.client_configured():
            return (f"no Google OAuth client: save the 'Desktop app' client JSON as {self.account.client_file}, "
                    "then sign in on the page")
        if not self.account.has_token():
            return "sign in to Google first (button on the page, or python -m otp_server login)"
        return self.settings_error or self.account.last_error or "the settings sheet has not been read yet"

    def finish_google_login(self, state: str, code: str, error: str) -> str:
        """The OAuth redirect came back to ``/``: exchange the code; returns where to send the browser."""
        from urllib.parse import quote

        from .storage.base import StoreError

        if error:
            return "/?google_error=" + quote(f"Google sign-in was not completed: {error}")
        try:
            self.account.finish_login(state, code)
        except StoreError as exc:
            return "/?google_error=" + quote(str(exc))
        self.on_google_login()
        return "/"

    def on_google_login(self) -> None:
        """A new login: forget the old connection, read the settings, start the auto build once."""
        if self.store is not None and hasattr(self.store, "reset"):
            self.store.reset()
        self.refresh_settings(force=True)
        self.start_auto_build()

    def google_logout(self) -> None:
        if self.account is not None:
            self.account.logout()
        if self.store is not None and hasattr(self.store, "reset"):
            self.store.reset()
        with self._settings_lock:
            self.settings_loaded_at = None
            self.settings_checked_at = float("-inf")
            self.settings_error = "not signed in to Google"

    def start_auto_build(self) -> None:
        """Run :meth:`run_auto_build` in a thread once (after the first successful sign-in / startup)."""
        want = self.cfg.builds.auto if self.auto_build is None else self.auto_build
        if not want or self.auto_build_done or not self.google_ready():
            return
        self.auto_build_done = True
        threading.Thread(target=self.run_auto_build, name="auto-build", daemon=True).start()

    # ------------------------------------------------------------------ image settings (the page's form)
    #: Fields of POST /api/image besides the two passwords.
    IMAGE_FIELDS = ("name", "hostname", "timezone", "user", "ssh", "ssh_password_login", "ssh_authorized_keys",
                    "wifi_ssid", "wifi_country", "wifi_hidden")

    def image_settings(self) -> dict:
        """The ``image.*`` settings for the page: no password or hash, only whether they are set; plus the time
        zones and Wi-Fi countries the image knows (``choices``)."""
        from . import image_choices, imageconfig

        img = self.cfg.image
        view = imageconfig.public_view(img)
        view["ssh_authorized_keys"] = list(img.ssh_authorized_keys)
        return {"settings": view, "warnings": imageconfig.warnings(img), "choices": image_choices.page_view()}

    def save_image_settings(self, body: dict) -> dict:
        """Validate and save the image settings form; the image is rebuilt when ``builds.auto`` is on.

        ``password`` / ``wifi_password``: absent or null = unchanged, ``""`` = remove, else the new value
        (the account password is stored as a SHA-512 crypt hash, never as text).

        :raises ValueError: an unknown field or an invalid value (HTTP 400).
        :raises StoreError: the settings sheet could not be written (HTTP 503).
        """
        from dataclasses import asdict

        from .config import parse_image
        from .passhash import sha512_crypt
        from .storage.base import StoreError

        unknown = sorted(set(body) - set(self.IMAGE_FIELDS) - {"password", "wifi_password"})
        if unknown:
            raise ValueError("unknown image setting(s): " + ", ".join(unknown))
        changed = {k: body[k] for k in self.IMAGE_FIELDS if k in body and body[k] is not None}
        password = body.get("password")
        if password is not None:
            if not isinstance(password, str):
                raise ValueError("password must be a string")
            changed["password_hash"] = sha512_crypt(password) if password else ""
        wifi_password = body.get("wifi_password")
        if wifi_password is not None:
            if not isinstance(wifi_password, str):
                raise ValueError("wifi_password must be a string")
            changed["wifi_password"] = wifi_password
        if not changed:
            return {**self.image_settings(), "saved": []}
        merged = {**asdict(self.cfg.image), **changed}
        img = parse_image(merged)                      # ValueError names the field
        values = asdict(img)
        updates = {f"image.{k}": values[k] for k in changed}
        if self.settings is None:                      # no sheet wired (tests): apply in place
            self.cfg.image = img
        else:
            self.settings.write(updates)
            if not self.refresh_settings(force=True) or self.settings_error:
                raise StoreError(self.settings_error or "the settings sheet could not be read back")
        log.info("image settings saved: %s", ", ".join(sorted(updates)))
        want = self.cfg.builds.auto if self.auto_build is None else self.auto_build
        if want and self.artifacts is not None:
            threading.Thread(target=self.run_auto_build, name="image-settings-build", daemon=True).start()
        return {**self.image_settings(), "saved": sorted(updates)}

    def settings_status(self) -> dict:
        return {
            "ok": self.account is None or self.settings_loaded_at is not None,
            "error": self.settings_error,
            "unknown": list(self.settings_unknown),
            "worksheet": "settings",
        }

    # ------------------------------------------------------------------ status pieces
    def storage_status(self) -> dict:
        """``store.describe()``, or a synthetic failure record when the store is unusable."""
        if self.store is None:
            return {
                "backend": "gsheets",
                "ok": False,
                "location": "",
                "detail": self.store_error or "store not configured",
            }
        try:
            d = dict(self.store.describe())
        except Exception as exc:  # describe() should never raise; stay defensive
            return {"backend": getattr(self.store, "backend", "?"), "ok": False, "location": "",
                    "detail": f"store error: {exc}"}
        d.setdefault("backend", getattr(self.store, "backend", "?"))
        d.setdefault("ok", False)
        d.setdefault("location", "")
        d.setdefault("detail", "")
        return d

    def docker_status(self) -> dict:
        if self.docker is None:
            return {"ok": False, "version": "", "detail": "docker runner not available", "arm64": None}
        try:
            d = dict(self.docker.status())
        except Exception as exc:
            return {"ok": False, "version": "", "detail": f"docker status failed: {exc}", "arm64": None}
        for k, v in (("ok", False), ("version", ""), ("detail", ""), ("arm64", None)):
            d.setdefault(k, v)
        return d

    def artifacts_status(self) -> dict:
        """``{"tools", "gadget", "image"}``; a failing target is reported as not ready, never raised."""
        targets = ("tools", "gadget", "image")
        if self.artifacts is None:
            return {t: _missing_artifact(t, self.artifacts_error or "artifacts not available") for t in targets}
        try:
            st = dict(self.artifacts.status())
        except Exception as exc:
            log.exception("artifact status failed")
            return {t: _missing_artifact(t, f"status failed: {exc}") for t in targets}
        for t in targets:
            st.setdefault(t, _missing_artifact(t, "unknown"))
        return st

    def jobs_status(self) -> list[dict]:
        """The running job, else the last one, for every target that has jobs (newest first)."""
        if self.jobs is None:
            return []
        seen: set[str] = set()
        out: list[dict] = []
        for job in self.jobs.list():
            if job.target in seen:
                continue
            seen.add(job.target)
            active = self.jobs.active(job.target)
            out.append((active or job).to_dict())
        return out

    def usb_driver_status(self) -> dict | None:
        from .winusb import check_usb_driver

        try:
            return check_usb_driver()
        except Exception as exc:  # a read-only probe must never break /api/status
            return {"platform": "windows", "rpiboot": False, "fastboot": False, "detail": f"driver check failed: {exc}"}

    def status(self) -> dict:
        """The ``/api/status`` document (SPEC section 8)."""
        return {
            "version": __version__,
            "google": self.account.status() if self.account is not None else None,
            "google_ready": self.google_ready(),
            "settings": self.settings_status(),
            "config": self.cfg.summary(),
            "storage": self.storage_status(),
            "docker": self.docker_status(),
            "usb_driver": self.usb_driver_status(),
            "artifacts": self.artifacts_status(),
            "jobs": self.jobs_status(),
        }

    # ------------------------------------------------------------------ auto build
    def run_auto_build(self) -> list:
        """``artifacts.auto_build()``; errors are logged and remembered, never raised."""
        if self.artifacts is None:
            return []
        try:
            started = list(self.artifacts.auto_build() or [])
        except Exception as exc:
            self.auto_build_error = str(exc) or exc.__class__.__name__
            log.warning("auto build could not start: %s", self.auto_build_error)
            return []
        for job in started:
            log.info("auto build: %s (job %s)", getattr(job, "title", "?"), getattr(job, "id", "?"))
        return started


def _missing_artifact(target: str, detail: str) -> dict:
    return {"target": target, "ready": False, "source": None, "version": "", "path": "", "size": None,
            "built": None, "detail": detail, "job": None}


def create_services(cfg: Any, *, store: Any = None, docker: Any = None, jobs: Any = None, modules: Any = None,
                    artifacts: Any = None, account: Any = None, bootstrap: dict | None = None) -> Services:
    """Build the services for ``cfg``; injected objects are used as they are (tests).

    Without an injected store the registry is the Google spreadsheet of ``account`` (a
    :class:`~otp_server.google_account.GoogleAccount` for this repo + work dir unless given), and the
    settings come from its ``settings`` worksheet. ``bootstrap`` holds the CLI overrides that stay on top
    of the sheet settings.
    """
    svc = Services(cfg=cfg)
    svc.bootstrap = dict(bootstrap or {})
    try:
        cfg.ensure_dirs()
    except OSError as exc:
        log.warning("cannot create the work directories under %s: %s", cfg.work_dir, exc)
    if account is None and store is None and modules is None:
        from .google_account import GoogleAccount

        account = GoogleAccount(cfg.repo_root, cfg.work_dir)
    if account is not None:
        from .settings import SettingsSheet

        svc.account = account
        svc.settings = SettingsSheet(account)

    if modules is not None:
        svc.modules = modules
        svc.store = store if store is not None else getattr(modules, "store", None)
    else:
        if store is None:
            from .storage import GoogleSheetsStore

            store = GoogleSheetsStore(svc.account)
        svc.store = store
        if store is not None:
            from .modules import ModuleService

            svc.modules = ModuleService(cfg, store)

    if docker is None:
        from .docker import DockerRunner

        docker = DockerRunner(cfg)
    svc.docker = docker

    if jobs is None:
        from .jobs import JobManager

        jobs = JobManager(cfg.work_dir)
    svc.jobs = jobs

    if artifacts is None:
        try:
            from .artifacts import Artifacts

            artifacts = Artifacts(cfg, docker, jobs, svc.modules)
        except Exception as exc:
            svc.artifacts_error = f"{exc.__class__.__name__}: {exc}"
            log.exception("artifacts could not be initialised")
            artifacts = None
    svc.artifacts = artifacts
    return svc


# ----------------------------------------------------------------------------------------------------
# DNS rebinding / CSRF guard
# ----------------------------------------------------------------------------------------------------

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
WILDCARD_HOSTS = frozenset({"", "0.0.0.0", "::"})
SAFE_METHODS = frozenset({"GET", "HEAD"})


def _norm_hostname(h: str) -> str:
    return h.strip().strip("[]").rstrip(".").lower()


def host_header_hostname(value: str) -> str:
    """Hostname part of a ``Host`` header (``127.0.0.1:8765``, ``[::1]:8765``, ``localhost``); ports
    are ignored on purpose (a loopback proxy on another port is still this machine)."""
    v = value.strip()
    if v.startswith("["):
        end = v.find("]")
        return _norm_hostname(v[1:end] if end > 0 else v[1:])
    if v.count(":") == 1:
        v = v.split(":", 1)[0]
    return _norm_hostname(v)


def _is_ip_literal(h: str) -> bool:
    try:
        ipaddress.ip_address(h)
    except ValueError:
        return False
    return True


def host_header_port(value: str) -> int | None:
    """Port of a ``Host`` header, ``None`` when it has none (``localhost``, ``[::1]``)."""
    v = value.strip()
    if v.startswith("["):
        end = v.find("]")
        rest = v[end + 1:] if end > 0 else ""
        port = rest[1:] if rest.startswith(":") else ""
    elif v.count(":") == 1:
        port = v.split(":", 1)[1]
    else:
        port = ""
    return int(port) if port.isdigit() else None


_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}


class HostOriginGuard:
    """ASGI middleware rejecting (HTTP 403) requests that do not come from this machine's page.

    * ``Host`` must name a loopback address (``127.0.0.1``, ``localhost``, ``::1``) or the configured
      listen address. When the server listens on a wildcard (``0.0.0.0`` / ``::``) any IP literal and
      the machine's host name are accepted too -- a rebinding attack needs a DNS name, never an IP.
    * A method other than GET/HEAD must carry no ``Origin`` (curl, the CLI) or one whose hostname
      passes the same test; without ``Origin`` a ``Referer``, when present, is checked instead. A
      browser always sends ``Origin`` on a cross-site POST, so no web page can start builds or
      write the registry.

    Hostnames are compared, not ports.
    """

    def __init__(self, app: Any, configured_host: str = ""):
        self.app = app
        h = _norm_hostname(configured_host or "")
        self.wildcard = h in WILDCARD_HOSTS
        self.allowed = set(LOOPBACK_HOSTS)
        if not self.wildcard:
            self.allowed.add(h)
        else:
            try:
                name = _norm_hostname(socket.gethostname())
            except OSError:
                name = ""
            if name:
                self.allowed.add(name)

    def host_allowed(self, hostname: str) -> bool:
        if not hostname:
            return False
        if hostname in self.allowed:
            return True
        return self.wildcard and _is_ip_literal(hostname)

    def check(self, method: str, headers: dict[str, str]) -> str:
        """``""`` when the request may pass, else the reason for the 403."""
        host = headers.get("host")
        if host is None:
            return "request has no Host header"
        hn = host_header_hostname(host)
        if not self.host_allowed(hn):
            return (f"Host {hn or host!r} is not allowed: open the page at http://127.0.0.1:<port>/ "
                    "(DNS rebinding protection)")
        if method.upper() in SAFE_METHODS:
            return ""
        origin = headers.get("origin")
        if origin is not None:
            what, url = "Origin", origin
        elif headers.get("referer") is not None:
            what, url = "Referer", headers["referer"]
        else:
            return ""  # no browser involved (CLI tools, scripts)
        try:
            parts = urlsplit(url.strip())
            ohn = _norm_hostname(parts.hostname or "")
            oport = parts.port if parts.port is not None else _DEFAULT_PORTS.get(parts.scheme.lower())
        except ValueError:
            ohn, oport = "", None
        if ohn in self.allowed:
            return ""   # loopback / configured host / this machine: ports are not compared
        # Wildcard listen: an IP-literal Origin is accepted only when it IS this server (same host and
        # port as the Host header), never an arbitrary site reached by IP address.
        if self.wildcard and _is_ip_literal(ohn) and ohn == hn and oport is not None \
                and oport == (host_header_port(host) or _DEFAULT_PORTS["http"]):
            return ""
        return f"cross-site {method.upper()} rejected: {what} {url.strip()[:200]!r} is not this server's page"

    async def __call__(self, scope, receive, send):
        if scope.get("type") not in ("http", "websocket"):
            return await self.app(scope, receive, send)
        headers: dict[str, str] = {}
        for k, v in scope.get("headers") or ():
            name = k.decode("latin-1").lower()
            if name not in headers:  # first one wins; a duplicated Host is not trusted anyway
                headers[name] = v.decode("latin-1")
        reason = self.check(scope.get("method", "GET"), headers)
        if not reason:
            return await self.app(scope, receive, send)
        log.warning("rejected %s %s: %s", scope.get("method", "?"), scope.get("path", "?"), reason)
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        body = json.dumps({"detail": reason}).encode("utf-8")
        await send({"type": "http.response.start", "status": 403,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(body)).encode("ascii")),
                                (b"cache-control", b"no-store")]})
        await send({"type": "http.response.body", "body": body})


def create_app(cfg: Any, *, store: Any = None, docker: Any = None, jobs: Any = None, modules: Any = None,
               artifacts: Any = None, auto_build: bool | None = None, account: Any = None,
               bootstrap: dict | None = None) -> FastAPI:
    """The FastAPI application serving the page (``/``, ``/css``, ``/js``) and the API (``/api``).

    :param auto_build: start missing builds once signed in (default ``builds.auto`` from the settings
        sheet); runs in a background thread so startup never blocks on Docker or Google.
    """
    from .api import api_router, install_error_handlers, static_router

    svc = create_services(cfg, store=store, docker=docker, jobs=jobs, modules=modules, artifacts=artifacts,
                          account=account, bootstrap=bootstrap)
    svc.auto_build = auto_build

    def startup() -> None:
        svc.refresh_settings(force=True)
        svc.start_auto_build()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        t = threading.Thread(target=startup, name="startup", daemon=True)
        t.start()
        app.state.startup_thread = t
        yield

    app = FastAPI(title="OTP_Provisioner", version=__version__, lifespan=lifespan,
                  docs_url="/api/docs", redoc_url=None, openapi_url="/api/openapi.json")
    app.state.services = svc
    app.state.cfg = cfg
    install_error_handlers(app)
    app.add_middleware(HostOriginGuard, configured_host=str(getattr(cfg.server, "host", "") or ""))
    app.include_router(api_router(svc))
    app.include_router(static_router(cfg.web_dir, oauth_callback=svc.finish_google_login if svc.account else None))
    return app


__all__ = ["Services", "create_services", "create_app", "HostOriginGuard", "host_header_hostname"]
