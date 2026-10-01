"""FastAPI application factory and the service container shared by the API and the CLI.

``create_app(cfg)`` builds every service eagerly (store, module registry, docker runner, job manager,
artifacts) so the app can be driven directly with ``httpx.ASGITransport`` in tests. Nothing here may
prevent the server from starting:

* a misconfigured or unreachable store (``StoreError``) is reported in ``/api/status`` and turns the
  module endpoints into HTTP 503;
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

    # ------------------------------------------------------------------ status pieces
    def storage_status(self) -> dict:
        """``store.describe()``, or a synthetic failure record when the store is unusable."""
        if self.store is None:
            return {
                "backend": getattr(self.cfg.storage, "backend", "?"),
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
                    artifacts: Any = None) -> Services:
    """Build the services for ``cfg``; injected objects are used as they are (tests)."""
    svc = Services(cfg=cfg)
    try:
        cfg.ensure_dirs()
    except OSError as exc:
        log.warning("cannot create the work directories under %s: %s", cfg.work_dir, exc)

    if modules is not None:
        svc.modules = modules
        svc.store = store if store is not None else getattr(modules, "store", None)
    else:
        if store is None:
            from .storage import StoreError, make_store

            try:
                store = make_store(cfg)
            except StoreError as exc:
                svc.store_error = str(exc)
                log.error("storage backend %r is not usable: %s", cfg.storage.backend, exc)
                store = None
            except Exception as exc:  # e.g. a Google library missing
                svc.store_error = f"{exc.__class__.__name__}: {exc}"
                log.error("storage backend %r could not be created: %s", cfg.storage.backend, svc.store_error)
                store = None
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
               artifacts: Any = None, auto_build: bool | None = None) -> FastAPI:
    """The FastAPI application serving the page (``/``, ``/css``, ``/js``) and the API (``/api``).

    :param auto_build: start missing builds at startup (default ``cfg.builds.auto``); runs in a
        background thread so startup never blocks on Docker.
    """
    from .api import api_router, install_error_handlers, static_router

    svc = create_services(cfg, store=store, docker=docker, jobs=jobs, modules=modules, artifacts=artifacts)
    do_auto = cfg.builds.auto if auto_build is None else bool(auto_build)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if do_auto:
            t = threading.Thread(target=svc.run_auto_build, name="auto-build", daemon=True)
            t.start()
            app.state.auto_build_thread = t
        yield

    app = FastAPI(title="OTP_Provisioner", version=__version__, lifespan=lifespan,
                  docs_url="/api/docs", redoc_url=None, openapi_url="/api/openapi.json")
    app.state.services = svc
    app.state.cfg = cfg
    install_error_handlers(app)
    app.add_middleware(HostOriginGuard, configured_host=str(getattr(cfg.server, "host", "") or ""))
    app.include_router(api_router(svc))
    app.include_router(static_router(cfg.web_dir))
    return app


__all__ = ["Services", "create_services", "create_app", "HostOriginGuard", "host_header_hostname"]
