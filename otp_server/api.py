"""HTTP API (SPEC section 8) and the static page routes.

Error mapping (every error body is ``{"detail": "..."}``):

* unusable serial / malformed body / unknown build target -> 400
* unknown module, job, stage or file                     -> 404
* artifact not ready yet                                  -> 409 ``{"ready": false, "reason", "job"}``
* store unavailable (``StoreError``)                      -> 503
* anything else while preparing a stage                   -> 500

Endpoints that touch the store or Docker are plain ``def`` handlers, so FastAPI runs them in its
thread pool and a slow Google call or a per-board quick build never blocks the event loop. Only the
SSE job log is ``async``.

Static files: ``/`` (index.html), ``/css/<file>`` and ``/js/<file>`` from the repository; nothing
else of the repository is reachable, there are no directory listings, and page assets are sent with
``Cache-Control: no-store``.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Body, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

log = logging.getLogger(__name__)

NO_STORE = {"Cache-Control": "no-store"}
BUILD_TARGETS = ("tools", "gadget", "image")
STAGES = (1, 2, 3)

MEDIA_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json",
    ".map": "application/json",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
    ".txt": "text/plain; charset=utf-8",
}


# ----------------------------------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------------------------------


def _exc_text(exc: BaseException) -> str:
    """Readable message; KeyError's str() would add quotes."""
    if isinstance(exc, KeyError) and exc.args:
        return str(exc.args[0])
    return str(exc) or exc.__class__.__name__


def _store_error_types() -> tuple[type[BaseException], ...]:
    from .storage.base import StoreError

    return (StoreError,)


def _not_ready_type() -> type[BaseException] | None:
    try:
        from .artifacts.common import NotReady
    except Exception:  # pragma: no cover - artifacts package broken
        return None
    return NotReady


def _not_ready_response(exc: Any) -> JSONResponse:
    if hasattr(exc, "to_dict"):
        body = exc.to_dict()
    else:  # pragma: no cover - defensive
        job = getattr(exc, "job", None)
        body = {"ready": False, "reason": getattr(exc, "reason", str(exc)),
                "job": job.to_dict() if hasattr(job, "to_dict") else job}
    return JSONResponse(body, status_code=409, headers=NO_STORE)


def valid_file_name(name: str) -> bool:
    """A stage file name: one plain path component (no separators, dot segments, drive/stream
    colons or control characters)."""
    if not name or len(name) > 255:
        return False
    if name in (".", "..") or name.startswith("."):
        return False
    if any(c in name for c in ("/", "\\", ":")):
        return False
    return not any(ord(c) < 32 for c in name)


def safe_static_path(base: Path, rel: str) -> Path | None:
    """``base/rel`` when it is an existing regular file inside ``base``; ``None`` otherwise."""
    if not rel or "\x00" in rel or ":" in rel:
        return None
    parts = rel.replace("\\", "/").split("/")
    if any(p in ("", ".", "..") for p in parts):
        return None
    try:
        root = base.resolve()
        p = (root.joinpath(*parts)).resolve()
    except (OSError, ValueError):
        return None
    if not p.is_relative_to(root) or not p.is_file():
        return None
    return p


def _media_type(p: Path) -> str:
    # Explicit table: on Windows mimetypes reads the registry, which may map .js to text/plain.
    return MEDIA_TYPES.get(p.suffix.lower(), "application/octet-stream")


def install_error_handlers(app: FastAPI) -> None:
    """Request validation errors become HTTP 400 with a readable ``detail`` string."""

    @app.exception_handler(RequestValidationError)
    async def _validation(_request: Request, exc: RequestValidationError) -> JSONResponse:
        msgs = []
        for err in exc.errors():
            loc = ".".join(str(x) for x in err.get("loc", ()) if x not in ("body",))
            msgs.append(f"{loc}: {err.get('msg', 'invalid')}" if loc else str(err.get("msg", "invalid")))
        return JSONResponse({"detail": "; ".join(msgs) or "invalid request"}, status_code=400)


# ----------------------------------------------------------------------------------------------------
# API
# ----------------------------------------------------------------------------------------------------


def api_router(svc: Any) -> APIRouter:
    """All ``/api`` routes, bound to a :class:`otp_server.app.Services` instance."""
    r = APIRouter(prefix="/api")
    StoreErrors = _store_error_types()
    NotReady = _not_ready_type()

    def modules() -> Any:
        if svc.modules is None:
            raise HTTPException(503, detail=f"module store is not usable: {svc.store_error or 'not configured'}")
        return svc.modules

    def artifacts() -> Any:
        if svc.artifacts is None:
            raise HTTPException(503, detail=f"artifacts are not available: {svc.artifacts_error or 'not configured'}")
        return svc.artifacts

    def call(fn, *args, **kwargs):
        """Run a service call, mapping domain errors to HTTP errors."""
        try:
            return fn(*args, **kwargs)
        except HTTPException:
            raise
        except StoreErrors as exc:
            raise HTTPException(503, detail=f"module store error: {_exc_text(exc)}") from None
        except KeyError as exc:
            raise HTTPException(404, detail=_exc_text(exc)) from None
        except ValueError as exc:
            raise HTTPException(400, detail=_exc_text(exc)) from None

    def view(rec: dict) -> dict:
        return modules().public_view(rec)

    def check_stage(n: int) -> int:
        if n not in STAGES:
            raise HTTPException(404, detail=f"no stage {n} (stages are 1, 2 and 3)")
        return n

    def body_dict(body: Any, what: str = "body") -> dict:
        if body is None:
            return {}
        if not isinstance(body, dict):
            raise HTTPException(400, detail=f"{what} must be a JSON object")
        return body

    # ---------------------------------------------------------------- status
    @r.get("/status")
    def get_status() -> JSONResponse:
        return JSONResponse(svc.status(), headers=NO_STORE)

    # ---------------------------------------------------------------- modules
    @r.get("/modules")
    def list_modules() -> JSONResponse:
        m = modules()
        recs = call(m.list)
        return JSONResponse([m.public_view(x) for x in recs], headers=NO_STORE)

    @r.post("/modules/hello")
    def hello(body: Any = Body(default=None)) -> dict:
        b = body_dict(body)
        serial = b.get("serial")
        if not isinstance(serial, str):
            raise HTTPException(400, detail="board reported no usable USB serial: 'serial' must be a string")
        info = {k: b[k] for k in ("chip", "board", "usb", "rom_stage") if k in b and b[k] is not None}
        rec, created = call(modules().hello, serial, info)
        return {"module": view(rec), "created": bool(created)}

    @r.get("/modules/{serial}")
    def get_module(serial: str) -> JSONResponse:
        rec = call(modules().get, serial)
        if rec is None:
            raise HTTPException(404, detail=f"unknown module {serial!r}")
        return JSONResponse(view(rec), headers=NO_STORE)

    def require_module(serial: str) -> dict:
        rec = call(modules().get, serial)
        if rec is None:
            raise HTTPException(404, detail=f"unknown module {serial!r}")
        return rec

    def run_stage(fn, serial: str, n: int, *args):
        """Artifacts call with NotReady -> 409 and unexpected failures -> 500."""
        try:
            return call(fn, serial, n, *args), None
        except HTTPException:
            raise
        except FileNotFoundError as exc:
            raise HTTPException(404, detail=_exc_text(exc)) from None
        except Exception as exc:
            if NotReady is not None and isinstance(exc, NotReady):
                return None, _not_ready_response(exc)
            log.exception("stage %s for %s failed", n, serial)
            raise HTTPException(500, detail=f"cannot prepare stage {n} for {serial}: {_exc_text(exc)}") from None

    @r.get("/modules/{serial}/stage/{n}")
    def stage_manifest(serial: str, n: int):
        check_stage(n)
        require_module(serial)
        manifest, not_ready = run_stage(artifacts().stage_manifest, serial, n, "")
        if not_ready is not None:
            return not_ready
        return JSONResponse(manifest, headers=NO_STORE)

    @r.get("/modules/{serial}/stage/{n}/files/{name:path}")
    def stage_file(serial: str, n: int, name: str):
        check_stage(n)
        if not valid_file_name(name):
            raise HTTPException(404, detail="no such file")
        require_module(serial)
        path, not_ready = run_stage(artifacts().stage_file, serial, n, name)
        if not_ready is not None:
            return not_ready
        p = Path(path)
        if not p.is_file():
            raise HTTPException(404, detail=f"{name} is not available")
        return FileResponse(p, media_type="application/octet-stream", headers=NO_STORE)

    @r.post("/modules/{serial}/stage/{n}/result")
    def stage_result(serial: str, n: int, body: Any = Body(default=None)) -> dict:
        check_stage(n)
        b = body_dict(body)
        rec, verdict = call(modules().record_result, serial, n, b)
        return {"module": view(rec), "verdict": {"ok": bool(verdict.get("ok")), "notes": list(verdict.get("notes", []))}}

    @r.post("/modules/{serial}/facts")
    def module_facts(serial: str, body: Any = Body(default=None)) -> dict:
        b = body_dict(body)
        rec = call(modules().add_facts, serial, b)
        return {"module": view(rec)}

    @r.post("/modules/{serial}/otp")
    def module_otp(serial: str, body: Any = Body(default=None)) -> dict:
        """Operator override of the recorded OTP lock state (``python -m otp_server modules
        mark-locked|mark-unlocked`` sends it here when a server is running, so the change goes through
        this process's store cache instead of being overwritten by it)."""
        b = body_dict(body)
        action = b.get("action")
        note = str(b.get("note") or "")[:200]
        if action == "mark-locked":
            rec = call(modules().mark_locked, serial, note)
        elif action == "mark-unlocked":
            rec = call(modules().mark_unlocked, serial, note)
        else:
            raise HTTPException(400, detail="action must be 'mark-locked' or 'mark-unlocked'")
        return {"module": view(rec)}

    # ---------------------------------------------------------------- fastboot
    @r.post("/fastboot/identify")
    def fastboot_identify(body: Any = Body(default=None)) -> dict:
        b = body_dict(body)
        serialno = b.get("serialno")
        if not isinstance(serialno, str):
            raise HTTPException(400, detail="board reported no usable USB serial: 'serialno' must be a string")
        vars_ = b.get("vars")
        if vars_ is not None and not isinstance(vars_, dict):
            raise HTTPException(400, detail="vars must be a JSON object")
        rec, created = call(modules().identify_fastboot, serialno, vars_ or {})
        return {"module": view(rec), "created": bool(created)}

    # ---------------------------------------------------------------- builds
    @r.get("/builds")
    def get_builds() -> JSONResponse:
        return JSONResponse(svc.artifacts_status(), headers=NO_STORE)

    @r.post("/builds/{target}")
    def start_build(target: str, body: Any = Body(default=None)) -> dict:
        if target not in BUILD_TARGETS:
            raise HTTPException(400, detail=f"unknown build target {target!r} (expected tools, gadget or image)")
        b = body_dict(body)
        force = b.get("force", False)
        if not isinstance(force, bool):
            raise HTTPException(400, detail="force must be true or false")
        job = call(artifacts().start_build, target, force)
        return {"job": job.to_dict()}

    # ---------------------------------------------------------------- jobs
    @r.get("/jobs")
    def list_jobs() -> JSONResponse:
        return JSONResponse([j.to_dict() for j in svc.jobs.list()], headers=NO_STORE)

    @r.get("/jobs/{job_id}")
    def get_job(job_id: str) -> JSONResponse:
        job = svc.jobs.get(job_id)
        if job is None:
            raise HTTPException(404, detail=f"unknown job {job_id!r}")
        return JSONResponse(job.to_dict(), headers=NO_STORE)

    @r.get("/jobs/{job_id}/log")
    async def job_log(job_id: str) -> StreamingResponse:
        if svc.jobs.get(job_id) is None:
            raise HTTPException(404, detail=f"unknown job {job_id!r}")
        return StreamingResponse(
            svc.jobs.sse(job_id),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    return r


# ----------------------------------------------------------------------------------------------------
# static page
# ----------------------------------------------------------------------------------------------------


def static_router(web_dir: Path) -> APIRouter:
    """``/`` -> index.html, ``/css/<file>``, ``/js/<file>``; nothing else."""
    r = APIRouter()
    web = Path(web_dir)

    def send(p: Path | None) -> FileResponse:
        if p is None:
            raise HTTPException(404, detail="not found")
        return FileResponse(p, media_type=_media_type(p), headers=NO_STORE)

    @r.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return send(safe_static_path(web, "index.html"))

    @r.get("/css/{path:path}", include_in_schema=False)
    def css(path: str) -> FileResponse:
        return send(safe_static_path(web / "css", path))

    @r.get("/js/{path:path}", include_in_schema=False)
    def js(path: str) -> FileResponse:
        return send(safe_static_path(web / "js", path))

    return r


__all__ = ["api_router", "static_router", "install_error_handlers", "valid_file_name", "safe_static_path"]
