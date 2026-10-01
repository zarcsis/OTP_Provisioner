"""Local JSON store: one ``<dir>/<serial>.json`` per module (the default backend)."""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from .base import StoreError, check_serial_key, normalize_record, record_to_json

log = logging.getLogger(__name__)


class LocalJsonStore:
    """Records as pretty-printed JSON files in one directory.

    Writes are atomic (temp file in the same directory + ``os.replace``) and serialized by a lock, so
    a crash never leaves a half-written record. On POSIX the files are created ``0600`` because they
    hold the board private key and device secret.

    :param directory: target directory, or a :class:`~otp_server.config.Config` (its
        ``storage.local_dir`` is used).
    """

    backend = "local"

    def __init__(self, directory: Any):
        if hasattr(directory, "storage"):
            directory = directory.storage.local_dir
        self.dir = Path(directory)
        self._lock = threading.RLock()

    # -- helpers ------------------------------------------------------------------------------------

    def _path(self, serial: str) -> Path:
        return self.dir / f"{check_serial_key(serial)}.json"

    def _read(self, p: Path) -> dict:
        try:
            with open(p, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except ValueError as exc:
            raise StoreError(f"corrupt module record {p}: {exc}") from None
        except OSError as exc:
            raise StoreError(f"cannot read module record {p}: {exc}") from None
        if not isinstance(data, dict):
            raise StoreError(f"corrupt module record {p}: not a JSON object")
        return normalize_record(data)

    # -- ModuleStore --------------------------------------------------------------------------------

    def get(self, serial: str) -> dict | None:
        p = self._path(serial)
        with self._lock:
            if not p.is_file():
                return None
            return self._read(p)

    def put(self, record: dict) -> None:
        rec = normalize_record(record)
        p = self._path(rec["serial"])
        text = record_to_json(rec)
        with self._lock:
            try:
                self.dir.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise StoreError(f"cannot create registry directory {self.dir}: {exc}") from None
            fd, tmp = tempfile.mkstemp(prefix=f".{p.stem}.", suffix=".tmp", dir=self.dir)
            try:
                with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(text)
                    fh.flush()
                    os.fsync(fh.fileno())
                if os.name == "posix":
                    os.chmod(tmp, 0o600)
                self._replace(tmp, p)
            except BaseException:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise

    @staticmethod
    def _replace(src: str, dst: Path) -> None:
        # Windows: os.replace fails with PermissionError while another process (AV, indexer, a reader)
        # briefly holds the target open. Retry for a moment before giving up.
        for attempt in range(20):
            try:
                os.replace(src, dst)
                return
            except PermissionError:
                if attempt == 19:
                    raise
                time.sleep(0.05)

    def list(self) -> list[dict]:
        with self._lock:
            if not self.dir.is_dir():
                return []
            out = []
            for p in sorted(self.dir.glob("*.json")):
                try:
                    out.append(self._read(p))
                except StoreError as exc:
                    log.warning("skipping unreadable module record: %s", exc)
            return out

    def describe(self) -> dict:
        ok, detail = True, ""
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            n = len(list(self.dir.glob("*.json")))
            detail = f"{n} module record(s)"
            if not os.access(self.dir, os.W_OK):
                ok, detail = False, f"registry directory is not writable: {self.dir}"
        except OSError as exc:
            ok, detail = False, f"registry directory unusable: {exc}"
        return {"backend": self.backend, "ok": ok, "location": str(self.dir), "detail": detail}
