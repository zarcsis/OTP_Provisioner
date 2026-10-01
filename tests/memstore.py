"""In-memory :class:`~otp_server.storage.base.ModuleStore` for the tests (the product stores in Google Sheets only)."""

from __future__ import annotations

import copy
import threading

from otp_server.storage.base import check_serial_key, normalize_record


class MemoryStore:
    """Upsert-by-serial records kept in a dict; ``puts`` counts writes (tests assert on it)."""

    backend = "memory"

    def __init__(self) -> None:
        self._records: dict[str, dict] = {}
        self._lock = threading.Lock()
        self.puts = 0

    def get(self, serial: str) -> dict | None:
        key = check_serial_key(serial)
        with self._lock:
            rec = self._records.get(key)
            return copy.deepcopy(rec) if rec is not None else None

    def put(self, record: dict) -> None:
        rec = normalize_record(record)
        key = check_serial_key(rec["serial"])
        rec["serial"] = key
        with self._lock:
            self._records[key] = copy.deepcopy(rec)
            self.puts += 1

    def list(self) -> list[dict]:
        with self._lock:
            return [copy.deepcopy(r) for r in self._records.values()]

    def describe(self) -> dict:
        return {"backend": self.backend, "ok": True, "location": "memory",
                "detail": f"{len(self._records)} module record(s)"}
