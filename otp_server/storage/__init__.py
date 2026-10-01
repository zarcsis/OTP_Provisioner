"""Module registry storage (SPEC section 6).

``make_store(cfg)`` returns the backend selected by ``cfg.storage.backend``:

* ``local``   -- :class:`LocalJsonStore`, ``<work>/registry/<serial>.json`` (default)
* ``gsheets`` -- :class:`GoogleSheetsStore`, one row per module in a Google Sheets worksheet
* ``gdrive``  -- :class:`GoogleDriveStore`, one ``<serial>.json`` per module in a Drive folder

The Google libraries are imported lazily by the Google backends, so the server starts without them
when the local backend is used. The Google backends connect lazily too (first ``get``/``put``/
``list``/``describe``); ``make_store`` only validates the configuration.
"""

from __future__ import annotations

from typing import Any

from .base import (
    FIELDS,
    MAX_EVENTS,
    STAGES,
    ModuleStore,
    StoreError,
    normalize_record,
    utc_now_iso,
)
from .gdrive import GoogleDriveStore
from .gsheets import GoogleSheetsStore
from .local import LocalJsonStore

__all__ = [
    "FIELDS",
    "MAX_EVENTS",
    "STAGES",
    "ModuleStore",
    "StoreError",
    "normalize_record",
    "utc_now_iso",
    "LocalJsonStore",
    "GoogleSheetsStore",
    "GoogleDriveStore",
    "make_store",
]


def make_store(cfg: Any) -> ModuleStore:
    """Build the configured store.

    :raises StoreError: with an actionable message when the backend is unknown or its settings
        (spreadsheet / folder id / credential files) are missing.
    """
    backend = cfg.storage.backend
    if backend == "local":
        return LocalJsonStore(cfg.storage.local_dir)
    if backend == "gsheets":
        return GoogleSheetsStore(cfg)
    if backend == "gdrive":
        return GoogleDriveStore(cfg)
    raise StoreError(f"unknown storage backend {backend!r} (expected local, gsheets or gdrive)")
