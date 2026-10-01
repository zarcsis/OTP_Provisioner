"""Module registry storage (SPEC section 6): one Google Sheets worksheet, one row per module.

``make_store(account)`` returns the :class:`GoogleSheetsStore` of a signed-in
:class:`~otp_server.google_account.GoogleAccount`. The Google libraries are imported lazily and the store
connects lazily (first ``get``/``put``/``list``/``describe``). Nothing is kept in local files.
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
from .gsheets import GoogleSheetsStore

__all__ = [
    "FIELDS",
    "MAX_EVENTS",
    "STAGES",
    "ModuleStore",
    "StoreError",
    "normalize_record",
    "utc_now_iso",
    "GoogleSheetsStore",
    "make_store",
]


def make_store(account: Any) -> ModuleStore:
    """The Google Sheets store of ``account`` (connects on first use)."""
    return GoogleSheetsStore(account)
