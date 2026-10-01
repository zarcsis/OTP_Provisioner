"""Google Drive store (google-api-python-client, Drive v3): one ``<serial>.json`` file per module.

Setup (once, by the operator):

1. In a Google Cloud project enable the Google Drive API.
2. Pick who owns the files this store creates:

   * ``auth: service_account`` -- the folder **must be in a Shared Drive** (Google Workspace). Add the
     key's ``client_email`` to that Shared Drive as *Content manager* (or *Contributor*). A service
     account has no Drive storage quota, so it cannot own files: every ``files().create`` into a
     folder in a user's personal "My Drive" fails with 403 ``storageQuotaExceeded``, even when the
     folder is shared with it as Editor.
   * ``auth: oauth`` -- for a folder in a personal "My Drive". Create an OAuth "Desktop app" client,
     download its JSON, and run ``python -m otp_server login`` once on the station: it opens the
     browser and caches the token in ``storage.gdrive.token`` (refreshed automatically). The server
     itself never opens a browser; a missing or rejected token is reported and the operator runs
     ``login`` again.

3. Set ``storage.gdrive.folder_id`` to the folder id (the last part of the folder URL).
   ``python -m otp_server login`` with a service account checks that the folder can be opened and
   warns when it is not in a Shared Drive.

Each file holds the whole normalized record as JSON (including the board secrets: anyone who can
open the folder can read them). Metadata and contents are cached in memory: ``get``/``put`` look a
serial up again when the cache is older than 30 s or on a miss, ``list`` re-lists the folder at most
every 10 s and only downloads files whose ``modifiedTime`` changed; ``describe`` never refreshes.
"""

from __future__ import annotations

import copy
import io
import json
import logging
import threading
import time
from typing import Any, Callable

from .base import StoreError, check_serial_key, normalize_record, record_to_json
from .gsheets import (
    LOGIN_CMD,
    LOGIN_TIMEOUT,
    check_google_credentials,
    exc_named,
    explain_refresh_error,
    fs_permission_error,
    is_auth_failure,
    is_network_error,
    load_oauth_token,
    oauth_login,
    service_account_email,
)

log = logging.getLogger(__name__)

DRIVE_SCOPES = ["https://www.googleapis.com/auth/drive"]
FOLDER_MIME = "application/vnd.google-apps.folder"
FILE_FIELDS = "id,name,modifiedTime"


def _q(value: str) -> str:
    """Escape a value for a Drive query string literal."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _status(exc: BaseException) -> int | None:
    resp = getattr(exc, "resp", None)
    st = getattr(resp, "status", None)
    try:
        return int(st) if st is not None else None
    except (TypeError, ValueError):
        return None


def _reasons(exc: BaseException) -> set[str]:
    """The ``reason`` codes of a Drive API error (``error.errors[].reason`` / ``error.details[].reason``)."""
    out: set[str] = set()
    content = getattr(exc, "content", None)
    try:
        data = json.loads(content.decode("utf-8") if isinstance(content, bytes) else str(content or ""))
        err = data.get("error") if isinstance(data, dict) else None
        if isinstance(err, dict):
            for k in ("errors", "details"):
                for d in err.get(k) or []:
                    if isinstance(d, dict) and d.get("reason"):
                        out.add(str(d["reason"]))
    except (ValueError, TypeError, AttributeError):
        pass
    return out


class GoogleDriveStore:
    """Module registry as JSON files in one Google Drive folder.

    :param cfg: the server :class:`~otp_server.config.Config` (``cfg.storage.gdrive`` is used).
    :param client: an already built Drive v3 service (``googleapiclient.discovery.build("drive",
        "v3", ...)``) or a test double with the same ``files()`` API. When ``None`` the service is
        built lazily from the configured credentials.
    :param clock: monotonic clock (tests).
    """

    backend = "gdrive"
    INDEX_MAX_AGE = 30.0
    LIST_MAX_AGE = 10.0
    RETRY_CONNECT_AFTER = 10.0

    def __init__(self, cfg: Any, *, client: Any = None, clock: Callable[[], float] = time.monotonic):
        g = cfg.storage.gdrive
        self.gcfg = g
        if not g.folder_id:
            raise StoreError(
                "storage.gdrive.folder_id is not set: with auth: service_account create the folder in a "
                "Shared Drive that has the service account's client_email as Content manager; with auth: "
                "oauth any folder in your My Drive works. Put the folder id here"
            )
        if client is None:
            check_google_credentials(g, "storage.gdrive")
        self.folder_id = g.folder_id.strip()
        self._svc = client
        self._own_client = client is None   # only a service built here may be dropped and rebuilt
        self._clock = clock
        self._lock = threading.RLock()
        self._connected = False
        self._folder_name = ""
        self._drive_id = ""  # Shared Drive id of the folder ("" = a user's My Drive)
        self._files: dict[str, dict] = {}  # serial -> {"id","name","modifiedTime"}
        self._records: dict[str, dict] = {}  # serial -> record
        self._rec_mtime: dict[str, str] = {}  # serial -> modifiedTime of the cached content
        self._seen_at: dict[str, float] = {}  # serial -> clock of the last lookup
        self._loaded_at = float("-inf")
        self._last_attempt = float("-inf")
        self._last_error: str | None = None

    # -- credentials / service ----------------------------------------------------------------------

    @property
    def location(self) -> str:
        name = f"{self._folder_name} " if self._folder_name else ""
        return f"Google Drive folder {name}({self.folder_id})"

    def _credentials(self) -> Any:
        """Credentials for request threads: never interactive (see :meth:`login`)."""
        g = self.gcfg
        if g.auth == "service_account":
            from google.oauth2 import service_account

            return service_account.Credentials.from_service_account_file(str(g.credentials), scopes=DRIVE_SCOPES)
        return load_oauth_token(g, "storage.gdrive", DRIVE_SCOPES, "Google Drive")

    @staticmethod
    def _build(creds: Any) -> Any:
        try:
            from googleapiclient.discovery import build
        except ImportError:
            raise StoreError(
                "google-api-python-client is not installed (pip install -r requirements.txt)"
            ) from None
        # googleapiclient's own httplib2 transport carries a 60 s socket timeout
        return build("drive", "v3", credentials=creds, cache_discovery=False)

    def _make_service(self) -> Any:
        return self._build(self._credentials())

    def login(self, *, timeout: float = LOGIN_TIMEOUT, open_browser: bool = True) -> str:
        """``python -m otp_server login``: with ``auth: oauth`` run the browser login (bounded by
        ``timeout``) and cache the token; with a service account only check that the folder opens.
        Then connect once and return a one-line result for the operator.

        :raises StoreError: the login or the connectivity check failed.
        """
        g = self.gcfg
        svc = None
        if g.auth == "oauth":
            creds = oauth_login(g, "storage.gdrive", DRIVE_SCOPES, "Google Drive", timeout=timeout,
                                open_browser=open_browser)
            svc = self._build(creds)
            head = f"OAuth login done, token saved to {g.token}"
        else:
            head = f"service account {service_account_email(g)}"
        with self._lock:
            if svc is not None:
                self._svc = svc
            self._connected = False
            self._last_error = None
            self._last_attempt = float("-inf")
            self._connect()
            msg = f"{head}: {self.location} is reachable, {len(self._records)} module record(s)"
            if g.auth == "service_account" and not self._drive_id:
                msg += (
                    "; WARNING: the folder is not in a Shared Drive, so the service account cannot create "
                    "files in it (403 storageQuotaExceeded): move it to a Shared Drive or use auth: oauth"
                )
            return msg

    def _who(self) -> str:
        if self.gcfg.auth == "service_account":
            return "the service account's client_email (as a member of the Shared Drive that holds the folder)"
        return f"the Google account you logged in with ({LOGIN_CMD})"

    def _drop_client_on_auth_failure(self, exc: BaseException) -> None:
        """A rejected token/key: forget the connection so the next connect (after the retry throttle)
        rebuilds the service and re-reads the token file -- a ``python -m otp_server login`` done while
        the server runs then takes effect without a restart."""
        if not is_auth_failure(exc):
            return
        self._connected = False
        if self._own_client:
            self._svc = None

    def _explain(self, exc: BaseException) -> str:
        self._drop_client_on_auth_failure(exc)
        g = self.gcfg
        st = _status(exc)
        if st == 404:
            return (
                f"Google Drive folder {self.folder_id!r} (or a file in it) not found: check "
                f"storage.gdrive.folder_id and give {self._who()} access to the folder"
            )
        if st == 403:
            reasons = _reasons(exc)
            if "storageQuotaExceeded" in reasons or "storage quota" in str(exc).lower():
                if g.auth == "service_account":
                    return (
                        f"Google Drive refused to create a file ({exc}): a service account has no Drive "
                        "storage quota and cannot own files in a user's My Drive, even in a folder shared "
                        "with it as Editor. Put storage.gdrive.folder_id in a Shared Drive (Google "
                        "Workspace) with the service account's client_email as Content manager or "
                        f"Contributor, or switch storage.gdrive.auth to oauth and run '{LOGIN_CMD}'"
                    )
                return f"Google Drive storage of the logged-in account is full ({exc}): free up space or add storage"
            return f"Google Drive denied access ({exc}); give {self._who()} write access to the folder"
        if exc_named(exc, "RefreshError"):
            return explain_refresh_error(g, "storage.gdrive", "Google Drive", exc)
        if st == 401:
            fix = (
                f"check the service-account key {g.credentials}"
                if g.auth == "service_account"
                else f"run '{LOGIN_CMD}' to log in again"
            )
            return f"Google Drive authentication failed ({exc}); {fix}"
        if st is not None:
            return f"Google Drive API error {st}: {exc}"
        if is_network_error(exc):
            return f"Google Drive unreachable ({type(exc).__name__}: {exc}); check the network -- retrying"
        if fs_permission_error(exc):
            return f"local file-system permission error (not a Drive sharing problem): {exc}"
        if isinstance(exc, FileNotFoundError):
            return f"Google credentials file not found: {exc}"
        return f"Google Drive error: {type(exc).__name__}: {exc}"

    def _connect(self) -> Any:
        if self._connected:
            return self._svc
        now = self._clock()
        if self._last_error is not None and now - self._last_attempt < self.RETRY_CONNECT_AFTER:
            raise StoreError(self._last_error)
        self._last_attempt = now
        try:
            if self._svc is None:
                self._svc = self._make_service()
            meta = (
                self._svc.files()
                .get(fileId=self.folder_id, fields="id,name,mimeType,driveId", supportsAllDrives=True)
                .execute()
            )
            if meta.get("mimeType") != FOLDER_MIME:
                raise StoreError(f"storage.gdrive.folder_id {self.folder_id!r} is not a folder ({meta.get('mimeType')})")
            self._folder_name = str(meta.get("name") or "")
            self._drive_id = str(meta.get("driveId") or "")
            if self.gcfg.auth == "service_account" and not self._drive_id:
                log.warning(
                    "Google Drive folder %s is in a user's My Drive: a service account cannot create files "
                    "there (403 storageQuotaExceeded); use a Shared Drive folder or storage.gdrive.auth: oauth",
                    self.folder_id,
                )
            self._connected = True
            self._refresh_all()
        except StoreError as exc:
            self._connected = False
            self._last_error = str(exc)
            raise
        except Exception as exc:
            self._connected = False
            self._last_error = self._explain(exc)
            raise StoreError(self._last_error) from None
        self._last_error = None
        return self._svc

    # -- Drive calls --------------------------------------------------------------------------------

    def _list_files(self, q: str) -> list[dict]:
        out: list[dict] = []
        token = None
        while True:
            kwargs: dict[str, Any] = {
                "q": q,
                "fields": f"nextPageToken, files({FILE_FIELDS})",
                "supportsAllDrives": True,
                "includeItemsFromAllDrives": True,
                "pageSize": 1000,
            }
            if token:
                kwargs["pageToken"] = token
            resp = self._svc.files().list(**kwargs).execute()
            out.extend(resp.get("files", []))
            token = resp.get("nextPageToken")
            if not token:
                return out

    def _download(self, file_id: str) -> dict | None:
        data = self._svc.files().get_media(fileId=file_id, supportsAllDrives=True).execute()
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        try:
            obj = json.loads(data)
        except ValueError:
            log.warning("Drive file %s is not valid JSON; ignored", file_id)
            return None
        if not isinstance(obj, dict):
            log.warning("Drive file %s is not a JSON object; ignored", file_id)
            return None
        return normalize_record(obj)

    @staticmethod
    def _serial_of(name: str) -> str | None:
        if not name.endswith(".json"):
            return None
        try:
            return check_serial_key(name[: -len(".json")])
        except StoreError:
            return None

    def _absorb(self, key: str, files: list[dict]) -> None:
        """Update the cache for ``key`` from the files the listing returned (newest wins)."""
        now = self._clock()
        self._seen_at[key] = now
        if not files:
            self._files.pop(key, None)
            self._records.pop(key, None)
            self._rec_mtime.pop(key, None)
            return
        if len(files) > 1:
            log.warning("Drive folder has %d files named %s.json; using the newest", len(files), key)
        f = max(files, key=lambda x: str(x.get("modifiedTime") or ""))
        self._files[key] = f
        mtime = str(f.get("modifiedTime") or "")
        if mtime and self._rec_mtime.get(key) == mtime:
            return  # unchanged since the last download (readable or not)
        rec = self._download(f["id"])
        if rec is None:
            self._records.pop(key, None)
            self._rec_mtime[key] = mtime  # remember the unreadable version: do not download it again
            return
        if rec["serial"] != key:
            log.warning("Drive file %s.json holds serial %r; using the file name", key, rec["serial"])
            rec["serial"] = key
        self._records[key] = rec
        self._rec_mtime[key] = mtime

    def _refresh_all(self) -> None:
        q = f"'{_q(self.folder_id)}' in parents and trashed = false and name contains '.json'"
        try:
            files = self._list_files(q)
            grouped: dict[str, list[dict]] = {}
            for f in files:
                key = self._serial_of(str(f.get("name") or ""))
                if key is not None:
                    grouped.setdefault(key, []).append(f)
            for key in set(self._records) | set(self._rec_mtime) | set(self._files):
                if key not in grouped:
                    self._absorb(key, [])
            for key, fl in grouped.items():
                self._absorb(key, fl)
        except StoreError:
            raise
        except Exception as exc:
            raise StoreError(self._explain(exc)) from None
        self._loaded_at = self._clock()

    def _refresh_one(self, key: str) -> None:
        q = f"name = '{_q(key)}.json' and '{_q(self.folder_id)}' in parents and trashed = false"
        try:
            self._absorb(key, self._list_files(q))
        except StoreError:
            raise
        except Exception as exc:
            raise StoreError(self._explain(exc)) from None

    def _fresh(self, key: str) -> bool:
        seen = max(self._seen_at.get(key, float("-inf")), self._loaded_at)
        return key in self._records and self._clock() - seen <= self.INDEX_MAX_AGE

    # -- ModuleStore --------------------------------------------------------------------------------

    def get(self, serial: str) -> dict | None:
        key = check_serial_key(serial)
        with self._lock:
            self._connect()
            if not self._fresh(key):
                self._refresh_one(key)
            rec = self._records.get(key)
            return copy.deepcopy(rec) if rec is not None else None

    def put(self, record: dict) -> None:
        rec = normalize_record(record)
        key = check_serial_key(rec["serial"])
        rec["serial"] = key
        payload = record_to_json(rec).encode("utf-8")
        try:
            from googleapiclient.http import MediaIoBaseUpload
        except ImportError:
            raise StoreError("google-api-python-client is not installed (pip install -r requirements.txt)") from None

        def media() -> Any:
            return MediaIoBaseUpload(io.BytesIO(payload), mimetype="application/json", resumable=False)

        with self._lock:
            svc = self._connect()
            try:
                if key not in self._files:
                    self._refresh_one(key)
                meta = None
                f = self._files.get(key)
                if f is not None:
                    try:
                        meta = (
                            svc.files()
                            .update(fileId=f["id"], media_body=media(), fields=FILE_FIELDS, supportsAllDrives=True)
                            .execute()
                        )
                    except Exception as exc:
                        if _status(exc) != 404:
                            raise
                        meta = None  # deleted behind our back: create it again
                if meta is None:
                    meta = (
                        svc.files()
                        .create(
                            body={"name": f"{key}.json", "parents": [self.folder_id], "mimeType": "application/json"},
                            media_body=media(),
                            fields=FILE_FIELDS,
                            supportsAllDrives=True,
                        )
                        .execute()
                    )
            except StoreError:
                raise
            except Exception as exc:
                raise StoreError(self._explain(exc)) from None
            self._files[key] = dict(meta)
            self._records[key] = copy.deepcopy(rec)
            self._rec_mtime[key] = str(meta.get("modifiedTime") or "")
            self._seen_at[key] = self._clock()

    def list(self) -> list[dict]:
        with self._lock:
            self._connect()
            if self._clock() - self._loaded_at > self.LIST_MAX_AGE:
                self._refresh_all()
            return [copy.deepcopy(self._records[k]) for k in sorted(self._records)]

    def describe(self) -> dict:
        with self._lock:
            try:
                self._connect()
            except StoreError as exc:
                return {"backend": self.backend, "ok": False, "location": self.location, "detail": str(exc)}
            return {
                "backend": self.backend,
                "ok": True,
                "location": self.location,
                "detail": f"{len(self._records)} module record(s) cached",
            }
