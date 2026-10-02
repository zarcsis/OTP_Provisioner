#!/usr/bin/env python3
"""OTP_Provisioner server for the end-to-end test (tests/web/run_e2e.py): no Google, in-memory registry.

    python -B tests/web/e2e_server.py --port N [--work DIR] [--registry DIR] [--set provisioning.KEY=VALUE ...]

Builds the real app with ``create_app(cfg, store=<MemoryStore>, auto_build=False)``: without a Google account
nothing is gated (``/api/status`` says ``google: null``, ``google_ready: true``) and no build is started by the
server itself (stage files that need a per-board quick build are still prepared, as in production).
``cfg = load_config(overrides=...)``: the defaults (= an empty settings sheet) plus ``server.port``, no browser,
``builds.auto`` off, ``paths.work`` from ``--work`` (default: the normal work dir, so the real tools image, gadget
and OS images are used) and every ``--set`` (values are JSON when they parse, else text).

``--registry DIR``: every record the store writes is also dumped to ``DIR/<serial>.json`` -- secrets included,
it is test data -- so the runner can check what the server stored (the registry itself stays in memory).
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys

sys.dont_write_bytecode = True   # no __pycache__ in the tree (the repo has no .gitignore on purpose)
TESTS = pathlib.Path(__file__).resolve().parents[1]
REPO = TESTS.parent
for p in (str(REPO), str(TESTS)):
    if p not in sys.path:
        sys.path.insert(0, p)

from memstore import MemoryStore  # noqa: E402
from otp_server.storage.base import record_to_json  # noqa: E402


class DumpingMemoryStore(MemoryStore):
    """A :class:`MemoryStore` that also writes every stored record to ``<dump_dir>/<serial>.json``."""

    def __init__(self, dump_dir: pathlib.Path | None) -> None:
        super().__init__()
        self.dump_dir = dump_dir
        if dump_dir is not None:
            dump_dir.mkdir(parents=True, exist_ok=True)

    def put(self, record: dict) -> None:
        super().put(record)
        if self.dump_dir is None:
            return
        rec = self.get(record["serial"])
        target = self.dump_dir / f"{rec['serial']}.json"
        tmp = target.with_name(target.name + ".tmp")
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            f.write(record_to_json(rec))
        os.replace(tmp, target)


def _set(tree: dict, assignment: str) -> None:
    key, sep, raw = assignment.partition("=")
    if not sep or not key.strip():
        raise SystemExit(f"--set expects section.key=value, got {assignment!r}")
    try:
        value = json.loads(raw)
    except ValueError:
        value = raw
    cur = tree
    parts = key.strip().split(".")
    for p in parts[:-1]:
        cur = cur.setdefault(p, {})
    cur[parts[-1]] = value


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--work", help="work directory (default: the normal one, with the real artifacts)")
    ap.add_argument("--registry", help="dump every stored record to DIR/<serial>.json")
    ap.add_argument("--set", action="append", default=[], metavar="KEY=VALUE",
                    help="a settings override, e.g. provisioning.recovery_passphrase=true (repeatable)")
    ns = ap.parse_args(argv)

    import uvicorn

    from otp_server.app import create_app
    from otp_server.config import load_config

    overrides: dict = {"server": {"host": ns.host, "port": ns.port, "open_browser": False}, "builds": {"auto": False}}
    if ns.work:
        overrides["paths"] = {"work": str(pathlib.Path(ns.work).resolve())}
    for a in ns.set:
        _set(overrides, a)
    cfg = load_config(overrides=overrides)
    store = DumpingMemoryStore(pathlib.Path(ns.registry).resolve() if ns.registry else None)
    app = create_app(cfg, store=store, auto_build=False)
    svc = app.state.services
    print(f"e2e server: work {cfg.work_dir}, store {store.backend}"
          f"{' (dump ' + str(store.dump_dir) + ')' if store.dump_dir else ''}, google {'off' if svc.account is None else 'ON'}, "
          f"default_mode {cfg.provisioning.default_mode}, recovery_passphrase {cfg.provisioning.recovery_passphrase}",
          flush=True)
    uvicorn.run(app, host=ns.host, port=ns.port, log_level="info")
    return 0


if __name__ == "__main__":
    sys.exit(main())
