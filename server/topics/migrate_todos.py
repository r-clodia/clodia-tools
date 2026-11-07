"""One-shot migration: manual topic deadlines → to-do items (clodia-platform#658).

Usage (inside the gateway container, against the topic store):

    python3 -m server.topics.migrate_todos --root /datadir/clodia-vault/topics-store
    python3 -m server.topics.migrate_todos --root /datadir/clodia-vault/topics-store --apply

Dry-run is the default: nothing is written without `--apply`.

For every topic whose `meta.json` has NO `todos` key and a valid manual
`deadline`, one item `{"text": "Topic deadline", "due": <deadline>}` is written,
so the derived deadline is unchanged. Topics that already carry `todos` are
left alone, which makes the script idempotent: a second `--apply` writes
nothing.

`## Prossimi passi` stays narrative in the summary. Bullets that contain a
date are NOT converted — they are listed in the report, for the owner to turn
into to-do items if they are real action items.

The read path already converts a pre-#658 deadline on the fly (same item, same
id), so running this is not urgent: it makes the conversion explicit on disk
and produces the report.
"""
from __future__ import annotations

import argparse
import json
import sys

from .local_fs import LocalFsStorage
from .service import (LEGACY_DEADLINE_TODO_ID, VALID_TIER, TopicService,
                      _action_points, _coerce_deadline, _legacy_deadline_todo,
                      _parse_deadline)
from .storage import NotFound, VersionConflict


def migrate(svc: TopicService, apply: bool = False) -> dict:
    """Returns the report; writes only with `apply=True`."""
    report: dict = {"apply": apply, "migrated": [], "already": [],
                    "no_deadline": 0, "errors": [], "dated_bullets": []}
    for tier in VALID_TIER:
        for e in svc.s.list(tier):
            if e.kind != "dir":
                continue
            ref = f"{tier}/{e.name}"
            mp = svc._meta_p(tier, e.name)
            try:
                r = svc.s.read(mp)
                raw = json.loads(r.data.decode())
            except NotFound:
                continue
            except Exception as exc:  # noqa: BLE001 — reported, never fatal
                report["errors"].append({"topic": ref, "error": type(exc).__name__})
                continue
            if not isinstance(raw, dict):
                report["errors"].append({"topic": ref, "error": "meta is not an object"})
                continue
            try:
                summary = svc.s.read(svc._summary_p(tier, e.name)).data.decode()
            except Exception:  # noqa: BLE001 — no summary, no bullets
                summary = ""
            dated = [b for b in _action_points(summary) if _parse_deadline(b)]
            if dated:
                report["dated_bullets"].append({"topic": ref, "bullets": dated})
            if "todos" in raw:
                report["already"].append(ref)
                continue
            deadline = _coerce_deadline(raw.get("deadline"), ctx=ref)
            if not deadline:
                report["no_deadline"] += 1
                continue
            entry = {"topic": ref, "deadline": deadline}
            if apply:
                new = dict(raw)
                new["todos"] = [_legacy_deadline_todo(deadline)]
                try:
                    # The raw meta goes back as it was, plus `todos`: the
                    # migration adds one key, it does not re-normalise the rest.
                    svc.s.write(mp, json.dumps(new, ensure_ascii=False, indent=2).encode(),
                                if_version=r.version)
                except VersionConflict:
                    report["errors"].append({"topic": ref,
                                             "error": "meta changed during migration: re-run"})
                    continue
            report["migrated"].append(entry)
    return report


def _print(report: dict) -> None:
    mode = "APPLY" if report["apply"] else "DRY-RUN (nothing written; use --apply)"
    print(f"migrate_todos — {mode}")
    verb = "migrated" if report["apply"] else "would migrate"
    print(f"\n{verb}: {len(report['migrated'])}")
    for m in report["migrated"]:
        print(f"  {m['topic']}: deadline {m['deadline']} → todo "
              f"'{LEGACY_DEADLINE_TODO_ID}' (Topic deadline, due {m['deadline']})")
    print(f"already with todos: {len(report['already'])}")
    print(f"no manual deadline: {report['no_deadline']}")
    if report["errors"]:
        print(f"errors: {len(report['errors'])}")
        for err in report["errors"]:
            print(f"  {err['topic']}: {err['error']}")
    print(f"\ndated bullets in '## Prossimi passi' (NOT converted, for the owner):"
          f" {sum(len(d['bullets']) for d in report['dated_bullets'])}")
    for d in report["dated_bullets"]:
        print(f"  {d['topic']}")
        for b in d["bullets"]:
            print(f"    - {b}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", required=True, help="topic store root (local-fs)")
    ap.add_argument("--apply", action="store_true", help="write (default: dry-run)")
    ap.add_argument("--json", action="store_true", help="print the report as JSON")
    a = ap.parse_args(argv)
    report = migrate(TopicService(LocalFsStorage(a.root)), apply=a.apply)
    if a.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        _print(report)
    return 1 if report["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
