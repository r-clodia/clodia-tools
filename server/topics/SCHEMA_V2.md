# Topic Schema v2

`meta.json` uses schema version `2`.

Required fields:

- `schema_version`: `2`
- `tier`: `SEAL-0` | `SEAL-1` | `SEAL-2` | `SEAL-3` | `SEAL-4`
- `status`: `active` | `on-hold` | `done` | `archived`
- `deadline`: ISO date `YYYY-MM-DD` or `null`

Removed fields:

- `minutes`

Topic-level instructions live in `files/AGENTS.md` when present. The file is
optional Markdown and is versioned with the topic files instead of being parsed
as meta.

Snapshots:

- `manifest.json.version` is `2`
- exported `meta.json` files are normalized to v2
- `minutes/` is not exported
- importing non-v2 snapshots fails with `unsupported_snapshot_version`

Migration:

```bash
python3 -m server.topics.migrate_v2 --root /datadir/clodia-vault/topics-store
```

The migration creates a pre-flight tar.gz backup, normalizes all `meta.json`
files, moves any legacy `minutes/` directory to `.migrated-from-v1/minutes/`, and
verifies topic counts plus required v2 fields.
