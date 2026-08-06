# Topic Schema v2

`meta.json` uses schema version `2`.

Required fields:

- `schema_version`: `2`
- `tier`: `SEAL-0` | `SEAL-1` | `SEAL-2` | `SEAL-3` | `SEAL-4`
- `status`: `active` | `on-hold` | `done` | `archived`
- `deadline`: ISO date `YYYY-MM-DD` or `null`

Removed fields:

- `minutes`

Topic-level instructions live in `AGENTS.md` at the topic root, beside
`meta.json` and `summary.md` — **control plane, not `files/`**. Optional
Markdown, written only through `topic.save_agents_md` under the same optimistic
lock as the summary, and read back from `topic.open` as `agents_md` /
`agents_md_version`.

It moved out of `files/` on 6 Aug 2026 for three measured reasons: there it was
writable by **any participant** through `put_file` — the same store the reader
reads — so anyone in the room could dictate the text injected into every agent's
context on every turn; the read used the control-plane store while `put_file`
uses the files backend, so on a Drive-backed topic the UI showed one file while
the system injected another; and anything under `files/` is synchronised by a
remote, which meant a remote could rewrite a scope's instructions.

`files/AGENTS.md` is still **read** as a fallback for topics that have not been
migrated, and any file found there is retired to the topic's trash — never
deleted — the first time the new one is written. Migration:

```bash
python3 -c "from server.topics.service import TopicService; ..."   # or topic.migrate_agents_md
```

A file named `AGENTS.md` at the root of `files/` is now refused by `put_file`.
The refusal is only for the root: `files/procedure/AGENTS.md` is an ordinary
document and nothing injects it.

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
