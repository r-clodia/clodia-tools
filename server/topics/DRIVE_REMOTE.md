# Drive as a mount — REPEALED (decision-record #40, 7 Sep 2026)

> This entire design is retired. Kept as a design note because the lessons in
> it — measured, not theoretical — are worth knowing before anyone proposes a
> mount again. The authority on current behaviour is `service.py`
> (`drive_folders`, `_migrate_mounts_field`) + `test_mount_collection.py`.

## Why it was retired

Davide: navigating Drive from the webui file section was slow and not useful.
Measured in `service.py`'s own comment (inside `_open`'s `list()`): 22 Aug 2026,
across 98 topics, `list()` cost 4-7s and the webui answered 502 intermittently
on Drive latency. The mount was a **live proxy** — every read/write called the
Drive API directly, 5-second cache, no real sync — and that proxy is the
measured cause.

**The replacement.** A Drive folder reachable by the whitelist (entry 32,
unchanged) is reached by an agent through `gdrive.list/search/download/upload`
— already-existing verbs, independent of any mount — into its own scratch,
worked, and re-uploaded. Never a filesystem to navigate. Same shape entry 31
already gave git, whose mount turned out to be dead code nobody used.

**What survives, renamed.** The one thing the mount did that was not just
browsing: it told `gdrive_root.roots_for_call` which folder narrows a
channel's `gdrive.*` perimeter. That association — name↔folder-id — survives
as `meta["drive_folders"]`, an informational/authorization field a topic
declares (`drive_folder_add`/`drive_folder_remove`, still whitelist-checked,
still gated `walls`), never a mount.

## What follows, told as history

A topic could mount a Google Drive folder. The mount appeared in the file view
under `remote/<name>/`, beside `local/`, and Drive was **live**: reads and
writes proxied straight to `DriveStorage`, with last-write-wins and no
synchronisation cycle. Connecting a folder was a **metadata** operation — no
upload, no marker, no verify-and-clear.

### What this document used to claim before that, and why it stopped

Until 7 Aug 2026 it read: *"Drive is the source of truth […] the topic's local
files **disappear from view**: they are not shown, not synchronised, not
uploaded."* The two planes were in XOR.

Measured on `SEAL-1/proof-of-flex-2` the same day: **26 files shown** (Drive) and
**65 invisible** on disk — the Guide for Applicants, the deliverables, the
Portuguese pilot's slides. Hidden deliberately, with a confirmation given on
4 August, when there were 18 of them.

They became two **mounts** of one view. That fixed what a path meant: `local/x`
and `remote/drive/x` were different files that could share a name, which is why
the question "which of the two answers a read?" could not even be asked.

### Connecting (`remote_enable`, or `new(want_drive)`)

Connecting presupposed the content was **already** in the Drive folder (freshly
provisioned and empty, or pre-populated). Two guards:

1. **Anti-hiding.** If the topic had files only in `local/` and the mount would
   make Drive the answer for the legacy `files/…` paths, `remote_enable`
   **refused** rather than quietly shadowing them.
2. **SEAL cap** (anti-declassification, First Law / GDPR). A topic above
   `_DRIVE_SEAL_CAP` (SEAL-2) could not use Drive as live storage — this guard
   survives, unchanged, in `drive_folder_add`.

### Disconnecting (`remote_disable`)

The one transfer the design allowed ran the other way: it **materialised Drive
into local** (`_drive_pull_tree`, resumable, no pre-emptive clear). Retired
along with the mount — nothing materialises now, because nothing is ever the
sole copy of a file: an agent downloads to scratch and re-uploads, the folder
stays the source throughout.

### An agent editing a file — this part did not change

An agent that needs to *work* on a file never goes through an intermediate
filesystem: it downloads into **its own scratch**, edits there, and uploads
back. This was already true before #40 (`read_file`/`put_file` on a mount was
already just a proxy, not a working copy) — decision-record #40 only removed
the mount that made this feel optional.

### Credentials

The mount carried the **owner's** credential, resolved narrowest-first —
mount → scope → platform. Retired with the mount: `drive_folder_add` carries
no credential of its own — `gdrive.*` verbs resolve Drive access independently
and always did, never through this machinery.

### Legacy `storage: google-drive`

Topics with the old `storage: google-drive` already had their files on Drive:
converting them to a mount (`_migrate_legacy_drive`) was pure metadata — no
upload, no clear. Zero such topics remained in production by 7 Sep 2026
(measured before retiring the code): every one had already been migrated to a
mount, which `_migrate_mounts_field` now converts in turn to `drive_folders`.

### What was removed before this, and why — kept because the lesson generalises

An earlier model treated Drive as the destination of a *migration*:
`_ensure_drive_live` uploaded the local tree (`_upload_local_tree`), verified it,
deleted the local copy (`_clear_local_files`) and wrote a `.drive-live-v1`
marker — synchronously **on the read path**, and retried on **every access**
after a failure. With a non-writable Drive folder (403) this saturated the
gateway in a loop of failed uploads. The root error was conceptual: **a read
must not trigger a write**. The same family of lesson — a read path doing
network I/O nobody asked for — is exactly what made the *mount itself* slow
enough to retire in the end.
