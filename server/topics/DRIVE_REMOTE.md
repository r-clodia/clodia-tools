# Drive as a mount

> Design note. The authority on behaviour is `service.py` + `test_drive_live.py`
> + `test_mounts.py`; this file explains *why*, and records what it used to say.

A topic can mount a Google Drive folder. The mount appears in the file view
under `remote/<name>/`, beside `local/`, and Drive is **live**: reads and writes
proxy straight to `DriveStorage`, with last-write-wins and no synchronisation
cycle. Connecting a folder is a **metadata** operation — no upload, no marker, no
verify-and-clear.

## What this document used to claim, and why it does not any more

Until 7 Aug 2026 it read: *"Drive is the source of truth […] the topic's local
files **disappear from view**: they are not shown, not synchronised, not
uploaded."* The two planes were in XOR.

Measured on `SEAL-1/proof-of-flex-2` the same day: **26 files shown** (Drive) and
**65 invisible** on disk — the Guide for Applicants, the deliverables, the
Portuguese pilot's slides. Hidden deliberately, with a confirmation given on
4 August, when there were 18 of them.

They are now two **mounts** of one view. That fixes what a path means: `local/x`
and `remote/drive/x` are different files that may share a name, which is why the
question "which of the two answers a read?" cannot even be asked.

Two code sites still quote the old claim — `service.py` and `test_mounts.py` —
because a repeal is only legible next to what it repealed.

## Connecting (`remote_enable`, or `new(want_drive)`)

Connecting presupposes the content is **already** in the Drive folder (freshly
provisioned and empty, or pre-populated). Two guards:

1. **Anti-hiding.** If the topic has files only in `local/` and the mount would
   make Drive the answer for the legacy `files/…` paths, `remote_enable`
   **refuses** rather than quietly shadowing them. Populate the folder first, or
   stay local.
2. **SEAL cap** (anti-declassification, First Law / GDPR). A topic above
   `_DRIVE_SEAL_CAP` (SEAL-2) cannot use Drive as live storage.

## Disconnecting (`remote_disable`)

The one transfer the design allows, and it runs the other way: it
**materialises Drive into local** (`_drive_pull_tree`, resumable, with no
pre-emptive clear) so the topic keeps its files. If the pull fails halfway,
Drive is still the source — nothing is lost.

## An agent editing a file

An agent that needs to *work* on a file never goes through an intermediate
filesystem: it downloads into **its own scratch** (`read_file`), edits there, and
uploads back (`put_file` / `write_file`). The topic's file tree never holds
working copies.

## Credentials

The mount carries the **owner's** credential, resolved narrowest-first —
mount → scope → platform — with the provenance always visible and the value
never. The platform fallback is a Google **account**, not a folder: the sidebar
says so in as many words, because a silent fallback is how one becomes convinced
of an isolation that is not there.

## Legacy `storage: google-drive`

Topics with the old `storage: google-drive` already had their files on Drive:
converting them to a mount (`_migrate_legacy_drive`) is pure metadata — no
upload, no clear.

## What was removed, and why

An earlier model treated Drive as the destination of a *migration*:
`_ensure_drive_live` uploaded the local tree (`_upload_local_tree`), verified it,
deleted the local copy (`_clear_local_files`) and wrote a `.drive-live-v1`
marker — synchronously **on the read path**, and retried on **every access**
after a failure. With a non-writable Drive folder (403) this saturated the
gateway in a loop of failed uploads. The root error was conceptual: **a read must
not trigger a write**, and connecting Drive is not an upload. The whole
apparatus is gone.
