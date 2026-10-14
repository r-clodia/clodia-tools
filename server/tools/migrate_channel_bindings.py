"""Migrazione one-shot: `telegram-bindings.json` → `channel-bindings.json`.

    python3 -m server.tools.migrate_channel_bindings --dry-run
    python3 -m server.tools.migrate_channel_bindings

clodia-platform#521. La migrazione avviene **da sola** alla prima lettura del
registro (`channel_bindings._doc`), quindi questo comando non è un passo
obbligato del deploy: serve a *guardarla prima di farla* sull'istanza vera, che
è il criterio di accettazione della issue, e a rifarla a mano se qualcuno ha
spostato i file.

Non concede niente e non toglie niente: un binding dice quale istanza ascolta
quale chat, non chi può parlare in quella stanza (quello sta negli ingress dello
scope). Il file vecchio resta dov'è.
"""
from __future__ import annotations

import argparse
import json
import sys

from . import channel_bindings as cb


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dry-run", action="store_true",
                    help="mostra il piano senza scrivere nulla")
    ap.add_argument("--json", action="store_true", help="output JSON")
    args = ap.parse_args(argv)

    try:
        esito = cb.migrate_legacy(dry_run=args.dry_run)
    except cb.BindingsUnreadable as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    esito["legacy_file"] = str(cb._legacy_path())
    esito["target_file"] = str(cb._path())
    esito["dry_run"] = bool(args.dry_run)
    if args.json:
        print(json.dumps(esito, ensure_ascii=False, indent=2))
        return 0
    print(f"da:  {esito['legacy_file']}")
    print(f"a:   {esito['target_file']} (connettore '{cb.LEGACY_CONNECTOR}')")
    if esito["already"]:
        print("già migrato: il file di destinazione esiste, niente da fare.")
        for chat in esito["orphans"]:
            print(f"  ATTENZIONE chat {chat} è nel file vecchio e non in quello nuovo: "
                  f"NON viene rifusa (sarebbe un binding resuscitato).")
        return 0
    if not esito["migrated"]:
        print("nessun binding da migrare.")
        return 0
    verbo = "da migrare" if args.dry_run else "migrati"
    print(f"{len(esito['migrated'])} binding {verbo}:")
    for chat in esito["migrated"]:
        print(f"  chat {chat}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
