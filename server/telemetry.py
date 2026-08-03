"""Registro append-only dei verbi invocati (clodia-platform#110).

Perché serve, detto senza giri: oggi ogni misura sul modello di difesa è un
**inventario di capacità dichiarate**, non un'osservazione di azioni avvenute.
Sappiamo che nove agenti su dodici *possono* chiudere la trifecta; non sappiamo
quante volte l'hanno fatto, quali verbi usano davvero, quante volte un gate è
scattato o una destinazione è stata rifiutata. Senza questo registro ogni
riduzione è congetturale invece che sottrattiva — e resta congetturale anche la
domanda «la shell serve davvero a chi ce l'ha?».

**Metadati, mai argomenti.** Nome del verbo, agente, canale, esito, e i flag di
contesto. Non il corpo di una mail, non il testo di un messaggio, non il
destinatario: un indirizzo è un argomento, e la ragione per cui questo file
esiste non giustifica farne una rubrica. Chi deve costruire la whitelist trova
la destinazione nella riga di log `egress WOULD-DENY`, che è transitoria; qui
resta la storia, che è permanente.

Sul volume del SOLO gateway, come i consensi e il taint: un registro che un
agente può riscrivere non è un registro (clodia-platform#80). Append-only e
ruotato per dimensione — un log che cresce senza limite viene cancellato a mano
il giorno che riempie il disco, e allora non c'è più storia.
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Optional

from . import state_paths

LOG = logging.getLogger("clodia-tools.telemetry")

_FILE = "clodia-tools-verbs.jsonl"
#: Oltre questa soglia il file viene ruotato in `.1` (uno solo: la storia
#: profonda non serve a decidere, serve la distribuzione recente).
_MAX_BYTES = 8 * 1024 * 1024


def enabled() -> bool:
    """Spegnibile, ma ACCESO di default: un registro opt-in non esiste il giorno
    che serve. `CLODIA_VERB_LOG=off` per disattivarlo."""
    return (os.environ.get("CLODIA_VERB_LOG") or "on").strip().lower() != "off"


def _path():
    return state_paths.state_path(_FILE)


def _rotate(p) -> None:
    try:
        if p.is_file() and p.stat().st_size > _MAX_BYTES:
            os.replace(p, p.with_suffix(p.suffix + ".1"))
    except OSError:
        pass


def record(verb: str, agent: str, outcome: str, *, channel: Optional[str] = None,
           unattended: bool = False, gated: bool = False,
           egress_type: Optional[str] = None, tainted: bool = False,
           detail: str = "") -> None:
    """Registra UNA invocazione. Non solleva mai.

    `outcome` = `ok` | `denied` | `error`. `detail` è una CLASSE di motivo (es.
    `whitelist`, `egress`, `unattended`, `denied_tools`), non un messaggio: i
    messaggi contengono nomi di file e indirizzi.
    """
    if not enabled():
        return
    try:
        p = _path()
        p.parent.mkdir(parents=True, exist_ok=True)
        _rotate(p)
        row = {"at": int(time.time()), "verb": verb, "agent": agent,
               "outcome": outcome}
        # Campi opzionali solo se veri/presenti: il file si legge a occhio e le
        # righe piene di `false` nascondono quelle che contano.
        if channel:
            row["channel"] = channel
        if unattended:
            row["unattended"] = True
        if gated:
            row["gated"] = True
        if egress_type:
            row["egress"] = egress_type
        if tainted:
            row["tainted"] = True
        if detail:
            row["why"] = detail[:40]
        with open(p, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    except Exception as e:  # noqa: BLE001 — la misura non rompe il turno misurato
        LOG.warning("telemetry: riga non scritta (%s)", str(e)[:120])


def stats(limit: int = 5000) -> dict:
    """Aggregati sulle ultime `limit` righe: per verbo, per agente, per esito.

    Ritorna numeri, non righe: serve a rispondere «cosa usa davvero questo
    agente» e «quante volte abbiamo negato», non a rileggere la cronologia.
    """
    rows: list[dict] = []
    try:
        p = _path()
        if p.is_file():
            with open(p, encoding="utf-8") as f:
                for line in f.readlines()[-limit:]:
                    try:
                        rows.append(json.loads(line))
                    except ValueError:
                        continue
    except OSError as e:
        return {"error": str(e)[:120], "rows": 0}
    from collections import Counter
    by_verb: Counter = Counter()
    by_agent: Counter = Counter()
    by_outcome: Counter = Counter()
    denied_by_why: Counter = Counter()
    for r in rows:
        by_verb[r.get("verb", "?")] += 1
        by_agent[r.get("agent", "?")] += 1
        by_outcome[r.get("outcome", "?")] += 1
        if r.get("outcome") == "denied":
            denied_by_why[r.get("why", "?")] += 1
    return {"rows": len(rows),
            "first_at": rows[0].get("at") if rows else None,
            "last_at": rows[-1].get("at") if rows else None,
            "by_verb": dict(by_verb.most_common(40)),
            "by_agent": dict(by_agent),
            "by_outcome": dict(by_outcome),
            "denied_by_reason": dict(denied_by_why),
            "gated": sum(1 for r in rows if r.get("gated")),
            "unattended": sum(1 for r in rows if r.get("unattended")),
            "in_tainted_channel": sum(1 for r in rows if r.get("tainted"))}
