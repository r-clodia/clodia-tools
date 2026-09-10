"""SQL contro i datastore dichiarati dai pack — verbi generici read/write.

L'autorizzazione (clearance + seed allowlist) è compito del dispatch
(`_datastore_authorize` in `main.py`, clone di `_rag_authorize`): questo
modulo riceve l'entry già autorizzata e il path già risolto, ed esegue
l'istruzione — non riapre la domanda "chi può", la fa una volta sola a monte,
come `gdrive.download` riceve un `dest` già passato da `_safe_scratch_path`.

Perché SELECT/INSERT/UPDATE/DELETE e non SQL libero: un pack dichiara una
`purpose`, non un contratto di schema — un `DROP TABLE` o un `ATTACH` verso un
altro file sarebbero un salto fuori dal perimetro dichiarato, non
un'operazione sui dati che il pack promette di contenere. La whitelist è per
TIPO di istruzione (allow-only, stessa postura di `web_fetch._readable`), non
per tabella: un seed autorizzato al datastore vede tutte le sue tabelle, com'è
naturale per un CRM.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sqlite3
from urllib.parse import quote

#: Quanto entra nel CONTESTO per default — stessa ragione di `web_fetch.py`:
#: un risultato di tool resta nella conversazione e viene riletto a ogni
#: round trip del turno.
DEFAULT_RESPONSE_BYTES = 32 * 1024
MAX_RESPONSE_BYTES = 256 * 1024

_READ_RE = re.compile(r"^\s*(select|pragma\s+table_info|pragma\s+table_list)\b", re.I)
_WRITE_RE = re.compile(r"^\s*(insert|update|delete)\b", re.I)


def _audit_path() -> Path:
    root = Path(os.environ.get("CLODIA_VAULT_DIR") or (Path.home() / ".clodia"))
    return root / "datastore-audit.log"


def _audit(agent: str, action: str, target: str, result: str, **extra) -> None:
    record = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "agent": agent, "action": action, "target": target, "result": result,
        **extra,
    }
    try:
        path = _audit_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass


def _single_statement(sql: str) -> str:
    """Una sola istruzione: un `;` seguito da altro non-spazio è rifiutato. Un
    `;` finale (comune, non semantico) è tollerato — evita di poter impilare
    un `DROP TABLE` dietro una `SELECT` apparentemente innocua."""
    s = (sql or "").strip()
    body = s[:-1] if s.endswith(";") else s
    if ";" in body:
        raise ValueError("una sola istruzione per chiamata: rimuovi il resto dopo il ';'")
    if not body:
        raise ValueError("istruzione vuota")
    return body


def _limite(arguments: dict) -> int:
    grezzo = arguments.get("max_bytes")
    if grezzo in (None, ""):
        return DEFAULT_RESPONSE_BYTES
    try:
        n = int(grezzo)
    except (TypeError, ValueError):
        raise ValueError("max_bytes deve essere un intero di byte") from None
    if n <= 0:
        raise ValueError("max_bytes deve essere positivo")
    return min(n, MAX_RESPONSE_BYTES)


def _params(arguments: dict) -> list:
    params = arguments.get("params") or []
    if not isinstance(params, list):
        raise ValueError("params deve essere una lista")
    return params


def read(entry: dict, arguments: dict, *, agent: str) -> dict:
    target = f"{entry['pack']}/{entry['name']}"
    query = _single_statement(str(arguments.get("query") or ""))
    if not _READ_RE.match(query):
        _audit(agent, "datastore.read", target, "REFUSED", query=query[:200])
        raise ValueError(
            "query non ammessa: datastore.read accetta solo SELECT (o PRAGMA "
            "table_info/table_list per l'introspezione)")
    params = _params(arguments)
    limite = _limite(arguments)
    # mode=ro: difesa in profondità. Anche se il check sulla stringa avesse un
    # buco, la connessione stessa non può scrivere.
    uri = f"file:{quote(entry['abs_path'])}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True, timeout=5)
    except sqlite3.OperationalError as exc:
        _audit(agent, "datastore.read", target, "ERROR", error=str(exc))
        raise ValueError(f"datastore non raggiungibile: {exc}") from exc
    try:
        cur = conn.execute(query, params)
        cols = [d[0] for d in (cur.description or [])]
        rows: list[dict] = []
        size = 0
        truncated = False
        for row in cur:
            r = dict(zip(cols, row))
            chunk = json.dumps(r, ensure_ascii=False, default=str)
            if size + len(chunk) > limite:
                truncated = True
                break
            rows.append(r)
            size += len(chunk)
    except sqlite3.Error as exc:
        conn.close()
        _audit(agent, "datastore.read", target, "ERROR", error=str(exc))
        raise ValueError(f"query fallita: {exc}") from exc
    conn.close()
    _audit(agent, "datastore.read", target, "OK", rows=len(rows), truncated=truncated)
    out = {"ok": True, "datastore": target, "columns": cols, "rows": rows,
           "truncated": truncated}
    if truncated:
        out["note"] = (f"risultato tagliato a {limite} byte: restringi la query "
                       f"(WHERE/LIMIT) o alza max_bytes fino a {MAX_RESPONSE_BYTES}")
    return out


def write(entry: dict, arguments: dict, *, agent: str) -> dict:
    target = f"{entry['pack']}/{entry['name']}"
    statement = _single_statement(str(arguments.get("statement") or ""))
    if not _WRITE_RE.match(statement):
        _audit(agent, "datastore.write", target, "REFUSED", statement=statement[:200])
        raise ValueError(
            "istruzione non ammessa: datastore.write accetta solo INSERT/UPDATE/"
            "DELETE (niente DDL: CREATE/DROP/ALTER/ATTACH restano fuori dal "
            "perimetro dichiarato)")
    params = _params(arguments)
    try:
        conn = sqlite3.connect(entry["abs_path"], timeout=5)
    except sqlite3.OperationalError as exc:
        _audit(agent, "datastore.write", target, "ERROR", error=str(exc))
        raise ValueError(f"datastore non raggiungibile: {exc}") from exc
    try:
        cur = conn.execute(statement, params)
        conn.commit()
        rowcount = cur.rowcount
    except sqlite3.Error as exc:
        conn.rollback()
        conn.close()
        _audit(agent, "datastore.write", target, "ERROR", error=str(exc))
        raise ValueError(f"istruzione fallita: {exc}") from exc
    conn.close()
    _audit(agent, "datastore.write", target, "OK", rowcount=rowcount)
    return {"ok": True, "datastore": target, "rowcount": rowcount}
