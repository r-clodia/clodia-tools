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


# ── The Databases page (clodia-platform#671) ─────────────────────────────────
#
# Structured operations for a PERSON's session: the webui never sends SQL for
# content. Table and column names are identifiers — not bindable in SQL — so
# every one is checked for equality against what the datastore itself declares
# (`sqlite_master`, `PRAGMA table_info`) before a statement is built, and then
# quoted. Values always travel as parameters. The caller has already decided
# WHO may do this (`databases.authorize_person`); here: WHAT is done, audited.

MAX_PAGE_ROWS = 200

#: Column types the schema editor offers: SQLite's affinities, nothing else.
COLUMN_TYPES = ("TEXT", "INTEGER", "REAL", "NUMERIC", "BLOB")

_DDL_RE = re.compile(r"^\s*(create\s+table|alter\s+table|drop\s+table)\b", re.I)


def _q(ident: str) -> str:
    return '"' + str(ident).replace('"', '""') + '"'


def _ro(entry: dict) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{quote(entry['abs_path'])}?mode=ro", uri=True, timeout=5)


def _rw(entry: dict) -> sqlite3.Connection:
    if not Path(entry["abs_path"]).is_file():
        raise ValueError(f"datastore {entry['pack']}/{entry['name']}: file assente")
    return sqlite3.connect(entry["abs_path"], timeout=5)


def _objects(conn) -> dict[str, str]:
    """`{name: 'table' | 'view'}`, internal objects excluded."""
    rows = conn.execute("SELECT name, type FROM sqlite_master WHERE type IN ('table','view') "
                        "AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()
    return {n: t for n, t in rows}


def _columns(conn, table: str) -> list[dict]:
    return [{"name": r[1], "type": r[2] or "", "notnull": bool(r[3]), "default": r[4],
             "pk": int(r[5] or 0)}
            for r in conn.execute(f"PRAGMA table_info({_q(table)})").fetchall()]


def _has_rowid(conn, table: str) -> bool:
    try:
        conn.execute(f"SELECT rowid FROM {_q(table)} LIMIT 0")
        return True
    except sqlite3.Error:
        return False                        # a view, or a WITHOUT ROWID table


def tables(entry: dict, *, agent: str) -> dict:
    """Every table and view with its columns and row count."""
    target = f"{entry['pack']}/{entry['name']}"
    if not Path(entry["abs_path"]).is_file():
        return {"datastore": target, "tables": [], "missing": True}
    conn = _ro(entry)
    try:
        out = []
        for name, kind in _objects(conn).items():
            try:
                n = conn.execute(f"SELECT count(*) FROM {_q(name)}").fetchone()[0]
            except sqlite3.Error:
                n = None
            # A view whose definition names a column that no longer exists
            # fails PRAGMA table_info too: shown with its error, never taking
            # the whole datastore page down with it (contacts.db, view
            # active_contacts on the dropped `task` column, 12 Nov 2026).
            try:
                cols = _columns(conn, name)
                editable = kind == "table" and _has_rowid(conn, name)
                err = None
            except sqlite3.Error as e:
                cols, editable, err = [], False, str(e)[:200]
            row = {"name": name, "type": kind, "rows": n, "columns": cols,
                   "editable": editable}
            if err:
                row["error"] = err
            out.append(row)
    finally:
        conn.close()
    _audit(agent, "databases.tables", target, "OK", tables=len(out))
    return {"datastore": target, "tables": out}


def rows(entry: dict, table: str, *, limit: int = 50, offset: int = 0, q: str = "",
         agent: str) -> dict:
    """One page of `table`, with `__rowid__` when rows are addressable, and a
    case-insensitive search over every column when `q` is given."""
    target = f"{entry['pack']}/{entry['name']}"
    limit = max(1, min(int(limit), MAX_PAGE_ROWS))
    offset = max(0, int(offset))
    conn = _ro(entry)
    try:
        objs = _objects(conn)
        if table not in objs:
            raise ValueError(f"tabella '{table}' non presente in '{target}'. "
                             f"Tabelle: {', '.join(objs) or 'nessuna'}")
        cols = _columns(conn, table)
        rowid = objs[table] == "table" and _has_rowid(conn, table)
        sel = ("rowid AS __rowid__, *" if rowid else "*")
        where, params = "", []
        if q and cols:
            where = " WHERE " + " OR ".join(f"CAST({_q(c['name'])} AS TEXT) LIKE ?" for c in cols)
            params = [f"%{q}%"] * len(cols)
        total = conn.execute(f"SELECT count(*) FROM {_q(table)}{where}", params).fetchone()[0]
        cur = conn.execute(f"SELECT {sel} FROM {_q(table)}{where} LIMIT ? OFFSET ?",
                           params + [limit, offset])
        names = [d[0] for d in cur.description or []]
        data, size, truncated = [], 0, False
        for r in cur:
            row = dict(zip(names, r))
            for k, v in row.items():
                if isinstance(v, (bytes, bytearray)):
                    row[k] = f"<blob {len(v)} byte>"
            size += len(json.dumps(row, ensure_ascii=False, default=str))
            if size > MAX_RESPONSE_BYTES:
                truncated = True
                break
            data.append(row)
    except sqlite3.Error as exc:
        raise ValueError(f"lettura fallita: {exc}") from exc
    finally:
        conn.close()
    _audit(agent, "databases.rows", target, "OK", table=table, rows=len(data))
    return {"datastore": target, "table": table, "columns": cols, "rows": data,
            "total": total, "limit": limit, "offset": offset, "editable": rowid,
            "truncated": truncated}


def row_op(entry: dict, op: str, table: str, *, rowid=None, values: dict | None = None,
           agent: str) -> dict:
    """insert | update | delete of one row, built from validated identifiers."""
    target = f"{entry['pack']}/{entry['name']}"
    if op not in ("insert", "update", "delete"):
        raise ValueError("op: insert | update | delete")
    values = values or {}
    if not isinstance(values, dict):
        raise ValueError("values deve essere un oggetto {colonna: valore}")
    conn = _rw(entry)
    try:
        objs = _objects(conn)
        if objs.get(table) != "table":
            raise ValueError(f"'{table}' non è una tabella di '{target}'")
        if op != "insert" and not _has_rowid(conn, table):
            raise ValueError(f"'{table}' non ha rowid: righe non modificabili dalla UI")
        known = {c["name"] for c in _columns(conn, table)}
        bad = [k for k in values if k not in known]
        if bad:
            raise ValueError(f"colonne sconosciute in '{table}': {', '.join(bad)}")
        for v in values.values():
            if isinstance(v, (dict, list)):
                raise ValueError("valori ammessi: testo, numero, booleano o null")
        if op == "insert":
            if values:
                cols = ", ".join(_q(k) for k in values)
                marks = ", ".join("?" for _ in values)
                sql = f"INSERT INTO {_q(table)} ({cols}) VALUES ({marks})"
            else:
                sql = f"INSERT INTO {_q(table)} DEFAULT VALUES"
            params = list(values.values())
        else:
            try:
                rid = int(rowid)
            except (TypeError, ValueError):
                raise ValueError("rowid richiesto (intero)") from None
            if op == "update":
                if not values:
                    raise ValueError("niente da aggiornare")
                sets = ", ".join(f"{_q(k)} = ?" for k in values)
                sql = f"UPDATE {_q(table)} SET {sets} WHERE rowid = ?"
                params = list(values.values()) + [rid]
            else:
                sql = f"DELETE FROM {_q(table)} WHERE rowid = ?"
                params = [rid]
        cur = conn.execute(sql, params)
        conn.commit()
        out = {"ok": True, "datastore": target, "table": table, "op": op,
               "rowcount": cur.rowcount}
        if op == "insert":
            out["rowid"] = cur.lastrowid
    except sqlite3.Error as exc:
        conn.rollback()
        _audit(agent, f"databases.{op}", target, "ERROR", table=table, error=str(exc))
        raise ValueError(f"istruzione fallita: {exc}") from exc
    finally:
        conn.close()
    _audit(agent, f"databases.{op}", target, "OK", table=table, rowcount=out["rowcount"])
    return out


def _column_sql(col: dict) -> str:
    name = str((col or {}).get("name") or "").strip()
    if not name:
        raise ValueError("ogni colonna ha un nome")
    typ = str(col.get("type") or "TEXT").strip().upper()
    if typ not in COLUMN_TYPES:
        raise ValueError(f"tipo '{typ}' non ammesso ({', '.join(COLUMN_TYPES)})")
    sql = f"{_q(name)} {typ}"
    if col.get("pk"):
        sql += " PRIMARY KEY"
    if col.get("notnull"):
        sql += " NOT NULL"
    return sql


def _deny_attach(action, *_args):
    # SQLITE_ATTACH = 24, SQLITE_DETACH = 25: a schema change stays inside this file.
    return sqlite3.SQLITE_DENY if action in (24, 25) else sqlite3.SQLITE_OK


def ddl(entry: dict, body: dict, *, agent: str) -> dict:
    """A schema change on one datastore, for an ADMIN's session (the caller
    checks it): `create_table` {table, columns: [{name, type, pk?, notnull?}]},
    `add_column` {table, column}, `drop_table` {table}, or `statement` — a
    single CREATE/ALTER/DROP TABLE. `datastore.write` never accepts DDL."""
    target = f"{entry['pack']}/{entry['name']}"
    op = str((body or {}).get("op") or "")
    table = str(body.get("table") or "").strip()
    conn = _rw(entry)
    try:
        objs = _objects(conn)
        if op == "create_table":
            cols = body.get("columns") or []
            if not table or not isinstance(cols, list) or not cols:
                raise ValueError("create_table: table e almeno una colonna")
            if table in objs or table.lower().startswith("sqlite_"):
                raise ValueError(f"'{table}' esiste già o è un nome riservato")
            sql = f"CREATE TABLE {_q(table)} ({', '.join(_column_sql(c) for c in cols)})"
        elif op == "add_column":
            if objs.get(table) != "table":
                raise ValueError(f"'{table}' non è una tabella di '{target}'")
            col = dict(body.get("column") or {})
            if col.get("pk"):
                raise ValueError("una colonna aggiunta non può essere PRIMARY KEY")
            sql = f"ALTER TABLE {_q(table)} ADD COLUMN {_column_sql(col)}"
        elif op == "drop_table":
            if objs.get(table) != "table":
                raise ValueError(f"'{table}' non è una tabella di '{target}'")
            sql = f"DROP TABLE {_q(table)}"
        elif op == "statement":
            sql = _single_statement(str(body.get("statement") or ""))
            if not _DDL_RE.match(sql):
                raise ValueError("solo CREATE TABLE, ALTER TABLE o DROP TABLE")
        else:
            raise ValueError("op: create_table | add_column | drop_table | statement")
        conn.set_authorizer(_deny_attach)
        conn.execute(sql)
        conn.commit()
    except sqlite3.Error as exc:
        conn.rollback()
        _audit(agent, "databases.ddl", target, "ERROR", op=op, error=str(exc))
        raise ValueError(f"modifica dello schema fallita: {exc}") from exc
    finally:
        conn.close()
    _audit(agent, "databases.ddl", target, "OK", op=op, statement=sql[:300])
    return {"ok": True, "datastore": target, "op": op, "statement": sql}
