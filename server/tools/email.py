"""Email tool exposed via MCP — thin wrapper over the email_client CLI.

Le credenziali OAuth/IMAP vivono dentro l'ambiente del CLI, non vengono mai
esposte al subprocess MCP né al motore di inferenza. `email_client` è
vendorizzato nel repo (vendor/email_client.py) ed è puro stdlib (imaplib/
smtplib/email/urllib) — nessuna venv separata necessaria: lo si esegue con
l'interprete del gateway.
"""
from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional, Union

from .. import vault
from ..whitelist import agent_name, tool_allowed

_EMAIL_PY = sys.executable
_EMAIL_SCRIPT = str(Path(__file__).resolve().parents[2] / "vendor" / "email_client.py")
# Account legacy serviti da secrets/email_config.json (fallback senza vault).
_LEGACY_ACCOUNTS = {"demo", "studio"}


def _gmail_cred(account: str) -> str:
    return f"gmail_{account}"


def _mailbox_cred(account: str) -> str:
    return f"mailbox_{account}"


def known_accounts() -> set:
    """Account email disponibili: Gmail OAuth (gmail_*), caselle generiche
    (mailbox_*) e i legacy da email_config.json."""
    accts = set(_LEGACY_ACCOUNTS)
    for n in vault.store_names():
        if n.startswith("gmail_"):
            accts.add(n[len("gmail_"):])
        elif n.startswith("mailbox_"):
            accts.add(n[len("mailbox_"):])
    return accts


@contextlib.contextmanager
def _secrets_env(account: str):
    """Ambiente per eseguire il CLI per `account`, con credenziali materializzate
    dalla vault (grant-checkate sull'agente) in un dir effimero 0700:
    - Gmail OAuth (gmail_<account>) → token OAuth;
    - casella generica (mailbox_<account>) → email_config.json IMAP/SMTP;
    - altrimenti env corrente (legacy secrets/). Il segreto non raggiunge mai
      il motore: vive solo su disco del gateway per la durata del subprocess."""
    gcred, mcred = _gmail_cred(account), _mailbox_cred(account)
    if vault.has_credential(gcred):
        tmp = tempfile.mkdtemp(prefix="email_sec_")
        try:
            vault.materialize_google_oauth(agent_name(), gcred, Path(tmp))
            env = dict(os.environ)
            env["CLODIA_SECRETS_DIR"] = tmp
            yield env
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    elif vault.has_credential(mcred):
        bundle = vault.get_secret(agent_name(), mcred)  # grant-checked
        tmp = tempfile.mkdtemp(prefix="email_sec_")
        try:
            cfg = {"default": account, "accounts": {account: bundle}}
            cfg_path = Path(tmp) / "email_config.json"
            cfg_path.write_text(json.dumps(cfg, ensure_ascii=False), encoding="utf-8")
            os.chmod(cfg_path, 0o600)
            env = dict(os.environ)
            env["CLODIA_SECRETS_DIR"] = tmp
            yield env
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    else:
        yield dict(os.environ)


def _run_cli(account: str, cli_args: list[str], *, want_json: bool,
             timeout: int = 60) -> Union[dict, list]:
    """Esegue il CLI email_client per `account`, instradando le credenziali
    dalla vault se presente. Ritorna il JSON parsato (read tools) o un dict di
    esito (send/reply)."""
    if account not in known_accounts():
        raise ValueError(
            f"unknown account '{account}'; available: {sorted(known_accounts())}"
        )
    with _secrets_env(account) as env:
        cmd = [_EMAIL_PY, _EMAIL_SCRIPT, "--account", account, *cli_args]
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=timeout, env=env)
    if result.returncode != 0:
        raise RuntimeError(
            f"email {cli_args[0]} failed (exit {result.returncode}): "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    out = result.stdout.strip()
    if not want_json:
        return {"stdout": out}
    if not out:
        return {}
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {"raw": out}


def _run_json(account: str, cli_args: list[str], *, timeout: int = 60) -> Union[dict, list]:
    """Compat: esegue un comando di lettura/risposta e ritorna il JSON."""
    return _run_cli(account, cli_args, want_json=True, timeout=timeout)


def folders(account: str = "demo") -> dict:
    """Elenca le cartelle IMAP dell'account."""
    tool_allowed("email.folders")
    return {"account": account, "folders": _run_json(account, ["folders"])}


def list_messages(account: str = "demo", folder: str = "INBOX", limit: int = 10) -> dict:
    """Elenca i messaggi di una cartella (default INBOX)."""
    tool_allowed("email.list")
    return {
        "account": account,
        "folder": folder,
        "messages": _run_json(account, ["list", "--folder", folder, "--limit", str(limit)]),
    }


def read_message(email_id: str, account: str = "demo", folder: str = "INBOX") -> dict:
    """Legge un singolo messaggio per ID."""
    tool_allowed("email.read")
    return _run_json(account, ["read", str(email_id), "--folder", folder])



def get_attachment(email_id: str, filename: str, account: str = "demo",
                   folder: str = "INBOX") -> dict:
    """Contenuto base64 di un allegato (componibile con topic.write_file/profile)."""
    tool_allowed("email.get_attachment")
    if not filename:
        raise ValueError("'filename' must be provided")
    return _run_json(account, ["get-attachment", str(email_id), "--filename", filename,
                               "--folder", folder])

def search(query: str, account: str = "demo", folder: str = "INBOX", limit: int = 20) -> dict:
    """Cerca messaggi via query IMAP (es. FROM \"x@y.it\")."""
    tool_allowed("email.search")
    if not query:
        raise ValueError("'query' must be non-empty")
    return {
        "account": account,
        "query": query,
        "results": _run_json(account, ["search", query, "--folder", folder, "--limit", str(limit)]),
    }


def reply(email_id: str, body: str, account: str = "demo",
          folder: str = "INBOX", cc: Optional[str] = None) -> dict:
    """Risponde a un messaggio mantenendo il threading (SMTP)."""
    tool_allowed("email.reply")
    if body is None:
        raise ValueError("'body' must be provided (use empty string if intentional)")
    args = ["reply", str(email_id), "--body", body, "--folder", folder]
    if cc:
        args += ["--cc", cc]
    return _run_json(account, args)


def send(
    to: str,
    subject: str,
    body: str,
    account: str = "demo",
    cc: Optional[str] = None,
) -> dict:
    """Invia una email via account configurato.

    Wrap minimal del CLI `email_client.py send`. Nessun allegato in questa
    versione: i casi d'uso correnti (notifiche di Looper, ack di task) non
    ne hanno bisogno.
    """
    tool_allowed("email.send")
    if not to or "@" not in to:
        raise ValueError(f"invalid 'to' address: '{to}'")
    if not subject:
        raise ValueError("'subject' must be non-empty")
    if body is None:
        raise ValueError("'body' must be provided (use empty string if intentional)")

    args = ["send", "--to", to, "--subject", subject, "--body", body]
    if cc:
        args += ["--cc", cc]
    res = _run_cli(account, args, want_json=False)
    return {
        "ok": True,
        "to": to,
        "subject": subject,
        "account": account,
        "stdout": res.get("stdout", ""),
    }
