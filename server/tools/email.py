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
from typing import Optional, Sequence, Union

from .. import vault
from ..whitelist import agent_name, tool_allowed

_EMAIL_PY = sys.executable
_EMAIL_SCRIPT = str(Path(__file__).resolve().parents[2] / "vendor" / "email_client.py")

_VAULT_PREFIXES = ("google_", "gmail_", "mailbox_")
_REQUIRED_FIELDS = {
    "google": ("client_id", "client_secret", "refresh_token", "email"),
    "gmail": ("client_id", "client_secret", "refresh_token", "email"),
    "mailbox": ("email", "imap_server", "imap_port", "smtp_server", "smtp_port"),
}


def _gmail_cred(account: str) -> str:
    # Preferisci la credenziale Google UNIFICATA (google_<account>, che include lo
    # scope Gmail); fallback al legacy gmail_<account>.
    if vault.has_credential(f"google_{account}"):
        return f"google_{account}"
    return f"gmail_{account}"


def _mailbox_cred(account: str) -> str:
    return f"mailbox_{account}"


def _legacy_config_file() -> Path:
    secrets_dir = os.environ.get("CLODIA_SECRETS_DIR")
    if not secrets_dir:
        workspace = os.environ.get("CLODIA_WORKSPACE_ROOT")
        secrets_dir = (
            f"{workspace}/secrets" if workspace
            else str(Path(_EMAIL_SCRIPT).resolve().parent.parent.parent.parent / "secrets")
        )
    return Path(secrets_dir) / "email_config.json"


def _legacy_accounts() -> set[str]:
    try:
        data = json.loads(_legacy_config_file().read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return set()
    if "accounts" in data:
        return {str(name) for name in (data.get("accounts") or {})}
    return {"demo"} if data else set()


def credential_diagnostics() -> list[dict]:
    """Stato materializzabile delle credenziali email, senza valori segreti."""
    rows = []
    for credential in vault.store_names():
        prefix = next((p for p in _VAULT_PREFIXES if credential.startswith(p)), None)
        if prefix is None:
            continue
        kind = prefix[:-1]
        account = credential[len(prefix):]
        missing: list[str] = []
        error = None
        try:
            bundle = vault.read_internal(credential)
            missing = [field for field in _REQUIRED_FIELDS[kind] if not bundle.get(field)]
            if kind == "mailbox" and not (
                bundle.get("password") or bundle.get("app_password")
            ):
                missing.append("password|app_password")
        except Exception as exc:  # noqa: BLE001 - diagnostica, mai valori
            error = type(exc).__name__
        rows.append({
            "credential": credential,
            "account": account,
            "kind": kind,
            "operational": not missing and error is None,
            "missing": missing,
            "error": error,
        })
    return rows


def known_accounts() -> set[str]:
    """Account email disponibili: Gmail OAuth (gmail_*), caselle generiche
    (mailbox_*) e i legacy da email_config.json."""
    return _legacy_accounts() | {
        row["account"] for row in credential_diagnostics() if row["operational"]
    }


def available_accounts(agent: str) -> list[str]:
    """Account operativi che l'agente può davvero materializzare dal vault."""
    granted = set(vault.grants_for(agent))
    accounts = {
        row["account"]
        for row in credential_diagnostics()
        if row["operational"] and row["credential"] in granted
    }
    # Il legacy è autorizzato dalla whitelist e non ha grant per-account.
    accounts.update(_legacy_accounts())
    return sorted(accounts)


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


def _attachment_args(attachments: Optional[Sequence[str]]) -> list[str]:
    """Converte path locali in flag CLI --attachment, validandoli presto."""
    args: list[str] = []
    for raw in attachments or []:
        path = Path(str(raw)).expanduser()
        if not path.is_file():
            raise ValueError(f"attachment not found or not a file: '{raw}'")
        args += ["--attachment", str(path)]
    return args


def folders(account: str = "demo") -> dict:
    """Elenca le cartelle IMAP dell'account."""
    tool_allowed("email.folders")
    return {
        "account": account,
        "available_accounts": available_accounts(agent_name()),
        "folders": _run_json(account, ["folders"]),
    }


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
    """Contenuto base64 di un allegato (componibile con topic.write_file/profile).
    Per i binari grandi (PDF, immagini) usare email.save_attachment: il base64
    di un file reale non passa intero dal contesto del modello."""
    tool_allowed("email.get_attachment")
    if not filename:
        raise ValueError("'filename' must be provided")
    return _run_json(account, ["get-attachment", str(email_id), "--filename", filename,
                               "--folder", folder])


def get_attachment_bytes(email_id: str, filename: str, account: str = "demo",
                         folder: str = "INBOX") -> tuple[bytes, dict]:
    """Byte DECODIFICATI di un allegato + metadati — nessun base64 verso il
    modello. Backend di email.save_attachment (il gate whitelist usa quel nome;
    la scrittura su scratch la fa main.py con il path validato)."""
    tool_allowed("email.save_attachment")
    if not filename:
        raise ValueError("'filename' must be provided")
    r = _run_json(account, ["get-attachment", str(email_id), "--filename", filename,
                            "--folder", folder])
    if not isinstance(r, dict) or not r.get("data"):
        raise ValueError(f"allegato '{filename}' non trovato nel messaggio {email_id}")
    import base64
    raw = base64.b64decode(r["data"])
    return raw, {"filename": r.get("filename") or filename,
                 "content_type": r.get("content_type")}

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
          folder: str = "INBOX", cc: Optional[str] = None,
          attachments: Optional[Sequence[str]] = None) -> dict:
    """Risponde a un messaggio mantenendo il threading (SMTP)."""
    tool_allowed("email.reply")
    if body is None:
        raise ValueError("'body' must be provided (use empty string if intentional)")
    args = ["reply", str(email_id), "--body", body, "--folder", folder]
    if cc:
        args += ["--cc", cc]
    args += _attachment_args(attachments)
    return _run_json(account, args)


def send(
    to: str,
    subject: str,
    body: str,
    account: str = "demo",
    cc: Optional[str] = None,
    attachments: Optional[Sequence[str]] = None,
) -> dict:
    """Invia una email via account configurato.

    Wrap minimal del CLI `email_client.py send`, inclusi allegati locali gia'
    presenti nel filesystem del gateway/runtime.
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
    args += _attachment_args(attachments)
    res = _run_cli(account, args, want_json=False)
    return {
        "ok": True,
        "to": to,
        "subject": subject,
        "account": account,
        "attachments": [str(Path(str(p)).expanduser()) for p in attachments or []],
        "stdout": res.get("stdout", ""),
    }
