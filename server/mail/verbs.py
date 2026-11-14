"""`email.send`, the delivery-only verb of `channel.deliver` (clodia-platform
#683).

No agent calls it by name: `main._DELIVERY_ONLY_VERBS` makes it exist only
inside a `channel.deliver` to a `mailto:` destination, after every check of
the dispatcher — the caller's grant on `channel.deliver`, the egress PDP on
`to`/`cc` (the builtin `mail` manifest), gates, audit.

What this module adds, as it did in comms-pack's component (#558):
- the account of the call: the one named, else the only one;
- topic files attached BY REFERENCE: read with the compartment check
  (`Topics.read_file`), hashed into the call's audit record as `attachment`;
- an agent's own attachments, confined to its spawn scratch (#461).
"""
from __future__ import annotations

import logging
import os
import shutil
import stat
import tempfile
from typing import Any, Callable

from . import _host
from . import mail

LOG = logging.getLogger("clodia-tools.mail")


# ── the account of a call ──────────────────────────────────────────────────

def _email_account(arguments: dict) -> str:
    """Account per una chiamata email.*: quello richiesto esplicitamente,
    altrimenti l'UNICO account esistente. Con zero o più account solleva un
    errore azionabile: nessun fallback verso mailbox inesistenti. Chi può
    davvero usare la casella lo decide la whitelist `inbox:`/`outbox:` al
    momento della chiamata (`mail._secrets_env`), non questa funzione."""
    accounts = mail.available_accounts(_host.get().agent())
    acct = (arguments.get("account") or "").strip()
    if acct:
        if acct in accounts:
            return acct
        # Fail closed for a Google account without google-pack, and say so:
        # the gateway's mail code cannot see a Google credential, so the
        # account is "not existing" here — the reason is google-pack.
        why = _host.google_unavailable()
        raise ValueError(
            f"email: account '{acct}' non esistente. "
            f"Passa il parametro 'account' con uno di questi valori: {accounts}"
            + (f" ({why})" if why else "")
        )
    if len(accounts) == 1:
        return accounts[0]
    if not accounts:
        raise ValueError(
            "email: nessun account configurato. Configura una mailbox da "
            "Integrazioni → Email."
        )
    raise ValueError(
        "email: il parametro 'account' è obbligatorio quando sono disponibili "
        f"più mailbox. Valori accettati: {accounts}"
    )


# ── where a topic file comes from / goes to ────────────────────────────────

def _topic_of(a: dict) -> tuple[str | None, str | None]:
    """Topic indicato negli argomenti, altrimenti quello del canale corrente
    (dal claim firmato, letto dal gateway)."""
    tier, name = a.get("tier"), a.get("name")
    if tier and name:
        return tier, name
    return _host.get().current_topic()


def _topic_attachments(a: dict, agent: str) -> tuple[list, str | None, list]:
    """Materializza `topic_files` in una dir temporanea e ne ritorna i path,
    la dir (da cancellare nel `finally` del chiamante) e i byte letti.

    Il compartimento vale come per ogni altro accesso (`host.topics.read_file`,
    membership): un agente non allega file di topic di cui non è partecipante.
    """
    rels = [r for r in (a.get("topic_files") or []) if str(r).strip()]
    if not rels:
        return [], None, []
    tier, tname = _topic_of(a)
    if not (tier and tname):
        raise ValueError(
            "topic_files: non sono riuscito a ricavare il topic dal canale in cui "
            "stai lavorando — passa tier + name")
    topics = _host.get().topics
    d = tempfile.mkdtemp(prefix="attach-")
    out, blobs = [], []
    try:
        for rel in rels:
            # The crossing is noted by the caller, as `attachment`, after the
            # agent's own attachments: the native order of the audit record.
            data = topics.read_file(tier, tname, str(rel), crossing=None)
            dest = os.path.join(d, os.path.basename(str(rel)))
            with open(dest, "wb") as f:
                f.write(data)
            out.append(dest)
            blobs.append(data)
    except BaseException:
        shutil.rmtree(d, ignore_errors=True)
        raise
    LOG.info("email: %d allegati per riferimento da %s/%s (agent %s)",
             len(out), tier, tname, agent)
    return out, d, blobs


def _agent_attachments(paths) -> list[str]:
    """Attachment paths passed by an agent, confined to its own scratch
    (clodia-platform#461): each must resolve (symlinks included) inside the
    caller's scratch and be a regular file; the resolved path is what gets
    sent."""
    host = _host.get()
    out: list[str] = []
    for raw in paths or []:
        try:
            rp = host.scratch_path(str(raw))
        except ValueError:
            raise ValueError(
                f"attachment outside your scratch: '{raw}'. Attach files from your "
                f"scratch, or topic files with topic_files=[...]") from None
        try:
            st = os.stat(rp)
        except OSError:
            raise ValueError(f"attachment not found: '{raw}'") from None
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"attachment is not a regular file: '{raw}'")
        out.append(rp)
    return out


# ── the verb ───────────────────────────────────────────────────────────────

def send(a: dict) -> Any:
    # ALLEGATI PER RIFERIMENTO (#104 §8): il gateway legge i file dal topic e
    # li allega, il contenuto non entra nel contesto dell'agente.
    host = _host.get()
    agent = host.agent() or ""
    own = _agent_attachments(a.get("attachments"))
    extra, tmpdir, blobs = _topic_attachments(a, agent)
    try:
        for p in own:
            host.note_crossing(path=p, kind="attachment")
        for data in blobs:
            host.note_crossing(data=data, kind="attachment")
        return mail.send(
            a["to"],
            a["subject"],
            a["body"],
            account=_email_account(a),
            cc=a.get("cc"),
            attachments=own + extra,
        )
    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)
