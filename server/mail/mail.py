"""The gateway's mail code: accounts, the mailbox whitelist, the courier's
reads, sending — and the IMAP/SMTP client run (clodia-platform#683).

Back in the gateway from comms-pack's gateway component (#558), WITHOUT the
agent verbs: no agent reads mail (owner, 14 Nov 2026). What stays is what the
courier and `channel.deliver` need:

- the accounts and their diagnostics (`credential_diagnostics`,
  `system_mailboxes`, `mailbox_address`), for the Tools page and the topic's
  mailbox option set;
- the courier's reads (`courier_envelopes`, `courier_box_index`,
  `courier_attachment`, `courier_eml`), with the room's sender rules, the
  message-box tag and the mail-authentication verdict;
- `send`, reached only through `channel.deliver` (`main._DELIVERY_ONLY_VERBS`).

The perimeter facts (mailbox whitelist, the room's senders, the courier tag)
are read per call from the gateway (`_host.get().perimeter`), never from a
copy. The IMAP/SMTP client is `email_client.py`, run in a child process with
ONE mailbox's credential in a private 0700 directory and a minimal
environment.

A Google account is google-pack's (`_host.google_*`): its credential never
comes here. LEGACY accounts (`secrets/email_config.json`, no vault
credential) are listed, so the Tools page names them, and refused at use.
"""
from __future__ import annotations

import base64
import contextlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional, Sequence, Union

from . import _host
from ._host import vault

LOG = logging.getLogger("clodia-tools.mail")

_EMAIL_PY = sys.executable
_EMAIL_SCRIPT = str(Path(__file__).resolve().parent / "email_client.py")

_VAULT_PREFIXES = ("google_", "gmail_", "mailbox_")
_REQUIRED_FIELDS = {
    "google": ("client_id", "client_secret", "refresh_token", "email"),
    "gmail": ("client_id", "client_secret", "refresh_token", "email"),
    # Il minimo di una casella è **spedire**. L'IMAP è opzionale, e non per
    # tolleranza: esistono indirizzi che sono alias con SMTP e nessuna casella
    # dietro (team@uncommon-digital.it). Richiedere l'IMAP li dichiarava «non
    # operativi» — un giudizio falso su una configurazione legittima, che poi
    # nascondeva l'account agli agenti come se fosse rotto.
    "mailbox": ("email", "smtp_server", "smtp_port"),
}

#: Frase con cui si riconosce il rifiuto di ingresso stretto senza leggerne il
#: testo: il gateway (`main._denial_class`) la cerca per classificare la
#: decisione come `sender_not_vetted` nel registro (#436). Identica a quella del
#: gateway (`server/tools/email.py`): un test lo verifica.
MITTENTE_NON_VAGLIATO = "mittente non vagliato"


# ── the gateway, through the host ──────────────────────────────────────────


def _perimeter():
    return _host.get().perimeter


def is_send_only(bundle: dict) -> bool:
    """Casella di solo invio: SMTP dichiarato, nessun IMAP.

    È una **forma dichiarata**, non un errore ingoiato: se si assorbisse il
    fallimento IMAP, un guasto vero del server diventerebbe indistinguibile da
    una scelta di configurazione, e una lettura risponderebbe «nessun
    messaggio» — che non è «non posso leggere», è una bugia con la stessa forma
    di una verità.
    """
    return not (bundle.get("imap_server") or "").strip()


def _gmail_cred(account: str) -> str:
    # Preferisci la credenziale Google UNIFICATA (google_<account>, che include lo
    # scope Gmail); fallback al legacy gmail_<account>.
    if vault.has_credential(f"google_{account}"):
        return f"google_{account}"
    return f"gmail_{account}"


def _mailbox_cred(account: str) -> str:
    return f"mailbox_{account}"


# ── legacy accounts: listed, refused at use ────────────────────────────────

def _legacy() -> dict:
    try:
        return dict(_perimeter().legacy_mail_accounts() or {})
    except Exception:  # noqa: BLE001 — unreadable: no legacy account
        return {}


def _legacy_accounts() -> set[str]:
    return set(_legacy())


def _legacy_address(account: str) -> str | None:
    """Indirizzo di un account LEGACY, o `None` (letto dal gateway)."""
    addr = str(_legacy().get(account) or "").strip().lower()
    return addr or None


#: The refusal of a legacy account in `pack` position (since #523).
def _legacy_refusal(account: str) -> PermissionError:
    return PermissionError(
        f"l'account legacy '{account}' (email_config.json) non si usa: la "
        "posta gira con la credenziale di UNA casella dalla vault, e un account "
        "legacy non ne ha una sua. Spostalo nella vault (Integrazioni → Email) "
        "e riprova.")


# ── accounts ───────────────────────────────────────────────────────────────

def credential_diagnostics() -> list[dict]:
    """Stato materializzabile delle credenziali email, senza valori segreti.

    `mailbox_*`: calcolato qui, dal bundle (scope `mailbox_`). `google_*` /
    `gmail_*`: le righe di google-pack, che è chi ne custodisce il bundle —
    stessa forma, stessi campi richiesti."""
    google = {str(r["credential"]): r for r in _host.google_rows()}
    rows = []
    for credential in vault.store_names():
        prefix = next((p for p in _VAULT_PREFIXES if credential.startswith(p)), None)
        if prefix is None:
            continue
        kind = prefix[:-1]
        account = credential[len(prefix):]
        if kind != "mailbox":
            g = google.get(credential)
            if g is None:
                continue
            rows.append({k: g.get(k) for k in (
                "credential", "account", "kind", "operational", "send_only",
                "missing", "error")})
            continue
        missing: list[str] = []
        error = None
        solo_invio = False
        try:
            bundle = vault.read_internal(credential)
            missing = [field for field in _REQUIRED_FIELDS[kind] if not bundle.get(field)]
            if not (bundle.get("password") or bundle.get("app_password")):
                missing.append("password|app_password")
            solo_invio = is_send_only(bundle)
        except Exception as exc:  # noqa: BLE001 - diagnostica, mai valori
            error = type(exc).__name__
        rows.append({
            "credential": credential,
            "account": account,
            "kind": kind,
            "operational": not missing and error is None,
            # Dichiarato, non dedotto da un fallimento: chi legge questa riga
            # deve sapere che l'account NON si legge, prima di provarci.
            "send_only": solo_invio,
            # Switched off from Tools (#733): still configured, not used.
            "enabled": not _host.get().mailbox_disabled(account),
            "missing": missing,
            "error": error,
        })
    return rows


def known_accounts() -> set[str]:
    """Account email disponibili: Gmail OAuth (da google-pack), caselle
    generiche (mailbox_*) e i legacy da email_config.json."""
    return _legacy_accounts() | {
        row["account"] for row in credential_diagnostics() if row["operational"]
    }


def available_accounts(agent: str) -> list[str]:
    """Account operativi ESISTENTI (indipendente dall'agente). Il filtro reale —
    quale casella un canale può davvero leggere o scrivere — è la whitelist
    `inbox:`/`outbox:` per-scope, verificata al momento della chiamata
    (`_secrets_env`), non qui: qui si elenca cosa esiste, non cosa è permesso."""
    return sorted(known_accounts())


def _account_address(credential: str, account: str) -> str:
    try:
        bundle = vault.read_internal(credential)
    except Exception:  # noqa: BLE001 — diagnostica, non deve bloccare l'elenco
        return account
    return (bundle.get("email") or account).strip().lower()


def mailbox_address(account: str) -> str | None:
    """Indirizzo della casella `mailbox_<account>`, o `None` se non c'è.

    Serve a chi deve RITIRARE le autorizzazioni di una casella che sta per
    sparire (clodia-platform#411): l'indirizzo va letto PRIMA della rimozione.
    Non passa da `system_mailboxes` (solo operative) e non ripiega sul nome
    dell'account: un nome non è un indirizzo."""
    try:
        bundle = vault.read_internal(_mailbox_cred(account))
    except Exception:  # noqa: BLE001 — casella assente o illeggibile
        return None
    addr = (bundle.get("email") or "").strip().lower()
    return addr or None


def system_mailboxes() -> list[dict]:
    """Caselle di sistema selezionabili come connettore di un canale: gli
    account operativi con una credenziale, con il loro INDIRIZZO (è l'indirizzo
    che finisce nella whitelist `inbox:`/`outbox:`). I legacy restano fuori."""
    return sorted(
        (
            {
                "account": row["account"],
                "email": _account_address(row["credential"], row["account"]),
                "send_only": bool(row.get("send_only")),
            }
            for row in credential_diagnostics()
            # A mailbox switched off (#733) is no system mailbox: no room
            # reads it, no delivery sends with it, it is not offered.
            if row["operational"] and row.get("enabled", True)
        ),
        key=lambda r: r["account"],
    )


# ── strict ingress (#503) ──────────────────────────────────────────────────


def _record_ingress(verb: str, result: str) -> None:
    """La decisione di ingresso come RECORD: se il registro non si può
    scrivere, la lettura non si fa."""
    host = _host.get()
    try:
        host.audit_decision(verb, "ingress", result, reason_class="sender_not_vetted")
    except host.AuditUnavailable:
        raise PermissionError(
            "audit trail non disponibile: la decisione di ingresso non si può "
            "registrare, quindi la lettura non si fa"
        ) from None
    except Exception as e:  # noqa: BLE001 — la decisione vale anche se non registrata
        LOG.error("audit: decisione di ingresso di %s non registrata (%s)",
                  verb, type(e).__name__)


# ── the mailbox whitelist ──────────────────────────────────────────────────

def _assert_mailbox_allowed(direction: str, addr: str) -> None:
    """La casella `addr` è usabile in questa direzione da questo canale?"""
    if _perimeter().mailbox_allowed(direction, addr):
        return
    lista = "ingress" if direction == "inbox" else "egress"
    raise PermissionError(
        f"la casella '{addr}' non è nella whitelist {direction} di questo "
        f"canale. Le caselle si configurano a livello di istanza: chiedi a un "
        f"admin di aggiungere {direction}:{addr} agli {lista} globali "
        f"(Integrazioni)."
    )


#: Prefix of the per-call secrets directory.
_SECRETS_TMP_PREFIX = "email_sec_"


def _client_env(secrets_dir: str) -> dict:
    """The environment of ONE client run: nothing of the gateway's own (its
    variables are not the client's business), the call's secrets directory,
    and no bytecode next to the pinned component."""
    return {
        "PATH": os.environ.get("PATH") or "/usr/local/bin:/usr/bin:/bin",
        "LANG": os.environ.get("LANG") or "C.UTF-8",
        "HOME": secrets_dir,
        "CLODIA_SECRETS_DIR": secrets_dir,
        "PYTHONDONTWRITEBYTECODE": "1",
    }


@contextlib.contextmanager
def _secrets_env(account: str, direction: str):
    """La whitelist della casella per `direction`, poi l'ambiente del client.

    - Gmail (`google_`/`gmail_`, di google-pack): si controlla l'INDIRIZZO
      (letto da google-pack) e si cede `{}` — i file XOAUTH2 li prepara
      google-pack per la sua chiamata (`mail_exec`), non passano di qui;
    - casella (`mailbox_<account>`): `email_config.json` con il SOLO bundle di
      questa casella in un dir effimero 0700, cancellato a fine chiamata;
    - legacy: stessa whitelist per indirizzo (#503), poi rifiutato.

    `direction` ("inbox" per leggere, "outbox" per inviare/rispondere) decide
    QUALE whitelist si consulta.
    """
    gcred, mcred = _gmail_cred(account), _mailbox_cred(account)
    cred = gcred if vault.has_credential(gcred) else (
        mcred if vault.has_credential(mcred) else None)
    if cred == mcred and _host.google_mail_account_exists(account):
        # A Google account whose google-pack is not serving: never fall back
        # to a same-named IMAP mailbox — another sender address, and a reply
        # resolved in one mailbox sent from the other (review of #384).
        raise PermissionError(
            f"l'account '{account}' è un account Google: google-pack non è "
            "attivo su questa istanza, quindi la sua posta non si usa ora")
    if cred == mcred and _host.get().mailbox_disabled(account):
        raise PermissionError(
            f"la casella '{account}' è spenta (Strumenti → Email): non si legge "
            "e non si usa per spedire finché un admin non la riaccende")
    if cred is None:
        addr = _legacy_address(account)
        if not addr:
            raise PermissionError(
                f"l'account legacy '{account}' non dichiara un indirizzo in "
                "email_config.json: senza indirizzo non è confrontabile con la "
                f"whitelist {direction} di questo canale e non si usa. Aggiungi "
                "'email' alla sua voce, o spostalo nella vault."
            )
        _assert_mailbox_allowed(direction, addr)
        raise _legacy_refusal(account)
    bundle = vault.read_internal(cred)
    addr = (bundle.get("email") or account).strip().lower()
    _assert_mailbox_allowed(direction, addr)
    if cred == gcred:
        yield {}
        return
    tmp = tempfile.mkdtemp(prefix=_SECRETS_TMP_PREFIX)
    try:
        os.chmod(tmp, 0o700)
        cfg = {"default": account, "accounts": {account: bundle}}
        cfg_path = Path(tmp) / "email_config.json"
        cfg_path.write_text(json.dumps(cfg, ensure_ascii=False), encoding="utf-8")
        os.chmod(cfg_path, 0o600)
        yield _client_env(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _is_gmail(account: str) -> bool:
    """The account runs on a Google credential (google-pack's) — the same test
    `_secrets_env` uses to pick the credential, so routing and files agree."""
    return vault.has_credential(_gmail_cred(account))


def _unknown_account(account: str) -> ValueError:
    why = _host.google_unavailable()
    extra = f" ({why})" if why else ""
    return ValueError(
        f"unknown account '{account}'; available: {sorted(known_accounts())}{extra}"
    )


def _gmail_runner(account: str):
    """google-pack's `mail_exec`, or a refusal: never another client."""
    svc = _host.google_service(_host.GMAIL_EXEC)
    if svc is None:
        raise PermissionError(
            f"Gmail provider not available for '{account}': "
            f"{_host.google_unavailable() or 'google-pack has no mail_exec service'}")
    return svc


class _Result:
    """The shape `_run_cli` reads from `subprocess.run`, from google-pack."""

    def __init__(self, returncode: int, stdout: str, stderr: str) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _gmail_payload(account: str, cli_args: list[str], timeout: int) -> dict:
    """`{account, argv, files, timeout}` for google-pack's `mail_exec`.

    Only the call and its ATTACHMENTS: each `--attachment` travels as bytes
    (`att/<n>/<name>`, one directory per file so the MIME part keeps its
    name) and the argument becomes `{dir}/att/<n>/<name>`. No credential: the
    XOAUTH2 files are google-pack's to write."""
    files: dict[str, str] = {}
    argv: list[str] = []
    n = 0
    it = iter(cli_args)
    for arg in it:
        if arg != "--attachment":
            argv.append(arg)
            continue
        raw = next(it, None)
        if raw is None:
            raise ValueError("--attachment senza percorso")
        src = Path(raw)
        rel = f"att/{n}/{src.name}"
        files[rel] = base64.b64encode(src.read_bytes()).decode("ascii")
        argv += ["--attachment", "{dir}/" + rel]
        n += 1
    return {"account": account, "argv": argv, "files": files, "timeout": timeout}


def _run_gmail(runner, account: str, cli_args: list[str], timeout: int) -> _Result:
    try:
        data = runner(_gmail_payload(account, cli_args, timeout))
    except Exception as e:  # noqa: BLE001 — the provider failed, the verb did
        raise RuntimeError(
            f"email {cli_args[0]} failed: mail provider 'google-pack.mail_exec' "
            f"error: {e}") from None
    try:
        rc = data["returncode"]
        if not isinstance(rc, int) or isinstance(rc, bool):
            raise TypeError("returncode")
        return _Result(rc, str(data.get("stdout") or ""), str(data.get("stderr") or ""))
    except (KeyError, TypeError):
        raise RuntimeError(
            f"email {cli_args[0]} failed: mail provider 'google-pack.mail_exec' "
            "answered without {returncode, stdout, stderr}") from None


def _run_cli(account: str, cli_args: list[str], *, want_json: bool,
             direction: str, timeout: int = 60) -> Union[dict, list]:
    """Esegue il client per `account`. Ritorna il JSON parsato (letture) o un
    dict di esito (send/reply).

    `direction`: "inbox" per i verbi di lettura, "outbox" per invio/risposta —
    quale whitelist per-casella verificare (vedi `_secrets_env`). Un account
    Google va a google-pack (`mail_exec`), una casella al client incluso; un
    legacy è rifiutato. Mai un ripiego sul client nativo del gateway."""
    if account not in known_accounts():
        raise _unknown_account(account)
    if _is_gmail(account):
        runner = _gmail_runner(account)
        with _secrets_env(account, direction):
            result = _run_gmail(runner, account, cli_args, timeout)
    else:
        # A legacy account (no vault credential) is refused inside
        # `_secrets_env`, after the same address check as natively (#503).
        with _secrets_env(account, direction) as env:
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


def _run_json(account: str, cli_args: list[str], *, timeout: int = 60,
              direction: str = "inbox") -> Union[dict, list]:
    """Un comando di lettura/risposta che ritorna JSON. Un punto solo per la
    guardia «questa casella si legge?»: qui passano tutti i verbi che leggono, e
    **solo** `send` non passa da qui. `reply` passa con `direction="outbox"`."""
    if direction == "inbox":
        _assert_readable(account)
    return _run_cli(account, cli_args, want_json=True, direction=direction, timeout=timeout)


def _assert_readable(account: str) -> None:
    """Rifiuta una LETTURA su una casella di solo invio, dicendo perché (una
    lista vuota avrebbe la stessa forma di una verità)."""
    cred = _mailbox_cred(account)
    if not vault.has_credential(cred):
        return                      # google/legacy: la lettura è normale
    try:
        bundle = vault.read_internal(cred)
    except Exception:  # noqa: BLE001 — la diagnostica non deve bloccare l'accesso
        return
    if is_send_only(bundle):
        raise PermissionError(
            f"l'account '{account}' è di SOLO INVIO: è un alias con SMTP e nessuna "
            "casella IMAP dietro, quindi non c'è niente da leggere — non è un "
            "guasto e riprovare non cambia nulla. Per avere traccia di ciò che "
            f"spedisci da '{account}', mettiti in CC un account leggibile."
        )


def _attachment_args(attachments: Optional[Sequence[str]]) -> list[str]:
    """Converte path locali in flag --attachment, validandoli presto."""
    args: list[str] = []
    for raw in attachments or []:
        path = Path(str(raw)).expanduser()
        if not path.is_file():
            raise ValueError(f"attachment not found or not a file: '{raw}'")
        args += ["--attachment", str(path)]
    return args


# ── the verbs ──────────────────────────────────────────────────────────────


def safe_attachment_name(filename: str, fallback: str = "allegato") -> str:
    """Il nome di un allegato ridotto a UN nome di file (clodia-platform#420):
    il nome lo sceglie il mittente, e un `/` non deve diventare una cartella."""
    name = re.sub(r"[\\/]+", "-", filename or "")
    name = re.sub(r"\s+", " ", name).strip(" .-")
    return name or fallback


# ── the courier (#531): envelopes and attachments, never the body ─────────

def envelope_key(row: dict) -> str:
    """A stable key for one message: its Message-ID when it has one, else its
    date|from|subject. IMAP sequence ids shift when a message is deleted; the
    courier remembers what it delivered by this."""
    import hashlib
    mid = str(row.get("message_id") or "").strip()
    raw = f"mid|{mid}" if mid else "|".join(
        str(row.get(k) or "") for k in ("date", "from", "subject"))
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:24]


def _courier_sender_ok(sender: str) -> bool:
    """Does the CURRENT room itself declare this sender (`mailfrom:` among its
    own ingress entries, #576)? What the courier delivers there: the same
    mailbox feeds many rooms, so global entries and participants do not count,
    and a room that declares nobody gets nothing. Needs clodia-tools ≥ 2.126.0;
    an older gateway delivers nothing rather than everything."""
    ask = getattr(_perimeter(), "room_declares_sender", None)
    if ask is None:
        raise RuntimeError("the mail courier needs clodia-tools ≥ 2.126.0 "
                           "(perimeter.room_declares_sender, clodia-platform#576)")
    return bool(ask(sender or ""))


def _courier_tag() -> str:
    """The message-box code of this courier call (#583), "" outside one. Set
    by the gateway's courier route, never by a caller; an older gateway → ""."""
    ask = getattr(_perimeter(), "courier_tag", None)
    return str(ask() or "") if ask else ""


#: The gateway's tag for the message-box INDEX call (#585): every code at
#: once, keys only. Never a topic's code.
BOX_INDEX_TAG = "*"


def _refuse_index_tag() -> None:
    """A per-room courier call never runs under the index tag: that tag opens
    the colony mailbox for every code, so it serves `courier_box_index` only."""
    if _courier_tag() == BOX_INDEX_TAG:
        raise PermissionError("the message-box index tag serves courier_box_index only")


def _box_address(account: str, tag: str) -> str:
    """`local+TAG@domain` of `account`'s mailbox, lower-case."""
    addr = _mailbox_addr(account)
    local, at, domain = addr.partition("@")
    return f"{local}+{tag.lower()}@{domain}" if (at and tag) else ""


def _mailbox_addr(account: str) -> str:
    """The address of `account`'s mailbox, lower-case, "" if unknown."""
    addr = str(mailbox_address(account) or "").strip().lower()
    if not addr:
        # A Google account (the colony mailbox may be one): its address comes
        # from the same list the gateway names the colony mailbox from.
        try:
            for row in system_mailboxes() or []:
                if str(row.get("account") or "") == account:
                    addr = str(row.get("email") or "").strip().lower()
                    break
        except Exception:  # noqa: BLE001 — no address, no delivery
            addr = ""
    return addr


def _tag_ok(row: object, account: str) -> bool:
    """Outside a message-box call: always. Inside: only a mail whose recipient
    headers AS SENT (`rcpt_raw`) name `box+TAG@…` — no fallback, a client
    without them delivers nothing (#583)."""
    tag = _courier_tag()
    if not tag:
        return True
    want = _box_address(account, tag)
    if not want or not isinstance(row, dict):
        return False
    from email.utils import getaddresses
    seen = {a.strip().lower() for _n, a in getaddresses(
        [str(x) for x in (row.get("rcpt_raw") or [])]) if a}
    return want in seen


def _is_box_mail(row: object, account: str) -> bool:
    """Is this a message-box mail (#583): on the COLONY mailbox and addressed to
    one of its plus sub-addresses (`local+X@domain`)? Such mail belongs to the
    topic whose code is X and to nobody else — not to a room that reads the
    colony mailbox through its own `inbox:`, not to an agent's `email.*`
    (review of clodia-tools#416). An older gateway (no `colony_address`) →
    never: there is no message box to protect."""
    ask = getattr(_perimeter(), "colony_address", None)
    colony = str(ask() or "").strip().lower() if ask else ""
    if not colony or not isinstance(row, dict):
        return False
    local, at, domain = colony.partition("@")
    if not account or _mailbox_addr(account) != colony:
        return False
    if "rcpt_raw" not in row:
        # A client that does not say whom the mail was for (google-pack <
        # 2.3.0): on the colony mailbox it might be any topic's — hidden, not
        # shown (second review of #416).
        return True
    from email.utils import getaddresses
    for _n, a in getaddresses([str(x) for x in (row.get("rcpt_raw") or [])]):
        a = (a or "").strip().lower()
        if a.endswith("@" + domain) and a.startswith(local + "+"):
            return True
    return False


def _hide_box_mail(rows: object, account: str) -> tuple[object, int]:
    """Rows without the message-box mail, and how many were hidden."""
    if not isinstance(rows, list):
        return rows, 0
    tenuti = [r for r in rows if not _is_box_mail(r, account)]
    return tenuti, len(rows) - len(tenuti)


def _deny_box_mail(verb: str) -> None:
    _record_ingress(verb, "deny")
    raise PermissionError(
        "questo messaggio è indirizzato alla message box di un topic: lo riceve "
        "solo quel topic (clodia-platform#583)")


def _courier_rows(rows: object) -> tuple[list, int]:
    """The listed messages whose sender the room declares, and how many were
    left out (counted, recorded, never shown)."""
    if not isinstance(rows, list):
        _record_ingress("courier.mail", "filter")
        return [], 1 if rows else 0
    tenuti = [r for r in rows if isinstance(r, dict) and _courier_sender_ok(_raw_from(r))]
    tolti = len(rows) - len(tenuti)
    if tolti:
        _record_ingress("courier.mail", "filter")
    return tenuti, tolti


def _raw_from(row: dict) -> str:
    """The `From:` header as SENT (`from_raw`): the decoded one can turn an
    encoded display name into an address (review of clodia-tools#411). A
    client that does not give it → "" → the sender is not declared."""
    return str(row.get("from_raw") or "") if isinstance(row, dict) else ""


def _deny_courier(header: str) -> None:
    addr = _perimeter().address_of(header) or "?"
    _record_ingress("courier.mail", "deny")
    raise PermissionError(
        f"{MITTENTE_NON_VAGLIATO}: il corriere consegna in questa stanza solo "
        f"la posta dei mittenti che la stanza ascolta (mailfrom:{addr} fra le "
        "sue fonti In ascolto, lo aggiunge l'owner)")


def _assert_courier_sender(result: object) -> None:
    """Refuse a fetched message whose sender the room does not declare (#576),
    checked on the `From:` of what was ACTUALLY fetched: between two IMAP
    sessions a sequence id can name another message (review of #553)."""
    raw = _raw_from(result)
    if not _courier_sender_ok(raw):
        _deny_courier(raw)


def courier_envelopes(account: str, folder: str = "INBOX", limit: int = 20,
                      skip: list | None = None, keys_only: bool = False,
                      only: list | None = None) -> dict:
    """The newest messages of a mailbox as ENVELOPES — id, key, from, to,
    subject, date, Message-ID, attachment names — for the gateway's courier
    (clodia-platform#531). Never the body: a message is read here only to
    learn its attachments, and its text is dropped before returning.

    Runs inside the ROOM's claims (the gateway's courier route sets them): the
    mailbox must be in the room's `inbox:` list (`_secrets_env`), and only the
    senders the room ITSELF declares pass (#576; strict or not), the others
    counted. `skip` lists keys the courier already delivered: those are not
    read again. `only`, when given, restricts the pass to those keys (#585: the
    message-box index named them) — older mail of the same box stays out."""
    _refuse_index_tag()
    known = {str(k) for k in (skip or [])}
    wanted = None if only is None else {str(k) for k in only}
    limit = max(1, min(int(limit), 50))
    tag = _courier_tag()
    if tag:
        # The message box (#583): searched by recipient, not taken from the
        # newest N of the whole colony mailbox — busy between two passes, a
        # tagged mail would fall out of that window (review of #416).
        box = _box_address(account, tag)
        if not box:
            return {"account": account, "folder": folder, "withheld": 0,
                    **({"keys": []} if keys_only else {"envelopes": []})}
        query = f'OR OR TO "{box}" CC "{box}" HEADER Delivered-To "{box}"'
        rows = _run_json(account, ["search", query, "--folder", folder,
                                   "--limit", str(limit)])
    else:
        rows = _run_json(account, ["list", "--folder", folder, "--limit", str(limit)])
    if wanted is not None and isinstance(rows, list):
        rows = [r for r in rows if isinstance(r, dict) and envelope_key(r) in wanted]
    # Keys this pass REFUSED (sender, box, tag) — reported only for an `only`
    # pass (#585): the courier remembers them as seen. A key that merely was
    # not reached (read failed, id race) is not refused and is retried.
    refused: list[str] = []

    def _refuse(gone):
        for r in gone:
            if isinstance(r, dict):
                refused.append(envelope_key(r))

    listed = list(rows) if isinstance(rows, list) else []
    rows, tolti = _courier_rows(rows)
    _refuse([r for r in listed if r not in rows])
    if not _courier_tag():
        before = list(rows)
        rows, nascosti = _hide_box_mail(rows, account)
        tolti += nascosti
        _refuse([r for r in before if r not in rows])
    if _courier_tag():
        # The colony mailbox (#583): only the mail addressed to this topic's
        # message box, counted apart from the senders' filter.
        tenuti = [r for r in rows if _tag_ok(r, account)]
        tolti += len(rows) - len(tenuti)
        _refuse([r for r in rows if r not in tenuti])
        rows = tenuti
    if keys_only:
        # The courier's first pass over a mailbox only records what is there:
        # the keys come from the listing, no message is read.
        return {"account": account, "folder": folder, "withheld": tolti,
                "keys": [envelope_key(r) for r in (rows if isinstance(rows, list) else [])
                         if isinstance(r, dict)]}
    out = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        key = envelope_key(row)
        if key in known:
            continue
        full = _run_json(account, ["read", str(row.get("id")), "--folder", folder])
        if not isinstance(full, dict):
            continue
        # IMAP ids are sequence numbers: between the listing and this read the
        # same id can name ANOTHER message (an expunge in between). Only the
        # message that was listed — same key — goes out, and its sender is
        # checked again on what was actually read.
        if envelope_key(full) != key:
            continue
        if not _courier_sender_ok(_raw_from(full)) or not _tag_ok(full, account) \
                or (not _courier_tag() and _is_box_mail(full, account)):
            _record_ingress("courier.mail", "filter")
            tolti += 1
            refused.append(key)
            continue
        out.append({"id": str(row.get("id")), "key": key,
                    "from": full.get("from"), "to": full.get("to"),
                    "subject": full.get("subject"), "date": full.get("date"),
                    "message_id": full.get("message_id"),
                    "attachments": [str(a) for a in (full.get("attachments") or [])]})
    res = {"account": account, "folder": folder, "envelopes": out, "withheld": tolti}
    if wanted is not None:
        res["withheld_keys"] = sorted(set(refused) & wanted)
    return res


def courier_attachment(account: str, email_id: str, filename: str,
                       folder: str = "INBOX") -> dict:
    """The decoded bytes (base64 for transport) of one attachment, for the
    courier to store in the topic's files byte-identical (#531). Same room
    rules as `courier_envelopes`: mailbox in the room's `inbox:` list, and a
    sender the room itself declares (#576)."""
    _refuse_index_tag()
    if not filename:
        raise ValueError("'filename' must be provided")
    r = _run_json(account, ["get-attachment", str(email_id), "--filename", filename,
                            "--folder", folder])
    if not isinstance(r, dict) or not r.get("data"):
        raise ValueError(f"allegato '{filename}' non trovato nel messaggio {email_id}")
    _assert_courier_sender(r)
    if not _tag_ok(r, account):
        _deny_courier(_raw_from(r))
    if not _courier_tag() and _is_box_mail(r, account):
        _deny_box_mail("courier.mail")
    raw = base64.b64decode(r["data"])
    return {"filename": safe_attachment_name(r.get("filename") or filename),
            "content_type": r.get("content_type"), "size": len(raw),
            "content_b64": base64.b64encode(raw).decode("ascii")}


def courier_eml(account: str, email_id: str, folder: str = "INBOX",
                key: str = "") -> dict:
    """The whole message as RFC822 bytes (base64 for transport), for the
    courier to keep a `.eml` copy in the topic (#576). Same room rules as
    `courier_attachment`. The bytes go to the topic's files, untrusted, never
    to a model. `auth` (#586): whether the receiving server authenticated the
    sender (`mail_authentication`), for the courier to decide the copy's
    provenance."""
    _refuse_index_tag()
    if not email_id:
        raise ValueError("'email_id' must be provided")
    r = _run_json(account, ["get-eml", str(email_id), "--folder", folder])
    if not isinstance(r, dict) or not r.get("data"):
        raise ValueError(str((r or {}).get("error") or f"messaggio {email_id} non trovato")
                         if isinstance(r, dict) else f"messaggio {email_id} non trovato")
    _assert_courier_sender(r)
    if not _tag_ok(r, account):
        _deny_courier(_raw_from(r))
    if not _courier_tag() and _is_box_mail(r, account):
        _deny_box_mail("courier.mail")
    mid = str(r.get("message_id") or "").strip()
    if key and mid and envelope_key({"message_id": mid}) != key:
        # An IMAP id names another message now (expunge in between): not the
        # envelope's message, so neither its copy nor its verdict (review of
        # #558).
        raise PermissionError(f"il messaggio {email_id} non è più quello della busta")
    raw = base64.b64decode(r["data"])
    auth = mail_authentication(raw, _authserv_ids(account))
    if _courier_tag() and auth.get("authenticated") and not _box_in_to_cc(raw, account):
        # A DKIM-signed mail of a declared sender, re-sent unchanged to the box
        # (`Delivered-To` is not signed): genuine text, not written for this
        # topic. Only a mail whose signed To:/Cc: names the box is trusted
        # (second review of #558); a Bcc to the box is delivered, not trusted.
        auth = {**auth, "authenticated": False, "method": "",
                "reason": "the message box is not in the signed To:/Cc:"}
    if key and not mid and auth.get("authenticated"):
        # Without a Message-ID the bytes cannot be tied to the envelope: kept
        # as a copy, never as an authenticated (trusted) message.
        auth = {**auth, "authenticated": False, "method": "",
                "reason": "no Message-ID: the message cannot be tied to its envelope"}
    return {"size": len(raw), "message_id": r.get("message_id"), "auth": auth,
            "content_b64": base64.b64encode(raw).decode("ascii")}


def _box_in_to_cc(raw: bytes, account: str) -> bool:
    import email
    from email.utils import getaddresses
    want = _box_address(account, _courier_tag())
    try:
        msg = email.message_from_bytes(raw)
    except Exception:  # noqa: BLE001
        return False
    heads = [str(h) for k in ("To", "Cc") for h in (msg.get_all(k) or [])]
    return bool(want) and want in {a.strip().lower() for _n, a in getaddresses(heads) if a}


# ── the message-box index (#585) ──────────────────────────────────────────

#: How far back the index looks: a message-box mail not delivered within this
#: window (gateway down for days) is not delivered by the courier any more.
BOX_INDEX_DAYS = 2
BOX_INDEX_LIMIT = 200
_CODE_RE = re.compile(r"^[A-Z0-9]{1,16}$")


def courier_box_index(account: str, days: int = BOX_INDEX_DAYS,
                      limit: int = BOX_INDEX_LIMIT) -> dict:
    """The colony mailbox's recent mail addressed to a plus sub-address, as
    `{CODE: [keys]}` (#585): ONE search per courier cycle for every topic's
    message box, instead of one per topic. Keys only — no sender, subject or
    body leaves here; the courier then reads, room by room, only the codes
    named, through `courier_envelopes(only=…)` with that room's rules.

    Runs only under the gateway's index tag, and only on the colony mailbox
    (the perimeter allows no other mailbox under that tag)."""
    from datetime import datetime, timedelta, timezone
    from email.utils import getaddresses
    if _courier_tag() != BOX_INDEX_TAG:
        raise PermissionError("courier_box_index runs only under the gateway's index tag")
    ask = getattr(_perimeter(), "colony_address", None)
    colony = str(ask() or "").strip().lower() if ask else ""
    if not colony or _mailbox_addr(account) != colony:
        raise PermissionError("courier_box_index reads the colony mailbox only")
    local, _at, domain = colony.partition("@")
    since = (datetime.now(timezone.utc) - timedelta(days=max(1, int(days)))
             ).strftime("%d-%b-%Y")
    rows = _run_json(account, ["search", f"SINCE {since}", "--folder", "INBOX",
                               "--limit", str(max(1, min(int(limit), 500)))])
    tags: dict[str, list[str]] = {}
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict) or "rcpt_raw" not in row:
            continue
        key = envelope_key(row)
        for _n, a in getaddresses([str(x) for x in (row.get("rcpt_raw") or [])]):
            a = (a or "").strip().lower()
            if not (a.endswith("@" + domain) and a.startswith(local + "+")):
                continue
            code = a[len(local) + 1:-(len(domain) + 1)].upper()
            if _CODE_RE.match(code) and key not in tags.setdefault(code, []):
                tags[code].append(key)
    return {"account": account, "tags": tags}


# ── sender authentication (#586) ──────────────────────────────────────────

def _authserv_ids(account: str) -> set[str]:
    """The `authserv-id`s whose `Authentication-Results` this mailbox trusts:
    the receiving server's own. A Google account → `mx.google.com`; an IMAP
    mailbox → the `authserv_id` its vault bundle declares, if any. None → no
    mail of that mailbox counts as authenticated."""
    ids: set[str] = set()
    try:
        if vault.has_credential(_gmail_cred(account)):
            ids.add("mx.google.com")
        elif vault.has_credential(_mailbox_cred(account)):
            v = str((vault.read_internal(_mailbox_cred(account)) or {})
                    .get("authserv_id") or "").strip().lower()
            if v:
                ids.add(v)
    except Exception:  # noqa: BLE001 — unknown → nothing trusted
        return set()
    return ids


def _ar_tokens(value: str) -> list[list[str]]:
    """An `Authentication-Results` value as its `;`-separated statements, each
    a list of tokens (RFC 8601 / RFC 5322 lexing): comments are dropped with
    their nesting, quoted strings are ONE token and never split a statement.
    A `;` or `=pass` inside a comment or a quoted local part is data, not a
    result (review of #558)."""
    stmts, cur, tok = [], [], []
    i, n, depth = 0, len(value), 0

    def flush():
        if tok:
            cur.append("".join(tok))
            tok.clear()
    while i < n:
        c = value[i]
        if depth:
            if c == "\\":
                i += 2
                continue
            depth += {"(": 1, ")": -1}.get(c, 0)
            i += 1
            continue
        if c == "(":
            flush()
            depth = 1
        elif c == '"':
            j, buf = i + 1, ['"']
            while j < n and value[j] != '"':
                if value[j] == "\\" and j + 1 < n:
                    j += 1
                buf.append(value[j])
                j += 1
            if j >= n:                   # an unterminated quoted string
                return [["\x00unterminated"]]
            tok.extend(buf + ['"'])
            i = j
        elif c == ";":
            flush()
            stmts.append(cur)
            cur = []
        elif c.isspace():
            flush()
        else:
            tok.append(c)
        i += 1
    flush()
    stmts.append(cur)
    if depth:
        # An unterminated comment swallowed the rest: fail closed.
        return [["\x00unterminated"]]
    return stmts


def _aligned(domain: str, from_domain: str) -> bool:
    """The DKIM signing domain is the From: domain or one of ITS subdomains —
    a domain the From:'s owner controls. A parent-domain signer is not
    accepted here (a multi-tenant parent signs for every tenant); DMARC, which
    knows the organisational domain, covers that case."""
    d = (domain or "").strip().lower().lstrip("@").rstrip(".")
    if "@" in d:
        d = d.rpartition("@")[2]
    return bool(d) and "." in d and (d == from_domain or d.endswith("." + from_domain))


def mail_authentication(raw: bytes, authserv_ids: set[str]) -> dict:
    """Did the RECEIVING server authenticate this message's sender (#586)?

    Read from the TOPMOST `Authentication-Results` header only — the one the
    receiving server prepends — and only when its `authserv-id` is one this
    mailbox trusts: a sender can write its own `Authentication-Results`, but
    only below the receiver's. ASSUMED: the receiver adds one to every message
    it delivers (Gmail does on SMTP delivery); a mailbox whose server may not
    must not declare an `authserv_id`.

    DMARC is authoritative when the receiver reports it: authenticated iff
    every `dmarc=` result is `pass` for the From: domain. Without DMARC, a
    `dkim=pass` whose signing domain is the From: domain or a subdomain of it,
    and no other `dkim=` result for that domain. The From: must hold exactly
    one address. Anything else → not authenticated, with the reason; never an
    error."""
    import email
    from email.utils import getaddresses
    out = {"authenticated": False, "method": "", "domain": "", "reason": ""}
    try:
        msg = email.message_from_bytes(raw)
    except Exception:  # noqa: BLE001
        return {**out, "reason": "unparsable message"}
    froms = msg.get_all("From") or []
    found = [a.strip().lower() for _n, a in getaddresses([str(f) for f in froms]) if a]
    if len(froms) != 1 or len(found) != 1 or found[0].count("@") != 1 or any(
            c in found[0] for c in ' <>,;"\t\r\n'):
        return {**out, "reason": "From: is not exactly one address"}
    from_domain = found[0].rpartition("@")[2]
    out["domain"] = from_domain
    results = msg.get_all("Authentication-Results") or []
    if not results:
        return {**out, "reason": "no Authentication-Results"}
    # `dmarc = fail` is `dmarc=fail`: spaces around `=` are not a new token.
    stmts = _ar_tokens(re.sub(r"\s*=\s*", "=", " ".join(str(results[0]).split())))
    authserv = (stmts[0][0] if stmts and stmts[0] else "").lower()
    if authserv not in {a.lower() for a in authserv_ids}:
        return {**out, "reason": f"Authentication-Results from untrusted '{authserv[:60]}'"}
    dmarc, dkim = [], []
    for stmt in stmts[1:]:
        if not stmt or "=" not in stmt[0]:
            continue
        method, _, result = stmt[0].partition("=")
        method, result = method.lower(), result.lower()
        props = {}
        for t in stmt[1:]:
            k, eq, v = t.partition("=")
            if eq:
                props[k.lower()] = v.strip('"').lower()
        if method == "dmarc":
            dmarc.append((result, props.get("header.from", "")))
        elif method == "dkim":
            dkim.append((result, props.get("header.d") or props.get("header.i") or ""))
    if dmarc:
        if all(r == "pass" and d == from_domain for r, d in dmarc):
            return {**out, "authenticated": True, "method": "dmarc"}
        return {**out, "reason": "DMARC not passed for the From: domain"}
    mine = [(r, d) for r, d in dkim if _aligned(d, from_domain)]
    if mine and all(r == "pass" for r, _d in mine):
        return {**out, "authenticated": True, "method": "dkim"}
    return {**out, "reason": "no aligned DMARC/DKIM pass"}


def send(
    to: str,
    subject: str,
    body: str,
    account: str = "demo",
    cc: Optional[str] = None,
    attachments: Optional[Sequence[str]] = None,
) -> dict:
    """Invia una email via account configurato (allegati: path già validati).

    Reached only through `channel.deliver` (#683): the caller's grant was
    decided on `channel.deliver`, and the egress PDP judged `to`/`cc` before
    this runs. No second per-agent check here: `email.*` is denied to every
    agent (`authz_shadow.PLATFORM_TUPLES`), so asking again would refuse the
    delivery the gateway has just allowed. The mailbox whitelist (`outbox:`)
    still applies, in `_run_cli`."""
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
    # `outbox`: si controlla la casella che spedisce (clodia-platform#428).
    res = _run_cli(account, args, want_json=False, direction="outbox")
    return {
        "ok": True,
        "to": to,
        "subject": subject,
        "account": account,
        "attachments": [str(Path(str(p)).expanduser()) for p in attachments or []],
        "stdout": res.get("stdout", ""),
    }
