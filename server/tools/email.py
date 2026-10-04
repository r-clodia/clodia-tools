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
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional, Sequence, Union

from .. import vault
from ..whitelist import agent_name, tool_allowed

LOG = logging.getLogger(__name__)

_EMAIL_PY = sys.executable
_EMAIL_SCRIPT = str(Path(__file__).resolve().parents[2] / "vendor" / "email_client.py")

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


def is_send_only(bundle: dict) -> bool:
    """Casella di solo invio: SMTP dichiarato, nessun IMAP.

    È una **forma dichiarata**, non un errore ingoiato, e la differenza conta.
    Se si assorbisse il fallimento IMAP, un guasto vero del server diventerebbe
    indistinguibile da una scelta di configurazione, e una lettura risponderebbe
    «nessun messaggio» — che non è «non posso leggere», è una bugia con la stessa
    forma di una verità.
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
        solo_invio = False
        try:
            bundle = vault.read_internal(credential)
            missing = [field for field in _REQUIRED_FIELDS[kind] if not bundle.get(field)]
            if kind == "mailbox":
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
    """Account operativi ESISTENTI (indipendente dall'agente: non c'è più un
    grant per-agente sulla credenziale). Il filtro reale — quale casella un
    canale può davvero leggere o scrivere — è la whitelist `inbox:`/`outbox:`
    per-scope, verificata al momento della chiamata (`_secrets_env`), non qui:
    qui si elenca cosa esiste, non cosa è permesso."""
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
    sparire (clodia-platform#411): l'indirizzo va letto dal vault PRIMA della
    rimozione, perché è l'unica chiave con cui si ritrovano le voci
    `inbox:`/`outbox:` nelle liste.

    Non passa da `system_mailboxes`, che tiene solo le caselle OPERATIVE: una
    con la password mancante è esattamente quella che l'owner cancella, e
    ignorarla lascerebbe orfane proprio le sue voci. E non ripiega sul nome
    dell'account come `_account_address`: un nome non è un indirizzo, e
    scambiarli qui significherebbe revocare una voce che non c'entra.
    """
    try:
        bundle = vault.read_internal(_mailbox_cred(account))
    except Exception:  # noqa: BLE001 — casella assente o illeggibile
        return None
    addr = (bundle.get("email") or "").strip().lower()
    return addr or None


def system_mailboxes() -> list[dict]:
    """Caselle di sistema selezionabili come connettore di un canale.

    Gli account operativi che hanno una credenziale nella vault, con il loro
    INDIRIZZO: è l'indirizzo, non il nome dell'account, la cosa che finisce
    nella whitelist `inbox:`/`outbox:` (vedi `_secrets_env`), quindi chi deve
    autorizzare una casella per un canale ha bisogno di entrambi.

    I legacy di `email_config.json` restano fuori da QUESTO elenco: non hanno
    una credenziale nella vault da cui leggere l'indirizzo in modo affidabile.
    Non sono però più esenti dalla whitelist (clodia-platform#503): il loro
    indirizzo si prende da `_legacy_address` e vale la stessa regola di tutti —
    chi ne ha uno lo vede comparire in `accounts_not_allowed` finché non è
    autorizzato.
    """
    return sorted(
        (
            {
                "account": row["account"],
                "email": _account_address(row["credential"], row["account"]),
                # Dichiarato e non dedotto, come nella diagnostica: un alias di
                # solo invio non leggerà mai nulla, e chi lo collega deve
                # saperlo PRIMA di aspettarsi la posta in arrivo.
                "send_only": bool(row.get("send_only")),
            }
            for row in credential_diagnostics()
            if row["operational"]
        ),
        key=lambda r: r["account"],
    )


def accounts_not_allowed(direction: str, scope: str | None = None) -> list[str]:
    """Account che ESISTONO e funzionano, ma la cui casella non è nella
    whitelist `inbox:`/`outbox:` di questo canale.

    Sostituisce `accounts_not_granted`: prima la domanda era «questo agente ha
    il grant sulla credenziale», ora è «questo canale ha la casella in
    whitelist» — la stessa distinzione fra assenza e divieto, spostata da CHI a
    DOVE.

    Dal 4 ott 2026 (clodia-platform#503) il legacy (email_config.json) NON è
    più esente: se la sua casella non è in lista l'account compare qui come
    tutti gli altri. Elencarlo fra i disponibili mentre `_secrets_env` lo
    rifiuta sarebbe peggio del buco di prima — un account offerto e poi negato
    al primo uso.
    """
    from .. import egress
    out = []
    for row in credential_diagnostics():
        if not row["operational"]:
            continue
        addr = _account_address(row["credential"], row["account"])
        if not egress.mailbox_allowed(direction, addr, scope):
            out.append(row["account"])
    for nome in _legacy_accounts():
        addr = _legacy_address(nome)
        # Senza indirizzo non è confrontabile e `_secrets_env` lo rifiuta:
        # dichiararlo non ammesso è il referto vero, non una cautela.
        if not addr or not egress.mailbox_allowed(direction, addr, scope):
            out.append(nome)
    return sorted(set(out))


#: Frase con cui si riconosce questo rifiuto senza leggerne il testo:
#: `main._denial_class` la cerca per classificare la decisione come
#: `sender_not_vetted` nel registro (#436). Cambiandola qui va cambiata lì —
#: c'è un test che lo verifica, così la classe non torna "other" in silenzio.
MITTENTE_NON_VAGLIATO = "mittente non vagliato"


def strict_scope() -> str | None:
    """Lo scope della chiamata SE è un canale a ingresso stretto, altrimenti
    `None`.

    Un solo posto a cui chiedere «qui filtro?»: i sei verbi di lettura lo
    interrogano e non ripetono la condizione. Fuori da un canale (un job, una
    chiamata interna) non c'è scope, quindi non c'è stretto: lì vale la
    configurazione d'istanza come sempre.
    """
    from .. import egress
    scope = egress._scope_of_call()
    return scope if scope and egress.ingress_strict(scope) else None


def _sender_vetted(sender: str, scope: str) -> bool:
    """Il mittente di questo messaggio è dichiarato fidato per `scope`?

    `True` solo per chi è nel perimetro della stanza (owner e partecipanti) o
    per un `mailfrom:` dichiarato nella sua lista — `is_vetted_source` risponde
    già a entrambe, e in un canale stretto legge la sola lista di qui.

    Mittente non parsabile → `False`, fail-closed come `UNKNOWN` in uscita: un
    `From:` che non si legge non è una garanzia, è l'assenza di una garanzia.
    """
    from .. import egress
    addr = egress.address_of(sender or "")
    return bool(addr) and egress.is_vetted_source(f"mailfrom:{addr}", scope)


def _record_ingress(verb: str, result: str) -> None:
    """La decisione di ingresso come RECORD, non solo come filtro silenzioso.

    Stessa forma delle decisioni di uscita (#436) e stessa postura: se il
    registro non si può scrivere, la lettura non si fa — un filtro di cui non
    resta traccia è indistinguibile da un filtro che non c'è stato.
    """
    from .. import audit as _audit
    from ..audit import policy as _apol
    try:
        _apol.decision(verb, "ingress", result, reason_class="sender_not_vetted")
    except _audit.AuditWriteError:
        raise PermissionError(
            "audit trail non disponibile: la decisione di ingresso non si può "
            "registrare, quindi la lettura non si fa"
        ) from None
    except Exception as e:  # noqa: BLE001 — la decisione vale anche se non registrata
        LOG.error("audit: decisione di ingresso di %s non registrata (%s)",
                  verb, type(e).__name__)


def _deny_sender(verb: str, sender: str) -> None:
    """Rifiuta la lettura di un messaggio di mittente non vagliato."""
    from .. import egress
    addr = egress.address_of(sender or "") or "?"
    _record_ingress(verb, "deny")
    raise PermissionError(
        f"{MITTENTE_NON_VAGLIATO}: questo canale è a INGRESSO STRETTO e ammette "
        "solo i messaggi di chi è nella stanza (owner e partecipanti) o di un "
        f"mittente dichiarato. Per leggere questo messaggio serve mailfrom:{addr} "
        "negli ingress del canale, e lo aggiunge l'owner."
    )


def _filter_by_sender(rows: object, scope: str, verb: str) -> tuple[list, int]:
    """Tiene solo i messaggi di mittente vagliato; ritorna anche quanti ne ha
    tolti.

    Si filtra DOPO il CLI e non con una query IMAP `FROM`: la query la scrive
    il chiamante, e un filtro che si può riscrivere non è un filtro. Di ciò che
    viene tolto esce solo il NUMERO — un oggetto o un indirizzo sarebbero il
    contenuto che stiamo rifiutando, fatto passare dalla porta di servizio.
    """
    if not isinstance(rows, list):
        return ([] if rows is None else rows), 0
    tenuti = [r for r in rows
              if isinstance(r, dict) and _sender_vetted(str(r.get("from") or ""), scope)]
    tolti = len(rows) - len(tenuti)
    if tolti:
        _record_ingress(verb, "filter")
    return tenuti, tolti


def _sender_of(account: str, email_id: str, folder: str, direction: str) -> str:
    """Il `From:` del messaggio `email_id`, letto apposta per vagliarlo.

    SHORTCUT: una fetch IMAP in più, e dell'intero RFC822 — `get-attachment` e
    `reply` non hanno il mittente nel risultato, e qui serve PRIMA di
    restituire qualcosa. Regge perché succede solo nei canali stretti e solo
    sui tre verbi che non lo conoscono già. Quando peserà, la salita è un
    comando `headers` nel CLI (`RFC822.HEADER`, come fa già `list`) al posto di
    `read`. Il corpo resta nel gateway: di qui esce solo l'indirizzo.
    """
    msg = _run_cli(account, ["read", str(email_id), "--folder", folder],
                   want_json=True, direction=direction)
    return str((msg or {}).get("from") or "") if isinstance(msg, dict) else ""


def _assert_sender_vetted(verb: str, account: str, email_id: str, folder: str,
                          scope: str, *, direction: str = "inbox") -> None:
    """Rifiuta prima di restituire, se il mittente del messaggio non è vagliato.

    `direction` è quella del verbo chiamante, non "inbox" per forza: `reply`
    usa la casella per SPEDIRE ed è la sua whitelist di uscita che conta
    (clodia-platform#428) — vagliare il mittente non deve cambiare quale lista
    governa il verbo.
    """
    mittente = _sender_of(account, email_id, folder, direction)
    if not _sender_vetted(mittente, scope):
        _deny_sender(verb, mittente)


def _legacy_address(account: str) -> str | None:
    """Indirizzo di un account LEGACY (`secrets/email_config.json`), o `None`.

    Serve perché la whitelist per-casella si scrive sull'INDIRIZZO: senza
    questo, un account legacy non ha una chiave con cui essere confrontato, ed
    è esattamente il motivo per cui finora era esente dal controllo.
    """
    try:
        data = json.loads(_legacy_config_file().read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return None
    if "accounts" in data:
        bundle = (data.get("accounts") or {}).get(account)
    else:
        bundle = data if account == "demo" else None
    addr = str((bundle or {}).get("email") or "").strip().lower()
    return addr or None


def _assert_mailbox_allowed(direction: str, addr: str) -> None:
    """La casella `addr` è usabile in questa direzione da questo canale?

    Un punto solo, perché i chiamanti sono due (credenziale in vault e account
    legacy) e la regola è una: metterla in entrambi i rami era il modo in cui
    uno dei due è rimasto senza per un anno.
    """
    from .. import egress
    if egress.mailbox_allowed(direction, addr):
        return
    lista = "ingress" if direction == "inbox" else "egress"
    raise PermissionError(
        f"la casella '{addr}' non è nella whitelist {direction} di questo "
        f"canale. Chiedi all'owner di aggiungere {direction}:{addr} agli "
        f"{lista} del topic (o globalmente, da Integrazioni)."
    )


@contextlib.contextmanager
def _secrets_env(account: str, direction: str):
    """Ambiente per eseguire il CLI per `account`, con credenziali materializzate
    dalla vault (lette come infrastruttura, non più grant-checkate sull'agente)
    in un dir effimero 0700:
    - Gmail OAuth (gmail_<account>/google_<account>) → token OAuth;
    - casella generica (mailbox_<account>) → email_config.json IMAP/SMTP;
    - altrimenti env corrente (legacy secrets/). Il segreto non raggiunge mai
      il motore: vive solo su disco del gateway per la durata del subprocess.

    `direction` ("inbox" per leggere, "outbox" per inviare/rispondere) decide
    QUALE casella questo canale può usare: sostituisce il grant sulla
    credenziale con la whitelist `inbox:`/`outbox:` per-scope (refactor
    whitelist-mailbox, 18 set 2026) — il verbo resta governato da
    `tool_allowed`, questo controllo riguarda solo l'identità della casella.
    """
    gcred, mcred = _gmail_cred(account), _mailbox_cred(account)
    cred = gcred if vault.has_credential(gcred) else (
        mcred if vault.has_credential(mcred) else None)
    if cred is None:
        # LEGACY (`secrets/email_config.json`): fino a clodia-platform#503 qui si
        # usciva senza chiedere niente, e la whitelist per-casella non valeva
        # affatto per questi account — un'esenzione che nessuno aveva deciso,
        # nata dal ramo «nessuna credenziale in vault, tieni l'ambiente».
        # Ora si controllano come tutti, per INDIRIZZO. Senza indirizzo non c'è
        # niente da confrontare: si rifiuta, perché l'alternativa è esentare di
        # nuovo proprio il caso che non si sa giudicare.
        addr = _legacy_address(account)
        if not addr:
            raise PermissionError(
                f"l'account legacy '{account}' non dichiara un indirizzo in "
                "email_config.json: senza indirizzo non è confrontabile con la "
                f"whitelist {direction} di questo canale e non si usa. Aggiungi "
                "'email' alla sua voce, o spostalo nella vault."
            )
        _assert_mailbox_allowed(direction, addr)
        yield dict(os.environ)
        return
    bundle = vault.read_internal(cred)
    addr = (bundle.get("email") or account).strip().lower()
    _assert_mailbox_allowed(direction, addr)
    tmp = tempfile.mkdtemp(prefix="email_sec_")
    try:
        if cred == gcred:
            vault.materialize_google_oauth(gcred, Path(tmp))
        else:
            cfg = {"default": account, "accounts": {account: bundle}}
            cfg_path = Path(tmp) / "email_config.json"
            cfg_path.write_text(json.dumps(cfg, ensure_ascii=False), encoding="utf-8")
            os.chmod(cfg_path, 0o600)
        env = dict(os.environ)
        env["CLODIA_SECRETS_DIR"] = tmp
        yield env
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _run_cli(account: str, cli_args: list[str], *, want_json: bool,
             direction: str, timeout: int = 60) -> Union[dict, list]:
    """Esegue il CLI email_client per `account`, instradando le credenziali
    dalla vault se presente. Ritorna il JSON parsato (read tools) o un dict di
    esito (send/reply).

    `direction`: "inbox" per i verbi di lettura, "outbox" per invio/risposta —
    quale whitelist per-casella verificare (vedi `_secrets_env`)."""
    if account not in known_accounts():
        raise ValueError(
            f"unknown account '{account}'; available: {sorted(known_accounts())}"
        )
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
    """Compat: esegue un comando di lettura/risposta e ritorna il JSON.

    Un punto solo per la guardia «questa casella si legge?»: qui passano tutti i
    verbi che leggono, e **solo** `send` non passa da qui. Metterla in ognuno dei
    sei verbi sarebbe la stessa regola in sei copie, e la settima nascerebbe
    senza. `reply` passa da qui con `direction="outbox"`: legge per il threading
    ma la casella la usa per SPEDIRE, ed è quella whitelist che conta.
    """
    if direction == "inbox":
        _assert_readable(account)
    return _run_cli(account, cli_args, want_json=True, direction=direction, timeout=timeout)


def _assert_readable(account: str) -> None:
    """Rifiuta una LETTURA su una casella di solo invio, dicendo perché.

    L'alternativa sarebbe tentare e restituire il fallimento IMAP, o peggio una
    lista vuota. Vuota è la risposta peggiore: «nessun messaggio» ha la stessa
    forma di una verità e manda l'agente a concludere che la casella è deserta,
    quando invece non è leggibile per costruzione.

    Nominare la causa serve anche a chi legge la chat mesi dopo: «alias senza
    casella» è un fatto sull'indirizzo, non un guasto da riprovare.
    """
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
    ag = agent_name()
    out = {
        "account": account,
        "available_accounts": available_accounts(ag),
        "folders": _run_json(account, ["folders"]),
    }
    # Quali fra quelle disponibili servono SOLO a spedire. Detto nell'elenco e
    # non solo al primo rifiuto: un agente che pianifica «leggo la posta di X»
    # deve poterlo sapere prima, non scoprirlo a metà del lavoro.
    solo_invio = [r["account"] for r in credential_diagnostics()
                  if r.get("send_only") and r["account"] in out["available_accounts"]]
    if solo_invio:
        out["send_only_accounts"] = solo_invio
    # Se esistono caselle che questo canale non può leggere, lo si DICE. Senza,
    # l'unica cosa che l'agente osserva è un'assenza, e un'assenza si spiega col
    # nome sbagliato molto prima che con una whitelist mancante.
    negati = accounts_not_allowed("inbox")
    if negati:
        out["accounts_not_allowed"] = negati
        out["note"] = (
            f"esistono e funzionano anche: {', '.join(negati)} — ma la loro "
            "casella non è nella whitelist di questo canale. Chiedi all'owner "
            "di aggiungere inbox:<email> agli ingress del topic (o "
            "globalmente)."
        )
    return out


def list_messages(account: str = "demo", folder: str = "INBOX", limit: int = 10) -> dict:
    """Elenca i messaggi di una cartella (default INBOX)."""
    tool_allowed("email.list")
    out = {
        "account": account,
        "folder": folder,
        "messages": _run_json(account, ["list", "--folder", folder, "--limit", str(limit)]),
    }
    scope = strict_scope()
    if scope:
        out["messages"], tolti = _filter_by_sender(out["messages"], scope, "email.list")
        out["strict_ingress"] = True
        if tolti:
            out["withheld"] = tolti
            out["note"] = (
                f"{tolti} messaggi non mostrati: canale a ingresso stretto, il "
                "mittente non è nella stanza né dichiarato fra gli ingress. "
                "Di questi messaggi non si vede nulla, nemmeno l'oggetto."
            )
    return out


def read_message(email_id: str, account: str = "demo", folder: str = "INBOX") -> dict:
    """Legge un singolo messaggio per ID."""
    tool_allowed("email.read")
    out = _run_json(account, ["read", str(email_id), "--folder", folder])
    scope = strict_scope()
    # Sul RISULTATO, prima di restituirlo: il mittente è già lì (una seconda
    # fetch sarebbe una richiesta in più per un dato che abbiamo in mano), e il
    # corpo non ha ancora lasciato il gateway.
    if scope and not _sender_vetted(str((out or {}).get("from") or ""), scope):
        _deny_sender("email.read", str((out or {}).get("from") or ""))
    return out



def safe_attachment_name(filename: str, fallback: str = "allegato") -> str:
    """Il nome di un allegato ridotto a UN nome di file.

    Il nome arriva dal mittente — per un `.eml` inoltrato è il subject della mail
    che contiene — e finiva as-is come path relativo di scrittura nel topic: un
    `/` veniva letto come separatore di directory e l'allegato spariva dentro (o
    accanto a) una cartella che nessuno aveva chiesto, mentre il verbo dichiarava
    successo (clodia-platform#420). Qui il `/` torna a essere un carattere del
    nome, che è quello che era.

    Sanifica, non rifiuta: chi archivia la posta in arrivo non ha nessuno a cui
    chiedere un nome migliore, e l'alternativa a un file da rinominare sarebbe
    perdere il contenuto. Il path lo sceglie invece l'agente — lì un path
    illeggibile è un errore, non una rinomina a sorpresa (`_resolve_write_target`).
    """
    name = re.sub(r"[\\/]+", "-", filename or "")
    # Whitespace collassato: i subject decodificati da MIME portano a capo e tab,
    # e uno spazio ai bordi di un segmento rende il file non più elencabile.
    # Il punto iniziale se ne va con gli altri bordi: un dotfile è invisibile al
    # navigator del topic, cioè un altro modo di sparire in silenzio.
    # Fra i caratteri di bordo c'è anche il `-` che abbiamo appena introdotto:
    # un nome fatto di soli separatori deve cadere sul fallback, non diventare
    # un file chiamato "-".
    name = re.sub(r"\s+", " ", name).strip(" .-")
    return name or fallback


def get_attachment(email_id: str, filename: str, account: str = "demo",
                   folder: str = "INBOX") -> dict:
    """Contenuto base64 di un allegato (componibile con topic.write_file/profile).
    Per i binari grandi (PDF, immagini) usare email.save_attachment: il base64
    di un file reale non passa intero dal contesto del modello."""
    tool_allowed("email.get_attachment")
    if not filename:
        raise ValueError("'filename' must be provided")
    scope = strict_scope()
    if scope:
        _assert_sender_vetted("email.get_attachment", account, email_id, folder, scope)
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
    # Stessa lettura di `get_attachment`, altro verbo: la issue nominava solo
    # quello, ma lasciare scoperto il gemello significherebbe che il filtro si
    # aggira chiamando la porta accanto.
    scope = strict_scope()
    if scope:
        _assert_sender_vetted("email.save_attachment", account, email_id, folder, scope)
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
    out = {
        "account": account,
        "query": query,
        "results": _run_json(account, ["search", query, "--folder", folder, "--limit", str(limit)]),
    }
    scope = strict_scope()
    if scope:
        out["results"], tolti = _filter_by_sender(out["results"], scope, "email.search")
        out["strict_ingress"] = True
        if tolti:
            out["withheld"] = tolti
            out["note"] = (
                f"{tolti} risultati non mostrati: canale a ingresso stretto, il "
                "mittente non è nella stanza né dichiarato fra gli ingress."
            )
    return out


def reply(email_id: str, body: str, account: str = "demo",
          folder: str = "INBOX", cc: Optional[str] = None,
          attachments: Optional[Sequence[str]] = None) -> dict:
    """Risponde a un messaggio mantenendo il threading (SMTP)."""
    tool_allowed("email.reply")
    if body is None:
        raise ValueError("'body' must be provided (use empty string if intentional)")
    # Il destinatario di una risposta NON sta negli argomenti: è il mittente del
    # messaggio originale, cioè contenuto non fidato. In un canale stretto
    # rispondere a un mittente non vagliato sarebbe il modo di uscire verso
    # chiunque abbia scritto alla casella — qui quella strada si chiude.
    scope = strict_scope()
    if scope:
        _assert_sender_vetted("email.reply", account, email_id, folder, scope,
                              direction="outbox")
    args = ["reply", str(email_id), "--body", body, "--folder", folder]
    if cc:
        args += ["--cc", cc]
    args += _attachment_args(attachments)
    # `outbox`, come dice `_run_json`: la risposta la SPEDISCE questa casella, ed
    # è la sua whitelist di uscita che conta (clodia-platform#428 — passava da qui
    # col default `inbox`, cioè col controllo della casella sbagliato).
    return _run_json(account, args, direction="outbox")


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
    # `direction` è obbligatorio dal refactor whitelist-mailbox del 18 set 2026:
    # senza, ogni invio falliva con `TypeError` PRIMA di partire, dal 22 al 28 set
    # (clodia-platform#428). `outbox`: si controlla la casella che spedisce.
    res = _run_cli(account, args, want_json=False, direction="outbox")
    return {
        "ok": True,
        "to": to,
        "subject": subject,
        "account": account,
        "attachments": [str(Path(str(p)).expanduser()) for p in attachments or []],
        "stdout": res.get("stdout", ""),
    }
