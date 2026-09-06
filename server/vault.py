"""Vault delle credenziali dei tool — custodita dal gateway clodia-tools.

Modello (deciso 15 giu 2026): le credenziali dei tool NON vivono più in
`secrets/` editata a mano, ma in una **vault dedicata** su un volume separato
(`~/.clodia`) montato **solo** dal container clodia-tools. La vault è il
custode: un tool ottiene il valore di una credenziale solo se l'agente
chiamante (identità già verificata dal gateway via ckt1) ha il grant `fetch`.

Distinta dal keystore-colonia (clodia-logic), che resta per il broker
`git_push` e il lease execution-scoped degli agenti della colonia.

Layout della vault::

    $CLODIA_VAULT_DIR/                 # default ~/.clodia
      store/<credential>.json          # bundle della credenziale (valore)
      vault-policy.yaml                # grant per-agente
      audit.log                        # JSONL append-only di ogni accesso

`vault-policy.yaml`::

    credentials:
      gmail_demo:
        type: oauth2_google            # informa il materializzatore
        grants:
          - agent: clodia
            actions: [fetch]           # fetch = ottieni il valore
            principals: [davide]       # opzionale: per conto di CHI (assente = chiunque)
            topics: [SEAL-1/studio]    # opzionale: DOVE (assente = ovunque)

`principals` e `topics` sono chiavi di **restringimento**, e la loro assenza
significa «qualunque»: una policy scritta prima che esistessero si comporta
esattamente come prima (clodia-platform#270). Le due dimensioni non le dichiara
il chiamante — si leggono dal contesto **firmato** della richiesta (claim
`principal` e claim `chat` del token ckt1), quindi un agente non può dichiararsi
in un topic in cui non è, né spendere l'identità di un'altra persona.

Prima Legge: il valore del segreto è restituito SOLO a codice del gateway
(non a un modello). I tool lo usano per l'handshake col servizio e lo
scartano; non entra mai nel contesto LLM né viene loggato.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

VALID_ACTIONS = {"fetch"}


def vault_dir() -> Path:
    return Path(os.environ.get("CLODIA_VAULT_DIR") or (Path.home() / ".clodia")).expanduser()


def _store_dir() -> Path:
    return vault_dir() / "store"


def _policy_file() -> Path:
    return vault_dir() / "vault-policy.yaml"


def _audit_file() -> Path:
    return vault_dir() / "audit.log"


class VaultDenied(PermissionError):
    """L'agente non ha il grant richiesto sulla credenziale."""


def _caller_hint() -> str:
    """CHI sta cambiando l'autorità, per quanto il gateway riesce a saperlo.

    Il principal umano se la chiamata arriva dalla webui, l'agente altrimenti, e
    `shell` quando non c'è nessuna identità nel contesto — cioè un `docker exec`
    a mano. Quest'ultimo caso è quello che serviva di più e mancava: distingue
    «l'ha tolto la UI» da «l'ha tolto qualcuno dal guscio», che portano in due
    direzioni opposte.
    """
    try:
        from . import whitelist as _w
        return (_w.current_principal() or _w.agent_name_safe() or "shell")
    except Exception:  # noqa: BLE001 — l'audit non deve dipendere dal contesto
        return "shell"


def _caller_context() -> tuple[Optional[str], Optional[str]]:
    """(principal, topic) della richiesta corrente, dal contesto FIRMATO.

    Entrambi esistono già quando il vault decide, e nessuno dei due è
    dichiarabile da un modello: il principal è il claim `principal` del token, il
    topic è `<tier>/<nome>` derivato dal claim `chat` (`whitelist.current_channel`,
    un punto solo, quello che usano anche i gate). `None` significa «il contesto
    non lo dice» — un job schedulato, una shell — e NON «qualunque»: chi decide
    tratta i due casi in modo diverso (vedi `_restriction_failed`).
    """
    try:
        from . import whitelist as _w
        return _w.current_principal(), _w.current_channel()
    except Exception:  # noqa: BLE001 — il vault non deve dipendere dal contesto
        return None, None


def _audit(agent: str, action: str, credential: str, result: str, **extra) -> None:
    principal, topic = _caller_context()
    rec = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "agent": agent,
        # PER CONTO DI CHI e DOVE. Si scrivono sempre, anche `null`: la domanda
        # «di chi era l'identità quando quella casella è stata letta» non aveva
        # risposta nemmeno a posteriori, e un campo assente non si distingue da
        # un campo mai scritto (clodia-platform#270).
        "principal": principal,
        "topic": topic,
        "action": action,
        "credential": credential,
        "result": result,
    }
    if extra:
        rec.update(extra)
    try:
        d = vault_dir()
        d.mkdir(parents=True, exist_ok=True)
        with _audit_file().open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        # l'audit non deve mai rompere l'operazione, ma un fallimento va notato
        pass


def _load_policy() -> dict:
    f = _policy_file()
    if not f.is_file():
        return {}
    try:
        return yaml.safe_load(f.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        # default DENY: policy non parsabile ⇒ nessun grant
        return {}


#: Le due dimensioni di restringimento, e da dove si legge ciascuna. Una tupla
#: sola: aggiungere una terza dimensione qui la fa entrare insieme nel match,
#: nella scrittura e nella matrice, senza tre modifiche che possono divergere.
SCOPE_KEYS = ("principals", "topics")


def _scope_list(g: dict, key: str) -> list[str]:
    return [str(x).strip() for x in (g.get(key) or []) if str(x).strip()]


def _restriction_failed(g: dict, principal: Optional[str],
                        topic: Optional[str]) -> Optional[str]:
    """Quale restrizione del grant vieta QUESTA richiesta, o None se nessuna.

    Chiave assente (o lista vuota) = nessuna restrizione su quella dimensione:
    è ciò che rende la policy di ieri identica a se stessa.

    Contesto ignoto contro restrizione presente = **rifiuto**. È il verso in cui
    si deve sbagliare: se non sappiamo in che topic siamo, un grant ristretto a
    un topic varrebbe proprio là dove nessuno può verificarlo.
    """
    for key, value in zip(SCOPE_KEYS, (principal, topic)):
        allowed = _scope_list(g, key)
        if not allowed:
            continue
        if value is None or value not in allowed:
            return key
    return None


def _resolve_grant(spec: dict, agent: str, principal: Optional[str],
                   topic: Optional[str]) -> tuple[Optional[dict], Optional[str]]:
    """(grant applicabile, dimensione che ha rifiutato) — il PUNTO UNICO in cui
    si decide se un agente può usare una credenziale qui e ora.

    Lo interrogano `grants_for`, `list_for` e `get_secret`: tre letture parallele
    dello stesso dict divergono, ed è il difetto che abbiamo appena pagato
    altrove. Un elenco che mostra ciò che una fetch poi nega è una bugia con la
    forma di un permesso.
    """
    denied: Optional[str] = None
    for g in (spec.get("grants") or []):
        g = g or {}
        if g.get("agent") != agent:
            continue
        failed = _restriction_failed(g, principal, topic)
        if failed is not None:
            denied = denied or failed
            continue
        actions = {str(a) for a in (g.get("actions") or [])} & VALID_ACTIONS
        if actions:
            return {"actions": actions}, None
    return None, denied


def grants_for(agent: str) -> dict[str, dict]:
    """{credential_name: {actions: set, type: str}} per l'agente **qui e ora**.

    Solo credenziali il cui bundle esiste effettivamente nello store, e i cui
    grant non siano ristretti a un altro principal o a un altro topic.
    """
    principal, topic = _caller_context()
    out: dict[str, dict] = {}
    creds = (_load_policy().get("credentials") or {})
    for name, spec in creds.items():
        spec = spec or {}
        if not (_store_dir() / f"{name}.json").is_file():
            continue
        grant, _ = _resolve_grant(spec, agent, principal, topic)
        if grant:
            out[name] = {"actions": grant["actions"], "type": spec.get("type")}
    return out


def list_for(agent: str) -> list[str]:
    """Nomi (mai valori) delle credenziali leggibili dall'agente."""
    return sorted(grants_for(agent).keys())


def store_names() -> list[str]:
    """Nomi di tutte le credenziali presenti nello store (per lo stato dei
    connettori in UI). Mai valori."""
    d = _store_dir()
    if not d.is_dir():
        return []
    return sorted(p.stem for p in d.glob("*.json"))


def has_credential(credential: str) -> bool:
    """True se il bundle esiste nello store (indipendente dal grant).

    Serve ai tool per decidere se un account è 'vault-backed' (→ flusso vault)
    o ancora legacy (→ secrets/). Il controllo del grant avviene poi in
    get_secret/materialize, sull'identità dell'agente chiamante.
    """
    return (_store_dir() / f"{credential}.json").is_file()


def get_secret(agent: str, credential: str) -> dict:
    """Ritorna il bundle (valore) della credenziale se l'agente ha `fetch`.

    Solleva VaultDenied se non autorizzato. Ogni accesso è auditato.
    Il chiamante è codice del gateway: il valore NON deve raggiungere un modello.
    """
    principal, topic = _caller_context()
    spec = (_load_policy().get("credentials") or {}).get(credential) or {}
    grant, fuori_ambito = _resolve_grant(spec, agent, principal, topic)
    if not has_credential(credential):
        # TERZO caso, che il messaggio sotto non distingueva e che ha mandato un
        # admin a concedere una cosa inesistente. Su venere `telegram_bot_token`
        # non è nel vault: nessuno può averne il grant, e messaggero ha riferito
        # «serve che un amministratore conceda il permesso» — vero in generale,
        # falso su quell'istanza, dove il connettore non è mai stato collegato.
        #
        # Il rimedio è diverso e va nominato: collegare l'integrazione, non dare
        # un permesso. È la quarta volta oggi che l'informazione sul guasto esiste
        # (`has_credential` è False) e non raggiunge chi può agire.
        _audit(agent, "fetch", credential, "DENIED", reason="credential absent")
        raise VaultDenied(
            f"la credenziale '{credential}' NON ESISTE su questa istanza, quindi "
            f"non è questione di permessi: nessuno può concederla. Il connettore "
            f"non è collegato qui. Serve che un admin lo colleghi da Tools → "
            f"Integrations, e solo dopo ha senso concedere il grant a '{agent}'. "
            f"Riferiscilo così: chiedere un permesso non risolve, e nemmeno "
            f"delegare a un altro agente — su questa istanza quel canale non c'è "
            f"per nessuno.")
    if grant is None and fuori_ambito:
        # QUARTO caso: il grant c'è, ma non copre questa richiesta. Va detto in
        # modo diverso da «non ce l'hai», perché manda a fare una cosa diversa:
        # non «chiedi il permesso», ma «questa credenziale non è di questa
        # persona / di questa stanza». Chi legge deve poter riferire QUALE delle
        # due dimensioni ha rifiutato, altrimenti la sola mossa che gli resta è
        # chiedere di allargare tutto.
        _audit(agent, "fetch", credential, "DENIED",
               reason=f"out of scope: {fuori_ambito}")
        dove = ("il principal per conto del quale stai operando "
                f"({principal or 'nessuno: nessun utente firmato in questa richiesta'})"
                if fuori_ambito == "principals" else
                "il topic in cui stai operando "
                f"({topic or 'nessuno: questa richiesta non arriva da un canale'})")
        raise VaultDenied(
            f"agent '{agent}' HA un grant su '{credential}', ma ristretto: "
            f"{dove} non rientra nell'ambito concesso. Non è un permesso "
            f"mancante da chiedere in blocco — quella credenziale è stata legata "
            f"a un'altra persona o a un'altra stanza di proposito. Serve che un "
            f"admin estenda l'ambito, se davvero deve valere anche qui. NON si "
            f"risolve chiedendo a un altro agente di farlo per te: userebbe la "
            f"propria credenziale, e sarebbe l'identità sbagliata sul dato "
            f"esterno — cioè esattamente ciò che questa restrizione impedisce.")
    if grant is None:
        _audit(agent, "fetch", credential, "DENIED", reason="no grant")
        # Il rifiuto deve distinguere DUE cose che un modello confonde, e la
        # confusione ha una conseguenza precisa: messaggero, letto «non ha
        # grant», ha riferito in canale «non ho il capability email.send» e ha
        # chiesto a un altro agente di spedire per lui. Ma il verbo lo AVEVA —
        # quando questa funzione gira, la whitelist è già passata — e quello che
        # gli mancava era la credenziale.
        #
        # Delegare intorno a una credenziale mancante è un tentativo di confused
        # deputy: l'altro agente userebbe la PROPRIA credenziale, cioè un'uscita
        # che nessuno ha autorizzato per questa richiesta. Il messaggio lo dice,
        # perché è l'istinto dell'agente e va contraddetto dove nasce.
        #
        # Non si elenca CHI ha il grant: sarebbe indicare l'agente a cui
        # delegare, cioè suggerire proprio la mossa da evitare.
        raise VaultDenied(
            f"agent '{agent}' non ha grant 'fetch' per la credenziale "
            f"'{credential}'. Il VERBO ti è consentito — se sei arrivato qui la "
            f"whitelist è già passata: manca la credenziale, che è una cosa "
            f"diversa. NON si risolve chiedendo a un altro agente di farlo per "
            f"te: userebbe la propria credenziale, e sarebbe un'uscita che "
            f"nessuno ha autorizzato per questa richiesta. Serve che un admin "
            f"conceda '{credential}' a '{agent}'. Riferiscilo così a chi ti ha "
            f"chiesto l'operazione.")
    bundle_path = _store_dir() / f"{credential}.json"
    try:
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        _audit(agent, "fetch", credential, "ERROR", reason=type(e).__name__)
        raise RuntimeError(f"vault: bundle '{credential}' illeggibile") from e
    _audit(agent, "fetch", credential, "OK", type=grant.get("type"))
    return bundle


def read_internal(credential: str) -> dict:
    """Lettura interna del gateway, NON mediata da un agente: per le credenziali
    di **infrastruttura del gateway stesso** (es. il client OAuth dell'app,
    `app_google_oauth`, che serve a costruire l'URL di consenso e a scambiare
    il code). Audit come `system`. Da NON usare per credenziali esposte agli
    agenti (quelle passano da get_secret con grant).
    """
    bundle_path = _store_dir() / f"{credential}.json"
    if not bundle_path.is_file():
        _audit("system", "read_internal", credential, "DENIED", reason="absent")
        raise VaultDenied(f"credenziale di infrastruttura '{credential}' assente")
    try:
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        _audit("system", "read_internal", credential, "ERROR", reason=type(e).__name__)
        raise RuntimeError(f"vault: infrastruttura '{credential}' illeggibile") from e
    _audit("system", "read_internal", credential, "OK")
    return bundle


# ── Materializzazione per l'adapter email (tipo oauth2_google) ──────────────

# server IMAP/SMTP di Gmail (type oauth2_google ⇒ Gmail)
_GMAIL_SERVERS = {
    "imap_server": "imap.gmail.com", "imap_port": 993,
    "smtp_server": "smtp.gmail.com", "smtp_port": 587,
}


def materialize_google_oauth(agent: str, credential: str, dest_dir: Path) -> str:
    """Prepara in `dest_dir` un CLODIA_SECRETS_DIR effimero completo per
    `email_client` e ritorna il nome account. Scrive i 3 file che servono:
    `google_oauth_client.json`, `email_oauth_tokens.json` e un
    `email_config.json` minimale con l'account marcato `auth: oauth2` + i
    server Gmail. Il segreto vive solo per la durata della chiamata in una dir
    effimera (0700) dentro il container del gateway.

    Bundle atteso::

        {"client_id", "client_secret", "refresh_token", "email", "account"?}
    """
    b = get_secret(agent, credential)
    missing = [k for k in ("client_id", "client_secret", "refresh_token", "email")
               if not b.get(k)]
    if missing:
        raise RuntimeError(f"vault: bundle '{credential}' incompleto, manca {missing}")
    account = b.get("account") or b["email"].split("@")[0].replace(".", "_")
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(dest_dir, 0o700)

    client_f = dest_dir / "google_oauth_client.json"
    client_f.write_text(json.dumps(
        {"client_id": b["client_id"], "client_secret": b["client_secret"]}), encoding="utf-8")
    os.chmod(client_f, 0o600)

    tokens_f = dest_dir / "email_oauth_tokens.json"
    tokens_f.write_text(json.dumps(
        {account: {"refresh_token": b["refresh_token"], "email": b["email"]}}), encoding="utf-8")
    os.chmod(tokens_f, 0o600)

    config_f = dest_dir / "email_config.json"
    config_f.write_text(json.dumps({
        "accounts": {account: {"email": b["email"], "auth": "oauth2", **_GMAIL_SERVERS}},
        "default": account,
    }), encoding="utf-8")
    os.chmod(config_f, 0o600)
    return account


# ── Deposito (usato da connect_email e dai futuri flussi OAuth da clodia-web) ─

def deposit(credential: str, bundle: dict, *, cred_type: str = "opaque",
            grant_agents: Optional[list[str]] = None,
            actions: Optional[list[str]] = None) -> None:
    """Salva un bundle nello store e garantisce il grant in vault-policy.yaml.

    Idempotente: sovrascrive il bundle; aggiunge i grant mancanti senza
    duplicare quelli esistenti. Default grant `fetch` a `clodia`.
    """
    if grant_agents is None:
        grant_agents = ["clodia"]   # passa [] esplicito per credenziali infra (nessun grant)
    actions = actions or ["fetch"]
    store = _store_dir()
    store.mkdir(parents=True, exist_ok=True)
    bf = store / f"{credential}.json"
    bf.write_text(json.dumps(bundle, ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(bf, 0o600)

    policy = _load_policy()
    creds = policy.setdefault("credentials", {})
    spec = creds.setdefault(credential, {})
    spec["type"] = cred_type
    grants = spec.setdefault("grants", [])
    have = {g.get("agent") for g in grants if isinstance(g, dict)}
    for ag in grant_agents:
        if ag not in have:
            grants.append({"agent": ag, "actions": list(actions)})
    _policy_file().write_text(yaml.safe_dump(policy, sort_keys=False, allow_unicode=True),
                              encoding="utf-8")
    os.chmod(_policy_file(), 0o600)
    # Anche qui si registra CHI ha scritto, e con quali grant risulta la
    # credenziale DOPO. `deposit` è additivo per contratto, e questa riga è ciò
    # che permette di verificarlo sui fatti invece che sulla docstring: se un
    # giorno un grant sparisse dopo un deposit, la riga precedente lo direbbe.
    _audit(_caller_hint(), "deposit", credential, "OK",
           grants_after=sorted(x for x in (
               (g or {}).get("agent") for g in grants) if x))


def set_grant(credential: str, agent: str, granted: bool,
              actions: Optional[list[str]] = None,
              principals: Optional[list[str]] = None,
              topics: Optional[list[str]] = None) -> None:
    """Aggiunge/rimuove il grant di `agent` su `credential` in vault-policy.yaml.
    Idempotente. Usato per delegare un connettore (es. gmail_studio) a un agent.

    **Scrive nell'audit**, e non è un dettaglio di completezza. L'11 ago 2026 un
    grant su `mailbox_team` è sparito fra una sera e la mattina dopo: concesso e
    verificato due volte, assente il giorno seguente. L'audit registrava letture
    e rifiuti — quindi la domanda «chi l'ha tolto» non aveva risposta, e ci si
    poteva solo fare un'ipotesi.

    Un permesso che scompare senza traccia è peggio di un permesso mancante: il
    secondo si vede, il primo si scopre quando qualcosa smette di funzionare e
    manda a cercare la causa in un posto qualunque. Registrare CHI cambia
    l'autorità è la sola cosa che rende quella domanda rispondibile la prossima
    volta.

    `principals` / `topics` restringono il grant a certe persone o a certe
    stanze. Ometterli (o passare una lista vuota) NON scrive la chiave: una
    `principals: []` sul disco si leggerebbe «nessuno», che è l'opposto di
    «chiunque» (clodia-platform#270).
    """
    actions = actions or ["fetch"]
    policy = _load_policy()
    creds = policy.setdefault("credentials", {})
    spec = creds.setdefault(credential, {})
    grants = spec.setdefault("grants", [])
    prima = {(g or {}).get("agent") for g in grants}
    grants[:] = [g for g in grants if (g or {}).get("agent") != agent]
    if granted:
        voce = {"agent": agent, "actions": list(actions)}
        for key, valori in zip(SCOPE_KEYS, (principals, topics)):
            valori = [str(v).strip() for v in (valori or []) if str(v).strip()]
            if valori:
                voce[key] = valori
        grants.append(voce)
    _policy_file().write_text(yaml.safe_dump(policy, sort_keys=False, allow_unicode=True),
                              encoding="utf-8")
    os.chmod(_policy_file(), 0o600)
    # Anche il no-op si registra: «era già così» è un'informazione, e distingue
    # «nessuno l'ha toccato» da «nessuno lo sa».
    _audit(agent, "grant" if granted else "revoke", credential,
           "OK", by=_caller_hint(), was_granted=agent in prima)


def grant_scope(credential: str) -> dict[str, dict]:
    """{agent: {actions, principals, topics}} — l'ambito di ogni grant, per la UI.

    Liste vuote = nessuna restrizione su quella dimensione, cioè «chiunque» /
    «ovunque»: chi mostra la matrice deve poter scrivere la differenza fra «tutta
    l'istanza» e «solo Davide, solo in SEAL-1/studio», che oggi non è visibile in
    nessun punto della UI. Mai valori di credenziali, solo ambiti.
    """
    spec = (_load_policy().get("credentials") or {}).get(credential) or {}
    out: dict[str, dict] = {}
    for g in (spec.get("grants") or []):
        g = g or {}
        ag = g.get("agent")
        if not ag:
            continue
        voce = out.setdefault(ag, {"actions": [], "principals": [], "topics": []})
        voce["actions"] = sorted(set(voce["actions"]) |
                                 ({str(a) for a in (g.get("actions") or [])} & VALID_ACTIONS))
        for key in SCOPE_KEYS:
            voce[key] = sorted(set(voce[key]) | set(_scope_list(g, key)))
    return out


def agents_with_grant(credential: str) -> list[str]:
    """Agenti che hanno un grant su `credential` (per la matrice UI)."""
    policy = _load_policy()
    spec = (policy.get("credentials") or {}).get(credential) or {}
    return sorted({(g or {}).get("agent") for g in spec.get("grants", []) if (g or {}).get("agent")})


def email_connectors() -> list[str]:
    """Account email disponibili = credenziali gmail_<account> nello store."""
    return sorted(n[len("gmail_"):] for n in store_names() if n.startswith("gmail_"))


def remove(credential: str) -> bool:
    """Rimuove un bundle dallo store e la sua voce in vault-policy.yaml.

    Idempotente: ritorna True se c'era qualcosa da rimuovere, False altrimenti.
    Usato per il disconnect dei provider (Fase 4).
    """
    removed = False
    bf = _store_dir() / f"{credential}.json"
    if bf.is_file():
        bf.unlink()
        removed = True
    policy = _load_policy()
    creds = policy.get("credentials") or {}
    if credential in creds:
        creds.pop(credential, None)
        _policy_file().write_text(yaml.safe_dump(policy, sort_keys=False, allow_unicode=True),
                                  encoding="utf-8")
        os.chmod(_policy_file(), 0o600)
        removed = True
    return removed
