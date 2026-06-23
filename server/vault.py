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


def _audit(agent: str, action: str, credential: str, result: str, **extra) -> None:
    rec = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "agent": agent,
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


def grants_for(agent: str) -> dict[str, dict]:
    """{credential_name: {actions: set, type: str}} per l'agente.

    Solo credenziali il cui bundle esiste effettivamente nello store.
    """
    out: dict[str, dict] = {}
    creds = (_load_policy().get("credentials") or {})
    for name, spec in creds.items():
        spec = spec or {}
        if not (_store_dir() / f"{name}.json").is_file():
            continue
        for g in (spec.get("grants") or []):
            if (g or {}).get("agent") != agent:
                continue
            actions = {str(a) for a in (g.get("actions") or [])} & VALID_ACTIONS
            if actions:
                out[name] = {"actions": actions, "type": spec.get("type")}
            break
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
    grant = grants_for(agent).get(credential)
    if grant is None:
        _audit(agent, "fetch", credential, "DENIED", reason="no grant")
        raise VaultDenied(
            f"agent '{agent}' non ha grant 'fetch' per la credenziale '{credential}'")
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


def set_grant(credential: str, agent: str, granted: bool,
              actions: Optional[list[str]] = None) -> None:
    """Aggiunge/rimuove il grant di `agent` su `credential` in vault-policy.yaml.
    Idempotente. Usato per delegare un connettore (es. gmail_studio) a un agent."""
    actions = actions or ["fetch"]
    policy = _load_policy()
    creds = policy.setdefault("credentials", {})
    spec = creds.setdefault(credential, {})
    grants = spec.setdefault("grants", [])
    grants[:] = [g for g in grants if (g or {}).get("agent") != agent]
    if granted:
        grants.append({"agent": agent, "actions": list(actions)})
    _policy_file().write_text(yaml.safe_dump(policy, sort_keys=False, allow_unicode=True),
                              encoding="utf-8")
    os.chmod(_policy_file(), 0o600)


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
