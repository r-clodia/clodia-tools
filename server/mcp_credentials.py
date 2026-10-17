"""Credenziali dei backend MCP chieste al «Connetti» della card (clodia-platform#565).

Decisione dell'owner (17 ott 2026): l'installazione di un pack non chiede mai
segreti. Monta i suoi backend MCP **non connessi**; l'owner preme «Connetti»
sulla card e parte un consenso OAuth 2 oppure — se il backend lo consente — un
modulo chiede una credenziale (API key, o utente + password come per IMAP).
Stessa regola per i server montati da Tools.

Il backend dichiara cosa accetta in `auth.methods`, in ordine di preferenza:

    "auth": {"methods": [
      {"type": "oauth", "scope": "invoicetronic:read"},
      {"type": "credential",
       "fields": [{"name": "APIKEY", "label": "API key", "secret": true}],
       "inject": {"headers": {"Invoicetronic-ApiKey": "${APIKEY}"}}}
    ]}

`inject` scrive i campi in `headers` (http) o in `env` (stdio). Mai nella URL:
httpx scrive la URL di ogni richiesta nei log a livello INFO, e una URL può
puntare a un host diverso dal backend (review di #387). La
forma di prima, `auth: {type: oauth, …}`, resta valida e non cambia forma nel
config. Un config SENZA `auth` ma con placeholder `${NOME}` in headers/env
e senza il segreto nella richiesta diventa da sé un metodo `credential`: è il
caso di un `.mcp.json` di pack, che un segreto non lo porta mai.

Dove stanno i valori: un bundle nella vault, `mcp_cred_<slug>`, credenziale di
**infrastruttura** (`grant_agents=[]`). Nel config il campo diventa
`${VAULT:mcp_cred_<slug>.<CAMPO>}`, risolto dal proxy al momento della
chiamata. I valori non tornano mai al browser, non stanno nel config, non
finiscono nei log né nel contesto di un agente.

Connesso vuol dire PROVATO: il «Connetti» apre una sessione con i valori
inseriti e chiede `list_tools`; solo se risponde i valori vanno nella vault.
Un test fallito non salva niente.
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

from . import mcp_oauth
from . import vault

LOG = logging.getLogger("clodia-tools.mcp_credentials")

#: Nome di un campo: anche il nome del placeholder `${NOME}`.
_FIELD_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
_PH_RE = re.compile(r"\$\{([A-Za-z][A-Za-z0-9_]{0,63})\}")
#: Placeholder che NON sono credenziali: li risolve il runtime dei pack.
_RUNTIME_PLACEHOLDERS = {"CLAUDE_PLUGIN_ROOT", "CLAUDE_PLUGIN_DATA", "CLAUDE_PROJECT_DIR"}
#: Dove `inject` può scrivere, per transport. Non la URL: vedi il docstring.
_TARGETS = {"http": ("headers",), "stdio": ("env",)}
#: Quanto aspetta il test del «Connetti».
CONNECT_TIMEOUT_S = 30


class CredentialRequired(mcp_oauth.ReauthorizationRequired):
    """Il backend vuole una credenziale che solo l'owner può inserire."""


def cred_name(slug: str) -> str:
    return mcp_oauth.credential_cred_name(slug)


#: Slug che un backend non può avere: `mcp_<slug>_<NOME>` dei segreti di
#: Tools coinciderebbe con `mcp_cred_<x>` / `mcp_oauth_<x>` di un altro backend
#: (review di #387: il backend `cred` col segreto `invoicetronic` sovrascriveva
#: la credenziale di invoicetronic).
RESERVED_SLUGS = {"cred", "oauth"}


def fingerprint(backend: dict) -> tuple:
    """Ciò che, se cambia, rende la credenziale salvata non più dell'owner.

    Origin della URL, comando e argomenti, e dove il metodo la inietta: un
    Update del pack che punta altrove non eredita la chiave (review di #387).
    """
    from urllib.parse import urlparse
    u = urlparse(str(backend.get("url") or ""))
    method = credential_method(backend) or {}
    return (f"{u.scheme}://{u.netloc}", backend.get("command"),
            tuple(backend.get("args") or ()), repr(sorted((method.get("inject") or {}).items())))


# ── Config ──────────────────────────────────────────────────────────────────

def _placeholders(val: Any) -> set[str]:
    if isinstance(val, str):
        return set(_PH_RE.findall(val))
    if isinstance(val, dict):
        return set().union(*(_placeholders(v) for v in val.values())) if val else set()
    if isinstance(val, list):
        return set().union(*(_placeholders(v) for v in val)) if val else set()
    return set()


def _normalize_credential(raw: dict, transport: str) -> dict:
    fields_in = raw.get("fields")
    if not isinstance(fields_in, list) or not fields_in:
        raise ValueError("metodo 'credential' senza 'fields'")
    fields: list[dict] = []
    for f in fields_in:
        if isinstance(f, str):
            f = {"name": f}
        if not isinstance(f, dict) or not _FIELD_RE.match(str(f.get("name") or "")):
            raise ValueError(f"campo di credenziale non valido: {f!r}")
        name = str(f["name"])
        if any(x["name"] == name for x in fields):
            raise ValueError(f"campo di credenziale ripetuto: {name}")
        fields.append({"name": name, "label": str(f.get("label") or name),
                       "secret": bool(f.get("secret", True))})
    inject = raw.get("inject")
    if not isinstance(inject, dict) or not inject:
        raise ValueError("metodo 'credential' senza 'inject'")
    allowed = _TARGETS.get(transport, ())
    out_inject: dict[str, Any] = {}
    for target, val in inject.items():
        if target not in allowed:
            raise ValueError(f"inject.{target} non vale per un server {transport} "
                             f"(ammessi: {', '.join(allowed)}; una credenziale nella URL "
                             "finirebbe nei log)")
        if not isinstance(val, dict) or not all(
                isinstance(k, str) and isinstance(v, str) for k, v in val.items()):
            raise ValueError(f"inject.{target} deve essere un oggetto di stringhe")
        if any("${VAULT:" in v for v in val.values()):
            raise ValueError(f"inject.{target}: un riferimento al vault non è un campo da inserire")
        out_inject[target] = dict(val)
    names = {f["name"] for f in fields}
    used = _placeholders(out_inject)
    if used - names:
        raise ValueError(f"inject usa campi non dichiarati: {', '.join(sorted(used - names))}")
    if names - used:
        raise ValueError(f"campi dichiarati e mai usati in inject: {', '.join(sorted(names - used))}")
    return {"type": "credential", "fields": fields, "inject": out_inject}


def normalize(raw: Any, *, transport: str) -> dict:
    """Valida `auth` di un server mcp.json. La forma OAuth di prima non cambia."""
    if isinstance(raw, dict) and "methods" in raw:
        methods_in = raw.get("methods")
        if not isinstance(methods_in, list) or not methods_in:
            raise ValueError("'auth.methods' deve essere una lista non vuota")
        methods: list[dict] = []
        for m in methods_in:
            kind = str((m or {}).get("type") if isinstance(m, dict) else m or "").lower()
            if kind == "oauth":
                methods.append(mcp_oauth.normalize_auth(m, transport=transport))
            elif kind == "credential":
                methods.append(_normalize_credential(m, transport))
            else:
                raise ValueError(f"metodo di auth non supportato: {kind or '(vuoto)'} "
                                 "— attesi 'oauth' o 'credential'")
        if sum(1 for m in methods if m["type"] == "oauth") > 1 or \
           sum(1 for m in methods if m["type"] == "credential") > 1:
            raise ValueError("al più un metodo per tipo in 'auth.methods'")
        return {"methods": methods}
    return mcp_oauth.normalize_auth(raw, transport=transport)


def implicit_method(spec: dict, transport: str, provided: set[str]) -> dict | None:
    """Il metodo `credential` di un config che ha placeholder senza segreto.

    Solo in headers (http) o env (stdio), mai negli `args` né nella URL, e mai i
    placeholder del runtime dei pack (`${CLAUDE_PLUGIN_ROOT}`).
    """
    inject: dict[str, Any] = {}
    names: set[str] = set()
    for target in _TARGETS.get(transport, ()):
        val = spec.get(target)
        found = _placeholders(val) - _RUNTIME_PLACEHOLDERS - provided
        if not found:
            continue
        inject[target] = {k: v for k, v in (val or {}).items()
                          if _placeholders(v) & found}
        names |= found
    if not names:
        return None
    return {"type": "credential",
            "fields": [{"name": n, "label": n, "secret": True} for n in sorted(names)],
            "inject": inject}


def leftover_placeholders(backend: dict) -> set[str]:
    """I `${NOME}` rimasti nel backend montato, che nessuno riempirà mai.

    Negli `args`, nella URL, o in headers/env accanto a un `auth` esplicito:
    montarli darebbe una card verde che manda al vendor il placeholder
    letterale (review di clodia-web#244).
    """
    found: set[str] = set()
    for key in ("url", "args", "headers", "env"):
        found |= _placeholders(backend.get(key))
    return found - _RUNTIME_PLACEHOLDERS


def strip_injected(spec: dict, method: dict) -> dict:
    """Il config senza i valori che il metodo `credential` scrive al «Connetti»."""
    out = dict(spec)
    for target, val in method.get("inject", {}).items():
        rest = {k: v for k, v in (out.get(target) or {}).items() if k not in val}
        if rest:
            out[target] = rest
        else:
            out.pop(target, None)
    return out


# ── Stato ───────────────────────────────────────────────────────────────────

def methods(backend: dict) -> list[dict]:
    auth = (backend or {}).get("auth")
    if isinstance(auth, str):
        auth = {"type": auth}
    if not isinstance(auth, dict):
        return []
    if isinstance(auth.get("methods"), list):
        return [m for m in auth["methods"] if isinstance(m, dict)]
    return [auth] if str(auth.get("type") or "").lower() == "oauth" else []


def credential_method(backend: dict) -> dict | None:
    return next((m for m in methods(backend) if m.get("type") == "credential"), None)


def has_credential(backend: dict) -> bool:
    """C'è una credenziale USABILE: il bundle ha ogni campo che il metodo dichiara.

    Un Update del pack che rinomina un campo lascia un bundle vecchio: verde
    nella card e un placeholder letterale al vendor (review di #387).
    """
    cred = cred_name(str(backend.get("name") or ""))
    if not vault.has_credential(cred):
        return False
    method = credential_method(backend)
    if method is None:
        return True
    presenti = vault.field_names(cred)
    return all(f["name"] in presenti for f in method.get("fields") or [])


def active(backend: dict) -> str | None:
    """Il metodo con cui il backend è connesso, o None."""
    if credential_method(backend) and has_credential(backend):
        return "credential"
    if mcp_oauth.auth_spec(backend) and mcp_oauth.authorization_status(backend)["authorized"]:
        return "oauth"
    return None


def public_methods(backend: dict) -> list[dict]:
    """I metodi come li vede la card: tipi, scope, nomi ed etichette dei campi. Mai valori."""
    out = []
    for m in methods(backend):
        if m.get("type") == "credential":
            out.append({"type": "credential",
                        "fields": [{"name": f["name"], "label": f.get("label") or f["name"],
                                    "secret": bool(f.get("secret", True))}
                                   for f in m.get("fields") or []]})
        else:
            out.append({"type": "oauth", **({"scope": m["scope"]} if m.get("scope") else {})})
    return out


# ── Iniezione al momento della chiamata ─────────────────────────────────────

def _fill(val: Any, repl) -> Any:
    if isinstance(val, str):
        return _PH_RE.sub(lambda m: repl(m.group(1)), val)
    if isinstance(val, dict):
        return {k: _fill(v, repl) for k, v in val.items()}
    return val


def _inject(backend: dict, method: dict, repl) -> dict:
    b = dict(backend)
    for target, val in (method.get("inject") or {}).items():
        b[target] = {**(b.get(target) or {}), **_fill(val, repl)}
    return b


def apply(backend: dict) -> dict:
    """Il backend pronto per la sessione: credenziale iniettata come `${VAULT:…}`.

    Un backend che ha SOLO il metodo credential e non è connesso fallisce qui
    con un messaggio che dice cosa fare — invece di mandare al vendor un
    placeholder letterale.
    """
    method = credential_method(backend)
    if method is None:
        return backend
    slug = str(backend.get("name") or "")
    if has_credential(backend):
        cred = cred_name(slug)
        return _inject(backend, method, lambda f: "${VAULT:%s.%s}" % (cred, f))
    if mcp_oauth.auth_spec(backend):
        return backend  # resta il metodo OAuth: decide il provider
    raise CredentialRequired(
        f"il server MCP '{slug}' non è connesso: l'owner deve inserire la "
        f"credenziale dalla card con «Connetti». Nessun agente può farlo da sé.")


# ── «Connetti» / «Disconnetti» ──────────────────────────────────────────────

def _detail(e: BaseException) -> str:
    """Cosa dire all'owner di un test fallito: il TIPO del guasto e lo status HTTP.

    Mai `str(e)`: il test passa da `proxy.session`, che risolve ogni
    `${VAULT:…}` del backend, e il testo di un'eccezione di httpx può
    contenere headers e URL già risolti — anche segreti diversi da quelli
    appena inseriti (review di #387).
    """
    leaf = e
    while getattr(leaf, "exceptions", None):
        leaf = leaf.exceptions[0]
    status = getattr(getattr(leaf, "response", None), "status_code", None)
    for marker in ("401", "403", "404", "429"):
        if status is None and marker in type(leaf).__name__:
            status = int(marker)
    out = type(leaf).__name__
    if isinstance(status, int):
        out += f" (HTTP {status})"
    return out


async def connect(backend: dict, values: dict) -> dict:
    """Prova la credenziale e, solo se il backend risponde, la mette nella vault."""
    slug = str(backend.get("name") or "")
    method = credential_method(backend)
    if method is None:
        raise ValueError(f"il server MCP '{slug}' non accetta credenziali inserite")
    if not isinstance(values, dict):
        raise ValueError("'fields' deve essere un oggetto")
    declared = [f["name"] for f in method.get("fields") or []]
    extra = set(values) - set(declared)
    if extra:
        raise ValueError(f"campi non dichiarati: {', '.join(sorted(extra))}")
    clean: dict[str, str] = {}
    for name in declared:
        val = values.get(name)
        if not isinstance(val, str) or not val.strip():
            raise ValueError(f"manca il campo '{name}'")
        # Il valore com'è: una password IMAP può iniziare o finire con uno spazio.
        clean[name] = val
    if mcp_oauth.auth_spec(backend) and mcp_oauth.authorization_status(backend)["authorized"]:
        raise ValueError(f"il server MCP '{slug}' è già connesso con OAuth: "
                         "«Disconnetti» prima di usare una credenziale")
    probe = _inject(backend, method, lambda f: clean.get(f, ""))
    probe.pop("auth", None)  # il test è della credenziale, non di un consenso
    from . import proxy  # import locale: proxy importa questo modulo
    try:
        async def _try() -> int:
            async with proxy.session(probe) as s:
                return len((await s.list_tools()).tools)
        n = await asyncio.wait_for(_try(), timeout=CONNECT_TIMEOUT_S)
    except Exception as e:  # noqa: BLE001 — il dettaglio va all'owner, ripulito
        detail = _detail(e)
        LOG.info("mcp connect '%s': test fallito (%s), niente salvato", slug, type(e).__name__)
        raise ValueError(f"il server MCP non ha accettato la credenziale: {detail}") from None
    vault.deposit(cred_name(slug), clean, cred_type="mcp_credential", grant_agents=[])
    LOG.info("mcp connect '%s': credenziale salvata, %d tool esposti", slug, n)
    return {"connected": True, "server": slug, "method": "credential",
            "detail": f"{n} tool esposti"}


def disconnect(backend: dict) -> dict:
    """Cancella dalla vault credenziale e token OAuth del backend."""
    slug = str(backend.get("name") or "")
    removed_cred = vault.remove(cred_name(slug))
    removed_oauth = mcp_oauth.forget(slug)
    LOG.info("mcp disconnect '%s'", slug)
    return {"disconnected": True, "server": slug,
            "removed": [x for x, ok in (("credential", removed_cred),
                                         ("oauth", removed_oauth)) if ok]}
