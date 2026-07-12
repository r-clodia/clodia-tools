"""Backend minimale per la sezione Tools della UI (clodia-web).

Accanto al `/mcp` del gateway, espone gli endpoint che la webui usa per
**acquisire** le credenziali OAuth dei tool (Gmail in prima battuta) e
depositarle nella **vault**. Il chiamante è l'operatore via webui (non un
agente), quindi NON usa l'auth ckt1: è protetto da un bearer condiviso
(`CLODIA_TOOLS_UI_TOKEN`). Se la variabile non è impostata le route sono
aperte (assunzione: solo rete interna/Tailscale) — sconsigliato in prod.

Flusso (UI-driven, code-da-URL):
  GET  /tools                    → stato connettori (quali account connessi)
  GET  /tools/gmail/auth?...      → URL di consenso Google + state
  POST /tools/gmail/connect       → {account,email,code,state} → exchange → deposito

Il `client_secret` dell'app e il refresh token NON raggiungono mai un modello:
lo scambio è server-side, il deposito va nella vault.
"""
from __future__ import annotations

import json
import logging
import os
import re
import secrets as _secrets
import time

LOG = logging.getLogger("clodia-tools.tools_api")

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import google_oauth as go
from . import instance_profile
from . import proxy
from . import vault
from . import whitelist

# Nomi backend: lowercase slug, niente collisione coi prefissi nativi.
_NATIVE_PREFIXES = {"trello", "fs", "email", "agent", "topic", "runtime"}


def _slugify(name: str) -> str:
    """Nome del backend (namespace `slug.tool`): lo slug deve essere senza spazi
    né punti. Le chiavi mcpServers reali hanno spazi/trattini ("RapidAPI Hub -
    AeroDataBox") → le slugifichiamo; l'originale resta come `label` per la UI."""
    s = re.sub(r"[^a-z0-9]+", "-", (name or "").lower()).strip("-")
    return s[:40]


def _replace_placeholder(obj, name: str, repl: str):
    """Sostituisce ricorsivamente ${name} con repl nelle stringhe di obj."""
    ph = "${" + name + "}"
    if isinstance(obj, str):
        return obj.replace(ph, repl)
    if isinstance(obj, dict):
        return {k: _replace_placeholder(v, name, repl) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_replace_placeholder(v, name, repl) for v in obj]
    return obj

_UI_TOKEN = os.environ.get("CLODIA_TOOLS_UI_TOKEN")
_STATE_TTL = 600
_states: dict[str, dict] = {}   # state → {account, email, exp}


def _authorized(request: Request) -> bool:
    if not _UI_TOKEN:
        return True
    return request.headers.get("authorization", "") == f"Bearer {_UI_TOKEN}"


def _gc_states() -> None:
    now = time.time()
    for k in [k for k, v in _states.items() if v["exp"] < now]:
        _states.pop(k, None)


def _connector_guard(cid: str):
    """Gating dei connettori nativi dal profilo (integrations.connectors)."""
    try:
        instance_profile.connector_check(cid)
        return None
    except PermissionError as e:
        return JSONResponse({"error": str(e)}, status_code=403)


async def list_tools(request: Request):
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    names = vault.store_names()
    gmail_accounts = [n[len("gmail_"):] for n in names if n.startswith("gmail_")]
    gws_accounts = [n[len("gworkspace_"):] for n in names if n.startswith("gworkspace_")]
    connectors = [{
        "id": "gmail",
        "label": "Gmail",
        "provider": "google",
        "connected": bool(gmail_accounts),
        "accounts": gmail_accounts,
    }, {
        # Connettore nativo Google Workspace (Drive · Docs · Calendar),
        # distinto da Gmail. Sempre elencato (native, non state-dependent).
        "id": "google-workspace",
        "label": "Google Workspace",
        "provider": "google",
        "scopes": "Drive · Docs · Calendar",
        "connected": bool(gws_accounts),
        "accounts": gws_accounts,
    }]
    # Integrazione Image generation (OpenAI): attiva se la key è nel vault.
    connectors.append({
        "id": "openai-images",
        "label": "Image generation (OpenAI)",
        "provider": "openai",
        "connected": vault.has_credential("openai_api_key"),
        "accounts": [],
    })
    # Trello (nostra implementazione, tool trello.*): connesso se le creds sono
    # nel vault. "Connetti" inserisce API key + token.
    connectors.append({
        "id": "trello",
        "label": "Trello",
        "provider": "trello",
        "connected": vault.has_credential("trello"),
        "accounts": [],
    })
    # GitHub (server MCP ufficiale, tool github.*): connesso se il PAT è nel vault.
    # "Connetti" inserisce un Personal Access Token (paste-key) → vault.
    connectors.append({
        "id": "github",
        "label": "GitHub",
        "provider": "github",
        "connected": vault.has_credential("github_pat"),
        "accounts": [],
    })
    # Telegram (tool telegram.*): connesso se il bot token è nel vault.
    # "Connetti" inserisce il token di un bot dedicato (paste-key) → vault.
    try:
        from .tools import telegram as _tg
        _tg_status = _tg.status()
    except Exception:  # noqa: BLE001
        _tg_status = {"configured": vault.has_credential("telegram_bot_token")}
    connectors.append({
        "id": "telegram",
        "label": "Telegram",
        "provider": "telegram",
        "connected": bool(_tg_status.get("configured")),
        "bot_username": _tg_status.get("bot_username"),
        "accounts": [],
    })
    # Topic storage (Topic System v2): il backend attivo mostrato come
    # integrazione "built-in" (oggi local-fs; Drive/Dropbox in P4).
    try:
        from .topics_api import _service as _topics_service
        cap = _topics_service().s.capability()
        connectors.append({
            "id": "topic-storage",
            "label": f"Topic storage ({cap.name})",
            "provider": "storage",
            "connected": True,
            "builtin": True,
            "backend": cap.name,
            "versioning": cap.versioning,
            "accounts": [],
        })
    except Exception:  # noqa: BLE001 — lo stato connettori non deve mai rompersi
        pass
    # Backend MCP montati (Add-MCP): elencali come connettori "mcp".
    for b in (whitelist.CONFIG.get("mcp_backends") or []):
        connectors.append({
            "id": b.get("name"),
            "label": b.get("label") or b.get("name"),
            "provider": "mcp",
            "transport": b.get("transport", "stdio"),
            "connected": True,
            "accounts": [],
        })
    allowed = instance_profile.connectors_allowed()
    if allowed is not None:
        # backup/topic-storage/mcp non sono connettori nativi gated
        keep = set(allowed) | {"topic-storage"}
        connectors = [c for c in connectors
                      if c.get("provider") == "mcp" or c.get("id") in keep]
    return JSONResponse({"connectors": connectors})


async def register_mcp(request: Request):
    """Registra uno o più MCP server da mcp.json (UI Add-MCP). I placeholder
    ${NAME} presenti nel config vengono sostituiti con ${VAULT:mcp_<server>_<NAME>}
    e i valori segreti depositati nel vault (mai nel config.yaml)."""
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "bad_json"}, status_code=400)
    cfg = body.get("config")
    if isinstance(cfg, str):
        try:
            cfg = json.loads(cfg)
        except Exception:
            return JSONResponse({"error": "config non è JSON valido"}, status_code=400)
    servers = (cfg or {}).get("mcpServers") if isinstance(cfg, dict) else None
    if not isinstance(servers, dict) or not servers:
        return JSONResponse({"error": "manca l'oggetto mcpServers nel config"}, status_code=400)
    secrets_in = body.get("secrets") or {}

    backends = list(whitelist.CONFIG.get("mcp_backends") or [])
    agents = whitelist.CONFIG.setdefault("agents", {})
    clodia_tools = agents.setdefault("clodia", {}).setdefault("allowed_tools", [])
    registered = []
    for name, spec in servers.items():
        slug = _slugify(name)
        if not slug or slug in _NATIVE_PREFIXES:
            return JSONResponse({"error": f"nome backend non valido/riservato: {name!r} → {slug!r}"},
                                status_code=400)
        # Feature `integrations` (profilo istanza): off = nessun mount di MCP
        # esterni; fixed = solo la whitelist dell'edizione (i tool del pack).
        try:
            instance_profile.integrations_check(slug)
        except PermissionError as e:
            return JSONResponse({"error": str(e)}, status_code=403)
        if spec.get("url"):
            backend = {"name": slug, "label": name, "transport": "http", "url": spec["url"]}
            if spec.get("headers"):
                backend["headers"] = spec["headers"]
        elif spec.get("command"):
            backend = {"name": slug, "label": name, "transport": "stdio",
                       "command": spec["command"], "args": spec.get("args", [])}
            if spec.get("env"):
                backend["env"] = spec["env"]
        else:
            return JSONResponse({"error": f"server '{name}': serve 'url' (http) o 'command' (stdio)"},
                                status_code=400)
        # Secret: deposita nel vault (infra, no grant) e sostituisci nel config.
        for sname, sval in secrets_in.items():
            if not sval:
                continue
            cred = f"mcp_{slug}_{sname}"
            vault.deposit(cred, {"value": sval}, cred_type="mcp_secret", grant_agents=[])
            backend = _replace_placeholder(backend, sname, f"${{VAULT:{cred}}}")
        backends = [b for b in backends if b.get("name") != slug]  # dedup
        backends.append(backend)
        if f"{slug}.*" not in clodia_tools:
            clodia_tools.append(f"{slug}.*")
        registered.append(slug)

    whitelist.CONFIG["mcp_backends"] = backends
    whitelist.save_config()
    whitelist.reload_config()
    proxy.clear_cache()
    return JSONResponse({"registered": registered})


async def unregister_mcp(request: Request):
    """Rimuove un MCP server montato (config + grant clodia)."""
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    name = request.path_params["name"]
    cfg = whitelist.CONFIG
    cfg["mcp_backends"] = [b for b in (cfg.get("mcp_backends") or []) if b.get("name") != name]
    at = cfg.get("agents", {}).get("clodia", {}).get("allowed_tools", [])
    if f"{name}.*" in at:
        at.remove(f"{name}.*")
    whitelist.save_config()
    whitelist.reload_config()
    proxy.clear_cache()
    return JSONResponse({"unregistered": name})


def _account_from_email(email: str) -> str:
    return email.split("@")[0].replace(".", "_")


async def gmail_auth(request: Request):
    g = _connector_guard("gmail")
    if g is not None:
        return g
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    try:
        app = vault.read_internal(go.APP_CREDENTIAL)
    except vault.VaultDenied:
        return JSONResponse(
            {"error": "app_not_configured",
             "detail": f"manca la credenziale d'app '{go.APP_CREDENTIAL}' nella vault"},
            status_code=409)
    _gc_states()
    state = _secrets.token_urlsafe(24)
    _states[state] = {"exp": time.time() + _STATE_TTL}
    # prompt 'select_account consent' → l'utente SCEGLIE l'account nel widget
    # Google; l'email reale la ricaviamo dopo, dal profilo. Niente login_hint.
    url = go.consent_url(app["client_id"], app.get("redirect_uri", go.DEFAULT_REDIRECT),
                         state=state, prompt="select_account consent")
    return JSONResponse({"auth_url": url, "state": state,
                         "redirect_uri": app.get("redirect_uri", go.DEFAULT_REDIRECT)})


async def gmail_connect(request: Request):
    g = _connector_guard("gmail")
    if g is not None:
        return g
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "bad_json"}, status_code=400)
    code = (body.get("code") or "").strip()
    state = body.get("state") or ""
    if not code:
        return JSONResponse({"error": "missing_code"}, status_code=400)
    # state: solo anti-CSRF (l'account lo sceglie l'utente nel widget Google)
    st = _states.pop(state, None)
    if state and st is None:
        return JSONResponse({"error": "invalid_or_expired_state"}, status_code=400)

    try:
        app = vault.read_internal(go.APP_CREDENTIAL)
    except vault.VaultDenied:
        return JSONResponse({"error": "app_not_configured"}, status_code=409)
    # se l'utente ha incollato l'intero URL di redirect, estrai il code
    if code.startswith("http"):
        import urllib.parse
        code = urllib.parse.parse_qs(urllib.parse.urlparse(code).query).get("code", [""])[0]
    try:
        res = go.exchange_code(app["client_id"], app["client_secret"], code,
                               app.get("redirect_uri", go.DEFAULT_REDIRECT))
    except Exception as e:  # errore di rete/HTTP da Google
        return JSONResponse({"error": "exchange_failed", "detail": str(e)[:200]},
                            status_code=502)
    rt = res.get("refresh_token")
    if not rt:
        return JSONResponse(
            {"error": "no_refresh_token",
             "detail": "Google non ha restituito un refresh_token. App in Testing? "
                       "Mettila In production e riprova."},
            status_code=400)
    # ricava l'email REALE dall'account scelto: prima dal profilo Gmail (API),
    # poi fallback a userinfo (scope openid/email) se la Gmail API è disabilitata.
    try:
        email = go.get_profile_email(res["access_token"])
    except Exception as e_profile:  # noqa: BLE001
        try:
            email = go.get_userinfo_email(res["access_token"])
        except Exception as e_ui:  # noqa: BLE001
            return JSONResponse(
                {"error": "profile_failed",
                 "detail": f"profilo Gmail: {str(e_profile)[:160]} · userinfo: {str(e_ui)[:120]}"},
                status_code=502)
    account = _account_from_email(email)

    vault.deposit(
        f"gmail_{account}",
        {"client_id": app["client_id"], "client_secret": app["client_secret"],
         "refresh_token": rt, "email": email, "account": account},
        cred_type="oauth2_google", grant_agents=["clodia"],
    )
    return JSONResponse({"connected": True, "account": account, "email": email})


async def gworkspace_auth(request: Request):
    g = _connector_guard("google-workspace")
    if g is not None:
        return g
    """Avvia il consenso OAuth per il connettore Google Workspace (Drive ·
    Docs · Calendar). Stesso flusso di Gmail ma con scope Workspace."""
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    try:
        app = vault.read_internal(go.APP_CREDENTIAL)
    except vault.VaultDenied:
        return JSONResponse(
            {"error": "app_not_configured",
             "detail": f"manca la credenziale d'app '{go.APP_CREDENTIAL}' nella vault"},
            status_code=409)
    _gc_states()
    state = _secrets.token_urlsafe(24)
    _states[state] = {"exp": time.time() + _STATE_TTL}
    url = go.consent_url(app["client_id"], app.get("redirect_uri", go.DEFAULT_REDIRECT),
                         scope=go.WORKSPACE_SCOPE, state=state,
                         prompt="select_account consent")
    return JSONResponse({"auth_url": url, "state": state,
                         "redirect_uri": app.get("redirect_uri", go.DEFAULT_REDIRECT)})


async def gworkspace_connect(request: Request):
    g = _connector_guard("google-workspace")
    if g is not None:
        return g
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "bad_json"}, status_code=400)
    code = (body.get("code") or "").strip()
    state = body.get("state") or ""
    if not code:
        return JSONResponse({"error": "missing_code"}, status_code=400)
    st = _states.pop(state, None)
    if state and st is None:
        return JSONResponse({"error": "invalid_or_expired_state"}, status_code=400)
    try:
        app = vault.read_internal(go.APP_CREDENTIAL)
    except vault.VaultDenied:
        return JSONResponse({"error": "app_not_configured"}, status_code=409)
    if code.startswith("http"):
        import urllib.parse
        code = urllib.parse.parse_qs(urllib.parse.urlparse(code).query).get("code", [""])[0]
    try:
        res = go.exchange_code(app["client_id"], app["client_secret"], code,
                               app.get("redirect_uri", go.DEFAULT_REDIRECT))
    except Exception as e:
        return JSONResponse({"error": "exchange_failed", "detail": str(e)[:200]},
                            status_code=502)
    rt = res.get("refresh_token")
    if not rt:
        return JSONResponse(
            {"error": "no_refresh_token",
             "detail": "Google non ha restituito un refresh_token. App in Testing? "
                       "Mettila In production e riprova."},
            status_code=400)
    # email dall'endpoint userinfo (lo scope Workspace non include l'API Gmail)
    try:
        email = go.get_userinfo_email(res["access_token"])
    except Exception as e:
        return JSONResponse({"error": "profile_failed", "detail": str(e)[:200]},
                            status_code=502)
    account = _account_from_email(email)
    vault.deposit(
        f"gworkspace_{account}",
        {"client_id": app["client_id"], "client_secret": app["client_secret"],
         "refresh_token": rt, "email": email, "account": account,
         "scope": go.WORKSPACE_SCOPE},
        cred_type="oauth2_google", grant_agents=["clodia"],
    )
    LOG.info("gworkspace_connect: account %s collegato (Drive·Docs·Calendar)", account)
    return JSONResponse({"connected": True, "account": account, "email": email})


async def openai_connect(request: Request):
    g = _connector_guard("openai-images")
    if g is not None:
        return g
    """Attiva l'integrazione Image generation: l'owner incolla la API key, che
    viene depositata nel vault come credenziale infra (no grant per-agente: la
    legge solo il gateway). Per disconnettere: body {"api_key": ""}."""
    src = request.client.host if request.client else "?"
    LOG.info("openai_connect: ricevuta richiesta da %s", src)
    if not _authorized(request):
        LOG.warning("openai_connect: NON autorizzata da %s", src)
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        LOG.warning("openai_connect: body non-JSON da %s", src)
        return JSONResponse({"error": "bad_json"}, status_code=400)
    key = (body.get("api_key") or "").strip()
    # Mai loggare la key: solo lunghezza + prefisso per diagnosi.
    if not key:
        vault.remove("openai_api_key")
        LOG.info("openai_connect: key vuota → integrazione disconnessa")
        return JSONResponse({"connected": False})
    vault.deposit("openai_api_key", {"api_key": key},
                  cred_type="api_key", grant_agents=[])
    LOG.info("openai_connect: key depositata (len=%d, prefix=%s…)",
             len(key), key[:3])
    return JSONResponse({"connected": True})


async def google_app_status(request: Request):
    """L'app OAuth Google (client_id/secret) è configurata nel vault?"""
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    try:
        app = vault.read_internal(go.APP_CREDENTIAL)
        return JSONResponse({"configured": True,
                             "redirect_uri": app.get("redirect_uri", go.DEFAULT_REDIRECT)})
    except vault.VaultDenied:
        return JSONResponse({"configured": False, "redirect_uri": go.DEFAULT_REDIRECT})


async def google_app_config(request: Request):
    """Deposita la credenziale d'app OAuth Google. Body: {client_json} (il JSON
    scaricato da Google Cloud) oppure {client_id, client_secret, redirect_uri}."""
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "bad_json"}, status_code=400)
    cj = body.get("client_json")
    if cj:
        try:
            data = json.loads(cj) if isinstance(cj, str) else cj
            node = data.get("installed") or data.get("web") or data
            uris = node.get("redirect_uris") or []
            app = {"client_id": node.get("client_id"),
                   "client_secret": node.get("client_secret"),
                   "redirect_uri": uris[0] if uris else go.DEFAULT_REDIRECT}
        except Exception:
            return JSONResponse({"error": "bad_client_json"}, status_code=400)
    else:
        app = {"client_id": (body.get("client_id") or "").strip(),
               "client_secret": (body.get("client_secret") or "").strip(),
               "redirect_uri": (body.get("redirect_uri") or "").strip() or go.DEFAULT_REDIRECT}
    if not app["client_id"] or not app["client_secret"]:
        return JSONResponse({"error": "client_id e client_secret richiesti"}, status_code=400)
    vault.deposit(go.APP_CREDENTIAL, app, cred_type="google_app", grant_agents=[])
    LOG.info("google_app_config: app OAuth depositata (client_id=%s…)", app["client_id"][:12])
    return JSONResponse({"configured": True, "redirect_uri": app["redirect_uri"]})


async def email_mailboxes(request: Request):
    """GET → lista delle caselle generiche (mailbox_*) nel vault (solo nomi)."""
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    boxes = [n[len("mailbox_"):] for n in vault.store_names() if n.startswith("mailbox_")]
    return JSONResponse({"mailboxes": sorted(boxes)})


async def email_mailbox_add(request: Request):
    g = _connector_guard("mailboxes")
    if g is not None:
        return g
    """POST → aggiunge/aggiorna una casella IMAP/SMTP. Body: account, email,
    password, imap_server, smtp_server, [imap_port=993, smtp_port=587,
    display_name, sent_folder, smtp_user]. Creds nel vault (grant a clodia+ophelia)."""
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    try:
        b = await request.json()
    except Exception:
        return JSONResponse({"error": "bad_json"}, status_code=400)
    account = (b.get("account") or "").strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,40}", account or ""):
        return JSONResponse({"error": "account non valido (a-z0-9_-)"}, status_code=400)
    required = ("email", "password", "imap_server", "smtp_server")
    if any(not (b.get(k) or "").strip() for k in required):
        return JSONResponse({"error": f"campi richiesti: {', '.join(required)}"}, status_code=400)
    cfg = {
        "email": b["email"].strip(),
        "password": b["password"],
        "imap_server": b["imap_server"].strip(),
        "imap_port": int(b.get("imap_port") or 993),
        "smtp_server": b["smtp_server"].strip(),
        "smtp_port": int(b.get("smtp_port") or 587),
    }
    for opt in ("display_name", "sent_folder", "smtp_user"):
        if (b.get(opt) or "").strip():
            cfg[opt] = b[opt].strip()
    vault.deposit(f"mailbox_{account}", cfg, cred_type="mailbox",
                  grant_agents=["clodia", "ophelia"])
    LOG.info("email_mailbox_add: casella '%s' depositata (%s)", account, cfg["email"])
    return JSONResponse({"account": account, "connected": True})


async def email_mailbox_remove(request: Request):
    """DELETE → rimuove una casella generica dal vault."""
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    account = request.path_params["account"]
    removed = vault.remove(f"mailbox_{account}")
    return JSONResponse({"account": account, "removed": removed})


async def trello_connect(request: Request):
    g = _connector_guard("trello")
    if g is not None:
        return g
    """Deposita le credenziali Trello nel vault. Body: {api_key, token}.
    api_key/token vuoti → disconnette (rimuove la credenziale)."""
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "bad_json"}, status_code=400)
    key = (body.get("api_key") or "").strip()
    token = (body.get("token") or "").strip()
    if not key and not token:
        vault.remove("trello")
        LOG.info("trello_connect: credenziali rimosse")
        return JSONResponse({"connected": False})
    if not key or not token:
        return JSONResponse({"error": "servono sia api_key sia token"}, status_code=400)
    vault.deposit("trello", {"api_key": key, "token": token},
                  cred_type="api_key", grant_agents=[])
    LOG.info("trello_connect: creds depositate (key len=%d)", len(key))
    return JSONResponse({"connected": True})


async def telegram_status(request: Request):
    """Stato non sensibile dell'integrazione Telegram (per la card di setup e
    per Wainston via app_runtime). Mai il token."""
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    from .tools import telegram as tg
    try:
        return JSONResponse(tg.status())
    except Exception as e:  # noqa: BLE001
        return JSONResponse({"error": str(e)[:300]}, status_code=500)


async def telegram_connect(request: Request):
    g = _connector_guard("telegram")
    if g is not None:
        return g
    """Connette un bot Telegram dedicato. Body: {token}. Valida con getMe,
    deposita il token nel vault (grant clodia) e memorizza l'@username. token
    vuoto → disconnette (rimuove la credenziale). Il token non transita mai dal
    modello: lo usano solo i tool telegram.* via vault."""
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "bad_json"}, status_code=400)
    from .tools import telegram as tg
    token = (body.get("token") or "").strip()
    if not token:
        vault.remove("telegram_bot_token")
        tg.set_bot_username(None)
        LOG.info("telegram_connect: disconnesso (token rimosso)")
        return JSONResponse({"connected": False})
    # Valida il token con getMe prima di depositarlo.
    try:
        me = tg.api_call(token, "getMe")
    except Exception as e:  # noqa: BLE001
        LOG.warning("telegram_connect: getMe fallita (%s)", str(e)[:120])
        return JSONResponse({"error": f"token non valido: {str(e)[:200]}"}, status_code=400)
    username = me.get("username")
    vault.deposit("telegram_bot_token", {"token": token, "bot_username": username,
                                         "bot_id": me.get("id")},
                  cred_type="api_key", grant_agents=["clodia"])
    tg.set_bot_username(username)
    LOG.info("telegram_connect: bot @%s connesso (token len=%d)", username, len(token))
    return JSONResponse({"connected": True, "bot_username": username})


GITHUB_MCP_URL = "https://api.githubcopilot.com/mcp/"


async def github_connect(request: Request):
    """Deposita il PAT GitHub nel vault e registra/rimuove il backend MCP ufficiale
    GitHub. Body: {pat}. pat vuoto → disconnette (rimuove cred + backend).
    Il PAT non transita mai dal modello: il proxy lo risolve via ${VAULT:github_pat}."""
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "bad_json"}, status_code=400)
    pat = (body.get("pat") or body.get("token") or "").strip()
    if pat:
        g = _connector_guard("github")
        if g is not None:
            return g
        # Anche GitHub è un MCP esterno: segue il gating integrations del
        # profilo (la DISCONNESSIONE — pat vuoto — resta sempre permessa).
        try:
            instance_profile.integrations_check("github")
        except PermissionError as e:
            return JSONResponse({"error": str(e)}, status_code=403)
    backends = [b for b in (whitelist.CONFIG.get("mcp_backends") or [])
                if b.get("name") != "github"]
    if not pat:
        vault.remove("github_pat")
        whitelist.CONFIG["mcp_backends"] = backends
        whitelist.save_config(); whitelist.reload_config(); proxy.clear_cache()
        LOG.info("github_connect: disconnesso (cred + backend rimossi)")
        return JSONResponse({"connected": False})
    vault.deposit("github_pat", {"value": pat}, cred_type="mcp_secret", grant_agents=[])
    backends.append({
        "name": "github", "label": "GitHub", "transport": "http",
        "url": GITHUB_MCP_URL,
        "headers": {"Authorization": "Bearer ${VAULT:github_pat}"},
    })
    whitelist.CONFIG["mcp_backends"] = backends
    agents = whitelist.CONFIG.setdefault("agents", {})
    ct = agents.setdefault("clodia", {}).setdefault("allowed_tools", [])
    if "github.*" not in ct:
        ct.append("github.*")
    whitelist.save_config(); whitelist.reload_config(); proxy.clear_cache()
    LOG.info("github_connect: PAT depositato + backend github registrato (len=%d)", len(pat))
    return JSONResponse({"connected": True})


# ── Backup gestito (ISO 27001 A.8.13) ────────────────────────────────────────
async def backup_configure(request: Request):
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    from . import backup
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "bad_json"}, status_code=400)
    try:
        return JSONResponse(backup.configure(body))
    except Exception as e:
        return JSONResponse({"error": str(e)[:300]}, status_code=400)


async def backup_status(request: Request):
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    from . import backup
    try:
        return JSONResponse(backup.status())
    except Exception as e:
        return JSONResponse({"error": str(e)[:300]}, status_code=500)


async def backup_snapshots(request: Request):
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    from . import backup
    try:
        return JSONResponse({"snapshots": backup.snapshots()})
    except Exception as e:
        return JSONResponse({"error": str(e)[:300]}, status_code=500)


async def backup_run(request: Request):
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    from . import backup
    try:
        return JSONResponse(backup.run_backup())
    except Exception as e:
        return JSONResponse({"error": str(e)[:400]}, status_code=500)


async def backup_restore_test(request: Request):
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    from . import backup
    try:
        return JSONResponse(backup.restore_test())
    except Exception as e:
        return JSONResponse({"error": str(e)[:400]}, status_code=500)


def _test_connector(cid: str) -> dict:
    """Verifica REALE della connessione di un'integrazione (chiamata al provider).
    Ritorna {ok: bool|None, detail}. ok=None → non testabile. Mai il segreto."""
    import requests as _rq

    def _c(name):
        try:
            return vault.read_internal(name) if vault.has_credential(name) else None
        except Exception:  # noqa: BLE001
            return None

    try:
        if cid == "github":
            b = _c("github_pat")
            if not b:
                return {"ok": False, "detail": "nessun PAT nel vault"}
            r = _rq.get("https://api.github.com/user",
                        headers={"Authorization": f"token {b.get('value','')}"}, timeout=15)
            if r.status_code == 200:
                return {"ok": True, "detail": f"autenticato come {r.json().get('login')}"}
            return {"ok": False, "detail": f"GitHub {r.status_code}: {r.json().get('message','')}"}

        if cid == "trello":
            b = _c("trello")
            if not b:
                return {"ok": False, "detail": "nessuna credenziale nel vault"}
            r = _rq.get("https://api.trello.com/1/members/me",
                        params={"key": b.get("api_key",""), "token": b.get("token","")}, timeout=15)
            return ({"ok": True, "detail": f"utente {r.json().get('username')}"} if r.status_code == 200
                    else {"ok": False, "detail": f"Trello {r.status_code}"})

        if cid == "telegram":
            b = _c("telegram_bot_token")
            tok = (b or {}).get("value") or (b or {}).get("token") or ""
            if not tok:
                return {"ok": False, "detail": "nessun bot token nel vault"}
            r = _rq.get(f"https://api.telegram.org/bot{tok}/getMe", timeout=15)
            j = r.json()
            return ({"ok": True, "detail": f"bot @{j['result'].get('username')}"} if j.get("ok")
                    else {"ok": False, "detail": j.get("description", "token non valido")})

        if cid in ("openai-images", "openai"):
            b = _c("openai_api_key")
            key = (b or {}).get("value") or ""
            if not key:
                return {"ok": False, "detail": "nessuna API key nel vault"}
            r = _rq.get("https://api.openai.com/v1/models",
                        headers={"Authorization": f"Bearer {key}"}, timeout=15)
            return ({"ok": True, "detail": "API key valida"} if r.status_code == 200
                    else {"ok": False, "detail": f"OpenAI {r.status_code}"})

        if cid == "topic-storage":
            return {"ok": True, "detail": "storage locale sempre disponibile"}
    except _rq.RequestException as e:
        return {"ok": False, "detail": f"rete: {str(e)[:120]}"}

    return {"ok": None, "detail": "test non disponibile per questa integrazione"}


async def test_connector(request: Request):
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    cid = request.path_params["id"]
    return JSONResponse(_test_connector(cid))


routes = [
    Route("/tools", list_tools, methods=["GET"]),
    Route("/tools/{id}/test", test_connector, methods=["POST"]),
    Route("/tools/trello/connect", trello_connect, methods=["POST"]),
    Route("/tools/email/mailboxes", email_mailboxes, methods=["GET"]),
    Route("/tools/email/mailboxes", email_mailbox_add, methods=["POST"]),
    Route("/tools/email/mailboxes/{account}", email_mailbox_remove, methods=["DELETE"]),
    Route("/tools/google/app", google_app_status, methods=["GET"]),
    Route("/tools/google/app", google_app_config, methods=["POST"]),
    Route("/tools/gmail/auth", gmail_auth, methods=["GET"]),
    Route("/tools/gmail/connect", gmail_connect, methods=["POST"]),
    Route("/tools/gworkspace/auth", gworkspace_auth, methods=["GET"]),
    Route("/tools/gworkspace/connect", gworkspace_connect, methods=["POST"]),
    Route("/tools/openai/connect", openai_connect, methods=["POST"]),
    Route("/tools/github/connect", github_connect, methods=["POST"]),
    Route("/tools/telegram/status", telegram_status, methods=["GET"]),
    Route("/tools/telegram/connect", telegram_connect, methods=["POST"]),
    Route("/tools/backup/config", backup_configure, methods=["POST"]),
    Route("/tools/backup/status", backup_status, methods=["GET"]),
    Route("/tools/backup/snapshots", backup_snapshots, methods=["GET"]),
    Route("/tools/backup/run", backup_run, methods=["POST"]),
    Route("/tools/backup/restore-test", backup_restore_test, methods=["POST"]),
    Route("/tools/mcp", register_mcp, methods=["POST"]),
    Route("/tools/mcp/{name}", unregister_mcp, methods=["DELETE"]),
]
