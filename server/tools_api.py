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
from .tools import email as email_tool

# Nomi backend: lowercase slug, niente collisione coi prefissi nativi.
_NATIVE_PREFIXES = {"fs", "email", "agent", "topic", "runtime"}


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

_ADMIN_ROLES = ("superadmin", "admin")


def _is_human_admin(name: str) -> bool:
    """True se il principal è un human con ruolo admin/superadmin. Il gateway
    legge il ruolo da /datadir/agents/<name>/agent.yaml (montaggio condiviso con
    l'agent-server) — stessa fonte di verità di admin.is_admin lato backend."""
    if not name:
        return False
    from pathlib import Path
    ay = Path(os.environ.get("CLODIA_DATA", "/datadir")) / "agents" / name / "agent.yaml"
    if not ay.is_file():
        return False
    try:
        import yaml
        d = yaml.safe_load(ay.read_text(encoding="utf-8")) or {}
    except Exception:
        return False
    return d.get("type") == "human" and str(d.get("role") or "") in _ADMIN_ROLES


def _revocata(payload: dict) -> bool:
    """Vero se la sessione è stata revocata.

    Queste rotte acquisiscono credenziali (PAT, OAuth, backup, server MCP): la
    revoca di un client MCP umano era letta solo da `_AuthMiddleware`, cioè solo
    su `/mcp`, e un token revocato continuava ad amministrarle fino alla scadenza
    naturale — che per un client MCP è di trenta giorni (clodia-platform#261).
    """
    from . import internal_auth
    return internal_auth.refuse_if_revoked(payload, log=LOG) is not None


def _authorized(request: Request) -> bool:
    """Gestione integrations/credenziali/backup = **territorio ADMIN**. Autorizza
    se: (a) trusted-core via UI token, oppure (b) ckt1 valido di un ADMIN — umano
    admin (claim on_behalf/human_role o ruolo in agent.yaml) o super-agent
    (clodia/ophelia). Chiude il buco: prima, con UI_TOKEN assente, era aperto a
    chiunque loggato (un non-admin poteva rimuovere un MCP)."""
    hdr = request.headers.get("authorization", "")
    if _UI_TOKEN and hdr == f"Bearer {_UI_TOKEN}":
        return True  # trusted-core (chiamanti interni/headless)
    token = hdr[7:] if hdr.lower().startswith("bearer ") else ""
    if not token:
        return False
    from .pki_verify import verify_session_token
    try:
        p = verify_session_token(token)
    except Exception:
        return False
    if _revocata(p):
        return False
    if p.get("on_behalf"):
        return (p.get("human_role") or "user") == "admin"
    ag = str(p.get("agent") or "")
    return ag in ("clodia", "ophelia") or _is_human_admin(ag)


def _authorized_owner(request: Request) -> bool:
    """Come `_authorized`, MA senza la scorciatoia dei super-agent.

    `_authorized` accetta `clodia`/`ophelia`, e per gestire i connettori va bene.
    Per il confinamento di Drive no: allargare il perimetro è più privilegiato di
    qualunque uso del perimetro, e un agente che può spostare il proprio confine
    non ha un confine. Qui passa solo un UMANO admin (o il trusted-core interno,
    che un agente non può impersonare perché non ha il token).
    """
    hdr = request.headers.get("authorization", "")
    if _UI_TOKEN and hdr == f"Bearer {_UI_TOKEN}":
        return True
    token = hdr[7:] if hdr.lower().startswith("bearer ") else ""
    if not token:
        return False
    from .pki_verify import verify_session_token
    try:
        p = verify_session_token(token)
    except Exception:
        return False
    if _revocata(p):
        return False
    if p.get("on_behalf"):
        return (p.get("human_role") or "user") == "admin"
    return _is_human_admin(str(p.get("agent") or ""))


def _folder_id(raw: str) -> str:
    """Accetta un id o una URL di Drive e ritorna l'id.

    Incollare la URL è ciò che una persona fa davvero; pretendere l'id nudo
    sposta su chi configura un lavoro di estrazione a mano, ed è lì che si
    incolla la cosa sbagliata.
    """
    raw = (raw or "").strip()
    if "/" in raw:
        import re as _re
        m = _re.search(r"/folders/([A-Za-z0-9_-]+)", raw) or \
            _re.search(r"[?&]id=([A-Za-z0-9_-]+)", raw)
        if m:
            return m.group(1)
        raw = raw.rstrip("/").rsplit("/", 1)[-1].split("?")[0]
    return raw


def _describe_folder(account: str, fid: str) -> dict:
    """Nome e tipo di una cartella, per far CONFERMARE un nome invece di un id.

    Un id di 33 caratteri non è verificabile a occhio: senza il nome, l'unico
    errore possibile — confinare alla cartella sbagliata — è anche invisibile.
    """
    from .tools import gdrive
    out = {"id": fid}
    try:
        svc, _ = gdrive._service(account)
        meta = svc.files().get(fileId=fid, fields="id, name, mimeType",
                               supportsAllDrives=True).execute()
        out["name"] = meta.get("name")
        out["is_folder"] = meta.get("mimeType") == \
            "application/vnd.google-apps.folder"
    except Exception as e:                       # noqa: BLE001
        out["error"] = f"{type(e).__name__}: {str(e)[:100]}"
        out["is_folder"] = False
    return out


async def gdrive_confinement(request: Request):
    """GET /tools/gdrive/confinement → stato del confinamento per account."""
    if not _authorized_owner(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    from . import whitelist
    from .tools import gdrive
    whitelist.reload_config()
    roots = whitelist.gdrive_roots_all()
    out = []
    for acct in gdrive.gworkspace_accounts():
        ids = roots.get(acct) or roots.get("*") or []
        out.append({"account": acct, "confined": bool(ids),
                    "folders": [_describe_folder(acct, i) for i in ids]})
    return JSONResponse({
        "accounts": out,
        # Il costo va detto DOVE si prende la decisione, non solo in un commento
        # del config: chi confina perde il calendario, e deve saperlo prima.
        "closes_verbs": ["gcalendar.*"],
        "note": ("Confinare un account limita gdrive/gdocs/gsheets a quella "
                 "cartella e CHIUDE gcalendar: un'agenda non sta in una "
                 "cartella, quindi non può essere tenuta allo stesso perimetro.")})


async def gdrive_confinement_set(request: Request):
    """POST /tools/gdrive/confinement → imposta o rimuove il confinamento.

    Rimuovere (lista vuota) è l'operazione che CONCEDE, quindi è esplicita: serve
    `confirm_widen: true`. Non è un attrito decorativo — è l'unica azione qui che
    trasforma un account confinato in un account che vede tutto il Drive.
    """
    if not _authorized_owner(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    body = await request.json()
    account = str(body.get("account") or "").strip()
    raw = body.get("folders") or []
    if isinstance(raw, str):
        raw = [raw]
    from . import whitelist
    from .tools import gdrive, gdrive_root
    if account not in gdrive.gworkspace_accounts():
        return JSONResponse({"error": f"account '{account}' non collegato"},
                            status_code=400)
    ids = [_folder_id(r) for r in raw]
    ids = [i for i in ids if i]
    if not ids:
        if not body.get("confirm_widen"):
            return JSONResponse({"error": (
                "rimuovere il confinamento rende raggiungibile TUTTO il Drive di "
                f"'{account}' da qualunque agente con il grant: ripeti la "
                "richiesta con confirm_widen=true")}, status_code=409)
        whitelist.set_gdrive_roots(account, [])
        gdrive_root.reset_cache()
        LOG.warning("gdrive confinement RIMOSSO per %s", account)
        return JSONResponse({"account": account, "confined": False, "folders": []})
    described = [_describe_folder(account, i) for i in ids]
    bad = [d for d in described if not d.get("is_folder")]
    if bad:
        # Un id non risolvibile non va scritto: un confinamento a una cartella
        # inesistente non è "più stretto", è un tool che non funziona e che
        # qualcuno riaprirà per sbloccarsi.
        return JSONResponse({"error": "non sono cartelle raggiungibili da questo "
                                      "account", "folders": bad}, status_code=400)
    whitelist.set_gdrive_roots(account, ids)
    gdrive_root.reset_cache()
    LOG.info("gdrive confinement per %s → %s", account, ids)
    return JSONResponse({"account": account, "confined": True, "folders": described})


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
    # Integrazione Google UNIFICATA: un solo consenso (Gmail + Drive + Docs +
    # Calendar) → una sola credenziale google_<account> = un solo refresh token,
    # niente cross-invalidation dei due consensi separati (gmail_/gworkspace_).
    email_diagnostics = email_tool.credential_diagnostics()
    google_rows = [row for row in email_diagnostics if row["kind"] == "google"]
    google_accounts = sorted(row["account"] for row in google_rows if row["operational"])
    connectors = [{
        "id": "google",
        "label": "Google",
        "provider": "google",
        "scopes": "Gmail · Drive · Docs · Calendar",
        "connected": bool(google_accounts),
        "operational": bool(google_rows) and all(row["operational"] for row in google_rows),
        "accounts": google_accounts,
        "issues": [
            {"account": row["account"], "missing": row["missing"], "error": row["error"]}
            for row in google_rows if not row["operational"]
        ],
    }]
    mailbox_rows = [row for row in email_diagnostics if row["kind"] == "mailbox"]
    mailbox_accounts = sorted(row["account"] for row in mailbox_rows if row["operational"])
    connectors.append({
        "id": "mailboxes",
        "label": "Email mailboxes",
        "provider": "email",
        "connected": bool(mailbox_accounts),
        "operational": bool(mailbox_rows) and all(row["operational"] for row in mailbox_rows),
        "accounts": mailbox_accounts,
        "issues": [
            {"account": row["account"], "missing": row["missing"], "error": row["error"]}
            for row in mailbox_rows if not row["operational"]
        ],
    })
    # Integrazione Image generation (OpenAI): attiva se la key è nel vault.
    connectors.append({
        "id": "openai-images",
        "label": "Image generation (OpenAI)",
        "provider": "openai",
        "connected": vault.has_credential("openai_api_key"),
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


class McpRegisterError(ValueError):
    """Errore di registrazione MCP con status HTTP suggerito."""
    def __init__(self, msg: str, status: int = 400):
        super().__init__(msg)
        self.status = status


def register_mcp_core(config, secrets: dict | None = None) -> dict:
    """Core riutilizzabile della registrazione MCP (UI Add-MCP e tool mcp.add).
    I placeholder ${NAME} nel config vengono sostituiti con
    ${VAULT:mcp_<server>_<NAME>} e i segreti depositati nel vault (mai nel
    config.yaml). Solleva McpRegisterError su input non valido."""
    cfg = config
    if isinstance(cfg, str):
        try:
            cfg = json.loads(cfg)
        except Exception:
            raise McpRegisterError("config non è JSON valido")
    servers = (cfg or {}).get("mcpServers") if isinstance(cfg, dict) else None
    if not isinstance(servers, dict) or not servers:
        raise McpRegisterError("manca l'oggetto mcpServers nel config")
    secrets_in = secrets or {}

    backends = list(whitelist.CONFIG.get("mcp_backends") or [])
    agents = whitelist.CONFIG.setdefault("agents", {})
    clodia_tools = agents.setdefault("clodia", {}).setdefault("allowed_tools", [])
    registered = []
    for name, spec in servers.items():
        slug = _slugify(name)
        if not slug or slug in _NATIVE_PREFIXES:
            raise McpRegisterError(f"nome backend non valido/riservato: {name!r} → {slug!r}")
        # Feature `integrations` (profilo istanza): off = nessun mount di MCP
        # esterni; fixed = solo la whitelist dell'edizione (i tool del pack).
        try:
            instance_profile.integrations_check(slug)
        except PermissionError as e:
            raise McpRegisterError(str(e), status=403)
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
            raise McpRegisterError(f"server '{name}': serve 'url' (http) o 'command' (stdio)")
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
    return {"registered": registered}


def unregister_mcp_core(name: str) -> dict:
    """Core della rimozione MCP (config + grant clodia). Riutilizzato da mcp.remove."""
    cfg = whitelist.CONFIG
    cfg["mcp_backends"] = [b for b in (cfg.get("mcp_backends") or []) if b.get("name") != name]
    at = cfg.get("agents", {}).get("clodia", {}).get("allowed_tools", [])
    if f"{name}.*" in at:
        at.remove(f"{name}.*")
    whitelist.save_config()
    whitelist.reload_config()
    proxy.clear_cache()
    return {"unregistered": name}


async def register_mcp(request: Request):
    """Registra uno o più MCP server da mcp.json (UI Add-MCP)."""
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "bad_json"}, status_code=400)
    try:
        return JSONResponse(register_mcp_core(body.get("config"), body.get("secrets") or {}))
    except McpRegisterError as e:
        return JSONResponse({"error": str(e)}, status_code=e.status)


async def unregister_mcp(request: Request):
    """Rimuove un MCP server montato (config + grant clodia)."""
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return JSONResponse(unregister_mcp_core(request.path_params["name"]))


def _account_from_email(email: str) -> str:
    return email.split("@")[0].replace(".", "_")


async def google_auth(request: Request):
    """Avvia il consenso Google UNIFICATO (Gmail + Drive + Docs + Calendar)."""
    g = _connector_guard("google")
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
    url = go.consent_url(app["client_id"], app.get("redirect_uri", go.DEFAULT_REDIRECT),
                         scope=go.UNIFIED_SCOPE, state=state, prompt="select_account consent")
    return JSONResponse({"auth_url": url, "state": state,
                         "redirect_uri": app.get("redirect_uri", go.DEFAULT_REDIRECT)})


async def google_connect(request: Request):
    """Scambia il code del consenso unificato → un solo refresh token con TUTTI
    gli scope, salvato come google_<account>. I tool email.* e gdrive/gdocs/
    gcalendar.* leggono questa credenziale (fallback ai legacy gmail_/gworkspace_)."""
    g = _connector_guard("google")
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
        return JSONResponse({"error": "exchange_failed", "detail": str(e)[:200]}, status_code=502)
    rt = res.get("refresh_token")
    if not rt:
        return JSONResponse(
            {"error": "no_refresh_token",
             "detail": "Google non ha restituito un refresh_token. App in Testing? "
                       "Mettila In production e riprova."}, status_code=400)
    try:
        email = go.get_profile_email(res["access_token"])
    except Exception as e_profile:  # noqa: BLE001
        try:
            email = go.get_userinfo_email(res["access_token"])
        except Exception as e_ui:  # noqa: BLE001
            return JSONResponse(
                {"error": "profile_failed",
                 "detail": f"profilo: {str(e_profile)[:140]} · userinfo: {str(e_ui)[:100]}"},
                status_code=502)
    account = _account_from_email(email)
    vault.deposit(
        f"google_{account}",
        {"client_id": app["client_id"], "client_secret": app["client_secret"],
         "refresh_token": rt, "email": email, "account": account, "scope": go.UNIFIED_SCOPE},
        cred_type="oauth2_google", grant_agents=["clodia"],
    )
    return JSONResponse({"connected": True, "account": account, "email": email})


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
    rows = [
        row for row in email_tool.credential_diagnostics()
        if row["kind"] == "mailbox"
    ]
    return JSONResponse({
        "mailboxes": sorted(row["account"] for row in rows if row["operational"]),
        "statuses": [
            {"account": row["account"], "operational": row["operational"],
             "missing": row["missing"], "error": row["error"]}
            for row in rows
        ],
    })


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
    # L'IMAP è OPZIONALE: esistono indirizzi che sono alias con SMTP e nessuna
    # casella dietro. Richiederlo li rendeva impossibili da configurare, e chi
    # provava lo stesso otteneva una casella dichiarata «non operativa» —
    # nascosta agli agenti come se fosse rotta, mentre spedire funzionava.
    required = ("email", "password", "smtp_server")
    if any(not (b.get(k) or "").strip() for k in required):
        return JSONResponse({"error": f"campi richiesti: {', '.join(required)}"}, status_code=400)
    cfg = {
        "email": b["email"].strip(),
        "password": b["password"],
        "smtp_server": b["smtp_server"].strip(),
        "smtp_port": int(b.get("smtp_port") or 587),
    }
    if (b.get("imap_server") or "").strip():
        cfg["imap_server"] = b["imap_server"].strip()
        cfg["imap_port"] = int(b.get("imap_port") or 993)
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
    # I verbi che il collegamento concede a clodia, per NOME. Prima qui c'era
    # `github.*`, e una wildcard sul namespace di un backend esterno concede
    # anche ciò che quel backend aggiungerà domani: misurato il 17 ago 2026,
    # `delete_repository`, `force_push` e `delete_branch` risultavano concessi a
    # chi aveva la wildcard. Ciò che è irreversibile non si gata, non si concede
    # (decision-record 35) — e una lista esplicita fa nascere negato ogni verbo
    # nuovo, che è la direzione giusta in cui sbagliare.
    _GH_CONCESSI = [
        "github.clone", "github.pull", "github.push", "github.pull_request",
        "github.add_issue_comment", "github.get_commit", "github.get_file_contents",
        "github.get_pull_request", "github.issue_read", "github.issue_write",
        "github.list_branches", "github.list_commits", "github.list_issues",
        "github.list_pull_requests", "github.list_releases", "github.list_tags",
        "github.search_code", "github.search_commits", "github.search_issues",
    ]
    agents = whitelist.CONFIG.setdefault("agents", {})
    ct = agents.setdefault("clodia", {}).setdefault("allowed_tools", [])
    # Toglie una wildcard lasciata da un collegamento precedente: senza questo,
    # chi si era collegato prima del fix se la porterebbe dietro per sempre.
    ct[:] = [v for v in ct if v != "github.*"]
    for v in _GH_CONCESSI:
        if v not in ct:
            ct.append(v)
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


async def delegation_list(request: Request):
    """Deleghe permanenti attive (async·A). Admin."""
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    from . import delegation
    return JSONResponse({"delegations": delegation.list_active()})


async def delegation_register(request: Request):
    """Registra una delega FIRMATA dall'utente (client-side). Admin. Il token è
    ri-verificato (firma vs cert CA + scope): non ci si fida del client."""
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    try:
        b = await request.json()
    except Exception:  # noqa: BLE001
        return JSONResponse({"error": "bad_json"}, status_code=400)
    from . import delegation
    v = delegation.register((b.get("token") or "").strip())
    if not v:
        return JSONResponse({"error": "delega non valida (firma/scope/scadenza)"}, status_code=400)
    return JSONResponse({"ok": True, **v})


async def delegation_revoke(request: Request):
    """Revoca le deleghe di un principal su un verbo. Admin."""
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    b = await request.json()
    from . import delegation
    return JSONResponse({"revoked": delegation.revoke(
        (b.get("principal") or "").strip(), (b.get("verb") or "").strip())})


async def backup_restore_test(request: Request):
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    from . import backup
    try:
        return JSONResponse(backup.restore_test())
    except Exception as e:
        return JSONResponse({"error": str(e)[:400]}, status_code=500)


def _prova_smtp(b: dict, account: str) -> str:
    """Login SMTP, per le caselle che sanno solo spedire. Ritorna l'esito in
    parole, mai il segreto né il messaggio grezzo del server."""
    import smtplib
    porta = int(b.get("smtp_port") or 587)
    utente = b.get("smtp_user") or b.get("email") or account
    pwd = b.get("password") or b.get("app_password") or ""
    try:
        # 465 è SMTPS implicito, 587 è STARTTLS: distinguerli qui evita un
        # «connessione rifiutata» che sembra un host sbagliato e invece è una
        # porta usata col protocollo dell'altra.
        if porta == 465:
            s = smtplib.SMTP_SSL(b.get("smtp_server"), porta, timeout=15)
        else:
            s = smtplib.SMTP(b.get("smtp_server"), porta, timeout=15)
            s.starttls()
        try:
            s.login(utente, pwd)
            return "ok"
        finally:
            try:
                s.quit()
            except Exception:  # noqa: BLE001
                pass
    except smtplib.SMTPAuthenticationError:
        # Il rimedio dipende da COSA si è usato come utente, e i due casi
        # portano da parti opposte: rigenerare una password, o scoprire che
        # l'utenza non è l'indirizzo. I relay (SMTP2GO, Mailgun, SendGrid, Brevo)
        # autenticano con un utente dedicato; dirlo qui evita di far reimpostare
        # una password che era giusta.
        if not (b.get("smtp_user") or "").strip():
            return ("autenticazione SMTP rifiutata usando l'indirizzo come utente. "
                    "Se il server è un relay (smtp2go, mailgun, sendgrid, brevo…) "
                    "l'utenza NON è l'indirizzo: compila «utente SMTP» con quella "
                    "del relay")
        return "autenticazione SMTP rifiutata (password sbagliata per l'utente indicato)"
    except Exception as e:  # noqa: BLE001
        return type(e).__name__


def _test_mailboxes() -> dict:
    """Prova un login IMAP VERO per ogni casella configurata.

    Fino a ieri le mailbox cadevano nel ramo «test non disponibile», e l'unico
    segnale su una casella era la parola «operativa» — che vuol dire *i campi ci
    sono*, non *il login funziona*. Una parola che promette più di quanto
    verifica manda a cercare il guasto dalla parte sbagliata: è successo con
    `team` (clodia-platform#176), dichiarata operativa e con la password
    rifiutata dal server IMAP, e il difetto è stato cercato nella visibilità
    dell'account per mezz'ora.

    Le altre integrazioni (GitHub, Telegram, OpenAI) avevano già una prova reale.
    Questa colma l'unica che ne era priva — e quindi l'unica che poteva mentire.

    Il segreto non esce: si ritorna l'esito per account, mai il bundle.
    """
    import imaplib

    esiti, ok_tutti = [], True
    for nome in sorted(vault.store_names()):
        if not nome.startswith("mailbox_"):
            continue
        account = nome[len("mailbox_"):]
        try:
            b = vault.read_internal(nome)
        except Exception:  # noqa: BLE001
            esiti.append(f"{account}: credenziale illeggibile")
            ok_tutti = False
            continue
        pwd = b.get("password") or b.get("app_password") or ""
        if not pwd:
            esiti.append(f"{account}: manca la password")
            ok_tutti = False
            continue
        # Una casella di SOLO INVIO si prova sull'SMTP. Provarla sull'IMAP la
        # dichiarerebbe guasta per sempre: è la differenza fra «non funziona» e
        # «non fa quella cosa», e confonderle manda a cercare una password
        # sbagliata dove manca invece un servizio.
        server = (b.get("imap_server") or "").strip()
        if not server:
            esiti.append(f"{account}: {_prova_smtp(b, account)} (solo invio)")
            if "ok" not in esiti[-1]:
                ok_tutti = False
            continue
        try:
            imap = imaplib.IMAP4_SSL(server, int(b.get("imap_port") or 993), timeout=15)
            try:
                imap.login(b.get("email") or account, pwd)
                esiti.append(f"{account}: ok")
            finally:
                try:
                    imap.logout()
                except Exception:  # noqa: BLE001
                    pass
        except imaplib.IMAP4.error:
            # Il messaggio del server IMAP non si riporta: su alcuni provider
            # contiene l'utenza. Il rimedio è lo stesso in ogni caso.
            esiti.append(f"{account}: autenticazione IMAP rifiutata (password "
                         "sbagliata, oppure l'indirizzo è un alias di solo "
                         "invio: in quel caso togli il server IMAP)")
            ok_tutti = False
        except Exception as e:  # noqa: BLE001 — host irraggiungibile, TLS, timeout
            esiti.append(f"{account}: {type(e).__name__}")
            ok_tutti = False
    if not esiti:
        return {"ok": None, "detail": "nessuna casella configurata"}
    return {"ok": ok_tutti, "detail": " · ".join(esiti)}


# Nome leggibile degli scope del consenso Google, per dire QUALE servizio manca
# invece di stampare un URL. Chi legge la card ragiona per servizi, non per URI.
_GOOGLE_SERVIZI = {
    "https://mail.google.com/": "Gmail",
    "https://www.googleapis.com/auth/drive": "Drive",
    "https://www.googleapis.com/auth/documents": "Docs",
    "https://www.googleapis.com/auth/calendar": "Calendar",
}
# id della card → prefisso della credenziale nel vault. `google` prova SOLO le
# credenziali unificate, cioè gli account che la card elenca (list_tools li
# prende da `credential_diagnostics` con kind=google): provare anche i legacy
# renderebbe rossa una card per un account che non mostra.
_GOOGLE_PREFISSI = {"google": "google_", "gworkspace": "gworkspace_", "gmail": "gmail_"}


def _nome_servizio(scope: str) -> str:
    return _GOOGLE_SERVIZI.get(scope) or scope.rstrip("/").rsplit("/", 1)[-1]


def _prova_google(bundle: dict, atteso: str) -> tuple[bool, str]:
    """Prova UN account Google: refresh del token + una chiamata a `userinfo`.

    Il refresh è il punto dove il guasto vero di questa integrazione si vede —
    consenso revocato dal proprietario dell'account, oppure refresh token
    scalzato da un secondo consenso sugli stessi scope — e Google lo dice con
    `invalid_grant`. La chiamata a `userinfo` aggiunge la sola cosa che il
    refresh non prova: che l'access token sia poi accettato da un'API, e da
    quale identità. Nient'altro: `userinfo` è la chiamata più leggera coperta
    dal consenso, non tocca dati dell'owner e non consuma quota di Drive/Gmail.
    """
    import requests as _rq

    r = _rq.post(go.TOKEN_URL, data={
        "client_id": bundle["client_id"],
        "client_secret": bundle["client_secret"],
        "refresh_token": bundle["refresh_token"],
        "grant_type": "refresh_token",
    }, timeout=15)
    if r.status_code != 200:
        try:
            err = (r.json() or {}).get("error") or ""
        except Exception:  # noqa: BLE001 — un 5xx di Google non è JSON
            err = ""
        if err == "invalid_grant":
            # Il rimedio è uno e va detto qui: la webui non ha altro posto dove
            # scriverlo, e «invalid_grant» da solo non dice cosa fare.
            return False, ("consenso revocato o refresh token non più valido — "
                           "riconnetti l'account")
        return False, f"Google OAuth {r.status_code}{': ' + err if err else ''}"
    tok = r.json() or {}
    access = tok.get("access_token") or ""
    if not access:
        return False, "Google non ha restituito un access token"
    ui = _rq.get("https://www.googleapis.com/oauth2/v2/userinfo",
                 headers={"Authorization": f"Bearer {access}"}, timeout=15)
    if ui.status_code != 200:
        return False, f"userinfo {ui.status_code} (token rinfrescato ma non accettato)"
    email = (ui.json() or {}).get("email") or "account senza email"
    detail = f"ok ({email})"
    # Consenso incompleto: la connessione FUNZIONA e una parte della card no.
    # È «non fa quella cosa», non «non funziona» — la stessa distinzione di
    # «solo invio» per le caselle. Rosso qui manderebbe a rigenerare un token
    # sano, e il consenso nuovo scalzerebbe quello vecchio.
    mancanti = [s for s in atteso.split() if s not in (tok.get("scope") or "").split()]
    nominabili = [_nome_servizio(s) for s in mancanti if s in _GOOGLE_SERVIZI]
    if nominabili:
        detail += f" · fuori dal consenso: {', '.join(nominabili)} (riconnetti per aggiungerli)"
    return True, detail


def _test_google(cid: str) -> dict:
    """Prova REALE del connettore Google della card /integrations (#284).

    Prima di questa, l'id `google` cadeva nel ramo «test non disponibile» e sulla
    card compariva il badge «—»: l'integrazione che apre cinque servizi era,
    insieme alle caselle (chiuse in clodia-platform#176), la sola senza una
    verifica. E «Connesso» dice che i campi della credenziale ci sono, non che il
    refresh token sia ancora valido — cioè tace esattamente su ciò che scade.
    """
    prefisso = _GOOGLE_PREFISSI[cid]
    atteso = go.UNIFIED_SCOPE if cid == "google" else ""
    esiti, ok_tutti = [], True
    for nome in sorted(vault.store_names()):
        if not nome.startswith(prefisso):
            continue
        account = nome[len(prefisso):]
        try:
            b = vault.read_internal(nome)
        except Exception:  # noqa: BLE001 — mai il motivo interno del vault
            esiti.append(f"{account}: credenziale illeggibile")
            ok_tutti = False
            continue
        # Un campo che manca si giudica dal vault: chiamare Google con un token
        # vuoto ritorna un errore del provider al posto del nome del campo, e
        # manda a cercare il guasto dalla parte dell'account invece che qui.
        mancanti = [f for f in ("client_id", "client_secret", "refresh_token")
                    if not b.get(f)]
        if mancanti:
            esiti.append(f"{account}: mancano {', '.join(mancanti)} — riconnetti")
            ok_tutti = False
            continue
        ok, detail = _prova_google(b, atteso)
        esiti.append(f"{account}: {detail}")
        ok_tutti = ok_tutti and ok
    if not esiti:
        return {"ok": None, "detail": "nessun account Google connesso"}
    return {"ok": ok_tutti, "detail": " · ".join(esiti)}


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
            key = (b or {}).get("api_key") or (b or {}).get("value") or ""
            if not key:
                return {"ok": False, "detail": "nessuna API key nel vault"}
            r = _rq.get("https://api.openai.com/v1/models",
                        headers={"Authorization": f"Bearer {key}"}, timeout=15)
            return ({"ok": True, "detail": "API key valida"} if r.status_code == 200
                    else {"ok": False, "detail": f"OpenAI {r.status_code}"})

        if cid in _GOOGLE_PREFISSI:
            return _test_google(cid)

        if cid == "mailboxes":
            return _test_mailboxes()

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
    Route("/tools/gdrive/confinement", gdrive_confinement, methods=["GET"]),
    Route("/tools/gdrive/confinement", gdrive_confinement_set, methods=["POST"]),
    Route("/clodia/delegations", delegation_list, methods=["GET"]),
    Route("/clodia/delegations", delegation_register, methods=["POST"]),
    Route("/clodia/delegations/revoke", delegation_revoke, methods=["POST"]),
    Route("/tools", list_tools, methods=["GET"]),
    Route("/tools/{id}/test", test_connector, methods=["POST"]),
    Route("/tools/email/mailboxes", email_mailboxes, methods=["GET"]),
    Route("/tools/email/mailboxes", email_mailbox_add, methods=["POST"]),
    Route("/tools/email/mailboxes/{account}", email_mailbox_remove, methods=["DELETE"]),
    Route("/tools/google/app", google_app_status, methods=["GET"]),
    Route("/tools/google/app", google_app_config, methods=["POST"]),
    Route("/tools/google/auth", google_auth, methods=["GET"]),
    Route("/tools/google/connect", google_connect, methods=["POST"]),
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
