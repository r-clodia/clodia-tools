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

import ssl
import asyncio
import hashlib
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
from . import mcp_credentials
from . import mcp_oauth
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


def _norm_backend(name) -> str:
    """Il nome di un backend nella forma in cui lo confronta la PROPRIETÀ.

    Una sola implementazione, quella di `connectors.resolved`: importata qui
    dentro perché quel modulo tira dentro il registry dei connettori e questo
    file è importato dal boot del gateway.
    """
    from .connectors.resolved import norm_name
    return norm_name(str(name or ""))


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
    """Gestione integrations/credenziali/backup = **territorio ADMIN**.

    Passa:
    - il trusted-core via UI token (chiamanti interni/headless);
    - una sessione on-behalf con `human_role: admin`;
    - un token nudo il cui principal è un umano admin (`agent.yaml`);
    - l'AGENT-SERVER, che lo dichiara nel claim firmato `role` — è il chiamante
      di `/internal/connectors/validate` durante l'import di un pack.

    NON passa più il token di RUNTIME di clodia/ophelia (clodia-platform#539 §5).
    Era un residuo del tempo in cui erano super-agent: quel token vive
    nell'ambiente di ogni spawn, quindi un agente poteva depositare o
    sostituire le credenziali dell'istanza — Google, GitHub, Telegram, le
    caselle — senza che nessuna persona lo vedesse. Le credenziali sono
    territorio di chi risponde dell'istanza: un umano admin, o il servizio che
    sta eseguendo un'installazione per lui. «Super» non è «amministratore»: il
    primo è un'ampiezza di verbi, il secondo è una responsabilità.
    """
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
    from .pki_mint import ROLE_AGENT_SERVER
    if p.get("role") == ROLE_AGENT_SERVER:
        return True
    return _is_human_admin(str(p.get("agent") or ""))


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

    Answered by whichever side implements Google on this instance
    (`google_switch`, #558): the component's `describe_folder` in `pack`
    position. A component that is not serving is a folder that cannot be
    confirmed — refused like an unreachable one.
    """
    from .tools import google_switch
    try:
        return google_switch.describe_folder(account, fid)
    except google_switch.ComponentUnavailable as e:
        return {"id": fid, "is_folder": False, "error": str(e)[:200]}


async def gdrive_confinement(request: Request):
    """GET /tools/gdrive/confinement → stato del confinamento per account."""
    if not _authorized_owner(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    from . import whitelist
    from .tools import google_switch
    whitelist.reload_config()
    roots = whitelist.gdrive_roots_all()
    out = []
    try:
        accounts = google_switch.accounts()
    except google_switch.ComponentUnavailable as e:
        return JSONResponse({"error": str(e)}, status_code=503)
    for acct in accounts:
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
    from .tools import google_switch
    try:
        accounts = google_switch.accounts()
    except google_switch.ComponentUnavailable as e:
        return JSONResponse({"error": str(e)}, status_code=503)
    if account not in accounts:
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
        google_switch.perimeter_changed()
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
    google_switch.perimeter_changed()
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


def connectors_snapshot() -> list[dict]:
    """Stato dei connettori del gateway, senza HTTP e senza Request.

    È la sorgente UNICA: la serve `GET /tools` alla webui e la legge in-process
    il verbo `integrations.list` (clodia-platform#410). Prima quel verbo faceva
    il giro lungo gateway → agent-server `/api/connectors` → gateway
    `/internal/connectors`, rotta che non è mai esistita: 502 garantito. Lo
    stato dei connettori vive qui, dove vive la vault: non c'è niente da
    chiedere a nessuno.
    """
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
    # The mailboxes from the side in charge of mail (#558): on `mail: pack`
    # comms-pack's component reads `mailbox_*`, and says nothing if absent.
    from .tools import mail_switch
    mailbox_issue = []
    if mail_switch.in_pack():
        mailbox_rows = [row for row in mail_switch.credential_diagnostics()
                        if row["kind"] == "mailbox"]
        try:
            mail_switch.service("diagnostics")
        except mail_switch.ComponentUnavailable:
            mailbox_issue = [{"account": "-", "missing": [],
                              "error": "component_unavailable"}]
    else:
        mailbox_rows = [row for row in email_diagnostics if row["kind"] == "mailbox"]
    mailbox_accounts = sorted(row["account"] for row in mailbox_rows if row["operational"])
    connectors.append({
        "id": "mailboxes",
        "label": "Email mailboxes",
        "provider": "email",
        "connected": bool(mailbox_accounts),
        "operational": (bool(mailbox_rows) and not mailbox_issue
                        and all(row["operational"] for row in mailbox_rows)),
        "accounts": mailbox_accounts,
        "issues": [
            {"account": row["account"], "missing": row["missing"], "error": row["error"]}
            for row in mailbox_rows if not row["operational"]
        ] + mailbox_issue,
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
    # `connected` diceva sempre True — «montato» non è «funzionante»: un server
    # MCP di pack le cui dipendenze pip non ci sono più (clodia-platform#451)
    # risultava verde nella UI e falliva a ogni chiamata. Qui il gap diventa
    # visibile dove l'owner guarda, con il nome di ciò che manca.
    gaps_by_server: dict[str, dict] = {}
    try:
        from .tools import pack_runtime
        for gap in pack_runtime.missing_requirements():
            for server in gap["mcp_servers"]:
                gaps_by_server[_slugify(server)] = gap
    except Exception:  # noqa: BLE001 — lo stato connettori non deve mai rompersi
        gaps_by_server = {}
    for b in (whitelist.CONFIG.get("mcp_backends") or []):
        row = {
            "id": b.get("name"),
            "label": b.get("label") or b.get("name"),
            "provider": "mcp",
            "transport": b.get("transport", "stdio"),
            "connected": True,
            "accounts": [],
        }
        # Un backend OAuth non ancora autorizzato è montato ma non usabile:
        # stessa distinzione delle dipendenze pip mancanti (#451), stesso posto.
        # Con `auth.methods` (#565) la card riceve anche i metodi del suo
        # «Connetti» — tipi, scope, nomi ed etichette dei campi, mai valori — e
        # con quale è connesso.
        metodi = mcp_credentials.public_methods(b)
        if metodi:
            attivo = mcp_credentials.active(b)
            row["auth_methods"] = metodi
            row["auth_active"] = attivo
            if any(m["type"] == "oauth" for m in metodi):
                row["auth"] = "oauth"  # forma di #532, che la webui già legge
                row["authorized"] = attivo == "oauth"
            if attivo is None:
                row["connected"] = False
                row["operational"] = False
                if mcp_oauth.auth_spec(b) and len(metodi) == 1:
                    detail = mcp_oauth.authorization_status(b)["detail"]
                else:
                    detail = "non connesso: serve «Connetti» dalla card"
                row["issues"] = [{"error": detail}]
        gap = gaps_by_server.get(_slugify(str(b.get("name") or "")))
        if gap:
            row["operational"] = False
            row["issues"] = [{
                "pack": gap["pack"],
                "missing": gap["missing"],
                "error": "dipendenze pip del pack non installate: il server MCP "
                         "non parte finché non vengono reinstallate "
                         "(packs.install_pip)",
            }]
        connectors.append(row)
    allowed = instance_profile.connectors_allowed()
    if allowed is not None:
        # backup/topic-storage/mcp non sono connettori nativi gated
        keep = set(allowed) | {"topic-storage"}
        connectors = [c for c in connectors
                      if c.get("provider") == "mcp" or c.get("id") in keep]
    return connectors


async def list_tools(request: Request):
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    # `services`: i processi lungo-vivi dichiarati dai pack, con stato e ultimo
    # errore (clodia-platform#515). Stessa rotta dei connettori perché è la
    # stessa pagina: un connettore che ha bisogno di un processo è rotto quanto
    # quel processo, e finora non c'era modo di vederlo da fuori.
    from . import services as _services
    return JSONResponse({"connectors": connectors_snapshot(),
                         "services": _services.snapshot()})


class McpRegisterError(ValueError):
    """Errore di registrazione MCP con status HTTP suggerito."""
    def __init__(self, msg: str, status: int = 400):
        super().__init__(msg)
        self.status = status


#: A plugin or pack name as the agent-server writes it on disk.
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


def _pack_plugin_roots(pack: str) -> list:
    """The resolved plugin directories that belong to `pack` and to no other
    installed pack (clodia-platform#539 §4, legacy adoption).

    The agent-server installs a pack's plugins under `$CLODIA_DATA/plugins/
    <plugin>/` and lists them in `$CLODIA_DATA/packs/<pack>/pack.yaml`
    (`plugins:`); `pack_mcp_mount` mounts each plugin's servers in the name of
    the pack that carries it, so `<plugin>` is not necessarily `<pack>` (on
    terra: `studio-commercialista` carries `assetti-contabili`). A plugin that
    two installed packs both list belongs to neither: ambiguity is refused.
    """
    from pathlib import Path
    import yaml
    data = Path(os.environ.get("CLODIA_DATA", "/datadir"))
    listed: dict[str, set[str]] = {}
    try:
        files = sorted((data / "packs").glob("*/pack.yaml"))
    except OSError:
        return []
    for f in files:
        try:
            meta = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        except Exception:  # noqa: BLE001 — unreadable manifest: proves nothing
            continue
        if not isinstance(meta, dict):
            continue
        owner = str(meta.get("name") or f.parent.name)
        plugins = meta.get("plugins")
        for pl in plugins if isinstance(plugins, list) else []:
            listed.setdefault(str(pl), set()).add(owner)
    try:
        base = (data / "plugins").resolve()
    except OSError:
        return []
    roots = []
    for plugin, owners in sorted(listed.items()):
        if owners != {pack} or not _SAFE_NAME.fullmatch(plugin) \
                or plugin in (".", ".."):
            continue
        lexical = base / plugin
        root = lexical.resolve()
        # A plugin dir that is a symlink — even to a sibling plugin dir — is
        # not the pack's: only a real directory under `plugins/` proves it.
        if root != lexical:
            continue
        roots.append(root)
    return roots


def _legacy_adoptable(entry: dict, pack: str) -> bool:
    """May `pack` adopt this backend that carries no `pack` stamp?

    Backends that packs mounted before clodia-tools 2.90.0 were never stamped:
    under the §4 guard they read as «mounted by an admin, reserved for
    everyone», so once clodia-logic passes `pack` on import/update, a trusted
    pack re-mounting its OWN legacy backend would get 409 and Updates would
    break. Ownership must still be PROVEN, not claimed: the proof is that the
    process the existing entry starts lives inside one of the pack's own
    plugin directories (`_pack_plugin_roots`).

    Fail closed on everything else: http backends (a URL proves nothing),
    entries without a path-like token, relative paths, any `..`, tokens with
    whitespace (a shell line, not a path), paths that — after resolving
    symlinks — fall outside the plugin dir, or that span two plugin dirs.
    """
    from pathlib import Path
    if not isinstance(entry, dict) or entry.get("pack"):
        return False
    if entry.get("transport") != "stdio":
        return False
    if not pack or not _SAFE_NAME.fullmatch(str(pack)):
        return False
    tokens = [entry.get("command")] + list(entry.get("args") or [])
    paths = []
    for tok in tokens:
        if not isinstance(tok, str):
            return False
        if "=" in tok and tok.startswith("-"):
            tok = tok.split("=", 1)[1]
        if "/" not in tok and "\\" not in tok:
            continue                      # `python3`, `-u`, `--stdio`
        if any(c.isspace() for c in tok) or "\\" in tok:
            return False
        p = Path(tok)
        if not p.is_absolute() or ".." in p.parts:
            return False
        paths.append(p)
    if not paths:
        return False
    roots = _pack_plugin_roots(str(pack))
    for root in roots:
        try:
            if all(p.resolve().is_relative_to(root) and p.resolve() != root
                   for p in paths):
                return True
        except (OSError, RuntimeError):  # symlink loop
            return False
    return False


def _core_entry_released(entry: dict, pack: str = "",
                         new: dict | None = None) -> bool:
    """Is `entry` the native connector's own backend, released to a pack?

    clodia-platform#525. `github_connect` mounted the official GitHub MCP
    backend as `github`, unstamped — it belonged to the core, not to a pack.
    With `connectors: {github: pack}` it-pack declares the connector and
    mounts that backend itself; without this its import would get the 409 for
    «already mounted by an administrator» and the switch could never complete.

    Narrow on purpose: only in `pack` position, only an UNSTAMPED entry, only
    a backend the core mounts (`resolved._CORE_BACKEND_CONNECTORS`), and only
    in the exact shape the native handler wrote (http, the official URL). An
    admin mount that merely shares the name is not the core's, and stays
    protected by the 409.
    """
    from .connectors import resolved as _resolved
    if not isinstance(entry, dict) or entry.get("pack"):
        return False
    cid = _resolved._CORE_BACKEND_CONNECTORS.get(
        _resolved.norm_name(str(entry.get("name") or "")))
    if cid is None or instance_profile.connector_mode(cid) != "pack":
        return False
    # Only the pack the connector is switched TO, and only to mount the same
    # official endpoint: otherwise any pack imported first replaced the
    # official mount with its own URL, carrying the PAT (review of #379).
    from .connectors import builtin as _builtin
    if pack != _builtin.RELEASED_TO.get(cid):
        return False
    if not (isinstance(new, dict) and new.get("transport") == "http"
            and str(new.get("url") or "") == GITHUB_MCP_URL):
        return False
    return (entry.get("transport") == "http"
            and str(entry.get("url") or "") == GITHUB_MCP_URL)


def register_mcp_core(config, secrets: dict | None = None,
                      pack: str | None = None) -> dict:
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
    # Nessun grant automatico (clodia-platform#393). Fino al 26 set 2026 ogni
    # mount aggiungeva `<slug>.*` agli `allowed_tools` di clodia — residuo di
    # quando era super — e così clodia si è trovata `sedia.*`, `normattiva.*`,
    # `contabilita.*`, `leads.*` senza che il suo seed li dichiarasse. Un backend
    # montato ora non è concesso a nessuno: lo ha chi lo dichiara nel proprio
    # seed, e clodia, se le serve, lo prende in prestito con `copybrain`.
    registered = []
    deposits: list[tuple[str, str]] = []
    forget_after: list[str] = []
    for name, spec in servers.items():
        slug = _slugify(name)
        if not slug or slug in _NATIVE_PREFIXES or slug in mcp_credentials.RESERVED_SLUGS:
            raise McpRegisterError(f"nome backend non valido/riservato: {name!r} → {slug!r}")
        # Feature `integrations` (profilo istanza): off = nessun mount di MCP
        # esterni; fixed = solo la whitelist dell'edizione (i tool del pack).
        try:
            instance_profile.integrations_check(slug)
        except PermissionError as e:
            raise McpRegisterError(str(e), status=403)
        if spec.get("url"):
            transport = "http"
            backend = {"name": slug, "label": name, "transport": "http", "url": spec["url"]}
            if spec.get("headers"):
                backend["headers"] = spec["headers"]
        elif spec.get("command"):
            transport = "stdio"
            backend = {"name": slug, "label": name, "transport": "stdio",
                       "command": spec["command"], "args": spec.get("args", [])}
            if spec.get("env"):
                backend["env"] = spec["env"]
        else:
            raise McpRegisterError(f"server '{name}': serve 'url' (http) o 'command' (stdio)")
        # Come si connette (clodia-platform#565): `auth` dichiarato, oppure i
        # placeholder `${NOME}` rimasti senza segreto — il caso di ogni
        # `.mcp.json` di pack — diventano un metodo `credential` da riempire
        # al «Connetti». Nessun segreto chiesto al mount.
        try:
            if spec.get("auth") is not None:
                backend["auth"] = mcp_credentials.normalize(spec["auth"], transport=transport)
                declared = mcp_credentials.credential_method(backend)
                if declared is not None:
                    # Lo stesso header scritto anche fuori da auth.methods: lo
                    # mette l'iniezione, nel config non deve restare.
                    backend = mcp_credentials.strip_injected(backend, declared)
            else:
                implicit = mcp_credentials.implicit_method(
                    backend, transport, provided={k for k, v in secrets_in.items() if v})
                if implicit is not None:
                    backend = mcp_credentials.strip_injected(backend, implicit)
                    backend["auth"] = {"methods": [implicit]}
        except ValueError as e:
            raise McpRegisterError(f"server '{name}': {e}")
        # Provenienza (review di #354): il backend montato DAL MOUNT DI UN PACK
        # porta il nome del pack, ed è l'unica prova con cui quel pack può
        # usarne il namespace per i propri connettori. Un mount da Tools o da
        # `mcp.add` senza `pack` non è di nessun pack.
        if pack:
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", str(pack)):
                raise McpRegisterError(f"nome di pack non valido: {pack!r}")
            backend["pack"] = str(pack)
        # The hash of the config AS MOUNTED (placeholders, never secret values:
        # those go to the vault below). The agent-server compares it with the
        # pack's declared config before a disable records a server to mount
        # back on enable: only what was reviewed and mounted comes back
        # (clodia-platform#563). Same normalisation as its `config_hash`.
        backend["config_sha256"] = hashlib.sha256(
            json.dumps(spec, sort_keys=True, default=str).encode("utf-8")).hexdigest()
        # PROPRIETÀ, non solo nome (clodia-platform#539 §4). Il dedup per slug
        # SOSTITUIVA la voce esistente e le scriveva sopra il `pack` del nuovo
        # mount: un pack che montasse un server chiamato come quello di un admin
        # — o di un altro pack — ne diventava il proprietario, e la proprietà è
        # proprio ciò che poi gli dà diritto a quel namespace per i suoi
        # connettori (`backend_owners`). Un rimount dallo STESSO proprietario
        # resta un aggiornamento legittimo: cambia URL, header, segreti.
        #
        # The check runs BEFORE any vault write (review of #363): the secret
        # name `mcp_<slug>_<name>` is shared with the backend already mounted,
        # so depositing first and refusing afterwards overwrote the legitimate
        # owner's secret with the refused caller's value.
        # Confronto NORMALIZZATO (clodia-platform#545 §2): `mcp_backends` è un
        # file, e un nome scritto a mano lì dentro non passa da `_slugify` —
        # `norm_attiva` non è uguale a `norm-attiva` per `==`, ma per la
        # proprietà (`resolved.norm_name`, che decide se un pack può prendersi
        # quel namespace) è lo stesso backend. Due confronti diversi sulla
        # stessa domanda: quello più largo vince, se no il mount passa qui e la
        # proprietà lo registra là.
        precedente = next((b for b in backends
                           if _norm_backend(b.get("name")) == _norm_backend(slug)),
                          None)
        if precedente is not None:
            prima = str(precedente.get("pack") or "")
            adesso = str(pack or "")
            if prima != adesso and not prima and adesso and \
                    _legacy_adoptable(precedente, adesso):
                # Legacy mount of this very pack (see `_legacy_adoptable`):
                # adopted, and the new entry below carries `pack: <adesso>`.
                LOG.info("mcp: backend '%s' senza proprietario adottato dal "
                         "pack '%s' (path nel suo plugin dir)", slug, adesso)
            elif prima != adesso and not prima and adesso and \
                    _core_entry_released(precedente, adesso, backend):
                # The gateway's own GitHub mount, left behind by the native
                # connector, on an instance whose profile hands `github` to a
                # pack (#525): the pack's mount replaces it.
                LOG.info("mcp: backend '%s' del connettore nativo sostituito "
                         "dal mount del pack '%s' (connettore passato al pack)",
                         slug, adesso)
            elif prima != adesso:
                chi_prima = f"il pack '{prima}'" if prima else "un amministratore"
                chi_ora = f"il pack '{adesso}'" if adesso else "un amministratore"
                raise McpRegisterError(
                    f"il backend MCP '{slug}' è già montato da {chi_prima}: "
                    f"{chi_ora} non può sostituirlo. Smontalo prima "
                    f"(mcp.remove), oppure monta il tuo con un altro nome.",
                    status=409)
            if mcp_credentials.fingerprint(precedente) != mcp_credentials.fingerprint(backend):
                # Rimount accettato (aggiornamento o adozione) che ora punta
                # altrove: credenziale e token restano dell'host di prima (#565).
                forget_after.append(slug)
        # Secrets: placeholders are replaced in the config now, but the vault
        # (infra, no grant) is written only once EVERY server of the request
        # has been accepted — a refusal on a later server must not leave the
        # earlier servers' secrets written.
        for sname, sval in secrets_in.items():
            if not sval:
                continue
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", str(sname)):
                # Il nome finisce nel nome del file del vault: niente `../`.
                raise McpRegisterError(f"server '{name}': nome di segreto non valido: {sname!r}")
            cred = f"mcp_{slug}_{sname}"
            deposits.append((cred, sval))
            backend = _replace_placeholder(backend, sname, f"${{VAULT:{cred}}}")
        # A backend reads only its own vault entries, or those its pack's
        # connectors bind (clodia-platform#568): refused at mount, naming them —
        # after ownership (409 wins) and after `${NAME}` became the backend's own
        # `${VAULT:mcp_<slug>_NAME}`.
        from .proxy import vault_refs_problem as _vrp
        _why = _vrp(backend)
        if _why:
            raise McpRegisterError(_why, status=403)
        avanzi = mcp_credentials.leftover_placeholders(backend)
        if avanzi:
            raise McpRegisterError(
                f"server '{name}': placeholder che nessuno riempirà: "
                f"{', '.join('${' + a + '}' for a in sorted(avanzi))}. Una credenziale va "
                "negli headers (http) o nell'env (stdio), oppure in un metodo "
                "'credential' di auth.methods — mai negli args né nella URL.")
        # Dedup sullo stesso confronto del 409: una riga che si normalizza
        # come la nuova È la stessa voce, e lasciarla farebbe dipendere la
        # proprietà da quale delle due viene letta per prima.
        backends = [b for b in backends
                    if _norm_backend(b.get("name")) != _norm_backend(slug)]
        backends.append(backend)
        registered.append(slug)

    for cred, sval in deposits:
        vault.deposit(cred, {"value": sval}, cred_type="mcp_secret", grant_agents=[])
    for slug in forget_after:
        vault.remove(mcp_credentials.cred_name(slug))
        mcp_oauth.forget(slug)
        LOG.info("mcp: backend '%s' rimontato verso un'altra destinazione: "
                 "credenziale e token dimenticati, serve un nuovo «Connetti»", slug)
    whitelist.CONFIG["mcp_backends"] = backends
    whitelist.save_config()
    whitelist.reload_config()
    proxy.clear_cache()
    return {"registered": registered}


def unregister_mcp_core(name: str) -> dict:
    """Core della rimozione MCP. Riutilizzato da mcp.remove.

    Non tocca più gli `allowed_tools` di nessuno: il mount non ne concede
    (clodia-platform#393), quindi non c'è grant da ritirare. I token OAuth
    invece sì: restassero nella vault, un remount dello stesso slug — magari
    verso un'altra URL — ripartirebbe con le credenziali del precedente."""
    cfg = whitelist.CONFIG
    # Token OAuth e credenziale inserita al «Connetti» (#565), qualunque sia il
    # metodo attivo: `forget`/`remove` sono idempotenti.
    mcp_oauth.forget(name)
    vault.remove(mcp_credentials.cred_name(name))
    cfg["mcp_backends"] = [b for b in (cfg.get("mcp_backends") or []) if b.get("name") != name]
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


def _mcp_backend(name: str) -> dict | None:
    for b in (whitelist.CONFIG.get("mcp_backends") or []):
        if b.get("name") == name:
            return b
    return None


async def mcp_oauth_start(request: Request):
    """POST /tools/mcp/{name}/oauth/start → `{state, auth_url, redirect_uri}`.

    Chi può montare un server MCP può autorizzarlo: stesso `_authorized` di
    `/tools/mcp`, cioè territorio admin. Il risultato non contiene segreti —
    la URL di consenso è pubblica per costruzione, il PKCE verifier resta nel
    provider.
    """
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    b = _mcp_backend(request.path_params["name"])
    if b is None:
        return JSONResponse({"error": "backend non montato"}, status_code=404)
    try:
        return JSONResponse(await mcp_oauth.begin(b))
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    except Exception as e:  # noqa: BLE001 — un backend di terzi rotto è un 502, non un 500 nostro
        LOG.warning("mcp oauth start fallito per %s: %s", b.get("name"), type(e).__name__)
        return JSONResponse({"error": f"{type(e).__name__}: {str(e)[:200]}"}, status_code=502)


async def mcp_oauth_complete(request: Request):
    """POST /tools/mcp/{name}/oauth/complete {state, code} → consenso concluso.

    `code` accetta sia il parametro nudo sia la URL intera su cui il browser è
    atterrato: incollare la URL è ciò che si fa davvero (stessa scelta di
    `google_connect`). Il token finisce nella vault e NON torna nella risposta.
    """
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "bad_json"}, status_code=400)
    try:
        res = await mcp_oauth.finish(str(body.get("state") or ""),
                                     str(body.get("code") or ""))
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    except Exception as e:  # noqa: BLE001
        LOG.warning("mcp oauth complete fallito: %s", type(e).__name__)
        return JSONResponse({"error": f"{type(e).__name__}: {str(e)[:200]}"}, status_code=502)
    proxy.clear_cache()  # ora il backend espone tool: la lista cache-ata è vecchia
    return JSONResponse(res)


async def mcp_connect(request: Request):
    """POST /tools/mcp/{name}/connect {fields: {...}} → credenziale provata e salvata.

    clodia-platform#565. Stesso territorio admin di `oauth/start`. I valori
    vanno nella vault SOLO se il backend, provato con quei valori, risponde a
    `list_tools`; la risposta non li contiene mai.
    """
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    b = _mcp_backend(request.path_params["name"])
    if b is None:
        return JSONResponse({"error": "backend non montato"}, status_code=404)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "bad_json"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "bad_json"}, status_code=400)
    try:
        res = await mcp_credentials.connect(b, body.get("fields") or {})
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    proxy.clear_cache()
    return JSONResponse(res)


async def mcp_disconnect(request: Request):
    """POST /tools/mcp/{name}/disconnect → credenziale e token OAuth fuori dalla vault."""
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    b = _mcp_backend(request.path_params["name"])
    if b is None:
        return JSONResponse({"error": "backend non montato"}, status_code=404)
    res = mcp_credentials.disconnect(b)
    proxy.clear_cache()
    return JSONResponse(res)


def _account_from_email(email: str) -> str:
    return email.split("@")[0].replace(".", "_")


async def _google_component_route(request: Request, path: str):
    """`/tools/google/<path>` in `pack` position (#558): the same route of
    google-pack's gateway component (`/tools/google-pack/<path>`), with ITS
    authentication (a human admin or the trusted core), method check and
    audit — so the Tools page keeps calling the URL it knows. The component
    not serving is a 503 that says why, never the native handler."""
    from . import components_api
    from .tools import google_switch
    from . import components
    spec = components.route(google_switch.PACK, path)
    if spec is None:
        try:
            google_switch.service("accounts")      # raises with the reason
        except google_switch.ComponentUnavailable as e:
            return JSONResponse({"error": "component_unavailable", "detail": str(e)},
                                status_code=503)
        return JSONResponse({"error": "component_unavailable",
                             "detail": f"google-pack's component has no route '{path}'"},
                            status_code=503)
    return await components_api.serve(request, spec)


def _google_in_pack() -> bool:
    from .tools import google_switch
    return google_switch.in_pack()


async def google_auth(request: Request):
    """Avvia il consenso Google UNIFICATO (Gmail + Drive + Docs + Calendar)."""
    g = _connector_guard("google")
    if g is not None:
        return g
    if _google_in_pack():
        return await _google_component_route(request, "auth")
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
    if _google_in_pack():
        return await _google_component_route(request, "connect")
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
    if _google_in_pack():
        return await _google_component_route(request, "app")
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
    if _google_in_pack():
        return await _google_component_route(request, "app")
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


def _mail_component_unavailable(e: Exception) -> JSONResponse:
    return JSONResponse({"error": "component_unavailable", "detail": str(e)},
                        status_code=503)


async def email_mailboxes(request: Request):
    """GET → lista delle caselle generiche (mailbox_*) nel vault (solo nomi).

    On `mail: pack` (#558) the list is comms-pack's component's (service
    `mailboxes_list`); this URL, its authentication and its answer stay."""
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    from .tools import mail_switch
    if mail_switch.in_pack():
        try:
            return JSONResponse(await asyncio.to_thread(
                mail_switch.call, "mailboxes_list"))
        except mail_switch.ComponentUnavailable as e:
            return _mail_component_unavailable(e)
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
    from .tools import mail_switch
    if mail_switch.in_pack():
        # #558: what a mailbox is (shape, validation, the deposit under
        # `mailbox_<acct>`) is comms-pack's component's; the URL, the guard,
        # the authentication and the parsing stay here.
        if not isinstance(b, dict):
            b = {}
        try:
            out = await asyncio.to_thread(mail_switch.call, "mailbox_add", b)
        except mail_switch.ComponentUnavailable as e:
            return _mail_component_unavailable(e)
        return JSONResponse(out["body"], status_code=int(out["status"]))
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
    """DELETE → rimuove una casella generica dal vault E le sue autorizzazioni.

    Le due cose sono un'operazione sola (clodia-platform#411): la credenziale
    vive nel vault, ma il permesso di usarla vive nelle liste `inbox:`/`outbox:`
    — globale e per scope — e toglierne una sola lasciava voci che nominano una
    casella inesistente. L'indirizzo si legge PRIMA di svuotare il vault: dopo
    non c'è più nessun modo di sapere quali voci fossero sue.

    La risposta dice quante stanze sono cambiate: un connettore Mailbox (#406)
    si collega con un click su ogni canale, quindi una rimozione può toccarne
    parecchi, e l'owner deve vederlo qui invece di scoprirlo dal pannello.
    """
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    account = request.path_params["account"]
    from .tools import mail_switch
    if mail_switch.in_pack():
        # #558: the credential is removed by comms-pack's component, which
        # reads the address first; the whitelist entries are withdrawn HERE,
        # by the gateway that owns the lists.
        try:
            info = await asyncio.to_thread(mail_switch.call, "mailbox_remove", account)
        except mail_switch.ComponentUnavailable as e:
            return _mail_component_unavailable(e)
        indirizzo, removed = info.get("email"), bool(info.get("removed"))
    else:
        indirizzo = email_tool.mailbox_address(account)
        removed = vault.remove(f"mailbox_{account}")
    from . import egress as eg
    pulizia = eg.forget_mailbox(indirizzo or "")
    if pulizia["scopes"] or pulizia["global"]:
        LOG.info("email_mailbox_remove: '%s' (%s) · voci ritirate: %d globali, "
                 "stanze %s", account, indirizzo, len(pulizia["global"]),
                 ", ".join(pulizia["scopes"]) or "nessuna")
    return JSONResponse({"account": account, "removed": removed,
                         "email": indirizzo, "scopes": pulizia["scopes"],
                         "topics_cleaned": len(pulizia["scopes"]),
                         "global_revoked": pulizia["global"]})


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
    """Deposita il PAT GitHub nel vault. Body: {pat}. pat vuoto → disconnette.
    Il PAT non transita mai dal modello: il proxy lo risolve via ${VAULT:github_pat}.
    Reached through the generic connector route (`connectors_api._delegate`),
    no longer at a route of its own.

    The native connector is retired (clodia-platform#525): the
    backend is it-pack's own mount, so this handler deposits the PAT only —
    same entry, same `{"value": pat}` shape, which the pack's mount reads as
    `${VAULT:github_pat.value}` — and keeps the grant to clodia. It mounts
    nothing, and it never touches the pack's stamped mount: what it removes is
    the native connector's leftover unstamped `github` entry, which would
    otherwise keep the pack's connector refused for a namespace clash."""
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "bad_json"}, status_code=400)
    # `value` is the field the connector manifest declares (#525): the form a
    # generic UI renders posts it under that name.
    pat = (body.get("pat") or body.get("token") or body.get("value") or "").strip()
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
    # The backend is it-pack's own mount (the native connector is retired,
    # #525): only the native leftover — an unstamped `github` entry — goes,
    # which would otherwise keep the pack's connector refused for a clash.
    backends = [b for b in (whitelist.CONFIG.get("mcp_backends") or [])
                if not (b.get("name") == "github" and not b.get("pack"))]
    if not pat:
        vault.remove("github_pat")
        whitelist.CONFIG["mcp_backends"] = backends
        whitelist.save_config(); whitelist.reload_config(); proxy.clear_cache()
        LOG.info("github_connect: disconnesso (credenziale rimossa)")
        return JSONResponse({"connected": False})
    vault.deposit("github_pat", {"value": pat}, cred_type="mcp_secret", grant_agents=[])
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
    LOG.info("github_connect: PAT depositato (backend: quello del pack, len=%d)",
             len(pat))
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
            s = smtplib.SMTP_SSL(b.get("smtp_server"), porta, timeout=15,
                                 context=ssl.create_default_context())
        else:
            s = smtplib.SMTP(b.get("smtp_server"), porta, timeout=15)
            s.starttls(context=ssl.create_default_context())
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
            imap = imaplib.IMAP4_SSL(server, int(b.get("imap_port") or 993), timeout=15,
                                    ssl_context=ssl.create_default_context())
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
# id della card → (prefisso della credenziale nel vault, consenso che la card
# PROMETTE). `google` prova SOLO le credenziali unificate, cioè gli account che
# la card elenca (list_tools li prende da `credential_diagnostics` con
# kind=google): provare anche i legacy renderebbe rossa una card per un account
# che non mostra.
#
# Lo scope atteso sta in questa tabella e non accanto al suo uso perché è una
# proprietà della card, non del connettore nuovo: ogni card va misurata su ciò
# che ha promesso. Misurare `gworkspace` su UNIFIED_SCOPE l'accuserebbe di non
# avere Gmail, che non elenca; lasciarla senza scope atteso — com'era — non la
# misura affatto, e un consenso Workspace senza Drive passa per completo. Una
# tabella sola e non due mappe sulle stesse chiavi: quelle divergono, e a
# divergere sarebbe di nuovo lo scope atteso.
_GOOGLE_CARD = {
    "google": ("google_", go.UNIFIED_SCOPE),
    "gworkspace": ("gworkspace_", go.WORKSPACE_SCOPE),
    "gmail": ("gmail_", go.SCOPE),
}


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
    #
    # Il confronto si fa solo se Google DICE quali scope ha concesso: RFC 6749
    # §5.1 rende `scope` opzionale nella risposta proprio quando coincide con
    # quello richiesto, cioè l'assenza è il caso normale e non «nessuno scope».
    # Dedurne il contrario nominerebbe tutti e cinque i servizi come fuori dal
    # consenso su un collegamento sano — e il rimedio che quella riga suggerisce
    # (riconnetti) fa un consenso nuovo che scalza il refresh token buono: la
    # prova provocherebbe il guasto che esiste per scoprire.
    concessi = (tok.get("scope") or "").split()
    mancanti = [s for s in atteso.split() if s not in concessi] if concessi else []
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
    prefisso, atteso = _GOOGLE_CARD[cid]
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

        if cid == "google":
            from .tools import google_switch
            if google_switch.in_pack():
                # #558: the unified card is google-pack's component's.
                return google_switch.component_test_connection()
        if cid in _GOOGLE_CARD:
            return _test_google(cid)

        if cid == "mailboxes":
            from .tools import mail_switch
            if mail_switch.in_pack():
                # #558: the mailboxes card is comms-pack's component's.
                return mail_switch.component_test_mailboxes()
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
    r = _test_connector(cid)
    if r["ok"] is None and cid in {b.get("name") for b in (whitelist.CONFIG.get("mcp_backends") or [])}:
        # non è uno dei provider nativi sopra: prova come backend MCP montato
        r = await proxy.test_backend(cid)
    return JSONResponse(r)


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
    Route("/tools/telegram/status", telegram_status, methods=["GET"]),
    Route("/tools/telegram/connect", telegram_connect, methods=["POST"]),
    Route("/tools/backup/config", backup_configure, methods=["POST"]),
    Route("/tools/backup/status", backup_status, methods=["GET"]),
    Route("/tools/backup/snapshots", backup_snapshots, methods=["GET"]),
    Route("/tools/backup/run", backup_run, methods=["POST"]),
    Route("/tools/backup/restore-test", backup_restore_test, methods=["POST"]),
    Route("/tools/mcp", register_mcp, methods=["POST"]),
    Route("/tools/mcp/{name}", unregister_mcp, methods=["DELETE"]),
    Route("/tools/mcp/{name}/oauth/start", mcp_oauth_start, methods=["POST"]),
    Route("/tools/mcp/{name}/oauth/complete", mcp_oauth_complete, methods=["POST"]),
    Route("/tools/mcp/{name}/connect", mcp_connect, methods=["POST"]),
    Route("/tools/mcp/{name}/disconnect", mcp_disconnect, methods=["POST"]),
]
