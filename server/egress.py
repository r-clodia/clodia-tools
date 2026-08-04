"""Destination whitelist for outbound verbs (clodia-platform#104 §7, step 5).

Why. Today "can send email" means "to anyone", so exfiltration is one line of
prompt away. A whitelist turns egress from a **binary capability** into a
**circumscribed** one: sending to a known destination stops being a risk, and a
gate is needed only for the destination that is new — which is rare. That is the
ceiling of the defence model, and the reason the per-agent verb reduction was
measured to be nearly worthless on its own.

Where the rules live, and why it matters. In the GATEWAY's own config
(`clodia-tools-config.yaml`, on the gateway-only volume), next to
`allowed_tools`. NOT in `agent.yaml`: that file sits on the datadir shared with
the agent-server, where agent code runs — whoever can rewrite it self-grants
destinations and the reference monitor falls from the inside (clodia-platform#80,
same argument as the whitelist itself).

    agents:
      messaggero:
        allowed_tools: [email.*, telegram.*]
        egress_allow:
          email:    ["@tomato.blue", "d.carboni@gmail.com"]
          telegram: ["76632169"]

Three properties from §7 that this module implements literally:

1. **Default empty = no egress.** A type with no entry denies. This is why the
   default mode is `report`: switching a live instance straight to `on` would
   mute every agent at once. The mode is what makes the rollout survivable, not
   a softening of the rule.
2. **An unmodelled destination type is denied, not free** (§7 property 6). A new
   connector type has no rules, and "no rules → pass" would mean the whitelist
   is bypassed by the mere arrival of a pack.
3. **An unknown destination is denied too.** `email.reply` is the case that
   forces this: its recipient is not in the arguments, it comes from the message
   being replied to — that is, from untrusted content. "Attacker mails in, agent
   replies with the data" is the injection path, so a destination that cannot be
   read from the call must not pass by default.

Modes, via `CLODIA_EGRESS_ENFORCE`:

    off      no check at all (escape hatch)
    report   decide and LOG, allow anyway. Useful to harvest destinations
             without involving the human at all.
    gate     a destination outside the whitelist asks the HUMAN — default.
             Approving both lets the call through and REMEMBERS the destination,
             so the whitelist fills up through use instead of being written up
             front. This is the decision of 3 Aug 2026: start empty, populate by
             using it, and never let an agent reach an unvetted address silently.
    on       hard deny, no question asked. The right mode where nobody can
             answer — an unattended job that hits a gate stalls until the
             request times out, and #116 is the lesson about unattended paths
             attempting gated actions.

The gate is the whole point of the `gate` mode: sending to an unknown address is
neither refused nor allowed, it is ASKED. `check()` returns the action and the
caller performs it, so the async gate machinery stays out of this module.
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any, Callable, Optional
from urllib.parse import urlsplit

LOG = logging.getLogger("clodia-tools.egress")

#: Sentinel: the call carries no readable destination (see property 3).
UNKNOWN = "?"


def mode() -> str:
    m = (os.environ.get("CLODIA_EGRESS_ENFORCE") or "gate").strip().lower()
    # An unknown value falls back to `gate`, never to `off`: a typo in the env
    # var must not silently disable the whitelist.
    return m if m in ("off", "report", "gate", "on") else "gate"


# ── destination extractors ───────────────────────────────────────────────────
# One per outbound verb. Each returns the list of destinations the call would
# reach. An empty list means "no destination readable from the arguments", which
# is NOT the same as "no destination": it becomes UNKNOWN and is denied.

def _emails(a: dict) -> list[str]:
    out = []
    for field in ("to", "cc", "bcc"):
        raw = a.get(field) or ""
        # Un solo campo può portare più indirizzi.
        out += [f"mailto:{x.strip().lower()}"
                for x in str(raw).replace(";", ",").split(",") if x.strip()]
    return out


def address_of(header: str) -> str:
    """Estrae l'indirizzo da un header From: `Nome <a@b.it>` → `a@b.it`.

    Serve a `email.reply`, il cui destinatario non sta negli argomenti: viene dal
    messaggio a cui si risponde. Funzione pura e separata dalla chiamata IMAP,
    così il parsing è testabile senza rete.
    """
    h = (header or "").strip()
    if "<" in h and ">" in h:
        h = h[h.index("<") + 1:h.index(">")]
    h = h.strip().strip('"').strip("'").lower()
    return h if "@" in h else ""


def _chat(a: dict) -> list[str]:
    c = str(a.get("chat_id") or "").strip()
    return [f"tg:{c}"] if c else []


def _http(a: dict) -> list[str]:
    """URL di destinazione ridotto a schema://host/ — su TLS il path non è
    comunque visibile a un proxy, e una whitelist che promette granularità che
    non ha è peggio di una che dichiara la propria."""
    url = str(a.get("url") or "").strip()
    if not url:
        return []
    u = urlsplit(url)
    h = (u.hostname or "").lower()
    return [f"{u.scheme or 'https'}://{h}/"] if h else []


def _repo(a: dict) -> list[str]:
    owner, repo = str(a.get("owner") or "").strip(), str(a.get("repo") or "").strip()
    return [f"https://github.com/{owner}/{repo}".lower()] if owner and repo else []


def _drive_target(a: dict) -> list[str]:
    """Dove finisce il contenuto, o con CHI viene condiviso.

    `gdrive.share` è uscita verso una PERSONA, non verso una cartella: la
    destinazione è l'indirizzo, ed è per questo che i due non si fondono. Con la
    notazione URI la differenza si vede — `mailto:` contro `gdrive:folder/`.
    """
    out = []
    for field in ("email", "folder_id", "parent_id"):
        v = str(a.get(field) or "").strip()
        if not v:
            continue
        out.append(f"mailto:{v.lower()}" if field == "email"
                   else f"gdrive:folder/{v}")
    return out


def _spreadsheet(a: dict) -> list[str]:
    v = str(a.get("spreadsheet_id") or "").strip()
    return [f"gsheets:{v}"] if v else []


#: verb → (destination type, extractor). A verb absent from this table is not
#: checked here. That is deliberate and limited: the table is the gateway's
#: explicit list of what it knows how to constrain, and #119's fail-closed rule
#: covers the scoring side. Widening it is one line per verb.
_SPECS: dict[str, tuple[str, Callable[[dict], list[str]]]] = {
    "email.send": ("email", _emails),
    # No `to` in the arguments: the recipient comes from the message being
    # replied to, i.e. from untrusted content. Extractor returns nothing on
    # purpose → UNKNOWN → denied unless the type explicitly allows "*".
    "email.reply": ("email", _emails),
    "telegram.send": ("telegram", _chat),
    "telegram.send_file": ("telegram", _chat),
    "web.post": ("http", _http),
    "gdrive.upload": ("drive", _drive_target),
    "gdrive.share": ("drive", _drive_target),
    "gdrive.mkdir": ("drive", _drive_target),
    "gdrive.move": ("drive", _drive_target),
    "gsheets.add_tab": ("gsheets", _spreadsheet),
    "gsheets.append_rows": ("gsheets", _spreadsheet),
    "gsheets.write_range": ("gsheets", _spreadsheet),
}

#: GitHub write verbs are proxied MCP tools, so they are matched by name rather
#: than declared one by one — the upstream list changes without us.
_GITHUB_WRITE = (
    "create_", "update_", "delete_", "push_", "fork_", "merge_", "add_",
    "issue_write", "pull_request_review_write", "sub_issue_write",
    "request_copilot_review",
)


def spec_for(verb: str) -> Optional[tuple[str, Callable[[dict], list[str]]]]:
    if verb in _SPECS:
        return _SPECS[verb]
    if verb.startswith("github."):
        tail = verb.split(".", 1)[1]
        if any(tail.startswith(p) or tail == p for p in _GITHUB_WRITE):
            return ("github", _repo)
    return None


# ── rule matching ────────────────────────────────────────────────────────────

#: Forme che un umano scrive naturalmente, ricondotte alla forma canonica. Un
#: URL di cartella Drive è ciò che si copia dalla barra del browser: se la
#: whitelist non lo accettasse, la notazione URI sarebbe un trabocchetto invece
#: di un aiuto — si incolla, non combacia, e nessuno capisce perché.
#: `gdrive://<id>` e `gdrive:folder/<id>` sono **la stessa risorsa in due
#: codifiche**, come l'URL del browser: accettarne una sola trasformerebbe una
#: questione di stile in un errore di configurazione silenzioso.
_CANON = (
    # forma con authority: gdrive://<id> e gdrive://folder/<id>
    (re.compile(r"^gdrive://(?:folder/)?([\w-]+)/?$"),
     lambda m: f"gdrive:folder/{m.group(1)}"),
    (re.compile(r"^gsheets://([\w-]+)/?$"), lambda m: f"gsheets:{m.group(1)}"),
    (re.compile(r"^https?://drive\.google\.com/drive/(?:u/\d+/)?folders/([\w-]+)"),
     lambda m: f"gdrive:folder/{m.group(1)}"),
    (re.compile(r"^https?://docs\.google\.com/spreadsheets/d/([\w-]+)"),
     lambda m: f"gsheets:{m.group(1)}"),
    (re.compile(r"^https?://docs\.google\.com/document/d/([\w-]+)"),
     lambda m: f"gdrive:doc/{m.group(1)}"),
    (re.compile(r"^https?://drive\.google\.com/file/d/([\w-]+)"),
     lambda m: f"gdrive:file/{m.group(1)}"),
)


def canonical(uri: str) -> str:
    """Forma canonica di un URI di destinazione.

    Riconduce gli URL che si copiano dal browser allo schema che il PDP confronta.
    Idempotente: applicarla a una forma già canonica non la cambia.
    """
    u = (uri or "").strip()
    if not u:
        return ""
    for rx, to in _CANON:
        m = rx.match(u)
        if m:
            return to(m)
    if u.lower().startswith(("http://", "https://")):
        # host in minuscolo, il resto no: un path può essere case-sensitive.
        sp = urlsplit(u)
        host = (sp.hostname or "").lower()
        port = f":{sp.port}" if sp.port else ""
        return f"{sp.scheme.lower()}://{host}{port}{sp.path or '/'}"
    scheme, sep, rest = u.partition(":")
    return f"{scheme.lower()}{sep}{rest}" if sep else u


def _matches(dest: str, rule: str) -> bool:
    """Una destinazione (URI) contro una regola (URI).

    Tre forme, e nessuna regex: una regola che l'operatore non legge è una regola
    che nessuno verifica.

        *                              qualunque destinazione (opt-out esplicito)
        mailto:*@tomato.blue           wildcard nella parte locale di uno schema
        https://github.com/r-clodia/   prefisso, per gli schemi gerarchici
        mailto:tizio@x.it              esatto

    Il PREFISSO vale solo per gli schemi in cui la gerarchia esiste (`http`,
    `https`, `gdrive`): `mailto:a@b.it` non è prefisso di `mailto:a@b.it.evil`
    perché un indirizzo non è un percorso, ed è esattamente il caso in cui un
    prefisso ingenuo aprirebbe un dominio ostile.
    """
    r = canonical(rule).lower()
    d = canonical(dest).lower()
    if not r or not d:
        return False
    if r == "*":
        return True
    # Anche qui, non solo in `allowed_uris`: una regola degenere che arrivasse da
    # un altro chiamante aprirebbe l'intero tipo in silenzio, e la difesa non deve
    # dipendere da quale porta si è usata per entrare.
    if _is_degenerate(r):
        return False
    if r == d:
        return True
    if "*" in r:
        # wildcard solo dentro lo stesso schema, e solo come suffisso
        r_s, _, r_rest = r.partition(":")
        d_s, _, d_rest = d.partition(":")
        if r_s != d_s:
            return False
        return r_rest.startswith("*") and d_rest.endswith(r_rest[1:])
    if r.split(":", 1)[0] in _HIERARCHICAL and d.startswith(r):
        return True
    return False


#: Schemi in cui il prefisso ha senso (c'è un percorso). Per gli altri il match
#: è esatto o wildcard: aprire per prefisso un indirizzo email o una chat id
#: aprirebbe destinazioni che nessuno ha approvato.
#: `mcp` è gerarchico sul namespace: `mcp:normattiva.` copre
#: `normattiva.search` e `normattiva.get` senza elencarli, e senza
#: coprire `normattiva-mirror.`.
_HIERARCHICAL = ("http", "https", "gdrive", "mcp")

#: Schemi ammessi in USCITA e in INGRESSO. Le due liste sono separate perché
#: l'errore ha direzioni diverse: sbagliare una destinazione è rumoroso (un invio
#: bloccato), sbagliare una fonte è SILENZIOSO — un taint che non si accende, e
#: tutti i gate a valle che non scattano. Un `mailfrom:` nella lista di uscita è
#: un errore di configurazione e va rifiutato, non ignorato.
EGRESS_SCHEMES = ("mailto", "tg", "http", "https", "gdrive", "gsheets")
#: `gdrive` fra le fonti: una cartella Drive vagliata è una fonte fidata, ed è il
#: caso che rende operativa questa lista — un topic collegato a una cartella di cui
#: l'owner risponde non deve contaminare a ogni lettura.
#: `mcp:<namespace>.` — un server MCP la cui RISPOSTA è scritta da un'unica
#: istituzione, non da un terzo qualsiasi: `mcp:normattiva.` restituisce il
#: testo di legge, e chi interroga sceglie QUALE norma, non cosa c'è scritto.
#: Il criterio è questo, e non è «viene da un pack»: un pack vaglia il
#: SERVER, non i byte che il server ripete — `web.fetch` sta in un pack e
#: ripete il web aperto. L'appartenenza a un contenitore non è una proprietà
#: del contenuto, e attribuirla spegnerebbe il taint sulla fonte più larga
#: che esista, nella direzione d'errore che non si vede.
SOURCE_SCHEMES = ("mailfrom", "http", "https", "gdrive", "gsheets", "mcp")


def is_vetted_source(uri: str) -> bool:
    """True se `uri` è fra le fonti fidate dichiarate.

    Lista vuota per default → tutto contamina, che è la direzione giusta: una
    fonte non dichiarata non è una fonte fidata, e sbagliare qui è SILENZIOSO
    (un taint che non si accende non lo si vede).
    """
    if not uri:
        return False
    return any(_matches(uri, r) for r in source_uris())


def allowed_uris(cfg: dict | None = None) -> list[str]:
    """Whitelist GLOBALE delle destinazioni.

    Globale e non per-agente (clodia-platform#128): l'approvazione giudica la
    DESTINAZIONE, non chi spedisce — è ciò che il dialog chiede. E per-agente la
    lista non converge mai: con quattordici agenti lo stesso indirizzo viene
    chiesto quattordici volte, mentre la rarità del gate è ciò che lo rende
    leggibile invece che riflesso.

    Migra al volo le vecchie voci per-agente, così un'istanza aggiornata non
    perde le destinazioni che un umano aveva già approvato.
    """
    from . import whitelist as _wl
    c = cfg if cfg is not None else _wl.CONFIG
    out: list[str] = [str(x).strip() for x in (c.get("egress_allow") or []) if str(x).strip()]
    for name, spec in (c.get("agents") or {}).items():
        legacy = (spec or {}).get("egress_allow")
        if not isinstance(legacy, dict):
            continue
        for dtype, rules in legacy.items():
            for r in rules or []:
                u = _legacy_to_uri(dtype, str(r))
                if u and u not in out:
                    out.append(u)
                    LOG.info("egress: migrata voce legacy %s/%s → %s (era di '%s')",
                             dtype, r, u, name)
    out = [canonical(u) for u in out]
    bad = [u for u in out if u != "*" and u.partition(":")[0] not in EGRESS_SCHEMES]
    for u in bad:
        LOG.warning("egress: voce con schema non ammesso in uscita, IGNORATA: %s", u)
    # Voce DEGENERE: un prefisso senza nulla dopo apre l'intero tipo — `gdrive:folder/`
    # consentirebbe qualunque cartella. Chi vuole quello scrive `*`, che si vede;
    # una barra finale dimenticata no.
    degenerate = [u for u in out if u not in bad and _is_degenerate(u)]
    for u in degenerate:
        LOG.warning("egress: voce che aprirebbe l'intero tipo, IGNORATA: %s "
                    "(per aprire tutto scrivi '*', così si vede)", u)
    drop = set(bad) | set(degenerate)
    return [u for u in out if u not in drop]


def _is_degenerate(uri: str) -> bool:
    """True se la regola non vincola nulla dentro il proprio schema."""
    scheme, sep, rest = uri.partition(":")
    if not sep:
        return False
    rest = rest.strip()
    if scheme in ("http", "https"):
        # `https://` senza host non vincola; `https://host/` sì.
        return not (urlsplit(uri).hostname or "")
    if scheme == "mcp":
        # `mcp:` nudo dichiarerebbe fidato ogni server montato, presente e futuro:
        # è la regola che una lista opt-in non deve poter esprimere per sbaglio.
        return rest in ("", ".")
    # `gdrive:folder/`, `mailto:`, `tg:` → niente dopo il separatore
    return rest in ("", "/") or rest.rstrip("/").endswith(":") or rest in ("folder/", "doc/")


def source_uris(cfg: dict | None = None) -> list[str]:
    """Whitelist GLOBALE delle fonti fidate (leggere da qui non contamina).

    Lista separata da quella di uscita, di proposito: vedi `SOURCE_SCHEMES`.
    Vuota per default — e va tenuta piccola e statica, perché è configurazione
    dell'istanza e non qualcosa da approvare in un dialog: la prima injection che
    chiedesse «aggiungi questo dominio alle fonti fidate» spegnerebbe il taint per
    sempre.
    """
    from . import whitelist as _wl
    c = cfg if cfg is not None else _wl.CONFIG
    out = [str(x).strip() for x in (c.get("source_allow") or []) if str(x).strip()]
    bad = [u for u in out if u.partition(":")[0] not in SOURCE_SCHEMES]
    for u in bad:
        LOG.warning("source: voce con schema non ammesso in ingresso, IGNORATA: %s", u)
    return [u for u in out if u not in bad]


def _legacy_to_uri(dtype: str, rule: str) -> str:
    """Converte una vecchia voce (tipo + valore nudo) in URI."""
    r = rule.strip()
    if not r:
        return ""
    if r == "*":
        return ""            # un `*` per-tipo non si promuove a `*` globale
    if dtype == "email":
        return f"mailto:{'*' + r if r.startswith('@') else r}".lower()
    if dtype == "telegram":
        return f"tg:{r}"
    if dtype == "github":
        return f"https://github.com/{r}".lower()
    if dtype == "http":
        return f"https://{r}/".lower()
    if dtype == "drive":
        return f"mailto:{r}" if "@" in r else f"gdrive:folder/{r}"
    if dtype == "gsheets":
        return f"gsheets:{r}"
    return ""


def decide(agent_cfg: dict, verb: str, arguments: dict) -> dict:
    """Decide se `verb` può raggiungere le destinazioni in `arguments`.

    `agent_cfg` resta nella firma per compatibilità con i chiamanti, ma la
    whitelist è GLOBALE (#128): la destinazione è approvata o non lo è, e non
    dipende da chi spedisce.
    """
    spec = spec_for(verb)
    if not spec:
        return {"checked": False, "allowed": True, "verb": verb}
    dtype, extract = spec
    try:
        dests = [d for d in extract(arguments or {}) if d]
    except Exception as e:  # noqa: BLE001 — una chiamata malformata non è una decisione
        LOG.warning("egress: destinatari non estraibili da %s (%s)", verb, e)
        dests = []
    rules = allowed_uris()

    if not dests:
        # Destinazione non leggibile dalla chiamata → nego, a meno che la lista
        # non sia stata aperta con `*` esplicito.
        wide = "*" in rules
        return {"checked": True, "allowed": wide, "verb": verb, "type": dtype,
                "destinations": [UNKNOWN], "rules": rules,
                "reason": ("destinazione non leggibile dalla chiamata"
                           if not wide else "uscita aperta con '*'")}

    refused = [d for d in dests if not any(_matches(d, r) for r in rules)]
    if refused:
        return {"checked": True, "allowed": False, "verb": verb, "type": dtype,
                "destinations": dests, "refused": refused, "rules": rules,
                "reason": (f"destinazione non in whitelist: {', '.join(refused)}"
                           if rules else
                           f"nessuna destinazione dichiarata: {', '.join(refused)}")}
    return {"checked": True, "allowed": True, "verb": verb, "type": dtype,
            "destinations": dests, "rules": rules}


def gate_key(dtype: str, dest: str) -> str:
    """Chiave del gate per una destinazione nuova.

    Per DESTINAZIONE, non per verbo: approvare «scrivi a mario@x.it» è una
    decisione diversa da «puoi mandare mail», ed è quella che l'umano è in grado
    di prendere guardando il dialog.
    """
    return f"egress:{dtype}:{dest}"


#: Avvertenze per CLASSE di destinazione. Nessuna chiamata di rete e nessun
#: lookup: sapere se un repo è pubblico richiederebbe l'API GitHub, che può
#: sbagliare, essere stale, e soprattutto sposterebbe la decisione dal giudizio
#: dell'owner a un'interrogazione. Se lo aggiunge lui è chiaro — il compito del
#: dialog è dirgli **cosa** sta concedendo, non decidere al suo posto.
_DANGER = {
    "github": ("un repository su github.com. Se è pubblico, tutto ciò che viene "
               "spinto lì è visibile a chiunque e resta nella storia del repo "
               "anche se cancellato dopo."),
    "http": ("un sistema di terzi raggiunto via HTTP. Non sai come tratta ciò "
             "che riceve, né per quanto lo conserva."),
    "mailto": ("un indirizzo email. Una volta inviato, il messaggio non è più "
               "richiamabile e la copia resta sul server del destinatario."),
    "tg": ("una chat su Telegram, cioè su un'infrastruttura non tua."),
    "gsheets": ("un foglio Google. Se è condiviso, lo vede chi ha il link."),
}


def danger_note(uri: str) -> str:
    """Avvertenza sulla classe di destinazione, o stringa vuota.

    Serve nel dialog di approvazione: approvare una destinazione la rende
    silenziosa da lì in avanti, quindi è il momento in cui l'informazione deve
    essere completa. Non blocca niente.
    """
    u = (uri or "").strip().lower()
    if not u or u == "*":
        return ("QUALUNQUE destinazione di questo tipo, senza ulteriori domande." if u == "*"
                else "")
    scheme = u.partition(":")[0]
    if scheme in ("http", "https"):
        host = urlsplit(u).hostname or ""
        return _DANGER["github"] if host.endswith("github.com") else _DANGER["http"]
    return _DANGER.get(scheme, "")


def gate_reason(agent: str, verb: str, dtype: str, dests: list[str]) -> str:
    """Testo del dialog. Dice ANCHE che approvando la destinazione resta.

    §7 proprietà 2: aggiungere una destinazione è più privilegiato della singola
    invocazione, perché la rende silenziosa per sempre. Se l'approvazione
    popola la whitelist — ed è la decisione presa — l'umano deve saperlo dal
    dialog, altrimenti concede un permesso permanente credendo di autorizzare un
    invio.
    """
    where = ", ".join(dests)
    notes = [n for n in {danger_note(d) for d in dests} if n]
    warn = ("\n⚠️ " + " ".join(sorted(notes))) if notes else ""
    return (f"@{agent} vuole usare {verb} verso {where}, che non è fra le "
            f"destinazioni consentite. Approvando, l'invio procede E {where} "
            f"viene aggiunto alle destinazioni ammesse — per TUTTI gli agenti, "
            f"non solo per {agent}: è la destinazione che stai giudicando, non "
            f"chi spedisce. I prossimi invii verso di lì non chiederanno più."
            f"{warn}")


def check(agent: str, agent_cfg: dict, verb: str, arguments: dict,
          unattended: bool = False) -> dict:
    """Verdetto + AZIONE da compiere, secondo il modo. Non solleva mai.

    L'azione è una stringa perché il chiamante deve poter fare `await` sul gate:
    tenere la macchina del consenso fuori da questo modulo lo lascia testabile
    senza event loop.

        allow   procedi
        deny    rifiuta (PermissionError, lo solleva il chiamante)
        gate    chiedi all'umano; se approva → `remember` e procedi
    """
    declared = mode()
    m = declared
    # La modalità di osservazione globale implica `report` qui: il rifiuto va
    # registrato come «sarebbe scattato», non come rifiuto. Senza questo il
    # verdetto direbbe `deny` e il chiamante lo tradurrebbe in un `would_deny` —
    # coerente nel risultato, ma con due punti che decidono la stessa cosa.
    from . import observe as _obs
    if _obs.skipping() and m in ("gate", "on"):
        m = "report"
    if m == "off":
        return {"checked": False, "action": "allow", "verb": verb, "mode": m}
    if unattended and m == "gate":
        # Nessun umano davanti al turno: un gate resterebbe appeso fino al
        # timeout. `on` è il modo giusto dove nessuno può rispondere — era già
        # scritto nella docstring del modulo, qui viene applicato.
        m = "on"
    v = decide(agent_cfg, verb, arguments)
    # Il modo DICHIARATO resta leggibile accanto a quello applicato: nel log,
    # «configurato on» e «gate degradato perché non presidiato» sono due
    # situazioni diverse e vanno distinte da chi legge.
    v["mode"] = declared
    v["applied_mode"] = m
    v["unattended"] = bool(unattended)
    if not v.get("checked"):
        v["action"] = "allow"
        return v
    if v["allowed"]:
        LOG.info("egress ok · %s · %s → %s", agent, verb,
                 ", ".join(v.get("destinations") or []))
        v["action"] = "allow"
        return v
    dests = [d for d in (v.get("refused") or v.get("destinations") or []) if d]
    if m == "report":
        # WARNING di proposito, non error: è la riga che si grepperebbe per
        # costruire la whitelist, e non deve sembrare un fallimento — non è
        # stato bloccato niente.
        LOG.warning("egress WOULD-DENY · %s · %s → %s · %s (mode=report, "
                    "chiamata consentita)", agent, verb, ", ".join(dests),
                    v.get("reason"))
        v["action"] = "allow"
        v["would_deny"] = True
        return v
    if m == "gate":
        # Una destinazione non vagliata non si rifiuta e non si consente: si
        # CHIEDE. È la decisione del 3 ago 2026 — whitelist vuota all'inizio,
        # popolata dall'uso.
        if UNKNOWN in dests:
            # Niente da approvare e niente da ricordare: il dialog dovrebbe dire
            # «verso una destinazione che non sappiamo qual è». Si nega, e resta
            # la via esplicita del `*` sul tipo.
            LOG.warning("egress DENY · %s · %s · destinazione non leggibile "
                        "dalla chiamata (nessun gate possibile)", agent, verb)
            v["action"] = "deny"
            return v
        v["action"] = "gate"
        v["gate_key"] = gate_key(v["type"], dests[0])
        v["gate_reason"] = gate_reason(agent, verb, v["type"], dests)
        v["remember"] = dests
        LOG.info("egress GATE · %s · %s → %s (%s)", agent, verb,
                 ", ".join(dests), v.get("reason"))
        return v
    LOG.warning("egress DENY · %s · %s → %s · %s", agent, verb,
                ", ".join(dests), v.get("reason"))
    v["action"] = "deny"
    return v


def denied_error(agent: str, v: dict) -> PermissionError:
    return PermissionError(
        f"uscita non consentita per l'agent '{agent}': {v.get('reason')}. "
        f"Le destinazioni ammesse si dichiarano in egress_allow.{v.get('type')} "
        f"nella config del gateway (modifica gated, come i grant).")


def remember(agent: str, dtype: str, dests: list[str]) -> list[str]:
    """Aggiunge le destinazioni approvate alla whitelist GLOBALE e persiste.

    Scrive nella config del gateway, sul suo volume: l'agent-server non la monta,
    quindi un agente non può aggiungersi destinazioni da sé
    (clodia-platform#80). `agent` resta solo per il log — chi ha chiesto è
    un'informazione di audit, non un criterio: la destinazione vale per tutti.

    Idempotente. Ritorna la lista risultante.
    """
    from . import whitelist as _wl
    added = [d for d in dests if d and d != UNKNOWN]
    if not added:
        return []
    cur = list(_wl.CONFIG.get("egress_allow") or [])
    for d in added:
        if d not in cur:
            cur.append(d)
    _wl.CONFIG["egress_allow"] = cur
    _wl.save_config()
    LOG.warning("egress whitelist · += %s (approvato da un umano, richiesto da %s)",
                ", ".join(added), agent or "?")
    return cur


# ── verbi di amministrazione delle liste (gated) ─────────────────────────────

_DIRECTIONS = {
    "egress": ("egress_allow", EGRESS_SCHEMES, "destinazione ammessa"),
    "ingress": ("source_allow", SOURCE_SCHEMES, "fonte fidata"),
}


def admin_note(direction: str, uri: str) -> str:
    """Cosa COSTA aggiungere questa voce. Va nel dialog del gate.

    Per l'uscita è l'avvertenza sulla classe di destinazione. Per l'ingresso è
    un'altra cosa e più grave: aggiungere una fonte fidata **spegne il taint** per
    tutto ciò che arriverà da lì, per sempre. Sbagliare una destinazione è
    rumoroso — un invio bloccato, lo vedi. Sbagliare una fonte è silenzioso: un
    taint che non si accende non produce nessun segnale, e tutti i gate a valle
    smettono di scattare senza che nulla lo dica.

    È l'unico punto del modello in cui un'injection che chiedesse «aggiungi questa
    fonte» otterrebbe un guadagno durevole. Il dialog non può impedirlo; può
    dirlo.
    """
    if direction == "ingress":
        return ("Da qui in avanti leggere da questa fonte NON contaminerà più il "
                "canale, e la prima uscita successiva non chiederà conferma. Se "
                "quella fonte contiene istruzioni nascoste, non lo saprai. "
                "Approva solo fonti di cui rispondi tu.")
    return danger_note(uri)


def check_grantable(direction: str, uri: str) -> str:
    """Solleva `ValueError` se `uri` non è concedibile in quella direzione.

    Estratta da `allow()` perché serve **senza concedere**: l'installazione di un
    pack deve poter mostrare all'owner cosa sarebbe concesso, e una convalida che
    per sapere la risposta deve prima scrivere non è una convalida.
    """
    _key, schemes, label = _direction(direction)
    u = canonical(uri)
    if not u:
        raise ValueError("uri richiesto")
    if u == "*":
        raise ValueError(
            "'*' aprirebbe qualunque destinazione: non si concede con un verbo, "
            "né dal manifest di un pack. Se serve davvero, va scritto nella "
            "config del gateway, dove si vede rileggendola.")
    scheme = u.partition(":")[0]
    if scheme not in schemes:
        raise ValueError(
            f"schema '{scheme}' non ammesso come {label}: ammessi {', '.join(schemes)}")
    if _is_degenerate(u):
        raise ValueError(
            f"'{u}' non vincola nulla dentro il suo schema: aprirebbe l'intero "
            f"tipo. Indica la risorsa completa.")
    return u


def allow(direction: str, uri: str) -> dict:
    """Aggiunge `uri` alla lista della direzione indicata. Idempotente.

    Rifiuta gli schemi della direzione sbagliata e le voci degeneri: `mailfrom:`
    in uscita è un errore di configurazione, `gdrive:folder/` aprirebbe l'intero
    Drive. Rifiutare qui e non solo al caricamento significa che l'errore si vede
    subito, invece di sparire in un warning che nessuno legge.
    """
    key, _schemes, _label = _direction(direction)
    u = check_grantable(direction, uri)
    from . import whitelist as _wl
    cur = list(_wl.CONFIG.get(key) or [])
    added = u not in cur
    if added:
        cur.append(u)
        _wl.CONFIG[key] = cur
        _wl.save_config()
    LOG.warning("%s · %s %s (approvato da un umano)", key,
                "+=" if added else "già presente:", u)
    return {"direction": direction, "uri": u, "added": added, "total": len(cur)}


def revoke(direction: str, uri: str) -> dict:
    """Rimuove `uri`. NON gated: togliere autorità non richiede un consenso —
    chiederlo insegnerebbe che anche restringere è un'operazione da negoziare."""
    key, _, _ = _direction(direction)
    u = canonical(uri)
    from . import whitelist as _wl
    cur = list(_wl.CONFIG.get(key) or [])
    if u not in cur:
        return {"direction": direction, "uri": u, "removed": False, "total": len(cur)}
    cur = [x for x in cur if x != u]
    _wl.CONFIG[key] = cur
    _wl.save_config()
    LOG.warning("%s · -= %s", key, u)
    return {"direction": direction, "uri": u, "removed": True, "total": len(cur)}


def listing(direction: str) -> dict:
    key, schemes, label = _direction(direction)
    uris = allowed_uris() if direction == "egress" else source_uris()
    return {"direction": direction, "label": label, "mode": mode(),
            "schemes": list(schemes), "uris": uris}


def _direction(direction: str):
    d = (direction or "").strip().lower()
    if d not in _DIRECTIONS:
        raise ValueError(f"direzione '{direction}' sconosciuta: egress | ingress")
    return _DIRECTIONS[d]


def summary(agent_cfg: dict | None = None) -> dict:
    """Per introspezione/UI: modo, destinazioni ammesse, fonti fidate."""
    return {"mode": mode(), "egress_allow": allowed_uris(),
            "source_allow": source_uris(),
            "egress_schemes": list(EGRESS_SCHEMES),
            "source_schemes": list(SOURCE_SCHEMES)}
