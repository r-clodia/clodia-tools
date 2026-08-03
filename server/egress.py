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
        # A single field may carry several addresses.
        out += [x.strip().lower() for x in str(raw).replace(";", ",").split(",")
                if x.strip()]
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
    return [c] if c else []


def _host(a: dict) -> list[str]:
    url = str(a.get("url") or "").strip()
    if not url:
        return []
    h = (urlsplit(url).hostname or "").lower()
    return [h] if h else []


def _repo(a: dict) -> list[str]:
    owner, repo = str(a.get("owner") or "").strip(), str(a.get("repo") or "").strip()
    return [f"{owner}/{repo}".lower()] if owner and repo else []


def _drive_target(a: dict) -> list[str]:
    """Where the content lands, or who it is shared with.

    `gdrive.share` is egress to a PERSON, not to a folder: the destination is
    the address, which is why the two are not folded together.
    """
    out = []
    for field in ("email", "folder_id", "parent_id"):
        v = str(a.get(field) or "").strip()
        if v:
            out.append(v.lower())
    return out


def _spreadsheet(a: dict) -> list[str]:
    v = str(a.get("spreadsheet_id") or "").strip()
    return [v] if v else []


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
    "web.post": ("http", _host),
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

def _matches(dest: str, rule: str) -> bool:
    """A destination against one rule.

    Three forms, and no regexes: a rule an operator cannot read is a rule nobody
    audits.
      *              any destination of this type (explicit opt-out)
      @domain        email suffix — "@tomato.blue" covers every address there
      exact          case-insensitive equality
    """
    r = (rule or "").strip().lower()
    d = (dest or "").strip().lower()
    if not r:
        return False
    if r == "*":
        return True
    if r.startswith("@"):
        return d.endswith(r)
    return d == r


def decide(agent_cfg: dict, verb: str, arguments: dict) -> dict:
    """Decide whether `verb` may reach the destinations in `arguments`.

    Returns a verdict dict; never raises. The caller enforces (or logs) it, so
    that the mode lives in one place and this function stays testable.
    """
    spec = spec_for(verb)
    if not spec:
        return {"checked": False, "allowed": True, "verb": verb}
    dtype, extract = spec
    try:
        dests = [d for d in extract(arguments or {}) if d]
    except Exception as e:  # noqa: BLE001 - a malformed call is not a decision
        LOG.warning("egress: destinatari non estraibili da %s (%s)", verb, e)
        dests = []
    allow = (agent_cfg or {}).get("egress_allow") or {}
    rules = allow.get(dtype)

    if not dests:
        # Property 3: no readable destination → deny, unless the type is
        # explicitly opened with "*".
        wide = bool(rules) and any(_matches("anything", r) for r in rules)
        return {"checked": True, "allowed": wide, "verb": verb, "type": dtype,
                "destinations": [UNKNOWN], "rules": rules,
                "reason": ("destinazione non leggibile dalla chiamata"
                           if not wide else "tipo aperto con '*'")}

    if rules is None:
        # Property 6: the type is not modelled for this agent at all.
        return {"checked": True, "allowed": False, "verb": verb, "type": dtype,
                "destinations": dests, "rules": None,
                "reason": f"nessuna regola di uscita dichiarata per '{dtype}'"}
    if not rules:
        # Property 1: declared but empty = deny. Distinct from the case above so
        # the operator can tell "never configured" from "deliberately muted".
        return {"checked": True, "allowed": False, "verb": verb, "type": dtype,
                "destinations": dests, "rules": [],
                "reason": f"uscita '{dtype}' dichiarata vuota (muta)"}

    refused = [d for d in dests if not any(_matches(d, r) for r in rules)]
    if refused:
        return {"checked": True, "allowed": False, "verb": verb, "type": dtype,
                "destinations": dests, "refused": refused, "rules": rules,
                "reason": f"destinazione non in whitelist: {', '.join(refused)}"}
    return {"checked": True, "allowed": True, "verb": verb, "type": dtype,
            "destinations": dests, "rules": rules}


def gate_key(dtype: str, dest: str) -> str:
    """Chiave del gate per una destinazione nuova.

    Per DESTINAZIONE, non per verbo: approvare «scrivi a mario@x.it» è una
    decisione diversa da «puoi mandare mail», ed è quella che l'umano è in grado
    di prendere guardando il dialog.
    """
    return f"egress:{dtype}:{dest}"


def gate_reason(agent: str, verb: str, dtype: str, dests: list[str]) -> str:
    """Testo del dialog. Dice ANCHE che approvando la destinazione resta.

    §7 proprietà 2: aggiungere una destinazione è più privilegiato della singola
    invocazione, perché la rende silenziosa per sempre. Se l'approvazione
    popola la whitelist — ed è la decisione presa — l'umano deve saperlo dal
    dialog, altrimenti concede un permesso permanente credendo di autorizzare un
    invio.
    """
    where = ", ".join(dests)
    return (f"@{agent} vuole usare {verb} verso {where}, che non è fra le "
            f"destinazioni consentite. Approvando, l'invio procede E "
            f"{where} viene aggiunto alla whitelist '{dtype}' di {agent}: "
            f"i prossimi invii verso quella destinazione non chiederanno più.")


def check(agent: str, agent_cfg: dict, verb: str, arguments: dict) -> dict:
    """Verdetto + AZIONE da compiere, secondo il modo. Non solleva mai.

    L'azione è una stringa perché il chiamante deve poter fare `await` sul gate:
    tenere la macchina del consenso fuori da questo modulo lo lascia testabile
    senza event loop.

        allow   procedi
        deny    rifiuta (PermissionError, lo solleva il chiamante)
        gate    chiedi all'umano; se approva → `remember` e procedi
    """
    m = mode()
    if m == "off":
        return {"checked": False, "action": "allow", "verb": verb, "mode": m}
    v = decide(agent_cfg, verb, arguments)
    v["mode"] = m
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
    """Aggiunge le destinazioni approvate alla whitelist di `agent` e persiste.

    Scrive nella config del GATEWAY, sul suo volume: l'agent-server non la monta,
    quindi un agente non può aggiungersi destinazioni da sé (clodia-platform#80).
    Idempotente. Ritorna le regole risultanti per quel tipo.
    """
    from . import whitelist as _wl
    added = [d for d in dests if d and d != UNKNOWN]
    if not added:
        return []
    agents = _wl.CONFIG.setdefault("agents", {})
    spec = agents.setdefault(agent, {})
    allow = spec.setdefault("egress_allow", {})
    rules = allow.setdefault(dtype, [])
    for d in added:
        if d not in rules:
            rules.append(d)
    _wl.save_config()
    LOG.warning("egress whitelist · %s · %s += %s (approvato da un umano)",
                agent, dtype, ", ".join(added))
    return list(rules)


def summary(agent_cfg: dict) -> dict:
    """For introspection/UI: what this agent may reach, by type."""
    allow = (agent_cfg or {}).get("egress_allow") or {}
    types = sorted({t for t, _ in _SPECS.values()} | {"github"})
    return {"mode": mode(),
            "types": {t: allow.get(t) for t in types}}
