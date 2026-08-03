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
    report   decide and LOG, allow anyway — default. Harvests the real
             destination set from real traffic, which is exactly how the four
             gaps in the network whitelist were found: by reading the log after
             traffic, not by guessing the list up front.
    on       enforce: a denied destination raises PermissionError

This module decides and explains. It does not know about gates: a denied
destination is a candidate for the "new destination" gate (§10 step 6), which
comes after this and needs this to exist.
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
    m = (os.environ.get("CLODIA_EGRESS_ENFORCE") or "report").strip().lower()
    return m if m in ("off", "report", "on") else "report"


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


def enforce(agent: str, agent_cfg: dict, verb: str, arguments: dict) -> dict:
    """Apply `decide` according to the mode. Raises PermissionError only in `on`.

    In `report` the call proceeds and the verdict is logged in a form meant to be
    harvested: the log IS the way the real destination set is discovered, so it
    carries agent, type and destinations, never the payload.
    """
    m = mode()
    if m == "off":
        return {"checked": False, "allowed": True, "verb": verb, "mode": m}
    v = decide(agent_cfg, verb, arguments)
    v["mode"] = m
    if not v.get("checked"):
        return v
    if v["allowed"]:
        LOG.info("egress ok · %s · %s → %s", agent, verb,
                 ", ".join(v.get("destinations") or []))
        return v
    if m == "report":
        # Deliberately WARNING, not error: it is the line an operator greps to
        # build the whitelist, and it must stand out without looking like a
        # failure — nothing was blocked.
        LOG.warning("egress WOULD-DENY · %s · %s → %s · %s (mode=report, "
                    "chiamata consentita)", agent, verb,
                    ", ".join(v.get("destinations") or []), v.get("reason"))
        v["allowed"] = True
        v["would_deny"] = True
        return v
    LOG.warning("egress DENY · %s · %s → %s · %s", agent, verb,
                ", ".join(v.get("destinations") or []), v.get("reason"))
    raise PermissionError(
        f"uscita non consentita per l'agent '{agent}': {v.get('reason')}. "
        f"Le destinazioni ammesse si dichiarano in egress_allow.{v.get('type')} "
        f"nella config del gateway (modifica gated, come i grant).")


def summary(agent_cfg: dict) -> dict:
    """For introspection/UI: what this agent may reach, by type."""
    allow = (agent_cfg or {}).get("egress_allow") or {}
    types = sorted({t for t, _ in _SPECS.values()} | {"github"})
    return {"mode": mode(),
            "types": {t: allow.get(t) for t in types}}
