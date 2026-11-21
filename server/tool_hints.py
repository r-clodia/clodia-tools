"""MCP tool annotations as A·V·R·Q read/write facts (clodia-platform#634).

A verb that no connector manifest maps used to be classified by the first word
of its name alone. That fails twice: a server that namespaces its tools
(`clickup.clickup_get_task`: first word `clickup`) has every read classified as
a write, and so does a server whose tools are not named in English
(`normattiva.risolvi`, clodia-platform#649). Both ask for a confirmation on
every read, in a room where the owner authorised the MCP for «read = allow».

The MCP server already says which tools only read: `ToolAnnotations` in its
`tools/list` (`readOnlyHint`, `destructiveHint`, spec 2025-03-26). This module
keeps those hints per backend, from the same listing the gateway caches
(`proxy._TOOL_CACHE`), and answers «read or write?» for a backend verb:

1. the PLATFORM first, when it is stricter: a verb with a connector mapping
   is classified by the mapping (`authz_shadow.facts`, before this module is
   asked); a gated verb (`gate.is_gated`) and a verb whose name says it cannot
   be undone (`IRREVERSIBLE_WORDS`) are writes whatever the server claims —
   a server can upgrade a verb to a write, never downgrade one to a read;
2. the hint, when the server declared one: `readOnlyHint: true` is a read,
   unless `destructiveHint: true` contradicts it (then a write);
   `readOnlyHint: false` or `destructiveHint: true` is a write;
3. no hint: `None`, and the caller falls back to the name heuristic.

The annotation is a third party's statement, but the decision it unlocks is
the room's own default for an MCP the owner already authorised there; the call
still runs under every other control (egress, taint, audit), an admin can
switch the tool off in Tools (#633), and nothing here is ever a global allow.

Hints are replaced on every listing of the backend and dropped with the tool
cache (`proxy.clear_cache`, called on every mount, unmount and reconfigure).
Before a backend has been listed there is no hint: the heuristic decides.
"""
from __future__ import annotations

import re
import threading
from typing import Any, Iterable, Optional

READ = "read"
WRITE = "write"

#: Words of a verb name the platform reads as «cannot be undone»
#: (decision-record 35; the same family `authz_roles.GITHUB_EXCLUDED` leaves
#: out of every role). A server's `readOnlyHint` never makes one of these a
#: read; `force_push` is matched as two consecutive words.
IRREVERSIBLE_WORDS = frozenset({"delete", "destroy", "drop", "purge", "wipe",
                                "erase", "merge", "transfer", "truncate"})
_IRREVERSIBLE_PAIRS = (("force", "push"),)

_lock = threading.Lock()
#: `{backend: {tool: (readOnlyHint, destructiveHint)}}`, each `True`, `False`
#: or `None` (not declared). Tool names as the backend lists them, unprefixed.
_HINTS: dict[str, dict[str, tuple[Optional[bool], Optional[bool]]]] = {}


def _flag(annotations: Any, name: str) -> Optional[bool]:
    if annotations is None:
        return None
    v = (annotations.get(name) if isinstance(annotations, dict)
         else getattr(annotations, name, None))
    return v if isinstance(v, bool) else None


def record(backend: str, tools: Iterable[Any]) -> None:
    """Replace the hints of `backend` with those of a fresh `tools/list`.

    `tools`: the backend's `Tool` objects (or dicts with `name` and
    `annotations`). A tool with no annotations is recorded with no hints, so
    a later listing that drops an annotation drops its effect too."""
    hints: dict[str, tuple[Optional[bool], Optional[bool]]] = {}
    for t in tools or ():
        name = t.get("name") if isinstance(t, dict) else getattr(t, "name", None)
        if not name:
            continue
        ann = t.get("annotations") if isinstance(t, dict) else getattr(t, "annotations", None)
        hints[str(name)] = (_flag(ann, "readOnlyHint"), _flag(ann, "destructiveHint"))
    with _lock:
        _HINTS[backend] = hints


def clear(backend: Optional[str] = None) -> None:
    with _lock:
        if backend is None:
            _HINTS.clear()
        else:
            _HINTS.pop(backend, None)


def hints_of(verb: str) -> tuple[Optional[bool], Optional[bool]]:
    """`(readOnlyHint, destructiveHint)` the backend declared for `verb`
    (`<backend>.<tool>`), `(None, None)` if unknown."""
    backend, sep, tool = (verb or "").partition(".")
    if not sep:
        return None, None
    with _lock:
        return (_HINTS.get(backend) or {}).get(tool, (None, None))


def _words(verb: str) -> list[str]:
    return [w for w in re.split(r"[_\-.]+", (verb or "").split(".", 1)[-1].lower()) if w]


def irreversible_by_name(verb: str) -> bool:
    w = _words(verb)
    if IRREVERSIBLE_WORDS & set(w):
        return True
    return any(w[i:i + len(p)] == list(p) for p in _IRREVERSIBLE_PAIRS
               for i in range(len(w)))


def platform_write(verb: str) -> bool:
    """True when the platform's own catalogue says `verb` writes, whatever
    the server declares: a gated verb, or one whose name cannot be undone.
    (A connector mapping is the first rule of `authz_shadow.facts`.)"""
    if irreversible_by_name(verb):
        return True
    try:
        from . import gate
        return gate.is_gated(verb)
    except Exception:  # noqa: BLE001 — in doubt a verb writes
        return True


def hint_kind(verb: str) -> Optional[str]:
    """`READ`/`WRITE` from the backend's annotations, or `None` when the
    server declared nothing for `verb` (the caller's heuristic decides)."""
    ro, destructive = hints_of(verb)
    if destructive is True or ro is False:
        return WRITE
    if ro is True:
        return WRITE if platform_write(verb) else READ
    return None


def irreversible(verb: str) -> bool:
    """`destructiveHint: true` from the server, or a name the platform reads
    as irreversible. `destructiveHint: false` never clears the latter."""
    _, destructive = hints_of(verb)
    return destructive is True or irreversible_by_name(verb)
