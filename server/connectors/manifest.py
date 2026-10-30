"""Connector manifest — the grammar a pack uses to declare a connector.

Today every connector is hardcoded twice over: the schemes and their validation
live in `egress.py` (`EGRESS_SCHEMES`, `SOURCE_SCHEMES`, `_SPECS`, `_CANON`,
`_HIERARCHICAL`, `_DANGER`), the MCP prefixes that must not taint a channel live
in `taint.py`, the topic buttons live in `topics_api.py` and the setup card lives
in `tools_api.py`. A pack can declare `ingress:`/`egress:` URIs and nothing else,
so shipping a connector means changing the core.

This module is the grammar that replaces those tables, and *only* the grammar:
it parses and validates, it does not decide anything. Building the registry on
top of it and deleting the tables is clodia-platform#518; applying the same
mappings at call time is #517; the generic endpoints are #519.

**Why it lives in the gateway and not in the agent-server.** The same reason
`pack_import.validate_flows` already gives for the flow declarations: the lists
and the rules live here, next to the PDP, and "a second copy would diverge, and
would diverge silently". The agent-server asks; it does not re-implement.

**Declaration, never a grant.** A manifest says what a connector *is* — not what
it may do. The author of a pack declares, the owner who installs grants. That is
the same line `declared_flows` draws, and it is the reason nothing in here reads
or writes the egress/ingress lists.

**The namespace rule (clodia-platform#516, non-negotiable).** A pack may map
verbs to destinations only inside its own namespace. Without that rule a pack
could declare someone else's outbound verb — `email.send`, `telegram.send` — as
a read, or map it to a harmless destination, and walk straight through the egress
check. `check_namespace` is exported on purpose: #517 applies it again at call
time, and two copies of this rule would be one copy too many.

The format itself is documented, with one example per connector that exists
today, in `SCHEMA.md` next to this file. `test_manifest.py` loads the examples
out of that document, so an example that rots fails the suite instead of
quietly lying.
"""
from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlsplit

#: Version of *this grammar*. A manifest declares the version it was written
#: for; a manifest from the future is refused by name instead of being parsed
#: with the wrong rules and half understood.
MANIFEST_VERSION = 1

DIRECTIONS = ("source", "egress", "both")
VERB_DIRECTIONS = ("egress", "source")
#: Where a mapping reads its value from: the call's arguments, or its answer.
READS_FROM = ("arguments", "result")

#: Platform-intrinsic schemes. They are not a connector's to declare — #518
#: leaves exactly these in a core manifest — but a pack may *point at* the
#: generic ones: GitHub's write verbs resolve to `https://github.com/<owner>/<repo>`
#: and are checked by the ordinary http rules, which is the strictest generic
#: path there is. Pointing at them bypasses nothing; declaring them would mean
#: owning the meaning of every URL on the instance.
CORE_SCHEME_DIRECTION = {
    "http": "both",
    "https": "both",
    "topic": "source",
    "mcp": "source",
}
CORE_SCHEMES = tuple(CORE_SCHEME_DIRECTION)
CREDENTIAL_KINDS = ("form", "oauth")
#: What a topic action may bind besides its whitelist entries.
BINDINGS = ("channel",)
HEALTH_KINDS = ("http", "tcp", "command")
RESTART_POLICIES = ("always", "on-failure", "never")

#: Bounds on a pack-supplied regular expression and on what it is run against.
#: See `_compiled` for why they exist and why they are checked at load time.
MAX_PATTERN_LENGTH = 200
MAX_VALUE_LENGTH = 2048

#: Value transforms the GATEWAY implements, that a verb mapping may name. A
#: closed list on purpose: these are the three things today's extractors do that
#: a template cannot (lowercase a host, drop a port, resolve a repository
#: shorthand), and a pack that could supply the transform itself would be
#: rewriting what a URL means on this instance. See `normalise.py`.
NORMALISERS = ("url_origin", "repo_url", "repo_pair", "email_from")

#: Insiemi di valori che il GATEWAY offre a un campo di un'azione di topic, al
#: posto del testo libero (clodia-platform#519). Lista chiusa come
#: `NORMALISERS`, e per la stessa ragione: un insieme di valori è «cose di cui
#: questa istanza risponde», e un pack che potesse definirne uno risponderebbe
#: al posto suo. Le implementazioni stanno in `actions.OPTION_SETS`.
OPTION_SETS = ("mailboxes",)

#: Fatti sulla CHIAMATA in corso che il gateway sa riempire da sé, e che un
#: connettore di pack può chiedere come argomenti (clodia-platform#522).
#: Lista chiusa come `NORMALISERS` e `OPTION_SETS`, e per una ragione più
#: forte: questi non sono dati, sono IDENTITÀ.
#:
#: Un verbo nativo le legge dal contesto del processo — `current_chat()` è il
#: claim FIRMATO della stanza, `agent_name()` l'agente autenticato — e quindi
#: nessun chiamante può mentire su chi è e da dove scrive. Un server MCP di
#: pack non ha né il claim né l'identità: gliele deve passare qualcuno. Se a
#: passarle fosse l'agente, sarebbero argomenti come gli altri, cioè
#: falsificabili, e «manda questo alla chat di questo topic» tornerebbe a
#: essere «manda questo alla chat che dico io» — il difetto che ha prodotto gli
#: invii al gruppo sbagliato del 23 set 2026.
#:
#: Perciò li riempie il GATEWAY, e SOVRASCRIVE sempre quello che il chiamante
#: ha messo: un valore del chiamante che venisse preferito, o anche solo usato
#: quando il gateway non ne ha uno, sarebbe la stessa falsificazione con un
#: passaggio in più.
CONTEXT_VALUES = ("channel", "agent")

#: I nomi che ciascun insieme RISOLVE, interpolabili nei template dell'azione
#: oltre ai nomi dei campi. Dichiarati qui perché la grammatica deve poterli
#: convalidare al caricamento; `actions.OPTION_SETS` li produce, e un test
#: verifica che le due facce dicano la stessa cosa.
OPTION_SET_VALUES = {"mailboxes": ("account", "address")}

#: Valori che il gateway sa mettere in un argomento OMESSO (`defaults:`).
#: `binding` = la chat legata al canale da cui si chiama, per QUESTO connettore
#: (`channel_bindings`). È l'altro fatto che un backend di pack non ha: il
#: registro dei binding è del gateway, lo scrive il bottone del topic, e un
#: processo che lo leggesse da sé leggerebbe anche i binding di tutti gli altri.
DEFAULT_VALUES = ("binding",)

_ID = re.compile(r"^[a-z][a-z0-9-]{0,39}$")
_NAMESPACE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]{0,31}$")
_VERB = re.compile(r"^[a-z][a-z0-9_]{0,31}\.[A-Za-z0-9_.]{1,63}$")
_ARG = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_FIELD_NAME = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_VAULT_ENTRY = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
#: `{1}` … `{9}` in a canonicalisation template, `{field}` in a topic action.
_PLACEHOLDER = re.compile(r"\{([A-Za-z0-9_]+)\}")


#: Vault entries the GATEWAY itself writes (`tools_api`, `backup`, `profile`,
#: `providers_api`, `mcp_oauth`, the topic git credentials). A pack credential
#: may never be stored under one of these: a form posted to the generic connect
#: route would overwrite — or, empty, remove — a credential that is not the
#: pack's, keeping its grants (review of #359/#360).
CORE_VAULT_PREFIXES = (
    "app_", "backup_", "github_", "gmail_", "google_", "gworkspace_",
    "mailbox_", "mcp_", "openai_", "profile_", "provider_", "scope_",
    "telegram_")
#: The stems of `CORE_VAULT_PREFIXES`: namespaces no pack may hold, so no
#: pack can reach those vault entries (second verification of #359:
#: `namespace: google` + `vault_entry: google_studio` loaded, because `google`
#: was no native namespace and the prefix was exempted by name). Added to
#: `core_namespaces()`, which every namespace check reserves — minus the ones
#: the pack-served connectors own (`reserved_namespaces`).
MIGRATING_NAMESPACES = frozenset(p.rstrip("_") for p in CORE_VAULT_PREFIXES)


def reserved_namespaces() -> frozenset[str]:
    """`MIGRATING_NAMESPACES` minus the namespaces and vault prefixes of the
    connectors first-party packs serve (`builtin.released()`: `telegram`,
    `github`, `openai`, …).

    Those are not free for everyone: `builtin.expected_claims()` hands each to
    its own pack only, and `resolved._strip_foreign_claims` drops any other
    pack's claim before the registry is built. Reserving them here as well
    would refuse exactly the pack that serves them.
    """
    from . import builtin as _builtin

    try:
        namespaces, prefixes = _builtin.released()
    except Exception:  # noqa: BLE001 — in doubt everything stays reserved
        return MIGRATING_NAMESPACES
    return MIGRATING_NAMESPACES - namespaces - {p.rstrip("_") for p in prefixes}


def entry_owner(entry: str, namespaces: Iterable[str]) -> str:
    """The namespace a vault entry belongs to: the LONGEST of `namespaces` that
    is `entry` itself or a `<ns>_` prefix of it, or "" when none is.

    Namespaces may contain `_`, so `foo_bar_token` is a valid entry for both
    `foo` and `foo_bar`: it belongs to `foo_bar` when that is installed.
    """
    return max((n for n in namespaces
                if entry == n or entry.startswith(f"{n}_")), key=len, default="")


def vault_entry_problem(entry: str, namespace: str,
                        reserved: Iterable[str] | None = None) -> str:
    """Why a PACK connector may not store its credential under `entry`, or "".

    The entry lives under the connector's own namespace — `<namespace>` or
    `<namespace>_…` — and never under another core credential prefix. A core
    prefix whose stem IS the namespace can only occur for a namespace that the
    namespace rule let through, and in production `MIGRATING_NAMESPACES` are
    reserved: there is no exemption by name. `reserved` is the namespace
    reservation in force (default `reserved_namespaces()`); only a registry
    reproduced with an explicit, smaller one — a test of the day after a
    migration — lets a stem namespace use its own prefix.
    """
    taken = reserved_namespaces() if reserved is None else frozenset(reserved)
    if entry != namespace and not entry.startswith(f"{namespace}_"):
        return (f"vault entry '{entry}' is outside namespace '{namespace}': a "
                f"connector stores its credential as '{namespace}' or "
                f"'{namespace}_<name>'")
    for prefix in CORE_VAULT_PREFIXES:
        if not (entry.startswith(prefix) or entry == prefix.rstrip("_")):
            continue
        if prefix.rstrip("_") == namespace and namespace not in taken:
            continue
        return (f"vault entry '{entry}' is a core credential name "
                f"('{prefix}…'), which a pack cannot write")
    return ""


class ManifestError(ValueError):
    """A manifest is refused as a whole, with a message an owner can act on.

    Never a per-entry warning: a connector accepted minus the mapping that did
    not pass would be a connector whose verbs go unchecked, which is the exact
    failure the namespace rule exists to prevent.

    `packs` names the installed packs the refusal is about, when the registry
    knows: `connectors.resolved` drops exactly those and keeps the others
    (review of #359 — one bad pack used to take every pack's connectors down).
    """

    packs: tuple[str, ...] = ()


def _blame(error: ManifestError, *packs: str) -> ManifestError:
    """Attach the packs responsible for `error` (see `ManifestError.packs`)."""
    error.packs = tuple(sorted(set(error.packs) | {p for p in packs if p}))
    return error


# --------------------------------------------------------------------------
# primitives
# --------------------------------------------------------------------------

def _at(pack: str, connector: str = "", detail: str = "") -> str:
    parts = [f"pack '{pack}'"]
    if connector:
        parts.append(f"connector '{connector}'")
    if detail:
        parts.append(detail)
    return ", ".join(parts)


def _mapping(raw: Any, where: str) -> dict:
    if not isinstance(raw, Mapping):
        raise ManifestError(f"{where}: expected a mapping, got {type(raw).__name__}")
    return dict(raw)


def _seq(raw: Any, where: str) -> list:
    if raw is None:
        return []
    if isinstance(raw, (str, bytes)) or isinstance(raw, Mapping):
        raise ManifestError(f"{where}: expected a list, got {type(raw).__name__}")
    if not isinstance(raw, Sequence):
        raise ManifestError(f"{where}: expected a list, got {type(raw).__name__}")
    return list(raw)


def _text(raw: Any, where: str, *, required: bool = True, default: str = "") -> str:
    if raw is None:
        if required:
            raise ManifestError(f"{where}: required")
        return default
    if not isinstance(raw, str):
        raise ManifestError(f"{where}: expected a string, got {type(raw).__name__}")
    value = raw.strip()
    if not value and required:
        raise ManifestError(f"{where}: required")
    return value or default


def _flag(raw: Any, where: str, *, default: bool = False) -> bool:
    if raw is None:
        return default
    if not isinstance(raw, bool):
        raise ManifestError(f"{where}: expected true or false, got {raw!r}")
    return raw


def _one_of(value: str, allowed: Sequence[str], where: str) -> str:
    if value not in allowed:
        raise ManifestError(
            f"{where}: '{value}' is not one of {', '.join(allowed)}")
    return value


def _matching(value: str, pattern: re.Pattern[str], where: str) -> str:
    if not pattern.match(value):
        raise ManifestError(f"{where}: '{value}' does not match {pattern.pattern}")
    return value


# ---- regex cost analysis (review of #358) ----------------------------------

try:  # Python ≥ 3.11
    from re import _constants as _sre_c, _parser as _sre_p
except ImportError:  # pragma: no cover — older interpreters
    import sre_constants as _sre_c  # type: ignore[no-redef]
    import sre_parse as _sre_p  # type: ignore[no-redef]

#: A bounded repeat with a larger maximum costs like an unbounded one on a
#: value of `MAX_VALUE_LENGTH` characters, so it is counted as one.
_BIG_REPEAT = 32
#: Unbounded repeats that can fight over the same characters, in sequence. Two
#: is quadratic on at most `MAX_VALUE_LENGTH` characters (~10 ms); three is
#: cubic (`\d*\d*\d*x` on 2000 characters: 6.4 s).
MAX_AMBIGUOUS_CHAIN = 2
#: Repeats of any kind in one pattern. `a?a?a?…aaa…` is exponential without a
#: single unbounded repeat: the bound is on how many choices a pattern can make.
MAX_REPEATS = 10
#: Alternations in one pattern, for the same reason.
MAX_BRANCHES = 4

_REPEATS = {_sre_c.MAX_REPEAT, _sre_c.MIN_REPEAT}
if hasattr(_sre_c, "POSSESSIVE_REPEAT"):
    _REPEATS.add(_sre_c.POSSESSIVE_REPEAT)
_REFUSED_OPS = {_sre_c.GROUPREF, _sre_c.GROUPREF_EXISTS, _sre_c.ASSERT,
                _sre_c.ASSERT_NOT}
#: The alphabet a character class is evaluated on: enough to tell which classes
#: can overlap, which is all the analysis needs.
_SAMPLE = tuple(range(0, 256)) + (0x100, 0x3B1, 0x4E00, 0x2028, 0x1F600)
_ALL = frozenset(_SAMPLE)
_CATEGORY_RE = {
    "CATEGORY_DIGIT": r"\d", "CATEGORY_NOT_DIGIT": r"\D",
    "CATEGORY_SPACE": r"\s", "CATEGORY_NOT_SPACE": r"\S",
    "CATEGORY_WORD": r"\w", "CATEGORY_NOT_WORD": r"\W",
}


def _category_chars(cat) -> frozenset[int]:
    rx = _CATEGORY_RE.get(str(cat))
    if rx is None:
        return _ALL
    probe = re.compile(rx)
    return frozenset(c for c in _SAMPLE if probe.fullmatch(chr(c)))


def _class_chars(items) -> frozenset[int]:
    negate, out = False, set()
    for op, av in items:
        if op is _sre_c.NEGATE:
            negate = True
        elif op is _sre_c.LITERAL:
            out.add(av)
        elif op is _sre_c.RANGE:
            out.update(c for c in _SAMPLE if av[0] <= c <= av[1])
        elif op is _sre_c.CATEGORY:
            out.update(_category_chars(av))
        else:
            return _ALL
    return frozenset(_ALL - out) if negate else frozenset(out)


def _chars(sub) -> frozenset[int]:
    """Every character `sub` can consume, approximated on `_SAMPLE`."""
    out: set[int] = set()
    for op, av in sub:
        if op is _sre_c.LITERAL:
            out.add(av)
        elif op is _sre_c.NOT_LITERAL:
            out |= _ALL - {av}
        elif op is _sre_c.ANY:
            return _ALL
        elif op is _sre_c.IN:
            out |= _class_chars(av)
        elif op in _REPEATS:
            out |= _chars(av[2])
        elif op is _sre_c.SUBPATTERN:
            out |= _chars(av[-1])
        elif op is _sre_c.BRANCH:
            for alt in av[1]:
                out |= _chars(alt)
        elif op is _sre_c.AT:
            continue
        else:
            out |= _ALL
    return frozenset(out)


def _single(op, av) -> frozenset[int] | None:
    """The character set of a one-character element, or None."""
    if op is _sre_c.LITERAL:
        return frozenset({av})
    if op is _sre_c.IN:
        return _class_chars(av)
    if op is _sre_c.NOT_LITERAL:
        return frozenset(_ALL - {av})
    if op is _sre_c.ANY:
        return _ALL
    return None


def _contains_repeat_or_branch(sub) -> bool:
    for op, av in sub:
        if op in _REPEATS and av[1] > 1:
            return True
        if op is _sre_c.BRANCH:
            return True
        if op is _sre_c.SUBPATTERN and _contains_repeat_or_branch(av[-1]):
            return True
        if op in _REPEATS and _contains_repeat_or_branch(av[2]):
            return True
        if op is getattr(_sre_c, "ATOMIC_GROUP", None) and \
                _contains_repeat_or_branch(av):
            return True
    return False


def _nullable(sub) -> bool:
    for op, av in sub:
        if op is _sre_c.AT:
            continue
        if op in _REPEATS:
            if av[0] > 0 and not _nullable(av[2]):
                return False
            continue
        if op is _sre_c.SUBPATTERN:
            if not _nullable(av[-1]):
                return False
            continue
        if op is _sre_c.BRANCH:
            if not any(_nullable(alt) for alt in av[1]):
                return False
            continue
        return False
    return True


def _regex_cost_problem(pattern: str) -> str:
    """Why this pattern's matching cost is not bounded, or `""`.

    Structural, on the parse tree (`re._parser`), not on the text: a textual
    heuristic is bypassed by an extra pair of parentheses (`((a+))+b`). The
    rules, each of which closes one family of super-linear matches:

    - a repeat (max > 1) whose body holds another repeat or an alternation —
      `(a+)+`, `((a+))+`, `(a|aa)+`, `(?:a|a)*` (exponential);
    - a repeat (max > 1) whose body can match the empty string — `(a?)*`;
    - more than `MAX_AMBIGUOUS_CHAIN` unbounded repeats in a run where they can
      consume the same characters — `\\d*\\d*\\d*x` (polynomial). A run is
      broken by a mandatory character the previous repeat cannot consume (the
      `@` in `[^@]+@[^@]+`): that repeat's extent is then fixed;
    - more than `MAX_REPEATS` repeats or `MAX_BRANCHES` alternations at all;
    - back-references and lookarounds, which no URI form needs.
    """
    try:
        tree = _sre_p.parse(pattern)
    except re.error as exc:
        return f"invalid regular expression ({exc})"
    counts = {"repeats": 0, "branches": 0}
    chains: list[int] = [0]
    last: list[frozenset[int] | None] = [None]

    def walk(sub, breaking: bool) -> str:
        for op, av in sub:
            if op in _REFUSED_OPS:
                return "back-references and lookarounds are not allowed"
            if op in _REPEATS:
                lo, hi, body = av
                counts["repeats"] += 1
                if hi > 1 and _contains_repeat_or_branch(body):
                    return ("a repeated group contains another repeat or an "
                            "alternation (exponential backtracking)")
                if hi > 1 and _nullable(body):
                    return "a repeated group can match the empty string"
                if hi == _sre_c.MAXREPEAT or hi > _BIG_REPEAT:
                    chains[-1] += 1
                    last[0] = _chars(body)
                    if chains[-1] > MAX_AMBIGUOUS_CHAIN:
                        return (f"more than {MAX_AMBIGUOUS_CHAIN} unbounded "
                                f"repeats compete for the same characters "
                                f"(polynomial backtracking)")
                elif hi <= 1:
                    err = walk(body, False)
                    if err:
                        return err
                continue
            if op is _sre_c.SUBPATTERN:
                err = walk(av[-1], breaking)
                if err:
                    return err
                continue
            if op is getattr(_sre_c, "ATOMIC_GROUP", None):
                err = walk(av, breaking)
                if err:
                    return err
                continue
            if op is _sre_c.BRANCH:
                counts["branches"] += 1
                for alt in av[1]:
                    err = walk(alt, False)
                    if err:
                        return err
                continue
            one = _single(op, av)
            if one is not None and breaking and last[0] is not None \
                    and not (one & last[0]):
                chains.append(0)
                last[0] = None
        return ""

    err = walk(tree, True)
    if err:
        return err
    if counts["repeats"] > MAX_REPEATS:
        return f"more than {MAX_REPEATS} repeats"
    if counts["branches"] > MAX_BRANCHES:
        return f"more than {MAX_BRANCHES} alternations"
    return ""


#: Longest value a PACK regex is ever applied to (second verification of
#: #358). Longer values are refused for pack schemes, never matched.
PACK_MAX_INPUT = 256
#: The safe subset a PACK regex must stay in. Heuristics on the parse tree
#: (above) kept being bypassed — bounded repeats, literals that earlier repeats
#: can also consume, character classes outside the sampled alphabet — so a pack
#: gets a grammar small enough to be bounded by construction instead:
PACK_MAX_REPEATS = 2      # quantified atoms with max > 1, bounded or not
PACK_MAX_OPTIONALS = 2    # `x?` atoms
PACK_MAX_BRANCHES = 1     # alternations
PACK_MAX_ALTERNATIVES = 4
_SINGLE_ATOMS = {_sre_c.LITERAL, _sre_c.NOT_LITERAL, _sre_c.IN, _sre_c.ANY,
                 getattr(_sre_c, "CATEGORY", None)}


def _pack_regex_problem(pattern: str) -> str:
    """Why `pattern` is outside the pack subset, or `""`.

    - at most `PACK_MAX_REPEATS` quantified atoms with max > 1 (`*`, `+`,
      `{m,n}` — bounded and unbounded count alike), `PACK_MAX_OPTIONALS` `?`;
    - a quantifier applies to ONE character atom (`a`, `[a-z]`, `\\d`, `.`),
      never to a group;
    - at most one alternation, of at most four alternatives, with no
      quantifier anywhere inside it;
    - no back-references, no lookarounds, no conditionals.

    With fullmatch on at most `PACK_MAX_INPUT` characters that is at most
    O(n²) × 2² × 4 steps, whatever the pattern says.
    """
    try:
        tree = _sre_p.parse(pattern)
    except re.error as exc:
        return f"invalid regular expression ({exc})"
    counts = {"repeat": 0, "optional": 0, "branch": 0}

    def walk(sub, in_branch: bool) -> str:
        for op, av in sub:
            if op in _REFUSED_OPS:
                return "back-references, lookarounds and conditionals are not allowed"
            if op in _REPEATS:
                lo, hi, body = av
                if len(body) != 1 or body[0][0] not in _SINGLE_ATOMS:
                    return ("a quantifier may apply only to a single character "
                            "or character class, never to a group")
                if in_branch:
                    return "no quantifier inside an alternation"
                counts["repeat" if hi > 1 else "optional"] += 1
                continue
            if op is _sre_c.SUBPATTERN:
                err = walk(av[-1], in_branch)
                if err:
                    return err
                continue
            if op is _sre_c.BRANCH:
                counts["branch"] += 1
                if len(av[1]) > PACK_MAX_ALTERNATIVES:
                    return f"more than {PACK_MAX_ALTERNATIVES} alternatives"
                for alt in av[1]:
                    err = walk(alt, True)
                    if err:
                        return err
                continue
            if op in _SINGLE_ATOMS or op is _sre_c.AT:
                continue
            return f"construct '{op}' is not allowed"
        return ""

    err = walk(tree, False)
    if err:
        return err
    if counts["repeat"] > PACK_MAX_REPEATS:
        return (f"more than {PACK_MAX_REPEATS} quantified atoms with a maximum "
                f"above one")
    if counts["optional"] > PACK_MAX_OPTIONALS:
        return f"more than {PACK_MAX_OPTIONALS} optional atoms"
    if counts["branch"] > PACK_MAX_BRANCHES:
        return f"more than {PACK_MAX_BRANCHES} alternation"
    return ""


def _compiled(raw: Any, where: str, *, builtin: bool = False) -> re.Pattern[str]:
    """A regex from the manifest, compiled here so a typo fails at load.

    Compiled eagerly and on purpose: a pattern that only blows up the first time
    a real destination is checked would turn an authoring mistake into a runtime
    denial in the middle of someone's turn.

    **Bounded cost** (review of clodia-tools#353). These patterns come from a
    pack and run inside the gateway's event loop on every destination check, so
    a catastrophic one — `(a+)+$` against a long non-matching value — would not
    merely be slow: it would hold the loop for everybody. Python's `re` has no
    timeout, and `regex`'s is not a dependency we have, so the bound has to be
    on the pattern and on the input instead of on the clock:

    - the pattern is capped in length;
    - the parse tree is checked by `_regex_cost_problem` (nested or ambiguous
      repeats, competing unbounded repeats, too many choices) — structurally,
      so an extra pair of parentheses does not hide `(a+)+`;
    - every match (`Form`, `Canonicalisation`, `DangerRule`) is a `fullmatch`
      on a value of at most `MAX_VALUE_LENGTH` characters.

    Refused at load, not at match time: a pack whose pattern is dangerous must
    fail where an owner can read the message, not in the middle of a turn.
    """
    pattern = _text(raw, where)
    if len(pattern) > MAX_PATTERN_LENGTH:
        raise ManifestError(
            f"{where}: regular expression is {len(pattern)} characters, over the "
            f"{MAX_PATTERN_LENGTH} this gateway will evaluate. A URI form that "
            f"needs more than that is describing something other than a URI")
    problem = (_regex_cost_problem(pattern) if builtin
               else _pack_regex_problem(pattern))
    if problem:
        raise ManifestError(
            f"{where}: '{pattern}' is refused: {problem}. This pattern would run "
            f"in the gateway's loop on every check, so its cost must be bounded")
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise ManifestError(f"{where}: invalid regular expression ({exc})") from exc


def _placeholders(template: str) -> list[str]:
    return _PLACEHOLDER.findall(template)


# --------------------------------------------------------------------------
# pieces of a connector
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Form:
    """One accepted shape of a URI under a scheme (`tg:-100123`, `tg:@handle`).

    `fullmatch`, never `match` (review of clodia-tools#353, applied here because
    #518 is where these patterns start deciding): with `^-?\\d+` as the group
    form, `match` accepts `-100123garbage` — a value that would be granted as a
    chat and could never be the chat anyone meant. A form says what the whole
    value looks like; a prefix of it is a different value.
    """

    label: str
    pattern: re.Pattern[str]
    example: str = ""
    #: `PACK_MAX_INPUT` for a pack's pattern, `MAX_VALUE_LENGTH` for ours.
    max_input: int = PACK_MAX_INPUT

    def matches(self, rest: str) -> bool:
        if len(rest or "") > self.max_input:
            # A pattern cannot cost more than the bound checked at load time
            # unless the *input* is unbounded. Nothing legitimate reaches this.
            return False
        return bool(self.pattern.fullmatch(rest or ""))


@dataclass(frozen=True)
class Canonicalisation:
    """Browser URL → canonical id, the declarative form of `egress._CANON`."""

    pattern: re.Pattern[str]
    template: str
    max_input: int = PACK_MAX_INPUT

    def apply(self, uri: str) -> str | None:
        # Bounded input and `fullmatch` (review of #358): the pattern is
        # pack-supplied and the URI attacker-supplied.
        if not uri or len(uri) > self.max_input:
            return None
        m = self.pattern.fullmatch(uri)
        if not m:
            return None
        return _PLACEHOLDER.sub(lambda g: m.group(int(g.group(1))), self.template)


@dataclass(frozen=True)
class DangerRule:
    """A warning about the URIs of a connector that lives on a SHARED scheme.

    `Scheme.danger` covers the schemes a connector owns. GitHub owns none — its
    destinations are ordinary `https://github.com/<owner>/<repo>` URLs — yet
    «if the repository is public, everything pushed there is visible to anyone»
    is precisely what an owner needs to read at the gate, and it cannot hang off
    `https:` as a whole. So the connector that knows those hosts declares the
    warning for them, and nobody has to write `github.com` in `egress.py`.
    """

    pattern: re.Pattern[str]
    text: str
    max_input: int = PACK_MAX_INPUT

    def matches(self, uri: str) -> bool:
        return bool(uri) and len(uri) <= self.max_input and bool(
            self.pattern.fullmatch(uri))


@dataclass(frozen=True)
class Scheme:
    """A URI scheme with its direction, its shapes and its gate warning."""

    name: str
    direction: str
    label: str = ""
    icon: str = ""
    danger: str = ""
    hierarchical: bool = False
    #: The whole URI is case-insensitive, so it is stored lowercased — the mail
    #: family. Not cosmetic: the extractors lowercase the destination of a call,
    #: so a whitelist entry with a capital would never match, i.e. would be
    #: granted and ineffective.
    lowercase: bool = False
    #: `<scheme>:*` is a legitimate rule. False for a scheme where covering
    #: everything is not a perimeter at all (`gcal:*` is the whole agenda).
    wildcard: bool = True
    forms: tuple[Form, ...] = ()
    canonicalise: tuple[Canonicalisation, ...] = ()

    @property
    def is_source(self) -> bool:
        return self.direction in ("source", "both")

    @property
    def is_egress(self) -> bool:
        return self.direction in ("egress", "both")


@dataclass(frozen=True)
class CredentialField:
    name: str
    label: str = ""
    secret: bool = False
    required: bool = True
    placeholder: str = ""


@dataclass(frozen=True)
class Credential:
    """How the owner connects a provider: a form stored in the vault, or OAuth."""

    kind: str
    vault_entry: str = ""
    fields: tuple[CredentialField, ...] = ()
    scopes: tuple[str, ...] = ()
    authorize_url: str = ""
    token_url: str = ""


@dataclass(frozen=True)
class Transport:
    """The pack's MCP tool that carries out a gateway verb's I/O (#523).

    Mail cannot follow the Telegram pattern, where the pack implements the
    verbs and the gateway only fills their context: before any byte of a
    mailbox comes back, the gateway takes decisions that belong to the
    reference monitor — which mailbox this channel may use, strict ingress
    (#503), topic attachments in and out. So the verbs stay in the gateway and
    only the TRANSPORT moves: `backend` is an MCP backend the pack mounts,
    `tool` the one tool of it the gateway calls, with that call's credential
    and nothing else. Agents never see that backend (`resolved.
    transport_backends`): it is a socket of the gateway, not a verb.
    """

    backend: str
    tool: str


@dataclass(frozen=True)
class Provider:
    """One implementation of a scheme vocabulary (Gmail and IMAP for mail)."""

    id: str
    label: str
    pack: str
    credential: Credential | None = None
    status_verb: str = ""
    test_verb: str = ""
    #: Where the gateway sends the transport operations of this provider
    #: (`Transport`, #523). Pack-only.
    transport: Transport | None = None


@dataclass(frozen=True)
class VerbMapping:
    """`verb → destination` and `read → source`: `egress._SPECS` made declarative.

    `arg` names the argument the destination is read from, exactly like the
    extractors in `egress.py` do today. `template` builds the URI from it and
    defaults to `<scheme>:{value}`; `multi` says the argument may carry a list,
    the way `email.send` carries several recipients.

    A verb may be mapped **more than once** (#518): `email.send` reads `to`,
    `cc` and `bcc`, and `gdrive.upload` reads a folder *and* a person to share
    with — two schemes for one call. One mapping per argument, so the grammar
    says what the extractor said, instead of hiding several arguments behind a
    name only the gateway understands.

    `prefix: true` makes `verb` a prefix instead of a name. It exists for the
    verbs of a proxied MCP backend, whose list changes upstream without us —
    `github.create_*` is the same decision whichever noun follows.

    `normalise` names one of `NORMALISERS`, for the three transforms a template
    cannot express. With it, `arg` may be omitted: the transform reads the
    arguments it needs.
    """

    verb: str
    direction: str
    scheme: str
    arg: str = ""
    template: str = ""
    multi: bool = False
    dtype: str = ""
    prefix: bool = False
    normalise: str = ""
    #: `arguments` (default) or `result`. A read whose source is only knowable
    #: from the ANSWER — the sender of a mail — is read from the result, which
    #: the gateway already has in hand when it judges the call.
    reads: str = "arguments"

    def uri_for(self, value: str) -> str:
        template = self.template or f"{self.scheme}:{{value}}"
        return template.replace("{value}", value)

    def covers(self, verb: str) -> bool:
        """Does this mapping describe `verb`? Exact name, or prefix if declared."""
        return verb.startswith(self.verb) if self.prefix else verb == self.verb


@dataclass(frozen=True)
class DefaultArg:
    """Un argomento che il gateway riempie SOLO se il chiamante lo ha omesso.

    Non è un `ContextArg`, e la differenza è tutta nella regola: il contesto è
    un'identità e si sovrascrive sempre, perché il caso «ce l'ha già messo il
    chiamante» è esattamente l'attacco. Un default è una comodità — «manda alla
    chat di questo topic» — e un valore esplicito del chiamante deve vincere,
    altrimenti non si potrebbe più scrivere a una chat diversa da quella legata.

    Vale per un VERBO alla volta, non per il namespace: `telegram.inbox` non ha
    una chat da riempire, e riempirgliela comunque significherebbe passare al
    backend un argomento che il suo schema non dichiara.
    """

    verb: str
    arg: str
    value: str


@dataclass(frozen=True)
class FileArgument:
    """Un argomento che nomina un FILE DI TOPIC, che il gateway consegna.

    `telegram.send_file` prende il path di un file dentro un topic. Leggerlo è
    lavoro di piattaforma, non di connettore: ci stanno attaccati il
    compartimento (chi chiama dev'essere partecipante del topic) e l'audit di
    ciò che attraversa il confine. Un backend di pack che leggesse da sé il
    filesystem dei topic li aggirerebbe entrambi — e potrebbe leggere i file di
    un topic di cui il chiamante non sa nulla.

    Così invece il pack dichiara *quali argomenti* sono il path, i byte e il
    nome; il gateway risolve il topic, verifica la membership, legge, annota il
    passaggio e riempie i due argomenti. Il pack riceve dei byte e non ha mai
    visto un percorso.

    Il topic si risolve in quest'ordine — lo stesso del codice nativo che
    sostituisce: `tier_arg`/`topic_arg` se il chiamante li passa entrambi,
    altrimenti il topic legato alla chat di `chat_arg`, altrimenti il canale da
    cui arriva la chiamata.
    """

    verb: str
    path_arg: str
    bytes_arg: str
    name_arg: str = ""
    tier_arg: str = ""
    topic_arg: str = ""
    chat_arg: str = ""


@dataclass(frozen=True)
class ActionField:
    """Un campo dell'azione: testo libero, oppure una scelta fra valori che il
    gateway fornisce (`options:`).

    La differenza non è di comodità, è di fiducia: il valore scelto da un
    insieme viene RISOLTO dal gateway — della casella si prende l'indirizzo che
    conosce lui — mentre un testo libero è del client e come tale va confrontato
    con le forme dello schema. Senza la distinzione, l'azione sulle caselle
    accetterebbe dal corpo della richiesta l'indirizzo da autorizzare, e una
    whitelist scritta da chi ne è soggetto non è una whitelist.
    """

    name: str
    label: str = ""
    required: bool = True
    placeholder: str = ""
    options: str = ""


@dataclass(frozen=True)
class TopicAction:
    """The button a connector adds to a topic, and what it writes.

    `adds` holds the ingress/egress URIs the action proposes, as templates over
    the action's own fields. It proposes: whether they are granted is still the
    owner's decision at the gate — see the module docstring.
    """

    id: str
    label: str
    fields: tuple[ActionField, ...] = ()
    adds_ingress: tuple[str, ...] = ()
    adds_egress: tuple[str, ...] = ()
    binding: str = ""
    #: L'azione la offre solo a un ADMIN dell'istanza, non a ogni owner di
    #: topic. Esiste perché ciò che l'azione autorizza può non appartenere a
    #: chi possiede la stanza: una casella di sistema è posta dell'istanza, e
    #: il bottone Mailbox è sotto `isAdmin` da settembre. Finché quella regola
    #: viveva in un `if` sul NOME del connettore, renderla generica la
    #: cancellava (clodia-platform#520); qui sta dove sta il resto della
    #: descrizione, e un connettore di pack può dichiararla per sé.
    #: È una regola di SUPERFICIE: l'enforcement vero resta
    #: `_authorize_topic_owner`, che non distingue admin da owner — un admin
    #: è comunque owner di ciò che gli si mostra.
    admin_only: bool = False


@dataclass(frozen=True)
class ToolsCard:
    """What the Tools page shows for this connector: setup, status, test.

    `blurb` and `scope` are the card's COPY — what this connector does, and
    the perimeter it touches. Until #520 they lived in a per-connector table
    inside clodia-web, which is the table the issue removes: a connector
    arriving with a pack had no way to say anything about itself, and the page
    could only draw it as an unnamed box. The text is the connector's, so it
    arrives with the connector.
    """

    setup_label: str = ""
    status_verb: str = ""
    test_verb: str = ""
    docs_url: str = ""
    blurb: str = ""
    scope: str = ""
    #: Quale GLIFO la pagina disegna per questo connettore. Il disegno è un
    #: asset del frontend — un logo è un file SVG, non un dato del gateway — ma
    #: la SCELTA è del connettore: finché la decideva il frontend, lo faceva
    #: deducendola dal nome, cioè sapendo chi sono i connettori. Un nome che la
    #: pagina non conosce ricade sul glifo generico.
    icon: str = ""


@dataclass(frozen=True)
class Service:
    """A long-running process the gateway supervises (clodia-platform#515).

    The shape is fixed here so the supervisor consumes it instead of inventing a
    second format; the semantics — start, health, backoff, stop, OS user, env
    scrubbing — belong to #515. `command` is a list and never a string: a string
    would mean a shell, and a shell is a way to smuggle an extra process into a
    manifest that declares one.
    """

    name: str
    pack: str
    command: tuple[str, ...]
    workdir: str = ""
    credentials: tuple[str, ...] = ()
    #: The namespace of the connector that declares the service. Carried so the
    #: supervisor can re-apply `vault_entry_problem` at launch (defence in
    #: depth, review of clodia-tools #362): "" means no credential at all.
    namespace: str = ""
    health_kind: str = ""
    health_target: str = ""
    health_interval: int = 30
    restart: str = "on-failure"
    backoff_seconds: int = 5

    @property
    def state_dir(self) -> str:
        """Path relative to the datadir, as #515 fixes it: state survives rebuilds."""
        return f"services/{self.pack}/{self.name}"


@dataclass(frozen=True)
class Relay:
    """A chat transport the connector brings to the room (clodia-platform#638).

    The transport is one of the connector's own `services` (#515), reached by
    the GATEWAY only, on loopback, at `base`: the gateway forwards the relay's
    three operations (`/poll`, `/send`, `/download`) there and nowhere else. The
    agent-server never sees `base` — it calls `/internal/channels/<id>/…`.

    `label` is how the transport is named in the room (the `transport` of a
    `channel` message). `attachments` says whether `/download` exists at all.

    Or, instead of `service`/`base` (#641): `backend`, a mounted MCP backend
    of the same pack offering `relay_poll`/`relay_send`/`relay_download`. The
    transport then runs in its own container, not under the supervisor;
    exactly one of the two forms is set.
    """

    service: str
    base: str
    label: str
    attachments: bool = False
    backend: str = ""
    #: The SEAL rank above which binding a room to this transport needs the
    #: owner's written acknowledgement (#405's flow). `None` in the manifest
    #: means the gateway's default for pack relays, `DEFAULT_RELAY_SEAL_CAP`:
    #: a transport nobody has assessed is treated as the weakest link.
    seal_cap: int | None = None


@dataclass(frozen=True)
class Pairing:
    """A device pairing step after the credential is saved (clodia-platform#639).

    `status` (GET) and `start` (POST) are PATHS on the service's loopback
    `base`; the gateway forwards to them from the admin-only
    `/tools/connectors/<id>/pairing` routes and returns only
    `{state, code?, qr?, me?, error?}`.
    """

    service: str
    base: str
    status: str = "/status"
    start: str = "/pair"
    #: #641: a mounted MCP backend offering `pairing_status`/`pairing_start`,
    #: instead of `service`/`base`.
    backend: str = ""


@dataclass(frozen=True)
class StorageRemote:
    """A topic storage backend a pack provides (Drive, clodia-platform#524)."""

    id: str
    label: str
    versioning: bool = False


@dataclass(frozen=True)
class ContextArg:
    """Un argomento che il GATEWAY riempie al posto del chiamante (#522).

    `arg` è il nome dell'argomento nella chiamata, `value` il fatto da metterci
    (`CONTEXT_VALUES`). Vale per OGNI verbo del namespace del connettore, non
    per i soli verbi mappati: `telegram.send` dichiara una destinazione,
    `telegram.inbox` no, e tutti e due hanno bisogno di sapere da quale stanza
    e da quale agente arriva la chiamata.
    """

    arg: str
    value: str


@dataclass(frozen=True)
class Connector:
    """One connector as a pack declares it.

    Two kinds, and the difference is the whole of the multi-provider decision of
    2026-10-08: a connector either **owns a vocabulary** (it declares `schemes`)
    or **extends** one declared elsewhere, contributing a provider and nothing
    else. Gmail lives in google-pack and IMAP in comms-pack, but `mailto:` means
    one thing: whoever owns the vocabulary owns its schemes, its canonical forms
    and its verb mappings, and a contributor cannot touch them.
    """

    id: str
    label: str
    pack: str
    namespace: str
    extends: str = ""
    schemes: tuple[Scheme, ...] = ()
    providers: tuple[Provider, ...] = ()
    verbs: tuple[VerbMapping, ...] = ()
    danger_rules: tuple[DangerRule, ...] = ()
    taint_prefixes: tuple[str, ...] = ()
    #: Verbs of the namespace that deliberately carry NO egress/source mapping
    #: (`unmapped:`, clodia-platform#558): the PDP has nothing to read for them
    #: and the implementation enforces its own perimeter. Required for a
    #: gateway component's verb that has neither a mapping nor a taint prefix,
    #: which is otherwise denied as unclassified (`components.loader`).
    unmapped_verbs: tuple[str, ...] = ()
    topic_actions: tuple[TopicAction, ...] = ()
    tools_card: ToolsCard | None = None
    services: tuple[Service, ...] = ()
    storage_remote: StorageRemote | None = None
    #: Argomenti che il gateway riempie SOLO se omessi (`DefaultArg`).
    defaults: tuple[DefaultArg, ...] = ()
    #: Argomenti che nominano un file di topic e che il gateway consegna come
    #: byte (`FileArgument`): la lettura resta dove stanno compartimento e audit.
    files: tuple[FileArgument, ...] = ()
    #: Gli argomenti di contesto che il gateway riempie nelle chiamate ai verbi
    #: di questo connettore (`ContextArg`, clodia-platform#522).
    context: tuple[ContextArg, ...] = ()
    #: A chat transport on one of this connector's services (#638).
    relay: Relay | None = None
    #: A device pairing step on one of this connector's services (#639).
    pairing: Pairing | None = None
    #: Shipped by the gateway itself (`builtin/*.yaml`) rather than installed
    #: with a pack. Those files are the connectors this gateway still implements
    #: natively, declared in the same grammar so the PDP has one source — see
    #: `builtin.py`. They are code, not input: they may declare the intrinsic
    #: schemes, they are not checked against the reserved namespaces (they *are*
    #: the gateway's namespaces), and they win any collision with a pack.
    builtin: bool = False

    @property
    def owns_vocabulary(self) -> bool:
        return not self.extends

    @property
    def vocabulary(self) -> str:
        return self.extends or self.id


# --------------------------------------------------------------------------
# the namespace rule
# --------------------------------------------------------------------------

def core_namespaces() -> frozenset[str]:
    """Namespaces the gateway itself owns, derived — never a second list.

    Imported inside the function so that `server.main` can import this module
    (#518) without a cycle, and so that a namespace added to the gateway is
    reserved here the same day it exists, without anybody remembering to.
    """
    from ..main import (_GATEWAY_RETAINED_VERBS, _packaged_namespaces,
                        all_native_verb_names)

    # The verbs the gateway keeps in a pack's namespace (Telegram's binding
    # verbs, which write the gateway's own binding registry) do not make the
    # namespace the gateway's again: otherwise keeping them would refuse the
    # pack connector.
    packaged = _packaged_namespaces()
    return frozenset(
        name.split(".", 1)[0] for name in all_native_verb_names()
        if "." in name and not (name in _GATEWAY_RETAINED_VERBS
                                and name.split(".", 1)[0] in packaged)
    ) | reserved_namespaces()


def check_namespace(namespace: str, verbs: Iterable[str], *,
                    reserved: Iterable[str] | None = None,
                    where: str = "") -> None:
    """The rule of clodia-platform#516: a pack maps only its own verbs.

    Exported because #517 has to apply it again when the call actually happens:
    a manifest validated at install time says nothing about a verb that appears
    later, and a second implementation of this check would be the place where the
    two drift apart.

    `reserved` defaults to the gateway's own namespaces. Pass it explicitly to
    check a manifest against a registry that also holds other packs.
    """
    taken = frozenset(reserved) if reserved is not None else core_namespaces()
    prefix = f"{namespace}."
    if namespace in taken:
        raise ManifestError(
            f"{where}: namespace '{namespace}' is already taken; a pack cannot "
            f"claim a namespace that is not its own")
    for verb in verbs:
        if not verb.startswith(prefix):
            raise ManifestError(
                f"{where}: verb '{verb}' is outside namespace '{namespace}'. A "
                f"pack may map only verbs it owns: mapping someone else's verb "
                f"would let it declare an outbound call as harmless and bypass "
                f"the egress check")


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------

def _max_input(builtin: bool) -> int:
    return MAX_VALUE_LENGTH if builtin else PACK_MAX_INPUT


def _parse_form(raw: Any, where: str, builtin: bool = False) -> Form:
    data = _mapping(raw, where)
    label = _text(data.get("label"), f"{where}.label", required=False)
    pattern = _compiled(data.get("pattern"), f"{where}.pattern", builtin=builtin)
    example = _text(data.get("example"), f"{where}.example", required=False)
    if example and not pattern.fullmatch(example):
        # The cheapest possible proof that the regex says what the author meant.
        raise ManifestError(
            f"{where}: example '{example}' does not match the declared pattern "
            f"'{pattern.pattern}'")
    return Form(label=label, pattern=pattern, example=example,
                max_input=_max_input(builtin))


def _parse_canonicalisation(raw: Any, where: str, scheme: str,
                            builtin: bool = False) -> Canonicalisation:
    data = _mapping(raw, where)
    pattern = _compiled(data.get("from"), f"{where}.from", builtin=builtin)
    template = _text(data.get("to"), f"{where}.to")
    # Review of #358: a rule rewrites a URI into THIS scheme, and it rewrites
    # it into something taken from the URI. `{from: '^.*', to: '*'}` turned
    # every whitelist rule into `*`.
    if not template.startswith(f"{scheme}:"):
        raise ManifestError(
            f"{where}.to: '{template}' must produce a '{scheme}:' URI; a "
            f"scheme canonicalises into itself, never into another scheme or "
            f"into a wildcard")
    if not _placeholders(template):
        raise ManifestError(
            f"{where}.to: '{template}' uses no capture group, so every URI it "
            f"matches would become the same destination")
    for ref in _placeholders(template):
        if not ref.isdigit():
            raise ManifestError(
                f"{where}.to: '{{{ref}}}' is not a capture group; a "
                f"canonicalisation refers to groups by number")
        if not (1 <= int(ref) <= pattern.groups):
            raise ManifestError(
                f"{where}.to: group {{{ref}}} does not exist in '{pattern.pattern}' "
                f"(it captures {pattern.groups})")
    return Canonicalisation(pattern=pattern, template=template,
                            max_input=_max_input(builtin))


def _parse_scheme(raw: Any, where: str, builtin: bool = False) -> Scheme:
    data = _mapping(raw, where)
    name = _matching(_text(data.get("scheme"), f"{where}.scheme"), _SCHEME,
                     f"{where}.scheme")
    direction = _one_of(_text(data.get("direction"), f"{where}.direction"),
                        DIRECTIONS, f"{where}.direction")
    forms = tuple(
        _parse_form(f, f"{where}.forms[{i}]", builtin)
        for i, f in enumerate(_seq(data.get("forms"), f"{where}.forms")))
    canon = tuple(
        _parse_canonicalisation(c, f"{where}.canonicalise[{i}]", name, builtin)
        for i, c in enumerate(
            _seq(data.get("canonicalise"), f"{where}.canonicalise")))
    return Scheme(
        name=name,
        direction=direction,
        label=_text(data.get("label"), f"{where}.label", required=False),
        icon=_text(data.get("icon"), f"{where}.icon", required=False),
        danger=_text(data.get("danger"), f"{where}.danger", required=False),
        hierarchical=_flag(data.get("hierarchical"), f"{where}.hierarchical"),
        lowercase=_flag(data.get("lowercase"), f"{where}.lowercase"),
        wildcard=_flag(data.get("wildcard"), f"{where}.wildcard", default=True),
        forms=forms,
        canonicalise=canon,
    )


def _parse_credential(raw: Any, where: str) -> Credential:
    data = _mapping(raw, where)
    kind = _one_of(_text(data.get("kind"), f"{where}.kind"), CREDENTIAL_KINDS,
                   f"{where}.kind")
    vault_entry = _text(data.get("vault_entry"), f"{where}.vault_entry",
                        required=kind == "form")
    if vault_entry:
        _matching(vault_entry, _VAULT_ENTRY, f"{where}.vault_entry")
    fields = []
    for i, f in enumerate(_seq(data.get("fields"), f"{where}.fields")):
        fdata = _mapping(f, f"{where}.fields[{i}]")
        fields.append(CredentialField(
            name=_matching(_text(fdata.get("name"), f"{where}.fields[{i}].name"),
                           _FIELD_NAME, f"{where}.fields[{i}].name"),
            label=_text(fdata.get("label"), f"{where}.fields[{i}].label",
                        required=False),
            secret=_flag(fdata.get("secret"), f"{where}.fields[{i}].secret"),
            required=_flag(fdata.get("required"), f"{where}.fields[{i}].required",
                           default=True),
            placeholder=_text(fdata.get("placeholder"),
                              f"{where}.fields[{i}].placeholder", required=False),
        ))
    if kind == "form" and not fields:
        raise ManifestError(
            f"{where}: a 'form' credential with no fields cannot be filled in")
    scopes = tuple(
        _text(s, f"{where}.scopes[{i}]")
        for i, s in enumerate(_seq(data.get("scopes"), f"{where}.scopes")))
    return Credential(
        kind=kind,
        vault_entry=vault_entry,
        fields=tuple(fields),
        scopes=scopes,
        authorize_url=_text(data.get("authorize_url"), f"{where}.authorize_url",
                            required=kind == "oauth"),
        token_url=_text(data.get("token_url"), f"{where}.token_url",
                        required=kind == "oauth"),
    )


def _parse_transport(raw: Any, where: str) -> Transport:
    """`transport: {backend, tool}` — both names, never a command or a URL.

    The backend is NAMED, not described: what it runs and with which secrets
    is the mount's business (`mcp_backends`, stamped with the pack that
    mounted it). A manifest that could spell a command here would be a second,
    unreviewed way to mount a process. Whether the named backend is really the
    pack's own is checked when it is used (`resolved.transport_for`), because
    a mount can change after the manifest was read.
    """
    data = _mapping(raw, where)
    unknown = sorted(set(data) - {"backend", "tool"})
    if unknown:
        raise ManifestError(
            f"{where}: unknown keys {', '.join(unknown)}; a transport names a "
            f"mounted MCP backend and one of its tools, nothing else")
    return Transport(
        backend=_matching(_text(data.get("backend"), f"{where}.backend"), _ID,
                          f"{where}.backend"),
        tool=_matching(_text(data.get("tool"), f"{where}.tool"), _ARG,
                       f"{where}.tool"))


def _parse_provider(raw: Any, where: str, *, pack: str,
                    builtin: bool = False) -> Provider:
    data = _mapping(raw, where)
    cred = data.get("credential")
    transport = None
    if data.get("transport") is not None:
        if builtin:
            # A gateway manifest describes what the GATEWAY implements: its
            # transport is in-process by definition, and a builtin naming a
            # backend would route a native verb's credentials to whatever is
            # mounted under that name.
            raise ManifestError(
                f"{where}.transport: a gateway manifest cannot declare a "
                f"transport — only a PACK provider hands the gateway's I/O to "
                f"an MCP backend")
        transport = _parse_transport(data.get("transport"), f"{where}.transport")
    return Provider(
        id=_matching(_text(data.get("id"), f"{where}.id"), _ID, f"{where}.id"),
        label=_text(data.get("label"), f"{where}.label", required=False)
        or _text(data.get("id"), f"{where}.id"),
        pack=pack,
        credential=_parse_credential(cred, f"{where}.credential") if cred else None,
        status_verb=_text(data.get("status_verb"), f"{where}.status_verb",
                          required=False),
        test_verb=_text(data.get("test_verb"), f"{where}.test_verb", required=False),
        transport=transport,
    )


def _parse_defaults(raw: Any, where: str) -> tuple[DefaultArg, ...]:
    """Il blocco `defaults:` — `[{verb, arg, value}]`."""
    out = []
    for i, entry in enumerate(_seq(raw, where)):
        at = f"{where}[{i}]"
        data = _mapping(entry, at)
        out.append(DefaultArg(
            verb=_matching(_text(data.get("verb"), f"{at}.verb"), _VERB, f"{at}.verb"),
            arg=_matching(_text(data.get("arg"), f"{at}.arg"), _ARG, f"{at}.arg"),
            value=_one_of(_text(data.get("value"), f"{at}.value"), DEFAULT_VALUES,
                          f"{at}.value")))
    return tuple(out)


def _parse_files(raw: Any, where: str) -> tuple[FileArgument, ...]:
    """Il blocco `files:` — gli argomenti di file che il gateway consegna."""
    out = []
    for i, entry in enumerate(_seq(raw, where)):
        at = f"{where}[{i}]"
        data = _mapping(entry, at)
        campi = {}
        for chiave, obbligatorio in (("path_arg", True), ("bytes_arg", True),
                                     ("name_arg", False), ("tier_arg", False),
                                     ("topic_arg", False), ("chat_arg", False)):
            valore = _text(data.get(chiave), f"{at}.{chiave}", required=obbligatorio)
            if valore:
                _matching(valore, _ARG, f"{at}.{chiave}")
            campi[chiave] = valore
        if campi["path_arg"] == campi["bytes_arg"]:
            raise ManifestError(
                f"{at}: 'path_arg' e 'bytes_arg' sono lo stesso argomento: i byte "
                f"sovrascriverebbero il percorso da cui sono stati letti")
        out.append(FileArgument(
            verb=_matching(_text(data.get("verb"), f"{at}.verb"), _VERB,
                           f"{at}.verb"),
            **campi))
    return tuple(out)


def _parse_verb(raw: Any, where: str) -> VerbMapping:
    data = _mapping(raw, where)
    verb = _matching(_text(data.get("verb"), f"{where}.verb"), _VERB, f"{where}.verb")
    direction = _one_of(_text(data.get("direction"), f"{where}.direction"),
                        VERB_DIRECTIONS, f"{where}.direction")
    scheme = _matching(_text(data.get("scheme"), f"{where}.scheme"), _SCHEME,
                       f"{where}.scheme")
    normalise = _text(data.get("normalise"), f"{where}.normalise", required=False)
    if normalise:
        _one_of(normalise, NORMALISERS, f"{where}.normalise")
    arg = _text(data.get("arg"), f"{where}.arg", required=not normalise)
    if arg:
        _matching(arg, _ARG, f"{where}.arg")
    reads = _one_of(
        _text(data.get("reads"), f"{where}.reads", required=False,
              default="arguments"), READS_FROM, f"{where}.reads")
    if reads == "result" and direction != "source":
        raise ManifestError(
            f"{where}.reads: only a read can take its destination from the "
            f"result; an outbound call is judged before it happens")
    template = _text(data.get("template"), f"{where}.template", required=False)
    if template and "{value}" not in template:
        raise ManifestError(
            f"{where}.template: '{template}' never uses {{value}}, so every call "
            f"would map to the same destination")
    return VerbMapping(
        verb=verb,
        direction=direction,
        scheme=scheme,
        arg=arg,
        template=template,
        multi=_flag(data.get("multi"), f"{where}.multi"),
        dtype=_text(data.get("dtype"), f"{where}.dtype", required=False),
        prefix=_flag(data.get("prefix"), f"{where}.prefix"),
        normalise=normalise,
        reads=reads,
    )


def _parse_topic_action(raw: Any, where: str) -> TopicAction:
    data = _mapping(raw, where)
    fields = []
    for i, f in enumerate(_seq(data.get("fields"), f"{where}.fields")):
        fdata = _mapping(f, f"{where}.fields[{i}]")
        fields.append(ActionField(
            name=_matching(_text(fdata.get("name"), f"{where}.fields[{i}].name"),
                           _FIELD_NAME, f"{where}.fields[{i}].name"),
            label=_text(fdata.get("label"), f"{where}.fields[{i}].label",
                        required=False),
            required=_flag(fdata.get("required"), f"{where}.fields[{i}].required",
                           default=True),
            placeholder=_text(fdata.get("placeholder"),
                              f"{where}.fields[{i}].placeholder", required=False),
            options=_one_of(
                _text(fdata.get("options"), f"{where}.fields[{i}].options",
                      required=False, default=""),
                ("",) + OPTION_SETS, f"{where}.fields[{i}].options"),
        ))
    # I nomi interpolabili: quelli dei campi, più i valori che un insieme
    # RISOLVE. `{address}` esiste perché la casella scelta porta con sé il
    # proprio indirizzo — ed è l'indirizzo, non il nome dell'account, la cosa
    # che finisce in whitelist.
    known = {f.name for f in fields}
    for f in fields:
        known.update(OPTION_SET_VALUES.get(f.options, ()))
    adds = _mapping(data.get("adds") or {}, f"{where}.adds")
    out: dict[str, tuple[str, ...]] = {}
    for key in ("ingress", "egress"):
        templates = []
        for i, t in enumerate(_seq(adds.get(key), f"{where}.adds.{key}")):
            tpl = _text(t, f"{where}.adds.{key}[{i}]")
            for ref in _placeholders(tpl):
                if ref not in known:
                    raise ManifestError(
                        f"{where}.adds.{key}[{i}]: '{{{ref}}}' is not one of the "
                        f"action's fields ({', '.join(sorted(known)) or 'none'})")
            templates.append(tpl)
        out[key] = tuple(templates)
    return TopicAction(
        id=_matching(_text(data.get("id"), f"{where}.id"), _ID, f"{where}.id"),
        label=_text(data.get("label"), f"{where}.label"),
        fields=tuple(fields),
        adds_ingress=out["ingress"],
        adds_egress=out["egress"],
        binding=_binding(data.get("binding"), f"{where}.binding"),
        admin_only=_flag(data.get("admin_only"), f"{where}.admin_only",
                         default=False),
    )


def _binding(raw: Any, where: str) -> str:
    """`binding` is a closed set: a typo (`chanel`) is a refusal, not an action
    that silently adds the whitelist entries and skips the binding."""
    value = _text(raw, where, required=False)
    return _one_of(value, BINDINGS, where) if value else ""


def _check_action_schemes(actions, owned, where: str, *,
                          require_forms: bool = False) -> None:
    """Every template of a topic action starts with a LITERAL scheme the
    connector owns: `tg:{chat}` yes, `{url}` or `https://{host}/` no — those
    would let whoever fills the field whitelist any address without the WALLS
    gate (review of #360)."""
    for a in actions:
        for key, templates in (("ingress", a.adds_ingress),
                               ("egress", a.adds_egress)):
            for tpl in templates:
                scheme, sep, _rest = tpl.partition(":")
                if not sep or scheme not in owned or "{" in scheme:
                    raise ManifestError(
                        f"{where}.topic_actions '{a.id}'.adds.{key}: '{tpl}' "
                        f"must start with one of the connector's own schemes "
                        f"({', '.join(sorted(owned)) or 'none'}), written out")
                # Second verification of #360: a scheme with no `forms` accepts
                # anything (`courier:*` included), so the run-time form check
                # would check nothing. A pack's action may write only into a
                # scheme that says what its addresses look like.
                if require_forms and isinstance(owned, Mapping) \
                        and not owned[scheme].forms:
                    raise ManifestError(
                        f"{where}.topic_actions '{a.id}'.adds.{key}: scheme "
                        f"'{scheme}' declares no `forms`, so any value — a "
                        f"wildcard included — would be written; declare its "
                        f"forms")


def _docs_url(raw: Any, where: str) -> str:
    """`docs_url` goes into an `href` on the Tools page, where the session
    token sits in localStorage: a `javascript:` or `data:` URL would run in
    that origin. A pack may point at its documentation, nothing else, so only
    an absolute `https://` URL with a host is accepted (review of #365).

    A HOST, not a netloc (clodia-platform#545 §7): `https://@` and
    `https://:443` have a netloc and no hostname, and a control character —
    NUL included — goes through `urlsplit` untouched. Userinfo is refused as
    well: `https://docs.pack.io@evil.it` reads as the first host and resolves
    to the second, and no documentation link needs credentials.
    """
    value = _text(raw, where, required=False)
    if not value:
        return ""
    try:
        parts = urlsplit(value)
        host = parts.hostname
    except ValueError:
        # `https://[` raises here, and a ValueError escaping the parser used
        # to empty the WHOLE registry instead of refusing this one pack
        # (review of clodia-tools#369).
        parts, host = None, None
    if parts is None or not value.startswith("https://") or parts.scheme != "https" \
            or not host or "@" in parts.netloc \
            or any(c.isspace() or not c.isprintable() for c in value):
        raise ManifestError(
            # `repr`: the refused value may carry control characters, and a log
            # line or a card that prints them raw is a second defect.
            f"{where}: {value!r} is not an https:// URL with a host; "
            f"only https:// documentation links are accepted")
    return value


def _parse_tools_card(raw: Any, where: str) -> ToolsCard:
    data = _mapping(raw, where)
    return ToolsCard(
        setup_label=_text(data.get("setup_label"), f"{where}.setup_label",
                          required=False),
        status_verb=_text(data.get("status_verb"), f"{where}.status_verb",
                          required=False),
        test_verb=_text(data.get("test_verb"), f"{where}.test_verb", required=False),
        docs_url=_docs_url(data.get("docs_url"), f"{where}.docs_url"),
        blurb=_text(data.get("blurb"), f"{where}.blurb", required=False),
        scope=_text(data.get("scope"), f"{where}.scope", required=False),
        icon=_text(data.get("icon"), f"{where}.icon", required=False),
    )


def _parse_int(raw: Any, where: str, *, default: int, minimum: int = 1) -> int:
    if raw is None:
        return default
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise ManifestError(f"{where}: expected a whole number, got {raw!r}")
    if raw < minimum:
        raise ManifestError(f"{where}: must be at least {minimum}, got {raw}")
    return raw


def workdir_problem(workdir: str) -> str:
    """Why `workdir` may not be a service's working directory, or "".

    The supervisor `chdir`s into it BEFORE dropping privileges (that is how
    CPython's `Popen(user=…)` works), so an arbitrary path would put the service
    inside a directory its uid could never enter — `/gateway-state`, the vault.
    A workdir is therefore a path RELATIVE to the pack directory, with no `..`
    and nothing absolute; empty means the service state dir. Symlinks are
    resolved, and the result re-confined, at launch (`services.launch`).
    """
    if not workdir:
        return ""
    if "\x00" in workdir or "\\" in workdir:
        return f"workdir '{workdir}' contains a forbidden character"
    if workdir.startswith(("/", "~")):
        return (f"workdir '{workdir}' is absolute; it must be relative to the "
                f"pack directory (empty means the service state dir)")
    if ".." in workdir.split("/"):
        return f"workdir '{workdir}' leaves the pack directory ('..')"
    return ""


def _workdir(raw: Any, where: str) -> str:
    workdir = _text(raw, where, required=False)
    problem = workdir_problem(workdir)
    if problem:
        raise ManifestError(f"{where}: {problem}")
    return workdir


def _parse_service(raw: Any, where: str, *, pack: str) -> Service:
    data = _mapping(raw, where)
    name = _matching(_text(data.get("name"), f"{where}.name"), _ID, f"{where}.name")
    raw_command = data.get("command")
    if isinstance(raw_command, str):
        raise ManifestError(
            f"{where}.command: expected a list of arguments, got a string. A "
            f"string would be run through a shell, and a shell is a way to hide "
            f"a second process inside a manifest that declares one")
    command = tuple(
        _text(c, f"{where}.command[{i}]")
        for i, c in enumerate(_seq(raw_command, f"{where}.command")))
    if not command:
        raise ManifestError(f"{where}.command: required")
    credentials = tuple(
        _matching(_text(c, f"{where}.credentials[{i}]"), _VAULT_ENTRY,
                  f"{where}.credentials[{i}]")
        for i, c in enumerate(_seq(data.get("credentials"), f"{where}.credentials")))
    health = _mapping(data.get("health") or {}, f"{where}.health")
    health_kind = ""
    health_target = ""
    health_interval = 30
    if health:
        health_kind = _one_of(_text(health.get("kind"), f"{where}.health.kind"),
                              HEALTH_KINDS, f"{where}.health.kind")
        health_target = _text(health.get("target"), f"{where}.health.target")
        health_interval = _parse_int(health.get("interval_seconds"),
                                     f"{where}.health.interval_seconds", default=30)
    restart = _mapping(data.get("restart") or {}, f"{where}.restart")
    policy = "on-failure"
    backoff = 5
    if restart:
        policy = _one_of(_text(restart.get("policy"), f"{where}.restart.policy"),
                         RESTART_POLICIES, f"{where}.restart.policy")
        backoff = _parse_int(restart.get("backoff_seconds"),
                             f"{where}.restart.backoff_seconds", default=5)
    return Service(
        name=name,
        pack=pack,
        command=command,
        workdir=_workdir(data.get("workdir"), f"{where}.workdir"),
        credentials=credentials,
        health_kind=health_kind,
        health_target=health_target,
        health_interval=health_interval,
        restart=policy,
        backoff_seconds=backoff,
    )


#: Sections that belong to whoever owns the vocabulary. A contributor adds an
#: implementation, never a meaning: letting it re-declare a scheme, a canonical
#: form or a verb mapping would hand the vocabulary of another pack to the one
#: that installed second.
#: `context`, `files` e `defaults` sono fra questi perché sono frasi sui VERBI
#: del namespace, e i verbi sono del proprietario del vocabolario: un
#: contributore che potesse dichiararli riscriverebbe gli argomenti delle
#: chiamate altrui — o si farebbe consegnare i file di topic, o la chat legata
#: al canale, per il verbo di un altro.
#: `relay` and `pairing` (#638, #639) as well: a transport speaks the
#: vocabulary's own URIs, and the vocabulary is its owner's.
_OWNER_ONLY = ("schemes", "verbs", "taint", "topic_actions", "context",
               "files", "defaults", "relay", "pairing")

#: Hosts a relay or pairing `base` may name: the gateway's own loopback, as
#: `services.launch.LOOPBACK` (a service listens on loopback only, #515).
_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")
#: A path on a service's loopback API (`pairing.status`, `pairing.start`).
_SERVICE_PATH = re.compile(r"^/[A-Za-z0-9._~-]{1,32}(?:/[A-Za-z0-9._~-]{1,32}){0,3}$")
#: Longest relay label: it is a name in a room, not a sentence.
MAX_RELAY_LABEL = 32
#: The SEAL cap of a pack relay that declares none (#638): SEAL-1, Telegram's.
DEFAULT_RELAY_SEAL_CAP = 1


def loopback_base_problem(value: str) -> str:
    """Why `value` may not be a service `base` (relay, pairing), or "".

    `http://<loopback>:<port>` and nothing else: no https (loopback needs no
    TLS, and a certificate check would only fail), no userinfo, no path, no
    query, no fragment. The gateway appends the operation's path itself, so a
    base with a path would be a way to aim the forward somewhere the contract
    does not name. Exported so the forwarding code re-checks at call time.
    """
    if not isinstance(value, str) or not value:
        return "required"
    if any(c.isspace() or not c.isprintable() or c == "\\" for c in value):
        return f"{value!r} contains a forbidden character"
    try:
        parts = urlsplit(value)
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return f"{value!r} is not a URL"
    if parts.scheme != "http" or not value.startswith("http://"):
        return f"{value!r} is not an http:// URL"
    if "@" in parts.netloc or parts.username is not None:
        return f"{value!r} carries userinfo"
    if parts.path or parts.query or parts.fragment or value.endswith(("?", "#")):
        return f"{value!r} has a path, a query or a fragment; a base is scheme, host and port"
    if host.lower() not in _LOOPBACK_HOSTS:
        return (f"{value!r} is not on loopback (127.0.0.1, localhost, [::1]): a "
                f"pack service is reachable by the gateway only")
    if port is None or not (1 <= port <= 65535):
        return f"{value!r} names no port"
    return ""


def _base(raw: Any, where: str) -> str:
    value = _text(raw, where)
    problem = loopback_base_problem(value)
    if problem:
        raise ManifestError(f"{where}: {problem}")
    return value


def _own_service(raw: Any, where: str, services: Sequence[Service]) -> Service:
    name = _matching(_text(raw, where), _ID, where)
    service = next((s for s in services if s.name == name), None)
    if service is None:
        raise ManifestError(
            f"{where}: '{name}' is not one of this connector's services "
            f"({', '.join(s.name for s in services) or 'none'}); a transport "
            f"runs in the pack that declares it")
    return service


def _host_port(value: str, kind: str) -> tuple[str, int] | None:
    """`(host, port)` of a base URL or of a health target, or None."""
    try:
        if kind == "tcp":
            host, _, port = value.rpartition(":")
            return host.strip("[]").lower(), int(port)
        parts = urlsplit(value)
        if parts.port is None:
            return None
        return (parts.hostname or "").lower(), parts.port
    except ValueError:
        return None


def _check_base_is_the_service(base: str, service: Service, where: str) -> None:
    """The base must be WHERE THE SERVICE LISTENS, as its health check says.

    The supervisor's `health` target is the only statement of the service's
    address the gateway verifies at run time (#515: loopback only); a base that
    pointed elsewhere would forward to whatever else listens on loopback —
    another pack's service, or a port of the gateway itself.
    """
    if service.health_kind not in ("http", "tcp"):
        raise ManifestError(
            f"{where}: service '{service.name}' must declare an http or tcp "
            f"`health` check on the address the gateway calls")
    declared = _host_port(service.health_target, service.health_kind)
    if declared is None or declared != _host_port(base, "http"):
        raise ManifestError(
            f"{where}: base {base!r} is not where service '{service.name}' "
            f"listens (health target {service.health_target!r}): host and port "
            f"must be the same")


def _service_path(raw: Any, where: str, default: str) -> str:
    value = _text(raw, where, required=False, default=default)
    if not _SERVICE_PATH.match(value) or ".." in value.split("/"):
        raise ManifestError(
            f"{where}: {value!r} is not a plain path ('/status', '/pair')")
    return value


#: The name of a mounted MCP backend, as `tools_api._slugify` produces it.
_BACKEND_SLUG = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$")


def _transport_form(data: Mapping, where: str) -> str:
    """`backend` or "" (= `service`/`base`), refusing a mix of the two (#641)."""
    has_backend = data.get("backend") is not None
    has_service = data.get("service") is not None or data.get("base") is not None
    if has_backend and has_service:
        raise ManifestError(
            f"{where}: declares both `backend` and `service`/`base`; a transport "
            f"is either a mounted MCP backend or a supervised service, not both")
    if not has_backend:
        return ""
    name = _text(data.get("backend"), f"{where}.backend")
    if not _BACKEND_SLUG.match(name):
        raise ManifestError(
            f"{where}.backend: {name!r} is not a mounted MCP backend name "
            f"(lowercase letters, digits and '-', at most 40)")
    return name


def _parse_relay(raw: Any, where: str, *, services: Sequence[Service],
                 schemes: Sequence[Scheme]) -> Relay:
    data = _mapping(raw, where)
    unknown = sorted(set(data) - {"service", "base", "label", "attachments",
                                  "seal_cap", "backend"})
    if unknown:
        raise ManifestError(f"{where}: unknown keys {', '.join(unknown)}")
    if not any(s.forms for s in schemes):
        # The gateway vets every row's `chat_uri`/`sender_uri` against the
        # connector's own forms; a scheme without forms accepts anything, so
        # there would be nothing to vet against.
        raise ManifestError(
            f"{where}: a relay needs at least one of the connector's schemes "
            f"to declare `forms`: the gateway checks every relayed chat and "
            f"sender against them")
    label = _text(data.get("label"), f"{where}.label")
    if len(label) > MAX_RELAY_LABEL or any(not c.isprintable() for c in label):
        raise ManifestError(
            f"{where}.label: at most {MAX_RELAY_LABEL} printable characters")
    backend = _transport_form(data, where)
    if backend:
        service_name, base = "", ""
    else:
        service = _own_service(data.get("service"), f"{where}.service", services)
        base = _base(data.get("base"), f"{where}.base")
        _check_base_is_the_service(base, service, f"{where}.base")
        service_name = service.name
    cap = None
    if data.get("seal_cap") is not None:
        raw_cap = _text(data.get("seal_cap"), f"{where}.seal_cap")
        m = re.fullmatch(r"SEAL-([0-4])", raw_cap)
        if not m:
            raise ManifestError(
                f"{where}.seal_cap: {raw_cap!r} is not one of SEAL-0 … SEAL-4")
        cap = int(m.group(1))
    return Relay(
        service=service_name,
        base=base,
        label=label,
        attachments=_flag(data.get("attachments"), f"{where}.attachments"),
        seal_cap=cap,
        backend=backend)


def _parse_pairing(raw: Any, where: str, *,
                   services: Sequence[Service]) -> Pairing:
    data = _mapping(raw, where)
    unknown = sorted(set(data) - {"service", "base", "status", "start", "backend"})
    if unknown:
        raise ManifestError(f"{where}: unknown keys {', '.join(unknown)}")
    backend = _transport_form(data, where)
    if backend:
        if data.get("status") is not None or data.get("start") is not None:
            raise ManifestError(
                f"{where}: `status`/`start` are paths of a service; a backend "
                f"offers the tools `pairing_status` and `pairing_start`")
        return Pairing(service="", base="", backend=backend)
    service = _own_service(data.get("service"), f"{where}.service", services)
    base = _base(data.get("base"), f"{where}.base")
    _check_base_is_the_service(base, service, f"{where}.base")
    return Pairing(
        service=service.name,
        base=base,
        status=_service_path(data.get("status"), f"{where}.status", "/status"),
        start=_service_path(data.get("start"), f"{where}.start", "/pair"))


def _parse_context(raw: Any, where: str) -> tuple[ContextArg, ...]:
    """Il blocco `context:` di un connettore: `{arg, value}` per riga."""
    out: list[ContextArg] = []
    seen: set[str] = set()
    for i, item in enumerate(_seq(raw, f"{where}.context")):
        at = f"{where}.context[{i}]"
        data = _mapping(item, at)
        arg = _matching(_text(data.get("arg"), f"{at}.arg"), _ARG, f"{at}.arg")
        value = _text(data.get("value"), f"{at}.value")
        if value not in CONTEXT_VALUES:
            raise ManifestError(
                f"{at}: context value '{value}' is not one the gateway can "
                f"fill; it knows {', '.join(CONTEXT_VALUES)}. A connector names "
                f"a fact about the call, it does not define one")
        if arg in seen:
            raise ManifestError(f"{at}: argument '{arg}' is filled twice")
        seen.add(arg)
        out.append(ContextArg(arg=arg, value=value))
    return tuple(out)


def parse_connector(raw: Any, *, pack: str,
                    reserved: Iterable[str] | None = None,
                    builtin: bool = False) -> Connector:
    """One entry of the `connectors:` block, validated on its own.

    `reserved` is passed through to `check_namespace`; cross-connector checks
    (duplicate ids, unknown `extends`, scheme owned twice) belong to
    `build_registry`, which is the only place that can see them.

    `builtin` marks a manifest the gateway ships with itself: it may declare the
    platform-intrinsic schemes, because that is where they are now declared, and
    its namespaces are the gateway's own. Nothing on disk can set it.
    """
    where = _at(pack)
    data = _mapping(raw, where)
    cid = _matching(_text(data.get("id"), f"{where}: connector id"), _ID,
                    f"{where}: connector id")
    where = _at(pack, cid)

    version = data.get("manifest_version")
    if version is None:
        raise ManifestError(f"{where}: manifest_version is required")
    if not isinstance(version, int) or isinstance(version, bool):
        raise ManifestError(
            f"{where}: manifest_version must be a whole number, got {version!r}")
    if version > MANIFEST_VERSION:
        raise ManifestError(
            f"{where}: manifest_version {version} is newer than this gateway "
            f"understands ({MANIFEST_VERSION}); refusing to read it with the "
            f"wrong rules")

    namespace = _matching(_text(data.get("namespace"), f"{where}.namespace"),
                          _NAMESPACE, f"{where}.namespace")
    extends = _text(data.get("extends"), f"{where}.extends", required=False)
    if extends:
        _matching(extends, _ID, f"{where}.extends")
        present = [s for s in _OWNER_ONLY if data.get(s)]
        if present:
            raise ManifestError(
                f"{where}: extends '{extends}', so it may not declare "
                f"{', '.join(present)} — those belong to the pack that owns the "
                f"vocabulary. A contributor adds a provider, not a meaning")
        if not data.get("providers"):
            raise ManifestError(
                f"{where}: extends '{extends}' but declares no provider, so it "
                f"contributes nothing")

    schemes = tuple(
        _parse_scheme(s, f"{where}.schemes[{i}]", builtin)
        for i, s in enumerate(_seq(data.get("schemes"), f"{where}.schemes")))
    seen_schemes: set[str] = set()
    for s in schemes:
        if s.name in CORE_SCHEMES and not builtin:
            raise ManifestError(
                f"{where}: scheme '{s.name}' is platform-intrinsic and stays in "
                f"the core manifest; a pack may map verbs onto it but not "
                f"redefine what it means")
        if s.name in seen_schemes:
            raise ManifestError(f"{where}: scheme '{s.name}' declared twice")
        seen_schemes.add(s.name)
    # A connector that only declares what of its own namespace taints is not
    # empty (#524): `google-calendar` has no verb with a destination or a
    # source, and `gcalendar.list_events` tainting is the whole of what the
    # PDP knows about it. Taint only ever makes a channel MORE restricted.
    if not (schemes or extends or data.get("providers") or data.get("verbs")
            or data.get("taint") or data.get("unmapped")):
        raise ManifestError(
            f"{where}: declares no scheme, no verb, no provider and no taint, "
            f"and extends nothing, so it is an empty connector")

    providers = tuple(
        _parse_provider(p, f"{where}.providers[{i}]", pack=pack, builtin=builtin)
        for i, p in enumerate(_seq(data.get("providers"), f"{where}.providers")))
    seen_providers: set[str] = set()
    for p in providers:
        if p.id in seen_providers:
            raise ManifestError(f"{where}: provider '{p.id}' declared twice")
        seen_providers.add(p.id)

    if not builtin:
        for p in providers:
            entry = p.credential.vault_entry if p.credential else ""
            problem = vault_entry_problem(entry, namespace, reserved) if entry else ""
            if problem:
                raise ManifestError(f"{where}.providers '{p.id}': {problem}")

    verbs = tuple(
        _parse_verb(v, f"{where}.verbs[{i}]")
        for i, v in enumerate(_seq(data.get("verbs"), f"{where}.verbs")))
    if not builtin:
        check_namespace(namespace, [v.verb for v in verbs], reserved=reserved,
                        where=where)
    danger_rules = tuple(
        DangerRule(
            pattern=_compiled(_mapping(d, f"{where}.danger_uris[{i}]").get("match"),
                              f"{where}.danger_uris[{i}].match", builtin=builtin),
            text=_text(_mapping(d, f"{where}.danger_uris[{i}]").get("text"),
                       f"{where}.danger_uris[{i}].text"),
            max_input=_max_input(builtin))
        for i, d in enumerate(_seq(data.get("danger_uris"),
                                   f"{where}.danger_uris")))

    taint = tuple(
        _text(t, f"{where}.taint[{i}]")
        for i, t in enumerate(_seq(data.get("taint"), f"{where}.taint")))
    for prefix in taint:
        if not builtin and not prefix.startswith(f"{namespace}."):
            raise ManifestError(
                f"{where}: taint prefix '{prefix}' is outside namespace "
                f"'{namespace}'. Declaring what does not taint a channel is a "
                f"statement about one's own tools, never about someone else's")

    unmapped: list[str] = []
    for i, raw_verb in enumerate(_seq(data.get("unmapped"), f"{where}.unmapped")):
        verb = _matching(_text(raw_verb, f"{where}.unmapped[{i}]"), _VERB,
                         f"{where}.unmapped[{i}]")
        if verb in unmapped:
            raise ManifestError(f"{where}: verb '{verb}' is listed twice in 'unmapped'")
        unmapped.append(verb)
    mapped_here = sorted({v.verb for v in verbs} & set(unmapped))
    if mapped_here:
        raise ManifestError(
            f"{where}: '{mapped_here[0]}' is both mapped in 'verbs' and listed in "
            f"'unmapped'. A verb either has a destination/source the PDP reads, "
            f"or it has none")
    if not builtin:
        check_namespace(namespace, unmapped, reserved=reserved, where=where)

    defaults = _parse_defaults(data.get("defaults"), f"{where}.defaults")
    if defaults and builtin:
        raise ManifestError(
            f"{where}: 'defaults' is for a connector a PACK implements; this "
            f"gateway resolves a binding from the inside")
    if not builtin:
        check_namespace(namespace, [d.verb for d in defaults], reserved=reserved,
                        where=where)
    files = _parse_files(data.get("files"), f"{where}.files")
    if files and builtin:
        raise ManifestError(
            f"{where}: 'files' is for a connector a PACK implements; this "
            f"gateway reads a topic file from the inside")
    if not builtin:
        # Stessa regola di namespace dei verbi (#516): un pack non si fa
        # consegnare i file di topic per il verbo di un altro.
        check_namespace(namespace, [f.verb for f in files], reserved=reserved,
                        where=where)

    actions = tuple(
        _parse_topic_action(a, f"{where}.topic_actions[{i}]")
        for i, a in enumerate(
            _seq(data.get("topic_actions"), f"{where}.topic_actions")))
    if not extends:
        # Review of #360: an action writes only into its connector's own
        # vocabulary. An `extends` provider is checked against the vocabulary
        # it joins, in `build_registry`, once that is resolved.
        _check_action_schemes(actions, {sch.name: sch for sch in schemes},
                              where, require_forms=not builtin)
    services = tuple(
        _parse_service(s, f"{where}.services[{i}]", pack=pack)
        for i, s in enumerate(_seq(data.get("services"), f"{where}.services")))
    seen_services: set[str] = set()
    for s in services:
        if s.name in seen_services:
            raise ManifestError(f"{where}: service '{s.name}' declared twice")
        seen_services.add(s.name)
        # Same rule as a provider credential (review of clodia-tools #362): a
        # service receives each declared entry as `CLODIA_CREDENTIAL_*`, so a
        # bare regex would hand any pack `github_pat` or another pack's token.
        for entry in s.credentials if not builtin else ():
            problem = vault_entry_problem(entry, namespace, reserved)
            if problem:
                raise ManifestError(f"{where}.services '{s.name}': {problem}")
    services = tuple(dataclasses.replace(s, namespace=namespace) for s in services)

    card = data.get("tools_card")
    remote = data.get("storage_remote")
    storage = None
    if remote:
        rdata = _mapping(remote, f"{where}.storage_remote")
        storage = StorageRemote(
            id=_matching(_text(rdata.get("id"), f"{where}.storage_remote.id"), _ID,
                         f"{where}.storage_remote.id"),
            label=_text(rdata.get("label"), f"{where}.storage_remote.label",
                        required=False),
            versioning=_flag(rdata.get("versioning"),
                             f"{where}.storage_remote.versioning"),
        )

    # No `seal_cap`: the owner decides a binding at the gate, which shows the
    # topic's tier (epic clodia-platform#527). Today's `_CHANNEL_SEAL_CAP` /
    # `_DRIVE_SEAL_CAP` die with #518 and must not come back as a field.
    if "seal_cap" in data:
        raise ManifestError(
            f"{where}: 'seal_cap' is not part of the manifest. There is no SEAL "
            f"ceiling on a binding: the owner decides, at the gate, per binding")

    context = _parse_context(data.get("context"), where)
    if context and builtin:
        # Un connettore che il GATEWAY implementa il contesto ce l'ha già: lo
        # legge dal processo, dal claim firmato della sessione. Scriverlo in un
        # argomento non gli aggiungerebbe niente e sovrascriverebbe un
        # argomento vero del verbo nativo. `context:` è per chi gira fuori di
        # qui. (Merito di #373, che chiudeva questa porta e io l'avevo lasciata
        # aperta.)
        raise ManifestError(
            f"{where}: 'context' is for a connector a PACK implements. A "
            f"gateway connector already has the call's context — it reads the "
            f"signed claim of the session — and filling an argument with it "
            f"would overwrite a real argument of the native verb")
    # Il gateway non riempie un argomento da cui il PDP ricava la destinazione.
    # Due ragioni, e basta la prima: la destinazione di una chiamata è una
    # proprietà della CHIAMATA — è ciò che l'owner legge sulla card e ciò che
    # la whitelist confronta — e lasciarla scrivere alla dichiarazione del
    # connettore significherebbe che a dire dove si va è il manifest. La
    # seconda: un fatto che il gateway non ha svuota l'argomento, e un
    # estrattore senza valore è un verbo senza destinazione dichiarata, cioè
    # il PDP disarmato su quel verbo, in silenzio.
    letti_dal_pdp = {v.arg for v in verbs if v.arg}
    collisione = sorted({a.arg for a in context} & letti_dal_pdp)
    if collisione:
        raise ManifestError(
            f"{where}: context fills '{collisione[0]}', which is also the "
            f"argument a verb mapping reads its destination from. A destination "
            f"is a property of the call, not of the manifest: pick another "
            f"argument name")

    relay = pairing = None
    for key in ("relay", "pairing"):
        if data.get(key) is not None and builtin:
            raise ManifestError(
                f"{where}: '{key}' is for a connector a PACK implements; it "
                f"names a service of the pack")
    if data.get("relay") is not None:
        relay = _parse_relay(data.get("relay"), f"{where}.relay",
                             services=services, schemes=schemes)
    if data.get("pairing") is not None:
        pairing = _parse_pairing(data.get("pairing"), f"{where}.pairing",
                                 services=services)

    return Connector(
        id=cid,
        label=_text(data.get("label"), f"{where}.label", required=False) or cid,
        pack=pack,
        namespace=namespace,
        extends=extends,
        schemes=schemes,
        providers=providers,
        verbs=verbs,
        danger_rules=danger_rules,
        taint_prefixes=taint,
        unmapped_verbs=tuple(unmapped),
        topic_actions=actions,
        tools_card=_parse_tools_card(card, f"{where}.tools_card") if card else None,
        services=services,
        storage_remote=storage,
        context=context,
        defaults=defaults,
        files=files,
        relay=relay,
        pairing=pairing,
        builtin=builtin,
    )


def load_manifest(pack_manifest: Mapping[str, Any], *, pack: str,
                  reserved: Iterable[str] | None = None,
                  builtin: bool = False) -> list[Connector]:
    """The `connectors:` block of one `pack.yaml`. No block → no connector."""
    raw = pack_manifest.get("connectors")
    if raw is None:
        return []
    entries = _seq(raw, f"{_at(pack)}: connectors")
    return [parse_connector(e, pack=pack, reserved=reserved, builtin=builtin)
            for e in entries]


def parse_services(pack_manifest: Mapping[str, Any], *, pack: str,
                   reserved: Iterable[str] | None = None) -> list[Service]:
    """Every service a pack declares, flattened — the entry point for #515.

    The supervisor reads the shape from here rather than parsing `pack.yaml`
    again: one format, one parser, one place where a field changes name.
    """
    return [s for c in load_manifest(pack_manifest, pack=pack, reserved=reserved)
            for s in c.services]


# --------------------------------------------------------------------------
# registry
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Registry:
    """Every connector of the installed packs, with `extends` resolved.

    A read-only view: #518 builds the PDP tables out of it. Nothing in here
    grants anything — see the module docstring.
    """

    connectors: tuple[Connector, ...] = ()
    #: Connectors dropped while building, with the reason. A pack that collides
    #: with a gateway connector is refused on its own, not by making the whole
    #: registry unbuildable: the alternative would be one malformed pack taking
    #: the PDP's tables down with it.
    refused: tuple[str, ...] = ()
    #: Non-empty when the gateway's OWN connectors could not be built: the
    #: reason. The PDP then fails closed instead of reading «no mapping» as
    #: «nothing to check» (review of #358).
    degraded: str = ""
    #: Outbound verbs of installed packs whose connectors could not be built:
    #: denied instead of «unmapped, allowed» (`resolved._failsafe_from`).
    failsafe_verbs: tuple[str, ...] = ()

    def by_id(self, cid: str) -> Connector | None:
        return next((c for c in self.connectors if c.id == cid), None)

    def scheme(self, name: str) -> Scheme | None:
        return next((s for s in self.schemes() if s.name == name), None)

    def mappings_for(self, verb: str,
                     direction: str) -> tuple[tuple[Connector, VerbMapping], ...]:
        """Every `(connector, mapping)` that describes `verb`, in declaration order.

        A verb may be mapped more than once — `email.send` to `to`, `cc` and
        `bcc` — and the destinations of one call are the union.

        An exact name wins over a prefix, and a builtin wins over a pack: the
        gateway's own connectors are consulted first for the same reason
        `egress.spec_for` consulted its tables before the registry (#517), and
        a prefix is a statement about the verbs nobody has named, so it must
        not quietly capture one that somebody has.
        """
        hits = [(c, v) for c in self.connectors for v in c.verbs
                if v.direction == direction and v.covers(verb)]
        for builtin in (True, False):
            for exact in (True, False):
                picked = tuple((c, v) for c, v in hits
                               if c.builtin is builtin and (not v.prefix) is exact)
                if picked:
                    return picked
        return ()

    def context_for(self, verb: str) -> tuple[tuple[Connector, ContextArg], ...]:
        """Gli `(connettore, argomento di contesto)` da riempire in `verb`.

        Selezionati per NAMESPACE e non fra i verbi mappati: un verbo in
        ingresso (`telegram.inbox`) non dichiara una destinazione, quindi non
        compare in `verbs:`, e ha comunque bisogno di sapere da quale stanza e
        da quale agente arriva la chiamata. Il namespace è già ciò che un pack
        deve dimostrare di possedere (`check_namespace`), e chi lo possiede
        possiede i suoi verbi: è la stessa autorità, non una più larga.
        """
        ns = verb.split(".", 1)[0] if "." in verb else ""
        if not ns:
            return ()
        return tuple((c, a) for c in self.connectors if c.namespace == ns
                     for a in c.context)

    def danger_for(self, uri: str) -> str:
        """The warning for this URI from a connector that claims its hosts, or
        `""`. Builtins first, so a pack cannot soften the gateway's own text.

        A PACK's rules apply only to URIs of a scheme that pack owns (review of
        #358): otherwise a pack matching every `https:` URI would replace the
        core warning of the shared scheme with its own text.
        """
        scheme = (uri or "").partition(":")[0].lower()
        for c in sorted(self.connectors, key=lambda c: not c.builtin):
            if not c.builtin and scheme not in {s.name for s in c.schemes}:
                continue
            for rule in c.danger_rules:
                if rule.matches(uri):
                    return rule.text
        return ""

    def elected_danger_for(self, uri: str, connector_ids: Iterable[str]) -> str:
        """The warning a PACK connector the owner put in a builtin's place
        declares for `uri` on a scheme it does not own, or `""`.

        clodia-platform#525. GitHub owns no scheme: «a public repository shows
        everything pushed there to anyone» hangs off `https:` URIs. While the
        gateway declared it that was a builtin rule; once it-pack declares the
        connector, `danger_for` (rightly) ignores a pack's rule on a shared
        scheme, and the warning would vanish from the gate card. A connector
        whose id the gateway hands to its first-party pack (`connector_ids`,
        `builtin.RELEASED_TO`) is not «any pack»: it is the elected one. Its rules
        apply — but the caller ADDS them to the scheme's own warning, never
        in place of it (`egress.danger_note`), so even the elected pack can
        say more than the core, never less.
        """
        ids = frozenset(connector_ids or ())
        if not ids:
            return ""
        scheme = (uri or "").partition(":")[0].lower()
        for c in self.connectors:
            if c.builtin or c.id not in ids:
                continue
            if scheme in {s.name for s in c.schemes}:
                continue          # its own scheme: `danger_for` already asked
            for rule in c.danger_rules:
                if rule.matches(uri):
                    return rule.text
        return ""

    def canonical(self, uri: str,
                  elected: Mapping[str, Iterable[str]] | None = None) -> str | None:
        """The first canonicalisation rule that rewrites `uri`, or None.

        A PACK's rules apply only to URIs of the scheme that declares them
        (review of #358): `canonicalise: [{from: '^.*', to: '*'}]` on a pack
        scheme used to rewrite every whitelist rule into `*`. The gateway's own
        rules may read a shared scheme — that is how a Drive URL copied from
        the browser becomes `gdrive:folder/<id>` — because they are code in
        the image, not input.

        `elected` (#524) is `{connector id: hosts}` for the pack connectors
        that replaced a builtin (`builtin.ELECTED_URL_HOSTS`). Such a
        connector's rules may also
        read an `http(s)` URL — but only one whose PARSED host is in its list:
        google-pack turns `https://drive.google.com/…` into `gdrive:folder/…`
        as the builtin did, and can never rewrite any other URL (a call's
        destination is canonicalised too, so `https://evil.example/` becoming
        an approved folder would be an egress bypass). The output is still in
        the connector's own scheme (`_parse_canonicalisation`).
        """
        scheme = (uri or "").partition(":")[0].lower()
        url_host = ""
        if elected and scheme in ("http", "https"):
            # The RAW prefix must be exactly `http(s)://<host>/` — no
            # userinfo, port, backslash or case games: Python's parser and a
            # browser's disagree on `https://evil.io\@drive.google.com/`
            # (review of clodia-tools#381).
            m = re.match(r"https?://([a-z0-9.-]+)/", uri or "")
            url_host = m.group(1) if m else ""
        for c in sorted(self.connectors, key=lambda c: not c.builtin):
            hosts = frozenset(h.lower() for h in (elected or {}).get(c.id, ())) \
                if not c.builtin else frozenset()
            for sch in c.schemes:
                if not c.builtin and sch.name != scheme \
                        and not (url_host and url_host in hosts):
                    continue
                for rule in sch.canonicalise:
                    out = rule.apply(uri)
                    if out is not None:
                        return out
        return None

    def vocabularies(self) -> tuple[Connector, ...]:
        return tuple(c for c in self.connectors if c.owns_vocabulary)

    def schemes(self, direction: str = "") -> tuple[Scheme, ...]:
        out = tuple(s for c in self.connectors for s in c.schemes)
        if direction == "egress":
            return tuple(s for s in out if s.is_egress)
        if direction == "source":
            return tuple(s for s in out if s.is_source)
        return out

    def scheme_names(self, direction: str = "") -> tuple[str, ...]:
        return tuple(sorted({s.name for s in self.schemes(direction)}))

    def providers_of(self, vocabulary: str) -> tuple[Provider, ...]:
        return tuple(p for c in self.connectors if c.vocabulary == vocabulary
                     for p in c.providers)

    def verb_map(self, direction: str = "egress") -> dict[str, VerbMapping]:
        return {v.verb: v for c in self.connectors for v in c.verbs
                if v.direction == direction}

    def defaults_for(self, verb: str) -> tuple[Connector, tuple[DefaultArg, ...]] | None:
        """Il connettore e i default dichiarati per QUESTO verbo, o None."""
        for c in self.connectors:
            if c.builtin:
                continue
            hits = tuple(d for d in c.defaults if d.verb == verb)
            if hits:
                return c, hits
        return None

    def file_for(self, verb: str) -> tuple[Connector, FileArgument] | None:
        """Il connettore e la dichiarazione di file per questa chiamata, o None.

        Per NOME ESATTO del verbo, e mai per un connettore `builtin`: consegnare
        dei byte a codice che vive dentro il gateway significherebbe leggere un
        file di topic due volte, e la seconda senza chi la sorveglia.
        """
        for c in self.connectors:
            if c.builtin:
                continue
            for f in c.files:
                if f.verb == verb:
                    return c, f
        return None

    def taint_prefixes(self) -> tuple[str, ...]:
        return tuple(sorted({p for c in self.connectors for p in c.taint_prefixes}))

    def unmapped_verbs(self) -> frozenset[str]:
        """Verbs a held connector declares as having no PDP mapping (#558)."""
        return frozenset(v for c in self.connectors for v in c.unmapped_verbs)

    def services(self) -> tuple[Service, ...]:
        return tuple(s for c in self.connectors for s in c.services)

    def topic_actions(self) -> tuple[TopicAction, ...]:
        return tuple(a for c in self.connectors for a in c.topic_actions)

    def relay_for_scheme(self, scheme: str) -> Connector | None:
        """The connector that owns `scheme` and declares a `relay:`, or None.

        Only a scheme with `forms` counts: those are the only URIs a relay is
        vetted against (`_parse_relay`), on the way in and on the way out.
        """
        name = (scheme or "").strip().lower()
        for c in self.connectors:
            if c.relay is not None and any(s.name == name and s.forms
                                           for s in c.schemes):
                return c
        return None


def build_registry(manifests: Mapping[str, Mapping[str, Any]], *,
                   reserved: Iterable[str] | None = None,
                   builtin: Iterable[str] = ()) -> Registry:
    """Resolve the connectors of every installed pack, in two passes.

    `manifests` maps pack name → the parsed `pack.yaml`. Two passes because
    `extends:` crosses packs and the install order is not an ordering: google-pack
    may well be installed before the pack that owns the mail vocabulary, and a
    first-pass failure there would mean a connector that works or not depending
    on the day it was installed.

    `builtin` names the manifests the gateway ships with itself (#518). They are
    parsed first and with the gateway's own privileges, and they **win** any
    collision with an installed pack: while the gateway still implements a
    connector natively, a pack claiming the same id or the same scheme is
    refused on its own — not merged, and not fatal to the registry. Letting the
    pack win would mean an installed manifest redefining what `mailto:` means
    while the native implementation is still the thing doing the sending.
    """
    reserved_set = set(core_namespaces() if reserved is None else reserved)
    builtin_names = list(dict.fromkeys(builtin))
    refused: list[str] = []
    parsed: list[Connector] = []
    for pack in builtin_names:
        parsed.extend(load_manifest(manifests[pack], pack=pack, builtin=True))
    builtin_ids = {c.id for c in parsed}
    builtin_schemes = {s.name for c in parsed for s in c.schemes}
    if reserved is None:
        # The namespaces of the gateway's own connectors are reserved against
        # the packs — belt and braces, since `core_namespaces()` already derives
        # them from the native verbs those connectors implement. Not added when
        # the caller passes `reserved` explicitly: that is how a registry from
        # BEFORE the gateway owned a namespace is reproduced, which is the only
        # way to hold a mapping that is illegitimate today (#517, call time).
        reserved_set.update(c.namespace for c in parsed)

    builtin_namespaces = {c.namespace for c in parsed}
    #: Names a pack namespace may not be a `_`-prefix of: with `foo` installed,
    #: `foo_bar…` entries would fall to the pack whenever the core `foo_bar`
    #: namespace is not itself a connector in this registry.
    core_names = set(reserved_set) | builtin_namespaces | set(reserved_namespaces())
    for pack in sorted(set(manifests) - set(builtin_names)):
        # Each pack is checked against the gateway's namespaces *and* against the
        # namespaces already claimed by the packs parsed before it.
        try:
            entries = _seq((manifests[pack] or {}).get("connectors"),
                           f"{_at(pack)}: connectors")
        except ManifestError as e:
            raise _blame(e, pack)
        for entry in entries:
            # The namespace of a connector the GATEWAY still implements is read
            # before parsing, because `check_namespace` would refuse the whole
            # manifest for it — and that would make the pack of the pending
            # migration uninstallable (comms-pack declares `telegram.` while the
            # native verbs still exist, clodia-platform#519). It is the same
            # situation as the id and scheme collisions below and it gets the
            # same answer: the connector is ignored, loudly, and becomes
            # effective by itself the day the builtin file goes away.
            ns = str((entry or {}).get("namespace") or "") \
                if isinstance(entry, Mapping) else ""
            shadowed = sorted(n for n in core_names if n.startswith(f"{ns}_")) \
                if ns else []
            if shadowed:
                raise _blame(ManifestError(
                    f"{_at(pack, str((entry or {}).get('id') or '?'))}: namespace "
                    f"'{ns}' is a prefix of the gateway's namespace "
                    f"'{shadowed[0]}', so its vault entries would overlap; "
                    f"choose a namespace that is not"), pack)
            if ns and ns in builtin_namespaces:
                refused.append(
                    f"{_at(pack, str((entry or {}).get('id') or '?'))}: namespace "
                    f"'{ns}' is still implemented by this gateway, so the pack's "
                    f"connector is ignored. It becomes effective when that "
                    f"implementation moves into a pack (epic clodia-platform#527)")
                continue
            try:
                connector = parse_connector(entry, pack=pack,
                                            reserved=reserved_set)
            except ManifestError as e:
                # A namespace already claimed by an earlier pack: both are
                # refused, so the winner is not whoever sorts first.
                claimant = next((c.pack for c in parsed if not c.builtin
                                 and c.namespace == ns), "")
                raise _blame(e, pack, claimant)
            clash = ""
            if connector.id in builtin_ids:
                clash = f"connector id '{connector.id}'"
            else:
                taken = [s.name for s in connector.schemes
                         if s.name in builtin_schemes]
                if taken:
                    clash = f"scheme '{taken[0]}'"
            if clash:
                refused.append(
                    f"{_at(pack, connector.id)}: {clash} is still implemented by "
                    f"this gateway, so the pack's connector is ignored. It "
                    f"becomes effective when that implementation moves into a "
                    f"pack (epic clodia-platform#527)")
                continue
            parsed.append(connector)
        reserved_set.update(
            c.namespace for c in parsed if c.pack == pack)

    by_id: dict[str, Connector] = {}
    for c in parsed:
        if c.id in by_id:
            raise _blame(ManifestError(
                f"connector '{c.id}' is declared by both '{by_id[c.id].pack}' and "
                f"'{c.pack}'"), by_id[c.id].pack, c.pack)
        by_id[c.id] = c

    scheme_owner: dict[str, Connector] = {}
    for c in parsed:
        for s in c.schemes:
            other = scheme_owner.get(s.name)
            if other is not None:
                raise _blame(ManifestError(
                    f"scheme '{s.name}' is declared by both '{other.pack}' "
                    f"(connector '{other.id}') and '{c.pack}' (connector "
                    f"'{c.id}'); a scheme vocabulary has exactly one owner"),
                    other.pack, c.pack)
            scheme_owner[s.name] = c

    provider_owner: dict[tuple[str, str], Connector] = {}
    for c in parsed:
        if c.extends:
            target = by_id.get(c.extends)
            if target is None:
                raise _blame(ManifestError(
                    f"{_at(c.pack, c.id)}: extends '{c.extends}', which no "
                    f"installed pack declares. Install the pack that owns that "
                    f"vocabulary, or fix the name"), c.pack)
            if not target.owns_vocabulary:
                raise _blame(ManifestError(
                    f"{_at(c.pack, c.id)}: extends '{c.extends}', which is "
                    f"itself an extension; a provider attaches to the vocabulary "
                    f"owner, not to another provider"), c.pack)
            try:
                _check_action_schemes(c.topic_actions,
                                      {sch.name: sch for sch in target.schemes},
                                      _at(c.pack, c.id),
                                      require_forms=not c.builtin)
            except ManifestError as e:
                raise _blame(e, c.pack)
        for p in c.providers:
            key = (c.vocabulary, p.id)
            other = provider_owner.get(key)
            if other is not None:
                raise _blame(ManifestError(
                    f"provider '{p.id}' of vocabulary '{c.vocabulary}' is "
                    f"declared by both '{other.pack}' and '{c.pack}'"),
                    other.pack, c.pack)
            provider_owner[key] = c

    _check_vault_entries(parsed)
    _check_service_bases(parsed)
    _check_service_addresses(parsed)
    _check_verb_schemes(parsed)
    return Registry(connectors=tuple(parsed), refused=tuple(refused))


def _check_vault_entries(connectors: list[Connector]) -> None:
    """A vault entry belongs to exactly one connector: the one whose namespace
    is its longest prefix. `sms` may not declare `sms_x_token` when `sms_x` is
    installed, and two connectors may not share an entry."""
    namespaces = {c.namespace: c for c in connectors}
    seen: dict[str, Connector] = {}
    for c in connectors:
        if c.builtin:
            continue
        # Service credentials obey the same longest-prefix ownership (review of
        # clodia-tools #362): `foo` may not hand its service `foo_bar_token`
        # while `foo_bar` is installed. A service may read the entry its own
        # connector's provider stores, so no "declared twice" check here.
        for svc in c.services:
            for entry in svc.credentials:
                owner = entry_owner(entry, namespaces)
                if owner and owner != c.namespace:
                    raise _blame(ManifestError(
                        f"{_at(c.pack, c.id)}.services '{svc.name}': vault entry "
                        f"'{entry}' falls under namespace '{owner}' of connector "
                        f"'{namespaces[owner].id}', not under its own "
                        f"'{c.namespace}'"), c.pack)
    for c in connectors:
        for p in c.providers:
            entry = p.credential.vault_entry if p.credential else ""
            if not entry:
                continue
            other = seen.get(entry)
            if other is not None and other is not c:
                raise _blame(ManifestError(
                    f"vault entry '{entry}' is declared by both '{other.pack}' "
                    f"(connector '{other.id}') and '{c.pack}' (connector "
                    f"'{c.id}')"), *(x.pack for x in (other, c) if not x.builtin))
            seen[entry] = c
            if c.builtin:
                continue
            owner = entry_owner(entry, namespaces)
            if owner and owner != c.namespace:
                raise _blame(ManifestError(
                    f"{_at(c.pack, c.id)}: vault entry '{entry}' falls under "
                    f"namespace '{owner}' of connector "
                    f"'{namespaces[owner].id}', not under its own "
                    f"'{c.namespace}'"), c.pack)


def _check_service_bases(connectors: list[Connector]) -> None:
    """Two connectors may not point their relay/pairing at the same loopback
    port (#638). Every loopback name is the same socket, so the PORT decides:
    the second connector would be forwarding to the first one's service."""
    seen: dict[int, Connector] = {}
    for c in connectors:
        ports = {_host_port(d.base, "http")[1]
                 for d in (c.relay, c.pairing) if d is not None
                 and _host_port(d.base, "http") is not None}
        for port in sorted(ports):
            other = seen.get(port)
            if other is not None and other is not c:
                raise _blame(ManifestError(
                    f"connectors '{other.id}' ({other.pack}) and '{c.id}' "
                    f"({c.pack}) both forward to loopback port {port}; a relay "
                    f"or pairing base belongs to one connector's service"),
                    *(x.pack for x in (other, c) if not x.builtin))
            seen[port] = c


def _health_address(service: Service):
    """The address a service's http/tcp health check says it listens on, as a
    comparable key: the PORT for any loopback name (one socket), else
    `(host, port)`. None for no health check or a `command` one."""
    if service.health_kind not in ("http", "tcp"):
        return None
    hp = _host_port(service.health_target, service.health_kind)
    if hp is None:
        return None
    host, port = hp
    return ("loopback", port) if host in _LOOPBACK_HOSTS else (host, port)


def _check_service_addresses(connectors: list[Connector]) -> None:
    """No two services of the instance may declare the same health address
    (#638, all packs, relay or not): the address is how the gateway reaches —
    and authenticates to — ONE service, and two claimants would mean the
    gateway's calls and its token reach whichever bound first."""
    seen: dict = {}
    for c in connectors:
        for svc in c.services:
            key = _health_address(svc)
            if key is None:
                continue
            prev = seen.get(key)
            if prev is not None and prev[1] is not svc:
                other, other_svc = prev
                raise _blame(ManifestError(
                    f"service '{svc.name}' of connector '{c.id}' ({c.pack}) and "
                    f"service '{other_svc.name}' of connector "
                    f"'{other.id}' ({other.pack}) declare the same address "
                    f"({svc.health_target!r}); every service listens on its own "
                    f"port"), *(x.pack for x in (other, c) if not x.builtin))
            seen[key] = (c, svc)


def _check_verb_schemes(connectors: list[Connector]) -> None:
    """Every mapping points at a scheme that EXISTS on this instance, in the
    right direction.

    Checked here and not inside `parse_connector`, because a connector alone
    cannot answer it: a pack may legitimately map its own verb onto a vocabulary
    someone else owns — a courier pack that sends mail is checked against the
    very same `mailto:` whitelist, which is the point of #517 — and the
    gateway's own files are organised by connector, so `gdocs.read` writes into
    the `gdrive:` vocabulary of the Google connector next to it. What stays
    forbidden is *declaring* someone else's scheme: using a vocabulary is not
    owning it.
    """
    declared = {s.name: s.direction for c in connectors for s in c.schemes}
    declared.update({k: v for k, v in CORE_SCHEME_DIRECTION.items()
                     if k not in declared})
    dtypes: dict[tuple[str, str], set[str]] = {}
    for c in connectors:
        for v in c.verbs:
            dtypes.setdefault((v.verb, v.direction), set()).add(v.dtype)
    for (verb, _d), seen in dtypes.items():
        if len({t for t in seen if t}) > 1:
            raise _blame(ManifestError(
                f"verb '{verb}' is mapped with two destination types "
                f"({', '.join(sorted(t for t in seen if t))}); the gate would "
                f"name the call differently depending on which argument it read"),
                *{c.pack for c in connectors if not c.builtin
                  and any(v.verb == verb for v in c.verbs)})
    for c in connectors:
        for v in c.verbs:
            direction = declared.get(v.scheme)
            if direction is None:
                raise _blame(ManifestError(
                    f"{_at(c.pack, c.id)}: verb '{v.verb}' maps to scheme "
                    f"'{v.scheme}', which no installed connector declares and "
                    f"which is not one of the platform schemes "
                    f"({', '.join(CORE_SCHEMES)})"), c.pack)
            if v.direction == "egress" and direction not in ("egress", "both"):
                raise _blame(ManifestError(
                    f"{_at(c.pack, c.id)}: verb '{v.verb}' writes to scheme "
                    f"'{v.scheme}', declared as '{direction}'"), c.pack)
            if v.direction == "source" and direction not in ("source", "both"):
                raise _blame(ManifestError(
                    f"{_at(c.pack, c.id)}: verb '{v.verb}' reads from scheme "
                    f"'{v.scheme}', declared as '{direction}'"), c.pack)
