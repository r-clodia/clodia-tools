"""Test support: give the agents of a test config their verbs as A·V·R·Q tuples.

Since clodia-platform#656 reachability is decided by the tuples only: the
seed-based matrix (`allowed_tools`, ancestry, archseed) no longer makes a verb
reachable, in any `authz_mode`. Many suites, though, are about what happens
DOWNSTREAM of reachability — the egress PDP, the gates, the audit, the relay —
and declared their agents' verbs the old way, in `whitelist.CONFIG`.

`seed_verbs_as_tuples(testcase)` translates, for the duration of the test, each
configured agent's resolved verbs (`whitelist.effective_tools`) into global
tuples that make them available — what the 25 Oct migration did on the real
instances — and, unless the test's config names a mode, runs the test in
`shadow`: the per-call A·V·R·Q effects stay off and the second line (egress
PDP, gates) decides exactly as these suites expect.

Not for suites whose subject IS reachability: those write their own tuples.
Not imported by the gateway: test-only, kept out of `test_*.py` so discovery
does not treat it as a test module.
"""
from __future__ import annotations

from unittest.mock import patch

from . import authz as A
from . import authz_runtime as R
from . import authz_shadow as S
from . import whitelist as W


def _tuples_from_config() -> tuple[list[A.Tuple], list[str]]:
    raw = []
    for agent in sorted((W.CONFIG or {}).get("agents") or {}):
        try:
            verbs = W.effective_tools(agent)
        except Exception:  # noqa: BLE001 — an unresolvable agent gets nothing
            continue
        for verb in sorted(verbs):
            raw.append({"id": f"seed:{agent}:{verb}", "agent": agent, "verb": verb,
                        "resource": "*", "rule": [{"effect": "allow", "match": "*"}]})
    ok, bad = A.parse_tuples(raw)
    return ok, [str(b) for b in bad]


def seed_verbs_as_tuples(testcase, *, mode: str = "shadow") -> None:
    """Install the translation for `testcase` (patches cleaned up after it)."""
    real_global = S.global_tuples

    def _global():
        g, problems = real_global()
        t, more = _tuples_from_config()
        return g + t, problems + more

    def _mode_raw():
        m = (W.CONFIG or {}).get(S.MODE_KEY)
        return str(m).strip().lower() if m else mode

    def _mode():
        m = _mode_raw()
        return m if m in ("off", "shadow", R.ENFORCE) else R.ENFORCE

    real_view = R._room_view

    def _room_view(scope):
        # A room the fixture never created (a token carrying a topic, and no
        # topic store behind it): read as a room with no members and no rules,
        # so the global grants above decide. The real gateway denies there.
        try:
            return real_view(scope)
        except R.RoomUnreadable:
            return real_view(None)

    R.invalidate()
    testcase.addCleanup(R.invalidate)
    for p in (patch.object(S, "global_tuples", _global),
              patch.object(R, "_room_view", _room_view),
              patch.object(S, "mode_raw", _mode_raw),
              patch.object(R, "mode", _mode)):
        p.start()
        testcase.addCleanup(p.stop)
    # The room view caches the global tuples for a couple of seconds: a test
    # that edits CONFIG mid-way must see it.
    p = patch.object(R, "_TTL", 0.0)
    p.start()
    testcase.addCleanup(p.stop)


class _ModuleCase:
    """Collects the cleanups of a module-wide installation."""

    def __init__(self):
        self._cleanups = []

    def addCleanup(self, fn, *args, **kw):
        self._cleanups.append((fn, args, kw))

    def close(self):
        while self._cleanups:
            fn, args, kw = self._cleanups.pop()
            fn(*args, **kw)


_module_case: list[_ModuleCase] = []


def module_start(mode: str = "shadow") -> None:
    """`setUpModule` form: the translation for every test of the module."""
    c = _ModuleCase()
    seed_verbs_as_tuples(c, mode=mode)
    _module_case.append(c)


def module_stop() -> None:
    """`tearDownModule` form."""
    if _module_case:
        _module_case.pop().close()


def global_grants(grants: dict) -> "patch":
    """A patcher whose global tuples give each agent its verbs (allow *):
    `{agent: [verb, ...]}`. For suites about what the tuples decide, written
    without a state dir. Call `authz_runtime.invalidate()` around it."""
    raw = [{"id": f"grant:{a}:{v}", "agent": a, "verb": v, "resource": "*",
            "rule": [{"effect": "allow", "match": "*"}]}
           for a, verbs in grants.items() for v in verbs]
    ok, _bad = A.parse_tuples(raw)
    return patch.object(S, "global_tuples", lambda: (list(ok), []))
