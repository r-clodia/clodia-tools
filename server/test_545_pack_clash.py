"""clodia-platform#545 §1: a clash must not switch off the healthy neighbour.

`_build_isolated` drops the packs a `ManifestError` blames and retries. A clash
blames BOTH sides — so installing a pack that declares a scheme (or a namespace)
already owned by a healthy pack took that healthy pack down with it: its
connectors left the registry and, since #358, its outbound verbs fell into the
failsafe, i.e. **denied**. Installing something unrelated is not an acceptable
way to lose `alpha.send`.

The incumbent wins: of the packs a single refusal blames, only the one installed
LAST is dropped. The order is the one `resolved.manifests()` returns (see the
`SHORTCUT` there), so these tests declare it by building the dict in that order
— and the newcomer sorts *before* the incumbent alphabetically, which is how
they tell «install order» from «whoever sorts first».
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import egress
from .connectors import resolved


def _pack(name: str, namespace: str, scheme: str) -> dict:
    return {"name": name, "connectors": [{
        "id": namespace, "manifest_version": 1, "namespace": namespace,
        "schemes": [{"scheme": scheme, "direction": "egress"}],
        "verbs": [{"verb": f"{namespace}.send", "direction": "egress",
                   "scheme": scheme, "arg": "to"}]}]}


class ClashKeepsTheIncumbentTests(unittest.TestCase):
    def setUp(self):
        resolved.invalidate()
        self.addCleanup(resolved.invalidate)

    def _install(self, *packs):
        """`packs` in INSTALL order (oldest first)."""
        ordered = {m["name"]: m for m in packs}
        p = patch.object(resolved, "manifests", lambda: dict(ordered))
        p.start()
        self.addCleanup(p.stop)
        resolved.invalidate()

    def _ids(self) -> set[str]:
        return {c.id for c in resolved.registry().connectors if not c.builtin}

    def test_a_scheme_clash_drops_only_the_newcomer(self):
        # `zeta-pack` was installed first and owns `courier:`; `alpha-pack`
        # arrives later claiming the same vocabulary — and sorts first.
        self._install(_pack("zeta-pack", "zeta", "courier"),
                      _pack("alpha-pack", "alpha", "courier"))
        self.assertEqual(self._ids(), {"zeta"})
        incumbent = egress.decide({}, "zeta.send", {"to": "x"})
        self.assertTrue(incumbent["checked"])
        self.assertFalse(resolved.failsafe_denied("zeta.send"))
        # The newcomer is the one that fails closed.
        self.assertTrue(resolved.failsafe_denied("alpha.send"))

    def test_a_namespace_clash_drops_only_the_newcomer(self):
        self._install(_pack("zeta-pack", "shared", "zeta-scheme"),
                      _pack("alpha-pack", "shared", "alpha-scheme"))
        self.assertEqual({c.pack for c in resolved.registry().connectors
                          if not c.builtin}, {"zeta-pack"})
        self.assertFalse(resolved.failsafe_denied("shared.send"))

    def test_a_malformed_pack_is_still_dropped_alone(self):
        """A refusal that blames ONE pack keeps behaving as before."""
        broken = _pack("broken-pack", "broken", "broken-scheme")
        broken["connectors"][0]["manifest_version"] = 99
        self._install(_pack("zeta-pack", "zeta", "courier"), broken)
        self.assertEqual(self._ids(), {"zeta"})
        self.assertTrue(resolved.failsafe_denied("broken.send"))

    def test_the_registry_says_which_side_was_dropped(self):
        self._install(_pack("zeta-pack", "zeta", "courier"),
                      _pack("alpha-pack", "alpha", "courier"))
        righe = " ".join(resolved.problems())
        self.assertIn("alpha-pack", righe)
        self.assertNotIn("pack 'zeta-pack' refused", righe)


class InstallOrderTests(unittest.TestCase):
    """`manifests()` answers in install order — oldest `pack.yaml` first."""

    def test_manifests_are_returned_oldest_first(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            from pathlib import Path
            root = Path(d) / "packs"
            for name, when in (("zz-old", 1000), ("aa-new", 2000)):
                p = root / name
                p.mkdir(parents=True)
                (p / "pack.yaml").write_text(f"name: {name}\n", encoding="utf-8")
                os.utime(p / "pack.yaml", (when, when))
            with patch.object(resolved, "_DATA", Path(d)):
                self.assertEqual(list(resolved.manifests()), ["zz-old", "aa-new"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
