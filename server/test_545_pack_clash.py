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
    """`manifests()` answers in install order: when the gateway FIRST saw each
    pack, not the mtime of `pack.yaml` (review of clodia-tools#369)."""

    def setUp(self) -> None:
        # The stamp file must be this test's: under `make test` a shared
        # CLODIA_TOOLS_STATE_DIR would carry other tests' stamps in.
        import tempfile
        from pathlib import Path
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        p = patch.object(resolved, "_first_seen_path",
                         lambda: Path(d.name) / "first-seen.json")
        p.start()
        self.addCleanup(p.stop)

    def _root(self, d):
        from pathlib import Path
        return Path(d) / "packs"

    def _install(self, root, name, when):
        p = root / name
        p.mkdir(parents=True)
        (p / "pack.yaml").write_text(f"name: {name}\n", encoding="utf-8")
        with patch("time.time", return_value=float(when)):
            resolved._first_seen([name])

    def test_manifests_are_returned_oldest_first(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d, \
                patch.object(resolved, "_DATA", Path(d)):
            root = self._root(d)
            self._install(root, "zz-old", 1000)
            self._install(root, "aa-new", 2000)
            self.assertEqual(list(resolved.manifests()), ["zz-old", "aa-new"])

    def test_rewriting_the_incumbent_does_not_make_it_the_newcomer(self):
        """The defect of the first version: «Finish setup» or a flow approval
        rewrites `pack.yaml`; with mtime ordering the incumbent became the
        latest arrival and lost its namespace to the intruder."""
        import os
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d, \
                patch.object(resolved, "_DATA", Path(d)):
            root = self._root(d)
            self._install(root, "mail-pack", 1000)
            self._install(root, "evil-pack", 2000)
            os.utime(root / "mail-pack" / "pack.yaml", (3000, 3000))
            (root / "mail-pack" / "pack.yaml").write_text(
                "name: mail-pack\nsetup_done: true\n", encoding="utf-8")
            self.assertEqual(list(resolved.manifests()), ["mail-pack", "evil-pack"])
            self.assertEqual(resolved.seniority(),
                             {"mail-pack": 1000.0, "evil-pack": 2000.0})

    def test_a_corrupted_stamp_never_breaks_or_wins(self):
        """Review of #369: "x"/null raised, NaN looped forever, 0 made an
        intruder the incumbent. A bad stamp = the pack arrives now."""
        import json
        import math
        import tempfile
        from pathlib import Path
        for bad in ("x", None, float("nan"), 0, -5, True):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as d, \
                    patch.object(resolved, "_DATA", Path(d)), \
                    patch.dict(resolved._SEEN_MEMORY, clear=True):
                root = self._root(d)
                self._install(root, "mail-pack", 1000)
                self._install(root, "evil-pack", 2000)
                f = resolved._first_seen_path()
                data = json.loads(f.read_text())
                data["evil-pack"] = bad
                f.write_text(json.dumps(data))
                with patch("time.time", return_value=5000.0):
                    anz = resolved.seniority()
                    self.assertEqual(list(resolved.manifests()),
                                     ["mail-pack", "evil-pack"])
                self.assertTrue(math.isfinite(anz["evil-pack"]))
                self.assertGreater(anz["evil-pack"], anz["mail-pack"])

    def test_a_removed_pack_s_stamp_is_not_inherited(self):
        import shutil
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d, \
                patch.object(resolved, "_DATA", Path(d)), \
                patch.dict(resolved._SEEN_MEMORY, clear=True), \
                patch.dict(resolved._MISSING_SINCE, clear=True):
            root = self._root(d)
            self._install(root, "old-removed", 1000)
            self._install(root, "zeta2", 2000)
            shutil.rmtree(root / "old-removed")
            with patch("time.time", return_value=2500.0):
                resolved.manifests()          # the gateway notices the removal
            with patch("time.time", return_value=2500.0 + resolved.PRUNE_AFTER_S):
                resolved.manifests()          # …and forgets it after the grace
            self._install(root, "old-removed", 3000)
            self.assertEqual(list(resolved.manifests()), ["zeta2", "old-removed"])

    def test_a_briefly_missing_incumbent_keeps_its_stamp(self):
        """An update that replaces the directory non-atomically: the glob may
        run while it is missing. Within the grace period nothing is pruned."""
        import shutil
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d, \
                patch.object(resolved, "_DATA", Path(d)), \
                patch.dict(resolved._SEEN_MEMORY, clear=True), \
                patch.dict(resolved._MISSING_SINCE, clear=True):
            root = self._root(d)
            self._install(root, "mail-pack", 1000)
            self._install(root, "evil-pack", 2000)
            shutil.move(str(root / "mail-pack"), str(Path(d) / "aside"))
            with patch("time.time", return_value=3000.0):
                resolved.manifests()
            shutil.move(str(Path(d) / "aside"), str(root / "mail-pack"))
            with patch("time.time", return_value=3010.0):
                self.assertEqual(list(resolved.manifests()),
                                 ["mail-pack", "evil-pack"])

    def test_a_pack_without_stamp_counts_as_newest(self):
        from server.connectors.manifest import ManifestError

        def fake_build(packs, builtin=()):
            if {"a-pack", "b-pack"} <= set(packs):
                e = ManifestError("clash")
                e.packs = ("a-pack", "b-pack")
                raise e
            return resolved.Registry()
        with patch.object(resolved, "build_registry", fake_build):
            _r, _d, packs = resolved._build_isolated(
                {}, {"a-pack": {}, "b-pack": {}}, {"a-pack": 1000.0})
        self.assertEqual(packs, ["b-pack"])

    def test_packs_first_seen_together_have_no_incumbent(self):
        """Same stamp (first boot, or dropped in together): a clash between
        them drops both sides — no order is invented."""
        from server.connectors.manifest import ManifestError
        calls = {"n": 0}

        def fake_build(packs, builtin=()):
            calls["n"] += 1
            if {"a-pack", "b-pack"} <= set(packs):
                e = ManifestError("namespace 'x' clash")
                e.packs = ("a-pack", "b-pack")
                raise e
            return resolved.Registry()
        with patch.object(resolved, "build_registry", fake_build):
            _reg, dropped, packs = resolved._build_isolated(
                {}, {"a-pack": {}, "b-pack": {}}, {"a-pack": 5.0, "b-pack": 5.0})
        self.assertEqual(sorted(packs), ["a-pack", "b-pack"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
