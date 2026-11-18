"""clodia-platform#699 — a broken INSTALLED pack does not block another pack.

18 Nov 2026: with comms-pack ≤ 2.8 still installed (refused since #683), the
updates of google-pack and it-pack were refused with comms-pack's error. The
preview now drops installed packs a refusal blames — as the runtime registry
does — and reports them as `others_refused`; the candidate's own errors and
clashes are still refusals.
"""
from __future__ import annotations

import copy
import unittest
from unittest.mock import patch

from . import first_party_fixture as FP
from . import resolved
from . import validate as cv


class OthersDoNotBlockTests(unittest.TestCase):
    def setUp(self) -> None:
        resolved.invalidate()
        self.addCleanup(resolved.invalidate)

    def _installed(self, packs: dict):
        p = patch.object(resolved, "manifests", lambda: packs)
        p.start()
        self.addCleanup(p.stop)

    def test_a_refused_comms_pack_does_not_block_it_pack(self) -> None:
        self._installed({**FP.manifests(), "comms-pack": FP.comms_pack()})
        it = FP.it_pack()
        out = cv.validate("it-pack", it["connectors"])
        self.assertTrue(out["ok"], out["errors"])
        self.assertEqual(out["errors"], [])
        self.assertTrue(any("comms-pack" in r for r in out["others_refused"]),
                        out["others_refused"])
        self.assertTrue({c["id"] for c in out["connectors"]} >= {"github"})

    def test_google_pack_too(self) -> None:
        self._installed({**FP.manifests(), "comms-pack": FP.comms_pack()})
        out = cv.validate("google-pack", FP.google_pack()["connectors"])
        self.assertTrue(out["ok"], out["errors"])

    def test_the_candidates_own_error_is_still_a_refusal(self) -> None:
        self._installed({**FP.manifests(), "comms-pack": FP.comms_pack()})
        broken = copy.deepcopy(FP.comms_pack()["connectors"])
        out = cv.validate("comms-pack", broken)
        self.assertFalse(out["ok"])
        self.assertTrue(out["errors"])

    def test_nothing_reported_when_every_installed_pack_is_fine(self) -> None:
        self._installed(FP.manifests())
        out = cv.validate("it-pack", FP.it_pack()["connectors"])
        self.assertTrue(out["ok"])
        self.assertEqual(out["others_refused"], [])


if __name__ == "__main__":
    unittest.main()
