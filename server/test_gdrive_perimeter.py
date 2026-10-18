"""The Drive perimeter as the gateway's lists declare it (#524).

What enforced it against Drive went with the native Google client: google-pack's
gateway component enforces it now (tested in clodia-logic). What stays is the
reading: per-account `gdrive_roots` and the approved `gdrive:folder/<id>`
entries of the lists, which the gateway uses for its own decisions.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import whitelist as wl
from .tools import gdrive_root as gr

ROOT = "ROOTFOLDER"


def _cfg(roots: dict, egress: list | None = None):
    return patch.object(wl, "CONFIG", {"gdrive_roots": roots,
                                       "egress_allow": list(egress or [])})


class RootsTests(unittest.TestCase):
    def test_a_star_entry_adds_to_the_specific_one(self):
        """`*` is a common minimum, not a default a specific entry replaces."""
        with _cfg({"*": ["GLOB"], "conto": [ROOT]}):
            self.assertEqual(gr.roots_for("conto"), ["GLOB", ROOT])

    def test_no_key_at_all_confines_nothing(self):
        with patch.object(wl, "CONFIG", {"agents": {}}):
            self.assertEqual(gr.roots_for("conto"), [])

    def test_a_malformed_config_does_not_disable_a_valid_entry(self):
        with _cfg({"conto": ROOT}):                     # a string, not a list
            self.assertEqual(gr.roots_for("conto"), [ROOT])
        with patch.object(wl, "CONFIG", {"gdrive_roots": ["not-a-dict"]}):
            self.assertEqual(gr.roots_for("conto"), [])


class ApprovedFoldersTests(unittest.TestCase):
    def test_folder_entries_of_the_list_are_approved_for_every_account(self):
        with _cfg({}, egress=["gdrive:folder/F1", "https://x.it/", "gdrive:folder/F2/"]):
            self.assertEqual(gr.approved_folders(), ["F1", "F2"])
            self.assertEqual(gr.roots_for("qualunque"), ["F1", "F2"])

    def test_legacy_roots_stay_per_account(self):
        """A root of account A is not a perimeter for B."""
        with _cfg({"a": [ROOT]}, egress=[]):
            self.assertEqual(gr.approved_folders(), [])
            self.assertEqual(gr.roots_for("b"), [])


if __name__ == "__main__":
    unittest.main()
