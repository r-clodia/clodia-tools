"""#652 — a room linked to a Drive folder works in it without cards.

Owner, 4 Nov 2026: clodia moved and uploaded into a subfolder of the room's
linked folder and got an A·V·R·Q card each time; the link granted reading
only. Writes are now allowed on any Drive target in a linked room, because the
google-pack component confines them to the linked subtree; `gdrive.share`
still asks; a room with no linked folder is unchanged; a global deny wins.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from server import authz as A
from server import authz_runtime as R

LINKED = {"drive_folders": [{"name": "drive", "folder": "ROOT"}]}
SUB = "gdrive:folder/SUBFOLDER"


def _decide(verb, target, meta=LINKED, g=()):
    with patch("server.topics.service.drive_folders",
               lambda m: list(m.get("drive_folders") or [])):
        t = R._drive_tuples(meta)
    return A.decide(list(g), t, agent="clodia", verb=verb, resource="gdrive:default",
                    targets=[target], kind=A.WRITE).effect


class DriveLinkWritesTests(unittest.TestCase):
    def test_writes_in_a_linked_room_are_allowed(self):
        for verb in R.DRIVE_WRITE:
            self.assertEqual(_decide(verb, SUB), A.ALLOW, verb)
        self.assertEqual(_decide("gdrive.update", "gdrive:file/F1"), A.ALLOW)

    def test_share_still_asks(self):
        self.assertNotEqual(_decide("gdrive.share", "gdrive:file/F1"), A.ALLOW)

    def test_no_linked_folder_no_grant(self):
        with patch("server.topics.service.drive_folders", lambda m: []):
            self.assertEqual(R._drive_tuples({}), [])

    def test_a_global_deny_still_wins(self):
        g, bad = A.parse_tuples([{"id": "g", "agent": "*", "verb": "gdrive.move", "resource": "*",
                                  "rule": [{"effect": "deny", "match": "*"}]}], level=A.GLOBAL)
        self.assertFalse(bad)
        self.assertEqual(_decide("gdrive.move", SUB, g=g), A.DENY)

    def test_reads_keep_their_folder_rule(self):
        self.assertEqual(_decide("gdrive.list", "gdrive:folder/ROOT"), A.ALLOW)
        self.assertEqual(_decide("gdrive.list", "gdrive:folder/ELSEWHERE"), A.DENY)


if __name__ == "__main__":
    unittest.main()
