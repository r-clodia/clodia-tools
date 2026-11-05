"""#654 — topic verbs nobody used in three months (and `add_minute`, which
Topic v2 refuses) are no longer agent verbs. The owner keeps the same
operations from the webui routes."""
from __future__ import annotations

import unittest

from . import main

GONE = ("new", "archive", "remove_participant", "egress_remove", "drive_folder_remove",
        "local_folder_remove", "link_add", "link_remove", "save_agents_md", "add_minute")


class UnusedTopicVerbsRemovedTests(unittest.TestCase):
    def test_not_offered(self):
        offered = {t.name for t in main._TOPIC_TOOLS}
        for v in GONE:
            with self.subTest(verb=v):
                self.assertNotIn(f"topic.{v}", offered)

    def test_not_dispatched(self):
        for v in GONE:
            with self.subTest(verb=v):
                self.assertNotIn(v, main._TOPIC_SCOPED_VERBS)
                self.assertNotIn(v, main._TOPIC_MUTATING_VERBS)

    def test_the_work_verbs_stay(self):
        offered = {t.name for t in main._TOPIC_TOOLS}
        for v in ("files", "read_file", "fetch", "put", "post_message", "open",
                  "save_summary", "add_participant", "ingress_add", "egress_add"):
            with self.subTest(verb=v):
                self.assertIn(f"topic.{v}", offered)


if __name__ == "__main__":
    unittest.main()
