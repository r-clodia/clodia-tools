"""A·V·R·Q judges a component verb on the facts its component establishes.

`gdrive.update` carries only a file id; its destination is the file's parent
folder, which google-pack's `pdp_arguments` reads from Drive. A·V·R·Q used to
judge the raw arguments: «no target», a write that asked on every call — in a
room linked to that very folder too — and whose approval could not be
remembered (owner, 12 Nov 2026: «perché mi chiede continuamente un gate per
accedere allo stesso doc su gdrive?»).
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from server import main


class AuthzArgumentsTests(unittest.TestCase):
    def test_a_component_verb_is_judged_on_the_enriched_arguments(self):
        spec = object()
        with patch.object(main, "_component_verb", lambda n: spec), \
                patch.object(main, "_component_pdp_arguments",
                             lambda s, n, a: {**a, "folder_id": "FOLDER1"}) as _p:
            out = main._authz_arguments("gdrive.update", {"file_id": "F1"})
        self.assertEqual(out, {"file_id": "F1", "folder_id": "FOLDER1"})

    def test_a_native_verb_keeps_its_arguments(self):
        with patch.object(main, "_component_verb", lambda n: None):
            self.assertEqual(main._authz_arguments("web.fetch", {"url": "u"}), {"url": "u"})

    def test_a_failing_lookup_leaves_the_raw_arguments(self):
        def boom(s, n, a):
            raise PermissionError("drive giù")
        with patch.object(main, "_component_verb", lambda n: object()), \
                patch.object(main, "_component_pdp_arguments", boom):
            self.assertEqual(main._authz_arguments("gdrive.update", {"file_id": "F1"}),
                             {"file_id": "F1"})


if __name__ == "__main__":
    unittest.main()
