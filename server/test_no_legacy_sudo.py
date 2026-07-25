from __future__ import annotations

import unittest

from . import gate, main
from .http_app import build_app


class NoLegacySudoTests(unittest.TestCase):
    def test_sudo_tool_and_routes_are_absent(self) -> None:
        self.assertNotIn("sudo", main._native_tool_namespaces())
        paths = [getattr(route, "path", "") for route in build_app().routes]
        self.assertFalse(any(path.startswith("/internal/sudo") for path in paths))

    def test_participant_mutations_remain_gated(self) -> None:
        self.assertTrue(gate.is_gated("topic.add_participant"))
        self.assertTrue(gate.is_gated("topic.remove_participant"))


if __name__ == "__main__":
    unittest.main()
