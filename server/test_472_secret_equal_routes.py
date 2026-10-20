"""#472 — an internal secret compared as `str` with `hmac.compare_digest`
raises TypeError on a non-ASCII character (a 500 instead of a 401). Every
internal-secret route compares through `audit.trace.secret_equal`."""
from __future__ import annotations

import ast
import unittest
from pathlib import Path
from unittest.mock import patch

from starlette.requests import Request

from . import egress_api, logic_api, mint_api

ROUTES = (egress_api, logic_api, mint_api)


def _req(value: bytes) -> Request:
    return Request({"type": "http", "method": "GET", "path": "/internal/x",
                    "headers": [(b"x-orchestrator-secret", value)], "query_string": b""})


class UiTokenTests(unittest.TestCase):
    def test_the_ui_token_is_compared_as_bytes(self):
        from . import tools_api
        self.assertTrue(tools_api._bearer_is("Bearer s3cret", "s3cret"))
        self.assertTrue(tools_api._bearer_is("bearer s3cret ", "s3cret"))
        self.assertFalse(tools_api._bearer_is("Bearer s3cre", "s3cret"))
        self.assertFalse(tools_api._bearer_is("Bearer sè3cret", "s3cret"))
        self.assertFalse(tools_api._bearer_is("s3cret", "s3cret"))
        self.assertFalse(tools_api._bearer_is("Bearer ", ""))


class InternalSecretTests(unittest.TestCase):
    def test_a_non_ascii_secret_is_refused_not_a_crash(self):
        for mod in ROUTES:
            with self.subTest(route=mod.__name__), \
                    patch.dict("os.environ", {"CLODIA_ORCHESTRATOR_SECRET": "s3cret"}):
                self.assertFalse(mod._authorized(_req("sè3cret".encode("latin-1"))))
                self.assertFalse(mod._authorized(_req("\xff\xfe".encode("latin-1"))))

    def test_a_non_ascii_configured_secret_does_not_crash_either(self):
        for mod in ROUTES:
            with self.subTest(route=mod.__name__), \
                    patch.dict("os.environ", {"CLODIA_ORCHESTRATOR_SECRET": "sècret"}):
                self.assertFalse(mod._authorized(_req(b"other")))

    def test_the_right_secret_still_passes(self):
        for mod in ROUTES:
            with self.subTest(route=mod.__name__), \
                    patch.dict("os.environ", {"CLODIA_ORCHESTRATOR_SECRET": "s3cret"}):
                self.assertTrue(mod._authorized(_req(b"s3cret")))
                self.assertFalse(mod._authorized(_req(b"")))

    def test_no_route_compares_secrets_with_compare_digest_directly(self):
        """The shared helper is the only place: a new route copying the old
        pattern would bring the 500 back."""
        root = Path(__file__).resolve().parent
        offenders = []
        for path in root.rglob("*.py"):
            if path.name.startswith("test_") or path.parts[-2:] == ("audit", "trace.py"):
                continue
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if (isinstance(node, ast.Attribute) and node.attr == "compare_digest") or (
                        isinstance(node, ast.Name) and node.id == "compare_digest") or (
                        isinstance(node, ast.ImportFrom) and any(
                            a.name == "compare_digest" for a in node.names)):
                    offenders.append(str(path.relative_to(root)))
                # A bearer secret compared with ==/!= (timing leak, #472 review).
                if isinstance(node, ast.Compare) and any(
                        isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops):
                    for side in [node.left, *node.comparators]:
                        if isinstance(side, ast.JoinedStr) and any(
                                isinstance(v, ast.Constant) and "Bearer " in str(v.value)
                                for v in side.values):
                            offenders.append(f"{path.relative_to(root)}:{node.lineno}")
        self.assertEqual(offenders, [], "use audit.trace.secret_equal")


if __name__ == "__main__":
    unittest.main()
