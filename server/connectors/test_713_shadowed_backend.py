"""clodia-platform#713 — a backend shadowed by a serving component keeps the
tools the component does not serve.

Live on 21 Nov 2026: it-pack's gateway component serves the `github` connector
(clone, pull, push, pull_request, mirror) and it-pack's plugin mounts the
official GitHub MCP backend, also `github`. The rule written for Telegram
(#522/#558: a pack's own backend named like a connector its component serves
is withheld) hid ALL 46 backend tools — no agent could read or write an
issue. Now only the verbs the component serves are withheld; provider
transports and relay backends stay withheld whole.
"""
from __future__ import annotations

import asyncio
import unittest
from types import SimpleNamespace as NS
from unittest.mock import patch

from mcp.types import Tool

from .. import main, proxy
from . import resolved

COMPONENT_VERBS = {"github.clone", "github.pull", "github.push",
                   "github.pull_request", "github.mirror"}

PACKS = {
    "it-pack": {"connectors": [{"id": "github", "namespace": "github"}]},
    "x-pack": {"connectors": [{"id": "x", "namespace": "x",
                               "providers": [{"id": "p", "transport": {
                                   "backend": "x-transport", "tool": "run"}}]}]},
    "chat-pack": {"connectors": [{"id": "chat", "namespace": "chat",
                                  "relay": {"backend": "chat-relay",
                                            "poll": "relay_poll"}}]},
}
OWNERS = {"it-pack": frozenset({"github"}),
          "x-pack": frozenset({resolved.norm_name("x-transport")}),
          "chat-pack": frozenset({resolved.norm_name("chat-relay")})}


class _Env(unittest.TestCase):
    def setUp(self) -> None:
        resolved._TRANSPORTS = None
        self.addCleanup(setattr, resolved, "_TRANSPORTS", None)
        ps = [patch.object(resolved, "manifests", lambda: PACKS),
              patch.object(resolved, "backend_owners", lambda packs=None: OWNERS),
              patch.object(resolved, "_manifest_files", lambda: []),
              patch.object(resolved, "_mount_signature", lambda: ()),
              patch.object(resolved, "_pins_signature", lambda: ()),
              patch("server.components.loader.serving_connectors",
                    lambda: (("it-pack", "github"),)),
              patch("server.components.loader.verb",
                    lambda n: NS(name=n) if n in COMPONENT_VERBS else None)]
        for p in ps:
            p.start()
            self.addCleanup(p.stop)


class ClassificationTests(_Env):
    def test_github_is_shadowed_not_a_transport(self) -> None:
        self.assertIn("github", resolved.shadowed_backends())
        self.assertNotIn("github", resolved.provider_transports())
        self.assertIn("github", resolved.transport_backends())   # the union

    def test_only_the_components_verbs_are_withheld(self) -> None:
        self.assertFalse(resolved.is_transport_backend("github"))
        self.assertFalse(resolved.is_transport_backend("github.issue_write"))
        self.assertFalse(resolved.is_transport_backend("github.list_issues"))
        self.assertTrue(resolved.is_transport_backend("github.push"))
        self.assertTrue(resolved.is_transport_backend("github.pull_request"))

    def test_real_transports_and_relays_stay_withheld_whole(self) -> None:
        for name in ("x-transport", "x-transport.run", "x-transport.anything",
                     "chat-relay", "chat-relay.relay_poll"):
            with self.subTest(name=name):
                self.assertTrue(resolved.is_transport_backend(name))


class CallAndListTests(_Env):
    def test_an_issue_write_is_not_refused_as_a_transport(self) -> None:
        with patch.object(proxy, "is_proxied", lambda n: True), \
                patch.object(main, "_component_verb",
                             lambda n: NS() if n in COMPONENT_VERBS else None):
            main._check_not_transport("github.issue_write")       # no raise
            with self.assertRaises(main._PackVerbRefused):
                main._check_not_transport("x-transport.run")

    def test_the_listing_keeps_the_backend_minus_the_components_verbs(self) -> None:
        cached = {
            "github": [Tool(name=f"github.{t}", description="", inputSchema={})
                       for t in ("issue_write", "list_issues", "push")],
            "x-transport": [Tool(name="x-transport.run", description="",
                                 inputSchema={})],
        }
        with patch.object(proxy, "_backends",
                          lambda: {"github": {}, "x-transport": {}}), \
                patch.dict(proxy._TOOL_CACHE, cached, clear=True), \
                patch("server.whitelist.disabled_backend_tools", lambda n: []):
            names = sorted(t.name for t in asyncio.run(proxy.list_proxied_tools()))
        self.assertEqual(names, ["github.issue_write", "github.list_issues"])


if __name__ == "__main__":
    unittest.main()
