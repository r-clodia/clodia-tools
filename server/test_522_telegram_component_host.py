"""clodia-platform#522/#558 — what the gateway gives comms-pack's Telegram
component: a private state file, and the relay calling its services."""
from __future__ import annotations

import asyncio
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch

from .components import host, loader, store
from . import telegram_api


class StatePathTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        p = patch.object(store, "root", return_value=Path(tmp.name))
        p.start()
        self.addCleanup(p.stop)
        self.h = host.Host.__new__(host.Host)
        self.h._c = NS(pack="comms-pack", id="telegram", key="comms-pack/telegram")
        self.root = Path(tmp.name)

    def test_a_private_file_per_component(self) -> None:
        path = Path(self.h.state_path("telegram-state.json"))
        self.assertEqual(path, self.root / "state" / "comms-pack" / "telegram" / "telegram-state.json")
        self.assertEqual(oct(path.parent.stat().st_mode & 0o777), "0o700")

    def test_no_directories_no_traversal(self) -> None:
        for bad in ("../x", "a/b", "", ".hidden", "x" * 80, "a/../../etc"):
            with self.assertRaises(host.HostError, msg=bad):
                self.h.state_path(bad)


class RelayUsesTheComponentTests(unittest.TestCase):
    def test_the_relay_calls_the_service_when_the_component_serves(self) -> None:
        calls = []
        spec = NS(handler=lambda a: calls.append(a) or {"messages": [], "count": 0})
        with patch.object(loader, "service", return_value=spec) as svc, \
             patch.object(telegram_api.proxy, "call_proxied") as proxied:
            out = asyncio.run(telegram_api._pack("updates", {"timeout": 5}))
        svc.assert_called_once_with("comms-pack", "telegram_updates")
        proxied.assert_not_called()
        self.assertEqual(calls, [{"timeout": 5}])
        self.assertEqual(out["count"], 0)

    def test_without_the_component_the_backend_is_used(self) -> None:
        async def proxied(name, args):
            return '{"messages": [], "count": 0}'
        with patch.object(loader, "service", return_value=None), \
             patch.object(telegram_api.proxy, "call_proxied", side_effect=proxied) as p:
            asyncio.run(telegram_api._pack("updates", {"timeout": 5}))
        p.assert_called_once_with("telegram.updates", {"timeout": 5})




class StaleBackendTests(unittest.TestCase):
    """A connector served by its pack's component: the pack's own stamped
    backend of the same name is withheld like a transport."""

    def test_the_old_backend_is_withheld_once_the_component_serves(self) -> None:
        from .connectors import resolved
        resolved._TRANSPORTS = None
        docs = {"comms-pack": {"connectors": [{"id": "telegram", "namespace": "telegram"}]}}
        with patch.object(resolved, "manifests", return_value=docs), \
             patch.object(resolved, "backend_owners", return_value={"comms-pack": {"telegram"}}), \
             patch.object(resolved, "core_backends", return_value=frozenset()), \
             patch.object(loader, "serving_connectors", return_value=(("comms-pack", "telegram"),)):
            self.assertIn("telegram", resolved.transport_backends())
        resolved._TRANSPORTS = None
        with patch.object(resolved, "manifests", return_value=docs), \
             patch.object(resolved, "backend_owners", return_value={"comms-pack": {"telegram"}}), \
             patch.object(resolved, "core_backends", return_value=frozenset()), \
             patch.object(loader, "serving_connectors", return_value=()):
            self.assertNotIn("telegram", resolved.transport_backends())
        resolved._TRANSPORTS = None


class TransportCheckTests(unittest.TestCase):
    """With the stale backend withheld, only calls that would reach it are
    refused: component verbs and the gateway's own pass the check."""

    def test_only_backend_bound_calls_are_refused(self) -> None:
        from . import main
        with patch.object(main.proxy, "is_proxied", return_value=True), \
             patch("server.connectors.resolved.is_transport_backend", return_value=True), \
             patch.object(main, "_component_verb",
                          side_effect=lambda n: object() if n == "telegram.send" else None):
            main._check_not_transport("telegram.send")            # the component's
            retained = next(iter(main._GATEWAY_RETAINED_VERBS))
            main._check_not_transport(retained)                  # the gateway's own
            with self.assertRaises(main._PackVerbRefused):
                main._check_not_transport("telegram.updates")    # the stale backend's


if __name__ == "__main__":
    unittest.main()
