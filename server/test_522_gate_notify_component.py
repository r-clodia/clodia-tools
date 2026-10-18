"""#522 — the owner notification of a pending gate goes through comms-pack's
component service `telegram_notify`: the gateway has no Telegram client."""
from __future__ import annotations

import unittest
from types import SimpleNamespace as NS
from unittest.mock import MagicMock, patch

from . import main
from .components import loader


def _agents(rows):
    client = MagicMock()
    client.__enter__.return_value.get.return_value.json.return_value = {"agents": rows}
    return patch("httpx.Client", return_value=client)


class GateNotifyTests(unittest.TestCase):
    HUMAN = {"name": "davide", "type": "human", "role": "superadmin",
             "contact_channels": {"telegram": "76632169"}}

    def test_the_component_service_sends_to_the_humans_numeric_id(self):
        sent = []
        svc = NS(handler=lambda a: sent.append(a) or {"ok": True})
        with _agents([self.HUMAN]), \
                patch.object(loader, "service",
                             lambda pack, name: svc if (pack, name) ==
                             ("comms-pack", "telegram_notify") else None):
            self.assertTrue(main._gate_notify_principal("fullstack-dev", "github.push", "davide"))
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0]["chat_id"], "76632169")
        self.assertIn("github.push", sent[0]["text"])

    def test_without_the_component_no_notification_and_no_error(self):
        with _agents([self.HUMAN]), patch.object(loader, "service", lambda *a: None):
            self.assertFalse(main._gate_notify_principal("a", "k", "davide"))


if __name__ == "__main__":
    unittest.main()
