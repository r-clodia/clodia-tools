"""clodia-platform#410 — `integrations.list` legge i connettori in-process.

Il verbo chiedeva lo stato all'agent-server (`/api/connectors`), che lo
richiedeva al gateway su `/internal/connectors`: rotta mai registrata, quindi
502 per costruzione. Lo stato dei connettori è del gateway, che ha la vault:
qui si verifica che il verbo lo legga da lì, senza alcun salto HTTP, e che
resti la stessa sorgente servita da `GET /tools`.
"""
import json
import unittest
from unittest.mock import patch

from starlette.requests import Request

from . import tools_api
from .tools import platform_ops

_DIAGNOSTICS = [
    {"credential": "google_studio", "account": "studio", "kind": "google",
     "operational": True, "missing": [], "error": None},
    {"credential": "mailbox_ufficio", "account": "ufficio", "kind": "mailbox",
     "operational": True, "missing": [], "error": None},
]


def _snapshot_env(allowed=None):
    """Vault e profilo finti: nessun connettore reale, nessun file letto."""
    return [
        patch.object(tools_api.email_tool, "credential_diagnostics",
                     return_value=_DIAGNOSTICS),
        patch.object(tools_api.vault, "has_credential", return_value=False),
        patch.object(tools_api.instance_profile, "connectors_allowed",
                     return_value=allowed),
        patch.dict(tools_api.whitelist.CONFIG, {"mcp_backends": []}, clear=True),
    ]


class IntegrationsListTest(unittest.TestCase):
    def _run(self, allowed=None):
        # Se il verbo torna a passare per HTTP, questo mock lo fa fallire:
        # è il punto del test, non un dettaglio del montaggio.
        boom = AssertionError("integrations.list non deve fare HTTP")
        with patch.object(platform_ops, "_get", side_effect=boom), \
             patch.object(platform_ops, "_req", side_effect=boom):
            for p in _snapshot_env(allowed):
                p.start()
                self.addCleanup(p.stop)
            return platform_ops.integrations_list()

    def test_lists_the_gateway_connectors_without_any_http_hop(self):
        rows = self._run()["connectors"]
        by_id = {r["id"]: r for r in rows}
        self.assertIn("google", by_id)
        self.assertIn("mailboxes", by_id)
        self.assertTrue(by_id["google"]["connected"])
        self.assertEqual(by_id["mailboxes"]["provider"], "email")
        self.assertFalse(by_id["github"]["connected"])

    def test_projects_only_id_label_provider_connected(self):
        for row in self._run()["connectors"]:
            self.assertEqual(set(row), {"id", "label", "provider", "connected"})
            # `connected` è un bool vero, non il valore di verità di un oggetto.
            self.assertIsInstance(row["connected"], bool)

    def test_honours_the_instance_profile_allowlist(self):
        rows = self._run(allowed=["google"])["connectors"]
        self.assertEqual({r["id"] for r in rows} - {"topic-storage"}, {"google"})


class ToolsRouteSharesTheSnapshotTest(unittest.IsolatedAsyncioTestCase):
    async def test_get_tools_serves_the_same_source(self):
        request = Request({"type": "http", "method": "GET", "path": "/tools",
                           "headers": [], "query_string": b""})
        for p in _snapshot_env():
            p.start()
            self.addCleanup(p.stop)
        with patch.object(tools_api, "_authorized", return_value=True):
            response = await tools_api.list_tools(request)
        served = json.loads(response.body)["connectors"]
        self.assertEqual([c["id"] for c in served],
                         [c["id"] for c in tools_api.connectors_snapshot()])
        # La rotta resta più ricca del verbo: accounts/issues servono alla webui.
        self.assertIn("accounts", served[0])


if __name__ == "__main__":
    unittest.main()
