"""clodia-platform#565 — la credenziale di un backend MCP si chiede al «Connetti».

Si verifica, senza rete:
  1. lo schema `auth.methods` (oauth + credential) e i suoi rifiuti;
  2. un `.mcp.json` con un placeholder senza segreto diventa un metodo
     `credential` — nessun segreto al mount;
  3. prima del «Connetti» la card dice *non connesso* e una chiamata fallisce
     con un messaggio che dice cosa fare, senza mandare un placeholder al vendor;
  4. «Connetti» prova la credenziale: se il backend risponde la salva, se no
     non salva niente; la risposta e i log non contengono il valore;
  5. dopo il «Connetti» l'header arriva al backend dalla vault; «Disconnetti»
     e lo smontaggio la cancellano;
  6. un consenso OAuth non parte su un backend connesso con credenziale.
"""
from __future__ import annotations

import logging
import unittest
from contextlib import asynccontextmanager
from unittest.mock import patch

from . import mcp_credentials, mcp_oauth, proxy, tools_api
from .test_532_mcp_oauth import _vault

URL = "https://mcp.invoicetronic.test"
KEY = "ik_test_chiave_segretissima"
DECL = {"methods": [
    {"type": "oauth", "scope": "invoicetronic:read"},
    {"type": "credential",
     "fields": [{"name": "APIKEY", "label": "API key", "secret": True}],
     "inject": {"headers": {"Invoicetronic-ApiKey": "${APIKEY}"}}},
]}


class _Tools:
    def __init__(self, n):
        self.tools = [object()] * n


class _FakeSession:
    def __init__(self, owner):
        self.owner = owner

    async def list_tools(self):
        return _Tools(3)

    async def call_tool(self, name, arguments):
        class R:
            content = []
        return R()


class _Recorder:
    """Al posto del transport: registra il backend RISOLTO e decide se accettarlo."""

    def __init__(self, accept=KEY):
        self.accept = accept
        self.seen: list[dict] = []

    def session(self):
        rec = self

        @asynccontextmanager
        async def _session(b, *, oauth_handlers=None):
            b = proxy._resolve_secrets(mcp_credentials.apply(b))
            rec.seen.append(b)
            if (b.get("headers") or {}).get("Invoicetronic-ApiKey") != rec.accept:
                raise RuntimeError("401 Unauthorized")
            yield _FakeSession(rec)
        return _session


class _Base(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.vault = _vault(self)
        for mod in (mcp_credentials, tools_api, proxy):
            q = patch.object(mod, "vault", self.vault)
            q.start()
            self.addCleanup(q.stop)
        p = patch.dict(tools_api.whitelist.CONFIG, {"mcp_backends": []}, clear=True)
        p.start()
        self.addCleanup(p.stop)
        for target in ("save_config", "reload_config"):
            q = patch.object(tools_api.whitelist, target)
            q.start()
            self.addCleanup(q.stop)
        for q in (patch.object(tools_api.proxy, "clear_cache"),
                  patch.object(tools_api.instance_profile, "integrations_check")):
            q.start()
            self.addCleanup(q.stop)
        self.rec = _Recorder()
        q = patch.object(proxy, "session", self.rec.session())
        q.start()
        self.addCleanup(q.stop)

    def mount(self, spec, secrets=None, name="invoicetronic"):
        tools_api.register_mcp_core({"mcpServers": {name: spec}}, secrets or {},
                                    pack="studio-commercialista")
        return tools_api._mcp_backend(name)

    def card(self, name="invoicetronic"):
        with patch.object(tools_api.email_tool, "credential_diagnostics", return_value=[]):
            return next(c for c in tools_api.connectors_snapshot() if c.get("id") == name)


class SchemaTests(_Base):

    def test_both_methods_survive_the_mount(self):
        b = self.mount({"url": URL, "auth": DECL})
        types = [m["type"] for m in b["auth"]["methods"]]
        self.assertEqual(types, ["oauth", "credential"])

    def test_legacy_oauth_keeps_its_shape(self):
        b = self.mount({"url": URL, "auth": {"type": "oauth", "scope": "x"}})
        self.assertEqual(b["auth"], {"type": "oauth", "scope": "x"})

    def test_refusals(self):
        bad = [
            {"methods": []},
            {"methods": [{"type": "mtls"}]},
            {"methods": [{"type": "credential", "fields": ["A"], "inject": {"headers": {"X": "${B}"}}}]},
            {"methods": [{"type": "credential", "fields": ["A", "B"], "inject": {"headers": {"X": "${A}"}}}]},
            {"methods": [{"type": "credential", "fields": ["A"], "inject": {"env": {"X": "${A}"}}}]},
            {"methods": [{"type": "credential", "fields": ["A"], "inject": {"url": "http://x/${A}"}}]},
            {"methods": [{"type": "credential", "fields": ["1A"], "inject": {"headers": {"X": "${1A}"}}}]},
        ]
        for auth in bad:
            with self.subTest(auth=auth), self.assertRaises(tools_api.McpRegisterError):
                self.mount({"url": URL, "auth": auth})

    def test_stdio_credential_goes_to_env(self):
        b = self.mount({"command": "python3", "args": ["${CLAUDE_PLUGIN_ROOT}/s.py"],
                        "auth": {"methods": [{"type": "credential", "fields": ["TOKEN"],
                                              "inject": {"env": {"TOKEN": "${TOKEN}"}}}]}},
                       name="stdio-srv")
        self.assertEqual(b["auth"]["methods"][0]["inject"], {"env": {"TOKEN": "${TOKEN}"}})


class ImplicitTests(_Base):

    def test_a_placeholder_without_secret_becomes_a_credential_method(self):
        b = self.mount({"url": URL, "headers": {"Invoicetronic-ApiKey": "${APIKEY}",
                                                "X-Fixed": "1"}})
        m = mcp_credentials.credential_method(b)
        self.assertEqual([f["name"] for f in m["fields"]], ["APIKEY"])
        self.assertEqual(b["headers"], {"X-Fixed": "1"}, "il placeholder non resta nel config")
        self.assertFalse(self.vault.store, "nessun segreto al mount")

    def test_with_the_secret_in_the_request_the_old_path_holds(self):
        b = self.mount({"url": URL, "headers": {"K": "${APIKEY}"}}, secrets={"APIKEY": KEY})
        self.assertNotIn("auth", b)
        self.assertEqual(b["headers"]["K"], "${VAULT:mcp_invoicetronic_APIKEY}")

    def test_runtime_placeholders_and_args_are_not_credentials(self):
        b = self.mount({"command": "python3", "args": ["${CLAUDE_PLUGIN_ROOT}/s.py", "${X}"],
                        "env": {"ROOT": "${CLAUDE_PLUGIN_ROOT}"}}, name="plain")
        self.assertNotIn("auth", b)


class ConnectTests(_Base):

    async def test_before_connect_the_card_is_red_and_calls_are_refused(self):
        b = self.mount({"url": URL, "headers": {"Invoicetronic-ApiKey": "${APIKEY}"}})
        card = self.card()
        self.assertFalse(card["connected"])
        self.assertEqual(card["auth_methods"][0]["type"], "credential")
        self.assertIsNone(card["auth_active"])
        with self.assertRaises(mcp_credentials.CredentialRequired):
            mcp_credentials.apply(b)

    async def test_connect_tests_then_stores(self):
        b = self.mount({"url": URL, "auth": DECL})
        res = await mcp_credentials.connect(b, {"APIKEY": KEY})
        self.assertTrue(res["connected"])
        self.assertNotIn(KEY, repr(res))
        self.assertEqual(self.vault.store["mcp_cred_invoicetronic"], {"APIKEY": KEY})
        self.assertEqual(self.card()["auth_active"], "credential")
        self.assertTrue(self.card()["connected"])
        # la chiamata vera: header dalla vault, nessun provider OAuth
        self.assertIsNone(mcp_oauth.auth_spec(b))
        async with proxy.session(b) as _s:
            pass
        self.assertEqual(self.rec.seen[-1]["headers"]["Invoicetronic-ApiKey"], KEY)
        self.assertNotIn(KEY, repr(tools_api._mcp_backend("invoicetronic")))

    async def test_a_wrong_key_stores_nothing_and_does_not_echo(self):
        b = self.mount({"url": URL, "auth": DECL})
        with self.assertLogs("clodia-tools.mcp_credentials", level=logging.INFO) as logs, \
             self.assertRaises(ValueError) as e:
            await mcp_credentials.connect(b, {"APIKEY": "ik_test_sbagliata_lunga"})
        self.assertNotIn("ik_test_sbagliata_lunga", str(e.exception))
        self.assertNotIn("ik_test_sbagliata_lunga", "\n".join(logs.output))
        self.assertNotIn("mcp_cred_invoicetronic", self.vault.store)
        self.assertFalse(self.card()["connected"])

    async def test_undeclared_or_missing_fields_are_refused(self):
        b = self.mount({"url": URL, "auth": DECL})
        for fields in ({}, {"APIKEY": " "}, {"APIKEY": KEY, "ALTRO": "x"}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                await mcp_credentials.connect(b, fields)
        self.assertFalse(self.rec.seen, "nessun test partito con campi sbagliati")

    async def test_disconnect_and_unmount_forget_the_credential(self):
        b = self.mount({"url": URL, "auth": DECL})
        await mcp_credentials.connect(b, {"APIKEY": KEY})
        mcp_credentials.disconnect(b)
        self.assertNotIn("mcp_cred_invoicetronic", self.vault.store)
        await mcp_credentials.connect(b, {"APIKEY": KEY})
        tools_api.unregister_mcp_core("invoicetronic")
        self.assertNotIn("mcp_cred_invoicetronic", self.vault.store)

    async def test_pack_update_keeps_the_credential(self):
        b = self.mount({"url": URL, "auth": DECL})
        await mcp_credentials.connect(b, {"APIKEY": KEY})
        self.mount({"url": URL, "auth": DECL})  # Update del pack: stesso proprietario
        self.assertIn("mcp_cred_invoicetronic", self.vault.store)

    async def test_oauth_consent_refused_while_connected_by_credential(self):
        b = self.mount({"url": URL, "auth": DECL})
        await mcp_credentials.connect(b, {"APIKEY": KEY})
        with self.assertRaises(ValueError) as e:
            await mcp_oauth.begin(b)
        self.assertIn("Disconnetti", str(e.exception))


if __name__ == "__main__":
    unittest.main()
