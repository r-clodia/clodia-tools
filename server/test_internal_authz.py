"""Le rotte `/internal/*` non sono il percorso MCP, e non ne applicavano le regole.

`http_app.build_app()` monta sullo stesso processo e sulla stessa porta il
`Mount("/mcp", …)` — avvolto da `_AuthMiddleware` — e tutte le rotte interne, che
si autorizzavano da sé su `agent ∈ CLODIA_PROVIDER_PRINCIPALS` e nient'altro. Ma
il claim `agent` è il **carrier**, non chi chiama: `proxy_auth.token_for` conia
sull'identità del carrier (di norma `clodia`), cioè esattamente il principal
privilegiato che queste API ammettono. Il tetto che sul percorso MCP tratteneva
quel token a quattro verbi di chat (`scoped_tools`) e la revoca vivevano solo in
`main`/`_AuthMiddleware`: fuori da `/mcp` non li leggeva nessuno.

Le tre rotte qui sotto sono il perché la cosa conta: due leggono segreti, la
terza **riscrive la whitelist dei verbi di un agente** — il punto di enforcement
che si lasciava riscrivere da chi vincola (clodia-platform#261).

Il quarto test è la direzione d'errore opposta, e non è decorativo: i chiamanti
reali (`git_client`, `provider_store`, `topics_client`, `telegram_client`,
`gateway_admin`, … in clodia-logic) coniano un token nudo sul principal, senza
`scoped_tools` né `on_behalf`. Una guardia che stringesse anche loro spegnerebbe
il runner in produzione.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from starlette.applications import Starlette
from starlette.testclient import TestClient

from . import agents_api, human_mcp, internal_auth, providers_api, vault_api, whitelist

_H = {"Authorization": "Bearer ckt1.finto"}

#: Come lo conia `proxy_auth.token_for`: carrier `clodia`, on-behalf di un
#: sistema terzo, stretto ai verbi di chat.
_PROXY = {"agent": "clodia", "principal": "crm-esterno", "principal_kind": "proxy",
          "on_behalf": True, "human_role": "user",
          "execution_id": "participant:SEAL-1/acme",
          "scoped_tools": list(human_mcp.PROXY_VERBS)}

#: Un client MCP umano il cui grant non sta (più) nel registro: `is_revoked`
#: risponde True, ed è la stessa lettura che fa `_AuthMiddleware` su `/mcp`.
_REVOCATO = {"agent": "clodia", "execution_id": "mcp_scomparso",
             "principal": "giovanni", "on_behalf": True}

#: Una sessione umana della webui (`gateway_pdp._token`): legittima, ma su
#: `/internal/tool` e `/internal/authorize`, non sulle rotte infrastrutturali.
_UMANO = {"agent": "clodia", "principal": "davide", "on_behalf": True,
          "human_role": "admin"}

#: Il runner di clodia-logic: `pki.mint_session_token(_PRINCIPAL, ttl)`, e basta.
_RUNNER = {"agent": "clodia"}


def _sessione(payload: dict):
    return patch.object(internal_auth, "verify_session_token", lambda _t: payload)


class _Rotte:
    """Le tre rotte sensibili dell'issue, con gli effetti collaterali neutralizzati:
    ciò che si misura è la DECISIONE, e un test che depositasse davvero nel vault
    o riscrivesse `config.yaml` misurerebbe anche altro."""

    def __enter__(self):
        # `vault_api.vault` e `providers_api.vault` sono lo STESSO modulo: la
        # doppia patch su `has_credential` si impilava, e uscendo si fermava in
        # ordine di avvio invece che inverso — quindi la lambda della seconda
        # restava installata su `server.vault` per tutta la sessione di test. Un
        # modulo eseguito dopo vedeva ogni credenziale come assente, e falliva
        # per un motivo che non era il suo. Una patch sola, e stop in ordine
        # inverso: l'isolamento è ciò che rende leggibile un rosso.
        self._p = [
            patch.object(vault_api.vault, "has_credential", lambda _n: False),
            patch.object(agents_api.whitelist, "upsert_agent",
                         lambda name, **kw: {"allowed_tools": ["topic.messages"]}),
            patch.object(agents_api.whitelist, "reload_config", lambda: None),
        ]
        for p in self._p:
            p.start()
        return TestClient(Starlette(routes=[*vault_api.routes, *providers_api.routes,
                                            *agents_api.routes]))

    def __exit__(self, *a):
        for p in reversed(self._p):
            p.stop()
        return False


def _tre_chiamate(c: TestClient) -> list:
    return [
        c.get("/internal/vault/github_pat", headers=_H),
        c.get("/internal/providers/anthropic", headers=_H),
        c.post("/internal/agents/whitelist", headers=_H,
               json={"agent": "vittima", "allowed_tools": ["*"]}),
    ]


class AProxyTokenIsNotAKeyToTheVaultTests(unittest.TestCase):

    def test_the_three_sensitive_routes_refuse_a_scoped_token(self):
        with _sessione(_PROXY), _Rotte() as c:
            for r in _tre_chiamate(c):
                self.assertEqual(r.status_code, 403, f"{r.request.url}: {r.text}")


class ARevokedSessionStopsEverywhereTests(unittest.TestCase):
    """Una revoca applicata su una porta sola non è una revoca: il token resta
    valido fino alla scadenza naturale su tutte le altre."""

    def test_the_three_sensitive_routes_refuse_a_revoked_token(self):
        with _sessione(_REVOCATO), _Rotte() as c:
            for r in _tre_chiamate(c):
                self.assertEqual(r.status_code, 401, f"{r.request.url}: {r.text}")


class TheInfrastructureRoutesAreNotAHumanFlowTests(unittest.TestCase):
    """Le credenziali e la whitelist non hanno un ramo umano: chi le tocca è il
    runner. Una sessione on-behalf qui non è un caso d'uso, è un carrier
    prestato."""

    def test_an_on_behalf_session_is_refused(self):
        with _sessione(_UMANO), _Rotte() as c:
            for r in _tre_chiamate(c):
                self.assertEqual(r.status_code, 403, f"{r.request.url}: {r.text}")


class TheRunnerStillGetsInTests(unittest.TestCase):
    """L'eccesso di zelo è il difetto successivo: qui si verifica che la guardia
    non abbia spento i chiamanti reali."""

    def test_the_bare_principal_token_passes_the_guard(self):
        with _sessione(_RUNNER), _Rotte() as c:
            vault_r, prov_r, agents_r = _tre_chiamate(c)
            # 404: autorizzati, la credenziale semplicemente non c'è.
            self.assertEqual(vault_r.status_code, 404)
            self.assertEqual(prov_r.status_code, 404)
            self.assertEqual(agents_r.status_code, 200)

    def test_the_decision_is_not_an_error(self):
        with _sessione(_RUNNER):
            payload, err = internal_auth.authorize(_finta_richiesta())
            self.assertIsNone(err)
            self.assertEqual(payload.get("agent"), "clodia")


class ThePiiRouterIsNotAServiceIdentityTests(unittest.TestCase):
    """`/internal/profile/*` si fida dell'header `X-Clodia-Principal` quando il
    carrier è un super-agent, e l'ACL di `profile.py` la applica a quel nome: un
    token di proxy (carrier `clodia`) dichiarava chi voleva e leggeva i PII."""

    def _chi(self, payload, declared="davide"):
        from starlette.requests import Request
        from . import profile_api
        req = Request({"type": "http", "method": "GET",
                       "path": "/internal/profile/davide",
                       "headers": [(b"authorization", b"Bearer ckt1.finto"),
                                   (b"x-clodia-principal", declared.encode())]})
        with patch.object(profile_api, "verify_session_token", lambda _t: payload):
            return profile_api._principal(req)

    def test_a_proxy_token_cannot_declare_a_principal(self):
        chi, err = self._chi(_PROXY)
        self.assertIsNone(chi)
        self.assertEqual(err.status_code, 403)

    def test_a_revoked_session_cannot_either(self):
        chi, err = self._chi(_REVOCATO)
        self.assertIsNone(chi)
        self.assertEqual(err.status_code, 401)

    def test_the_agent_server_service_token_still_declares(self):
        chi, err = self._chi(_RUNNER)
        self.assertIsNone(err)
        self.assertEqual(chi, "davide")


class TheTopicsApiKeepsItsHumanBranchTests(unittest.TestCase):
    """`/internal/topics` è l'unica di queste API con un ramo umano, e la
    differenza va tenuta: stringere anche lei spegnerebbe la pagina Topics."""

    def _decisione(self, payload, metodo="GET", path="/internal/topics"):
        from starlette.requests import Request
        from . import topics_api
        req = Request({"type": "http", "method": metodo, "path": path,
                       "headers": [(b"authorization", b"Bearer ckt1.finto")]})
        with _sessione(payload):
            return topics_api._authorize(req)

    def test_the_route_to_verb_map_covers_the_read_routes(self):
        from . import topics_api
        from starlette.requests import Request

        def verbo(metodo, path):
            return topics_api._verbo(Request({"type": "http", "method": metodo,
                                              "path": path, "headers": []}))

        self.assertEqual(verbo("GET", "/internal/topics"), "topic.list")
        self.assertEqual(verbo("GET", "/internal/topics/SEAL-1/acme"), "topic.open")
        self.assertEqual(verbo("GET", "/internal/topics/SEAL-1/acme/messages"),
                         "topic.messages")
        self.assertEqual(verbo("POST", "/internal/topics/SEAL-1/acme/messages"),
                         "topic.post_message")
        # Rotte di amministrazione: nessun verbo, quindi nessun token scoped.
        self.assertIsNone(verbo("GET", "/internal/topics/export"))
        self.assertIsNone(verbo("POST", "/internal/topics/SEAL-1/acme/participants"))

    def test_a_human_session_from_the_webui_still_reads_the_topics(self):
        chi, err = self._decisione(_UMANO)
        self.assertIsNone(err)
        self.assertEqual(chi, "clodia")

    def test_a_scoped_token_does_not_reach_the_admin_routes(self):
        _chi, err = self._decisione(
            {**_UMANO, "scoped_tools": ["topic.messages"]},
            metodo="POST", path="/internal/topics/SEAL-1/acme/participants")
        self.assertEqual(err.status_code, 403)


class ThePdpFacadeStopsARevokedSessionTests(unittest.TestCase):
    """`/internal/tool` esegue verbi: il tetto lo applica `call_tool` a valle, ma
    la revoca non la guardava nessuno."""

    def test_a_revoked_session_is_refused(self):
        from starlette.requests import Request
        from . import tool_api
        req = Request({"type": "http", "method": "POST", "path": "/internal/tool",
                       "headers": [(b"authorization", b"Bearer ckt1.finto")]})
        with patch.object(tool_api, "verify_session_token", lambda _t: _REVOCATO):
            _payload, _token, err = tool_api._auth(req)
        self.assertIsNotNone(err)
        self.assertEqual(err.status_code, 401)


class TheCredentialRoutesStopARevokedSessionTests(unittest.TestCase):
    """`/tools/*` deposita PAT, OAuth, configurazioni di backup e server MCP: la
    scadenza naturale di un client MCP umano è di trenta giorni, e senza questa
    lettura la revoca non arrivava prima."""

    def _ok(self, payload):
        from starlette.requests import Request
        from . import tools_api
        req = Request({"type": "http", "method": "POST", "path": "/tools/mcp",
                       "headers": [(b"authorization", b"Bearer ckt1.finto")]})
        with patch.object(tools_api, "_UI_TOKEN", None), \
             patch("server.pki_verify.verify_session_token", lambda _t: payload):
            return tools_api._authorized(req), tools_api._authorized_owner(req)

    def test_a_revoked_admin_session_cannot_administer_credentials(self):
        revocato = {**_REVOCATO, "human_role": "admin"}
        self.assertEqual(self._ok(revocato), (False, False))

    def test_a_live_admin_session_still_can(self):
        vivo = {"agent": "clodia", "principal": "davide", "on_behalf": True,
                "human_role": "admin"}
        self.assertEqual(self._ok(vivo), (True, True))


class TheCeilingRuleIsWrittenOnceTests(unittest.TestCase):
    """`scoped_tools` come tetto è la regola di `main._scoped_ceiling_ok`: qui si
    verifica che sia la STESSA, non una seconda copia che divergerà."""

    def test_a_verb_in_the_ceiling_passes(self):
        self.assertTrue(whitelist.scoped_ceiling_allows(
            "topic.messages", ["topic.messages"]))

    def test_a_namespace_wildcard_still_grants_the_namespace(self):
        self.assertTrue(whitelist.scoped_ceiling_allows("topic.files", ["topic.*"]))

    def test_a_verb_outside_the_ceiling_does_not(self):
        self.assertFalse(whitelist.scoped_ceiling_allows(
            "vault.read", list(human_mcp.PROXY_VERBS)))

    def test_no_ceiling_is_not_an_empty_ceiling(self):
        self.assertTrue(whitelist.scoped_ceiling_allows("vault.read", []))

    def test_main_delegates_to_the_same_rule(self):
        from . import main as M
        tok = whitelist.set_current_scoped_tools(list(human_mcp.PROXY_VERBS))
        try:
            self.assertTrue(M._scoped_ceiling_ok("topic.messages"))
            self.assertFalse(M._scoped_ceiling_ok("topic.write_file"))
        finally:
            whitelist.reset_current_scoped_tools(tok)


def _finta_richiesta(path: str = "/internal/vault/github_pat"):
    from starlette.requests import Request
    return Request({"type": "http", "method": "GET", "path": path,
                    "headers": [(b"authorization", b"Bearer ckt1.finto")]})


if __name__ == "__main__":
    unittest.main()
