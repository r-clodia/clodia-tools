"""Residui dei connettori dei pack, lato gateway (clodia-platform#539).

§1 the agent-server is recognised by a SIGNED claim, not by what its token
   fails to carry;
§3 a broken pack cannot switch off a healthy pack's verbs;
§4 mounting an MCP backend does not change its owner;
§5 the credential of a connector is not written by an agent's runtime token.

§7 lives in `test_437_tool_call_audit.py`, where the flaky test is.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from starlette.applications import Starlette
from starlette.testclient import TestClient

from . import connectors_api, pki_mint, tools_api, topics_api
from .connectors import resolved

_H = {"Authorization": "Bearer ckt1.finto"}

#: I token in gioco, come li conia chi li conia.
RUNNER = {"agent": "clodia", "execution_id": "", "role": "agent-server"}
RUNNER_VECCHIO = {"agent": "clodia", "execution_id": ""}   # prima di #539
AGENTE = {"agent": "clodia", "execution_id": "clodia-320",
          "chat": "chan:SEAL-1:acme:clodia"}
UMANO_ADMIN = {"agent": "clodia", "principal": "davide", "on_behalf": True,
               "human_role": "admin", "principal_kind": "human"}
UMANO = {"agent": "clodia", "principal": "giovanni", "on_behalf": True,
         "human_role": "user", "principal_kind": "human"}


# ── §1 il claim si firma e si pretende ───────────────────────────────────────
class ServiceRoleMintTests(unittest.TestCase):
    def test_il_ruolo_entra_nel_payload_firmato(self):
        visto = {}

        class _K:
            def sign(self, b):
                return b"firma"

        with patch.object(pki_mint, "_agent_key_path") as kp, \
             patch.object(pki_mint, "_load_private", return_value=_K()), \
             patch.object(pki_mint, "_b64e", side_effect=lambda b: _cattura(visto, b)):
            kp.return_value.is_file.return_value = True
            pki_mint.mint_session_token("clodia", role=pki_mint.ROLE_AGENT_SERVER)
        self.assertEqual(visto["payload"].get("role"), "agent-server")

    def test_un_ruolo_inventato_non_si_firma(self):
        with self.assertRaises(PermissionError):
            pki_mint.mint_session_token("clodia", role="admin")

    def test_l_endpoint_di_mint_inoltra_il_ruolo(self):
        """Il claim arriva al firmatario: senza, il runner lo chiede e nessuno
        glielo mette, e la rotta dei muri lo rifiuterebbe."""
        from . import mint_api
        visti = {}

        def finto(agent, **k):
            visti.update(k)
            return "ckt1.x"

        with patch.object(mint_api, "_authorized", lambda r: True), \
             patch.object(mint_api.pki_mint, "mint_session_token", finto):
            c = TestClient(Starlette(routes=mint_api.routes))
            r = c.post("/internal/mint", json={"kind": "session", "agent": "clodia",
                                               "role": "agent-server"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(visti.get("role"), "agent-server")


def _cattura(visto, b):
    import json
    try:
        visto["payload"] = json.loads(b.decode())
    except Exception:  # noqa: BLE001 — la firma passa di qui, non è JSON
        pass
    return "x"


class WallAuthorizationTests(unittest.TestCase):
    """`_authorize_topic_owner`: chi può toccare i muri di un topic."""

    def _esito(self, claims, owner="clodia"):
        class _Req:
            headers = {"authorization": "Bearer ckt1.finto"}
            path_params = {"tier": "SEAL-1", "name": "acme"}

            class state:
                pass

        req = _Req()

        def finto_authorize(r):
            """`_authorize` ha già fatto il suo mestiere: firma verificata,
            claim in `request.state`. Qui si misura solo ciò che viene DOPO."""
            r.state.auth_payload = dict(claims)
            return claims.get("agent"), None

        with patch.object(topics_api, "_authorize", finto_authorize), \
             patch.object(topics_api, "_service") as svc:
            svc.return_value.open.return_value = {"meta": {"owner": owner}}
            who, err = topics_api._authorize_topic_owner(req)
        return who, err

    def test_il_runner_passa_per_il_claim(self):
        who, err = self._esito(RUNNER)
        self.assertIsNone(err)
        self.assertEqual(who, "clodia")

    def test_senza_claim_il_token_del_runner_non_basta_piu(self):
        """Il cuore di §1: il riconoscimento per ASSENZA è chiuso. Un token
        senza `execution_id` e senza `chat` non è più, per ciò solo, il
        runner — e `_execution_id` torna `""` quando lo spawn non ha ancora il
        workspace, cioè l'assenza è producibile per sbaglio."""
        who, err = self._esito(RUNNER_VECCHIO)
        self.assertIsNotNone(err)
        self.assertEqual(err.status_code, 403)

    def test_un_token_di_agente_resta_fuori(self):
        _who, err = self._esito(AGENTE)
        self.assertIsNotNone(err)
        self.assertEqual(err.status_code, 403)

    def test_l_umano_admin_passa(self):
        who, err = self._esito(UMANO_ADMIN, owner="qualcunaltro")
        self.assertIsNone(err)
        self.assertEqual(who, "davide")

    def test_l_umano_owner_passa(self):
        who, err = self._esito(UMANO, owner="giovanni")
        self.assertIsNone(err)
        self.assertEqual(who, "giovanni")

    def test_l_umano_non_owner_no(self):
        _who, err = self._esito(UMANO, owner="qualcunaltro")
        self.assertEqual(err.status_code, 403)


# ── §5 le credenziali non si toccano col token di un agente ──────────────────
class CredentialAuthorizationTests(unittest.TestCase):
    def _req(self, claims=None, header="Bearer ckt1.finto"):
        class _Req:
            headers = {"authorization": header}
        req = _Req()
        self._claims = claims
        return req

    def _with_claims(self, claims):
        return patch.object(tools_api, "_session_payload",
                            lambda request: dict(claims or {}))

    def test_il_runner_passa(self):
        with self._with_claims(RUNNER), \
             patch.object(tools_api, "_authorized_owner", lambda r: False):
            self.assertTrue(tools_api._authorized_service(self._req()))

    def test_il_token_runtime_di_clodia_non_passa_piu(self):
        """`_authorized` lo accetta ancora come super-agent: è esattamente la
        differenza che §5 chiede, e il token sta nell'env di ogni spawn."""
        with self._with_claims(AGENTE), \
             patch.object(tools_api, "_authorized_owner", lambda r: False):
            self.assertFalse(tools_api._authorized_service(self._req()))

    def test_ophelia_nemmeno(self):
        with self._with_claims({"agent": "ophelia", "execution_id": "o-1"}), \
             patch.object(tools_api, "_authorized_owner", lambda r: False):
            self.assertFalse(tools_api._authorized_service(self._req()))

    def test_l_umano_admin_e_il_trusted_core_passano(self):
        with patch.object(tools_api, "_authorized_owner", lambda r: True):
            self.assertTrue(tools_api._authorized_service(self._req()))


class PackImportEndToEndTests(unittest.TestCase):
    """Il percorso REALE di `pack_import`: la rotta di convalida con il token
    che clodia-logic conia (claim `role`), servita dall'app vera."""

    def _call(self, claims):
        with patch.object(tools_api, "_revocata", lambda p: False), \
             patch("server.pki_verify.verify_session_token",
                   lambda t: dict(claims)), \
             patch.object(tools_api, "_UI_TOKEN", None), \
             patch.object(tools_api, "_is_human_admin", lambda n: False), \
             patch.object(resolved, "manifests", dict):
            c = TestClient(Starlette(routes=connectors_api.routes))
            return c.post("/internal/connectors/validate",
                          json={"pack": "sms-pack", "connectors": []}, headers=_H)

    def test_il_token_del_runner_convalida_un_pack(self):
        r = self._call(RUNNER)
        self.assertEqual(r.status_code, 200, r.text)

    def test_il_token_runtime_di_un_agente_no(self):
        r = self._call(AGENTE)
        self.assertEqual(r.status_code, 401, r.text)

    def test_l_admin_al_pannello_tools_convalida(self):
        r = self._call(UMANO_ADMIN)
        self.assertEqual(r.status_code, 200, r.text)


# ── §3 un pack rotto non spegne i verbi del vicino ───────────────────────────
#: Un manifest rotto che dichiara il namespace di un ALTRO pack (`sms`, che
#: non è né nativo né builtin: se lo fosse, il filtro di prima lo escluderebbe
#: già e il test non proverebbe nulla).
ROTTO = {"connectors": [{"namespace": "sms", "verbs": [
    {"verb": "sms.send", "direction": "egress"},
    {"verb": "sms.broadcast", "direction": "egress", "prefix": True}]}]}
SUO = {"connectors": [{"namespace": "citofono", "verbs": [
    {"verb": "citofono.send", "direction": "egress"}]}]}


class FailsafeScopeTests(unittest.TestCase):
    def test_i_verbi_di_un_namespace_altrui_non_finiscono_nel_failsafe(self):
        """Fallisce chiuso, quindi è un disservizio e non un bypass — ma il
        danneggiato è un pack che non ha fatto nulla: basta un manifest rotto
        che dichiari il suo namespace per negarne i verbi."""
        fs = resolved._failsafe_from({"rotto": ROTTO}, reserved={"sms"})
        self.assertEqual(fs, ())

    def test_i_verbi_propri_del_pack_rotto_restano_negati(self):
        """L'invariante di #358 non si perde per strada: senza registry un
        verbo non mappato sarebbe «non controllato, permesso»."""
        fs = resolved._failsafe_from({"rotto": SUO}, reserved={"sms"})
        self.assertEqual(fs, ("citofono.send",))

    def test_il_prefisso_sopravvive(self):
        fs = resolved._failsafe_from({"rotto": ROTTO}, reserved=())
        self.assertEqual(fs, ("sms.broadcast*", "sms.send"))

    def test_un_backend_mcp_montato_e_di_chi_lo_ha_montato(self):
        with patch.object(resolved, "mounted_backends",
                          lambda: frozenset({"sms"})):
            fs = resolved._failsafe_from({"rotto": ROTTO})
        self.assertEqual(fs, ())

    def test_un_namespace_nativo_resta_escluso_come_prima(self):
        tg = {"connectors": [{"namespace": "telegram", "verbs": [
            {"verb": "telegram.send", "direction": "egress"}]}]}
        self.assertEqual(resolved._failsafe_from({"rotto": tg}), ())

    def test_il_confronto_non_si_fa_ingannare_da_trattini_e_underscore(self):
        rotto = {"connectors": [{"namespace": "norm_attiva", "verbs": [
            {"verb": "norm_attiva.send", "direction": "egress"}]}]}
        self.assertEqual(resolved._failsafe_from({"r": rotto},
                                                 reserved={"norm-attiva"}), ())


# ── §4 il mount non cambia proprietario ──────────────────────────────────────
class MountOwnershipTests(unittest.TestCase):
    def _mount(self, montati, pack):
        with patch.dict(tools_api.whitelist.CONFIG,
                        {"mcp_backends": list(montati)}, clear=True), \
             patch.object(tools_api.whitelist, "save_config"), \
             patch.object(tools_api.whitelist, "reload_config"), \
             patch.object(tools_api.proxy, "clear_cache"), \
             patch.object(tools_api.instance_profile, "integrations_check"):
            tools_api.register_mcp_core(
                {"mcpServers": {"sedia": {"url": "https://x/mcp"}}}, pack=pack)
            return list(tools_api.whitelist.CONFIG["mcp_backends"])

    DI_ADMIN = {"name": "sedia", "label": "sedia", "transport": "http",
                "url": "https://vecchio/mcp"}
    DI_PACK = {**DI_ADMIN, "pack": "studio-pack"}

    def test_un_pack_non_si_prende_il_backend_dell_admin(self):
        with self.assertRaises(tools_api.McpRegisterError) as ctx:
            self._mount([self.DI_ADMIN], "studio-pack")
        self.assertEqual(ctx.exception.status, 409)
        self.assertIn("montato dall'admin", str(ctx.exception))

    def test_l_admin_non_si_prende_il_backend_di_un_pack(self):
        with self.assertRaises(tools_api.McpRegisterError) as ctx:
            self._mount([self.DI_PACK], None)
        self.assertEqual(ctx.exception.status, 409)
        self.assertIn("studio-pack", str(ctx.exception))

    def test_un_pack_non_si_prende_il_backend_di_un_altro_pack(self):
        with self.assertRaises(tools_api.McpRegisterError) as ctx:
            self._mount([self.DI_PACK], "altro-pack")
        self.assertEqual(ctx.exception.status, 409)
        self.assertIn("studio-pack", str(ctx.exception))

    def test_rimontare_il_proprio_backend_resta_lecito(self):
        out = self._mount([self.DI_PACK], "studio-pack")
        self.assertEqual([(b["name"], b.get("pack"), b["url"]) for b in out],
                         [("sedia", "studio-pack", "https://x/mcp")])

    def test_l_admin_rimonta_il_suo(self):
        out = self._mount([self.DI_ADMIN], None)
        self.assertEqual([(b["name"], b.get("pack"), b["url"]) for b in out],
                         [("sedia", None, "https://x/mcp")])

    def test_un_backend_nuovo_non_e_di_nessuno_e_passa(self):
        out = self._mount([], None)
        self.assertEqual([b["name"] for b in out], ["sedia"])

    def test_il_rifiuto_non_lascia_mezzo_mount(self):
        """Il config si scrive in fondo: un rifiuto non deve aver già toccato
        la voce esistente."""
        montati = [self.DI_ADMIN]
        with self.assertRaises(tools_api.McpRegisterError):
            self._mount(montati, "studio-pack")
        self.assertEqual(montati, [self.DI_ADMIN])


if __name__ == "__main__":
    unittest.main()
