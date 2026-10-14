"""clodia-platform#539 — i residui della verifica indipendente del 14 ott 2026.

Nessuno dei difetti qui misurati era sfruttabile sul codice di quel giorno: si
chiudono prima che altri pack portino connettori, cioè prima che le condizioni
che li rendevano inerti smettano di valere.

§1 il ruolo di servizio è firmato e il mint rifiuta gli altri valori
    (l'enforcement sulle rotte sta in `test_519_generic_second_verification`);
§3 un manifest rotto non spegne i verbi di un VICINO sano;
§4 un mount non cambia il proprietario di un backend già montato;
§7 un verbo che non esiste non apre una card: si risponde subito.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from . import pki_mint, proxy, tools_api, whitelist
from .connectors import resolved


# ── §1 ───────────────────────────────────────────────────────────────────────
class ServiceRoleMintTests(unittest.TestCase):
    """Il claim esiste, si firma, e non è un sistema di ruoli."""

    def setUp(self) -> None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        kd = Path(tmp.name) / "agents" / "clodia"
        kd.mkdir(parents=True)
        (kd / "identity.key").write_bytes(Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        env = patch.dict(os.environ, {"CLODIA_SECRETS_DIR": tmp.name,
                                      "CLODIA_ORCHESTRATOR_SECRET": "s"})
        env.start()
        self.addCleanup(env.stop)

    @staticmethod
    def _payload(token: str) -> dict:
        import base64
        import json
        body = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))

    def test_the_role_is_signed_into_the_token(self) -> None:
        tok = pki_mint.mint_session_token("clodia", role=pki_mint.ROLE_AGENT_SERVER)
        self.assertEqual(pki_mint.ROLE_AGENT_SERVER, self._payload(tok).get("role"))

    def test_a_token_without_it_does_not_carry_it(self) -> None:
        self.assertIsNone(self._payload(
            pki_mint.mint_session_token("clodia")).get("role"))

    def test_an_unknown_role_is_refused_at_the_mint(self) -> None:
        with self.assertRaises(PermissionError):
            pki_mint.mint_session_token("clodia", role="admin")

    def test_the_mint_route_forwards_it(self) -> None:
        """Il percorso VERO: clodia-logic non firma più da sé, chiede al
        gateway. Un claim che si ferma in `mint_api` è un claim che in
        produzione non esiste (è già successo con `origin`, #450)."""
        from starlette.applications import Starlette
        from starlette.testclient import TestClient
        from . import mint_api
        c = TestClient(Starlette(routes=mint_api.routes))
        r = c.post("/internal/mint", headers={"x-orchestrator-secret": "s"},
                   json={"kind": "session", "agent": "clodia", "role": "agent-server"})
        self.assertEqual(200, r.status_code, r.text)
        self.assertEqual("agent-server", self._payload(r.json()["token"])["role"])

    def test_the_mint_route_refuses_an_invented_role(self) -> None:
        from starlette.applications import Starlette
        from starlette.testclient import TestClient
        from . import mint_api
        c = TestClient(Starlette(routes=mint_api.routes))
        r = c.post("/internal/mint", headers={"x-orchestrator-secret": "s"},
                   json={"kind": "session", "agent": "clodia", "role": "admin"})
        self.assertEqual(403, r.status_code)

    def test_the_two_sides_agree_on_the_string(self) -> None:
        """Il nome è un contratto fra due repository: qui si firma, in
        clodia-logic (`colony.pki.ROLE_AGENT_SERVER`) si conia. Se uno dei due
        cambia stringa, il gateway rifiuta l'agent-server e la pagina Topics
        smette di funzionare — meglio leggerlo scritto."""
        self.assertEqual("agent-server", pki_mint.ROLE_AGENT_SERVER)
        self.assertEqual((pki_mint.ROLE_AGENT_SERVER,), pki_mint.ROLES)


# ── §3 ───────────────────────────────────────────────────────────────────────
def _pack(ns: str, verbo: str) -> dict:
    return {"connectors": [{
        "id": ns, "manifest_version": 1, "namespace": ns,
        "verbs": [{"verb": verbo, "direction": "egress"}]}]}


class BrokenPackDoesNotDenySomebodyElsesVerbsTests(unittest.TestCase):
    """Il failsafe è giusto che chiuda i verbi del pack ROTTO: non mappati
    varrebbe «non controllati». Non è giusto che chiuda quelli di chi sta bene —
    «installa un pack rotto che dichiara il namespace del concorrente» è una
    mossa da tre righe di YAML, e il risultato è un verbo altrui che smette di
    funzionare senza che nessuno capisca perché.
    """

    def test_its_own_verbs_fail_closed(self) -> None:
        fs = resolved._failsafe_from({"rotto": _pack("courier", "courier.ship")})
        self.assertEqual(("courier.ship",), fs)

    def test_a_healthy_packs_namespace_is_off_limits(self) -> None:
        fs = resolved._failsafe_from(
            {"rotto": _pack("courier", "courier.ship")},
            {"sano": _pack("courier", "courier.ship")})
        self.assertEqual((), fs)

    def test_a_mounted_backends_namespace_is_off_limits(self) -> None:
        with patch.object(resolved, "mounted_backends",
                          lambda: frozenset({"norm_attiva"})):
            fs = resolved._failsafe_from({"rotto": _pack("norm-attiva", "norm-attiva.cerca")})
        self.assertEqual((), fs)

    def test_the_comparison_survives_dashes_and_underscores(self) -> None:
        """Gli slug dei backend usano `-`, i namespace `_`: un confronto a
        stringa mancherebbe proprio il caso che questa guardia deve cogliere."""
        with patch.object(resolved, "mounted_backends",
                          lambda: frozenset({"norm_attiva"})):
            self.assertEqual((), resolved._failsafe_from(
                {"rotto": {"connectors": [{"id": "x", "manifest_version": 1,
                                           "namespace": "norm-attiva",
                                           "verbs": [{"verb": "norm-attiva.cerca",
                                                      "direction": "egress"}]}]}}))

    def test_the_gateways_own_namespaces_stay_off_limits(self) -> None:
        """La garanzia che c'era già e che non deve essersi persa."""
        self.assertEqual((), resolved._failsafe_from(
            {"rotto": _pack("email", "email.send")}))


# ── §4 ───────────────────────────────────────────────────────────────────────
class AMountDoesNotChangeOwnerTests(unittest.TestCase):
    """`register_mcp_core` deduplicava per slug: la voce nuova SOSTITUIVA la
    vecchia e le scriveva sopra il proprio `pack`. La proprietà di un backend è
    ciò che poi dà a un pack il diritto di usarne il namespace per i propri
    connettori (`backend_owners`), quindi il rimount era un passaggio di
    proprietà senza che nessuno lo decidesse.
    """

    def _monta(self, cfg, nome="courier", pack=None, url="http://c.invalid/mcp"):
        with patch.object(whitelist, "CONFIG", cfg), \
                patch.object(whitelist, "save_config", lambda: None), \
                patch.object(whitelist, "reload_config", lambda: None), \
                patch.object(proxy, "clear_cache", lambda: None), \
                patch("server.instance_profile.integrations_check", lambda s: None):
            return tools_api.register_mcp_core({"mcpServers": {nome: {"url": url}}},
                                               pack=pack)

    def test_a_pack_cannot_take_over_an_admins_backend(self) -> None:
        cfg = {"mcp_backends": []}
        self._monta(cfg)                                   # admin
        with self.assertRaises(tools_api.McpRegisterError) as e:
            self._monta(cfg, pack="courier-pack")
        self.assertEqual(409, e.exception.status)
        self.assertNotIn("pack", cfg["mcp_backends"][0])   # proprietà intatta
        self.assertEqual(1, len(cfg["mcp_backends"]))

    def test_an_admin_cannot_take_over_a_packs_backend(self) -> None:
        cfg = {"mcp_backends": []}
        self._monta(cfg, pack="courier-pack")
        with self.assertRaises(tools_api.McpRegisterError) as e:
            self._monta(cfg)
        self.assertEqual(409, e.exception.status)
        self.assertEqual("courier-pack", cfg["mcp_backends"][0]["pack"])

    def test_a_pack_cannot_take_over_another_packs_backend(self) -> None:
        cfg = {"mcp_backends": []}
        self._monta(cfg, pack="courier-pack")
        with self.assertRaises(tools_api.McpRegisterError) as e:
            self._monta(cfg, pack="rival-pack")
        self.assertEqual(409, e.exception.status)
        self.assertEqual("courier-pack", cfg["mcp_backends"][0]["pack"])

    def test_the_owner_can_still_remount_its_own(self) -> None:
        """Un rimount dallo stesso proprietario è un aggiornamento legittimo:
        cambia URL, header, segreti. Vietarlo sarebbe una seconda rottura."""
        cfg = {"mcp_backends": []}
        self._monta(cfg, pack="courier-pack")
        self._monta(cfg, pack="courier-pack", url="http://nuovo.invalid/mcp")
        self.assertEqual(1, len(cfg["mcp_backends"]))
        self.assertEqual("http://nuovo.invalid/mcp", cfg["mcp_backends"][0]["url"])
        self.assertEqual("courier-pack", cfg["mcp_backends"][0]["pack"])

    def test_an_admin_can_still_remount_its_own(self) -> None:
        cfg = {"mcp_backends": []}
        self._monta(cfg)
        self._monta(cfg, url="http://nuovo.invalid/mcp")
        self.assertEqual(1, len(cfg["mcp_backends"]))
        self.assertEqual("http://nuovo.invalid/mcp", cfg["mcp_backends"][0]["url"])

    def test_the_refusal_names_both_sides(self) -> None:
        """Il messaggio deve dire chi c'era e cosa fare: un 409 muto manda a
        leggere il codice del gateway."""
        cfg = {"mcp_backends": []}
        self._monta(cfg, pack="courier-pack")
        with self.assertRaises(tools_api.McpRegisterError) as e:
            self._monta(cfg, pack="rival-pack")
        msg = str(e.exception)
        self.assertIn("courier-pack", msg)
        self.assertIn("rival-pack", msg)
        self.assertIn("mcp.remove", msg)


# ── §7 ───────────────────────────────────────────────────────────────────────
class AnUnknownVerbIsNotApprovableTests(unittest.TestCase):
    """Un refuso dell'agente non è dichiarato nel profilo di nessuno, quindi
    `outside_profile` lo trovava «fuori profilo» e apriva una card: il turno
    restava appeso fino alla scadenza del gate e un umano era chiamato ad
    approvare `no.such_verb`, che al ritorno finiva comunque in `unknown tool`.
    Stessa regola del blocco non presidiato: chiedere un consenso che non può
    cambiare l'esito è il difetto di #116.
    """

    def test_an_invented_verb_is_not_implemented(self) -> None:
        from . import main
        self.assertFalse(main._verb_implemented("no.such_verb"))
        self.assertFalse(main._verb_implemented(""))

    def test_every_advertised_native_verb_is_implemented(self) -> None:
        """Il verso che conta: il catalogo è fail-closed, quindi un nativo che
        non ci fosse dentro verrebbe RIFIUTATO. Questo test è il motivo per cui
        si può permettere di esserlo."""
        from . import main
        mancanti = [n for n in main.all_native_verb_names()
                    if not main._verb_implemented(n)]
        self.assertEqual([], mancanti)

    def test_the_verbs_the_instance_profile_turns_off_still_exist(self) -> None:
        """«Esiste» e «ti è concesso» sono due domande con due guardie: se il
        profilo spegne rag, i suoi verbi non diventano refusi."""
        from . import main
        with patch("server.instance_profile.rag_enabled", lambda: False):
            self.assertTrue(main._verb_implemented("rag.search"))
            self.assertTrue(main._verb_implemented("eu_corpus.list"))

    def test_a_mounted_backends_verb_is_implemented(self) -> None:
        from . import main
        with patch.object(main.proxy, "is_proxied", lambda n: n.startswith("courier.")):
            self.assertTrue(main._verb_implemented("courier.ship"))
            self.assertFalse(main._verb_implemented("altro.verbo"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
