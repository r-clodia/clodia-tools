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
        # `ophelia` has a key too: the refusal of the service role on another
        # agent must come from the rule, not from a missing identity.
        for agent in ("clodia", "ophelia"):
            kd = Path(tmp.name) / "agents" / agent
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

    def test_the_role_is_signed_only_for_clodia(self) -> None:
        """Hardening (review of #363): the service role is the agent-server's,
        and the agent-server mints its own calls as `clodia`."""
        pki_mint.mint_session_token("ophelia")          # the identity is there
        with self.assertRaises(PermissionError):
            pki_mint.mint_session_token("ophelia", role=pki_mint.ROLE_AGENT_SERVER)

    def test_the_role_is_never_signed_on_a_turns_token(self) -> None:
        """`on_behalf`, `execution_id` and `chat` describe a human session or
        an agent in a turn: none of them belongs next to the service role."""
        for extra in ({"on_behalf": True, "principal": "davide",
                       "human_role": "admin"},
                      {"execution_id": "clodia-320"},
                      {"chat": "chan:SEAL-1:acme:clodia"}):
            with self.subTest(extra=extra), self.assertRaises(PermissionError):
                pki_mint.mint_session_token("clodia", role=pki_mint.ROLE_AGENT_SERVER,
                                            **extra)

    def test_the_mint_route_refuses_a_mixed_or_foreign_role_token(self) -> None:
        from starlette.applications import Starlette
        from starlette.testclient import TestClient
        from . import mint_api
        c = TestClient(Starlette(routes=mint_api.routes))
        for body in ({"agent": "ophelia"},
                     {"agent": "clodia", "on_behalf": True, "principal": "davide"},
                     {"agent": "clodia", "execution_id": "clodia-320"},
                     {"agent": "clodia", "chat": "chan:SEAL-1:acme:clodia"}):
            with self.subTest(body=body):
                r = c.post("/internal/mint", headers={"x-orchestrator-secret": "s"},
                           json={"kind": "session", "role": "agent-server", **body})
                self.assertEqual(403, r.status_code, r.text)

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
            {"rotto": _pack("courier", "courier.ship")}, reserved={"courier"})
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


    def test_a_broken_packs_own_mounted_backend_stays_denied(self) -> None:
        """Review of #363: excluding EVERY mounted backend also excluded the
        broken pack's own one. Once clodia-logic stamps `pack:` on its mounts,
        a broken manifest would have left those verbs unmapped — «not checked,
        allowed». Its own backend is not somebody else's: fail closed."""
        with patch.object(resolved, "mounted_backends",
                          lambda: frozenset({"courier", "norm_attiva"})), \
                patch.object(resolved, "backend_owners",
                             lambda packs=None: {"rotto": frozenset({"courier"}),
                                                 "altro": frozenset({"norm_attiva"})}):
            fs = resolved._failsafe_from({
                "rotto": {"connectors": [
                    _pack("courier", "courier.ship")["connectors"][0],
                    # a backend mounted by ANOTHER pack stays off limits
                    _pack("norm-attiva", "norm-attiva.cerca")["connectors"][0]]}})
        self.assertEqual(("courier.ship",), fs)

    def test_ownership_is_per_pack(self) -> None:
        """Two broken packs: each one's own backend is denied for it, not for
        the other."""
        with patch.object(resolved, "mounted_backends",
                          lambda: frozenset({"courier", "pigeon"})), \
                patch.object(resolved, "backend_owners",
                             lambda packs=None: {"a": frozenset({"courier"}),
                                                 "b": frozenset({"pigeon"})}):
            fs = resolved._failsafe_from({
                "a": {"connectors": [_pack("courier", "courier.ship")["connectors"][0],
                                     _pack("pigeon", "pigeon.fly")["connectors"][0]]},
                "b": {"connectors": [_pack("pigeon", "pigeon.fly")["connectors"][0]]}})
        self.assertEqual(("courier.ship", "pigeon.fly"), fs)

    def test_the_build_reserves_only_what_the_registry_holds(self) -> None:
        """Ported from #364: `_build` passes the namespaces of the connectors it
        KEEPS. A connector the registry refused does not own the namespace it
        claimed, so a broken pack declaring it still fails closed."""
        import inspect
        src = inspect.getsource(resolved._build)
        self.assertIn("reserved={c.namespace for c in keep}", src)


# ── §4 ───────────────────────────────────────────────────────────────────────
class AMountDoesNotChangeOwnerTests(unittest.TestCase):
    """`register_mcp_core` deduplicava per slug: la voce nuova SOSTITUIVA la
    vecchia e le scriveva sopra il proprio `pack`. La proprietà di un backend è
    ciò che poi dà a un pack il diritto di usarne il namespace per i propri
    connettori (`backend_owners`), quindi il rimount era un passaggio di
    proprietà senza che nessuno lo decidesse.
    """

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.vault_dir = Path(tmp.name) / "vault"
        env = patch.dict(os.environ, {"CLODIA_VAULT_DIR": str(self.vault_dir),
                                      "CLODIA_AUDIT_DIR": str(Path(tmp.name) / "audit"),
                                      "CLODIA_AUDIT_KEY_DIR": str(Path(tmp.name) / "k")})
        env.start()
        self.addCleanup(env.stop)

    def _monta(self, cfg, nome="courier", pack=None, url="http://c.invalid/mcp",
               secrets=None, servers=None):
        servers = servers or {nome: {"url": url,
                                     "headers": {"Authorization": "Bearer ${token}"}}}
        with patch.object(whitelist, "CONFIG", cfg), \
                patch.object(whitelist, "save_config", lambda: None), \
                patch.object(whitelist, "reload_config", lambda: None), \
                patch.object(proxy, "clear_cache", lambda: None), \
                patch("server.instance_profile.integrations_check", lambda s: None):
            return tools_api.register_mcp_core({"mcpServers": servers},
                                               secrets=secrets, pack=pack)

    def _vault_bytes(self) -> dict:
        if not self.vault_dir.exists():
            return {}
        return {str(f.relative_to(self.vault_dir)): f.read_bytes()
                for f in sorted(self.vault_dir.rglob("*"))
                if f.is_file() and "audit" not in f.name}

    def test_a_refused_mount_leaves_the_owners_secret_byte_identical(self) -> None:
        """Review of #363: the ownership check ran AFTER the vault deposit, and
        the secret name `mcp_<slug>_<name>` is shared — a mount refused with
        409 had already overwritten the legitimate owner's secret."""
        from . import vault
        cfg = {"mcp_backends": []}
        self._monta(cfg, pack="courier-pack", secrets={"token": "OWNER-SECRET"})
        prima = self._vault_bytes()
        self.assertTrue(prima)
        with self.assertRaises(tools_api.McpRegisterError) as e:
            self._monta(cfg, pack="rival-pack", secrets={"token": "RIVAL-SECRET"})
        self.assertEqual(409, e.exception.status)
        self.assertEqual(prima, self._vault_bytes())
        self.assertEqual("OWNER-SECRET",
                         vault.read_internal("mcp_courier_token")["value"])

    def test_a_refusal_on_a_later_server_writes_no_secret(self) -> None:
        """One request, two servers, the second refused: the first one's
        secret must not be left in the vault for a mount that did not happen."""
        cfg = {"mcp_backends": []}
        self._monta(cfg, nome="pigeon", pack="pigeon-pack")
        prima = self._vault_bytes()
        with self.assertRaises(tools_api.McpRegisterError):
            self._monta(cfg, pack="rival-pack", secrets={"token": "X"}, servers={
                "courier": {"url": "http://c.invalid/mcp",
                            "headers": {"Authorization": "Bearer ${token}"}},
                "pigeon": {"url": "http://p.invalid/mcp"}})
        self.assertEqual(prima, self._vault_bytes())
        self.assertEqual(["pigeon"], [b["name"] for b in cfg["mcp_backends"]])

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

# ── §1/§5 end to end ─────────────────────────────────────────────────────────
class PackImportEndToEndTests(unittest.TestCase):
    """The REAL path of `pack_import` (ported from #364): the validate route
    served by the real app (`http_app.build_app`), with tokens minted by the
    real signer and checked by the real verifier against a throwaway CA —
    nothing about the signature is patched."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        env = patch.dict(os.environ, {
            "CLODIA_SECRETS_DIR": str(base / "secrets"),
            "CLODIA_CA_CRT": str(base / "secrets" / "ca" / "ca.crt"),
            "CLODIA_PKI_CERTS": str(base / "pki" / "certs"),
            "CLODIA_PKI_REVOKED": str(base / "pki" / "revoked.json"),
            "CLODIA_DATA": str(base / "data"),
            "CLODIA_VAULT_DIR": str(base / "vault"),
            "CLODIA_AUDIT_DIR": str(base / "audit"),
            "CLODIA_AUDIT_KEY_DIR": str(base / "k"),
        })
        env.start()
        self.addCleanup(env.stop)
        pki_mint.init_ca()
        pki_mint.issue_agent_identity("clodia")
        ui = patch.object(tools_api, "_UI_TOKEN", None)
        ui.start()
        self.addCleanup(ui.stop)
        man = patch.object(resolved, "manifests", dict)
        man.start()
        self.addCleanup(man.stop)
        resolved.invalidate()
        self.addCleanup(resolved.invalidate)
        from starlette.testclient import TestClient
        from . import http_app
        self.client = TestClient(http_app.build_app())

    def _validate(self, token: str):
        return self.client.post("/internal/connectors/validate",
                                json={"pack": "sms-pack", "connectors": []},
                                headers={"Authorization": f"Bearer {token}"})

    def test_the_runners_service_token_validates_a_pack(self) -> None:
        tok = pki_mint.mint_session_token("clodia", role=pki_mint.ROLE_AGENT_SERVER)
        r = self._validate(tok)
        self.assertEqual(200, r.status_code, r.text)
        self.assertTrue(r.json().get("ok"), r.text)

    def test_an_agents_runtime_token_does_not(self) -> None:
        tok = pki_mint.mint_session_token("clodia", execution_id="clodia-320",
                                          chat="chan:SEAL-1:acme:clodia")
        self.assertEqual(401, self._validate(tok).status_code)

    def test_the_runner_token_without_the_claim_does_not(self) -> None:
        """Recognition by ABSENCE is closed: no `execution_id`, no `chat` is
        not, by itself, the agent-server."""
        self.assertEqual(401, self._validate(
            pki_mint.mint_session_token("clodia")).status_code)

    def test_a_claim_added_after_signing_does_not(self) -> None:
        import base64
        import json
        tok = pki_mint.mint_session_token("clodia")
        prefix, body, sig = tok.split(".")
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        payload["role"] = pki_mint.ROLE_AGENT_SERVER
        forged = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
        self.assertEqual(401, self._validate(f"{prefix}.{forged}.{sig}").status_code)

    def test_an_admin_at_the_tools_page_validates(self) -> None:
        tok = pki_mint.mint_session_token("clodia", principal="davide",
                                          on_behalf=True, human_role="admin",
                                          principal_kind="human")
        self.assertEqual(200, self._validate(tok).status_code)

    def test_a_non_admin_human_does_not(self) -> None:
        tok = pki_mint.mint_session_token("clodia", principal="giovanni",
                                          on_behalf=True, human_role="user",
                                          principal_kind="human")
        self.assertEqual(401, self._validate(tok).status_code)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()


from .connectors import first_party_fixture as _stamp


def setUpModule() -> None:
    # The mount-stamp declaration check is #641's own test; here every test
    # pack «declares» the servers it mounts (see the fixture's docstring).
    _stamp.any_pack_declares_any_backend()


def tearDownModule() -> None:
    _stamp.restore_backend_declarations()
