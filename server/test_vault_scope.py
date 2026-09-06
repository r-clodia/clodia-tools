"""Un grant nomina anche PER CONTO DI CHI e DOVE (clodia-platform#270).

Fino a qui un grant nominava un agente e nient'altro: due persone sulla stessa
istanza condividevano una sola identità nella casella di posta, e alla domanda
«per conto di chi è stata letta quella mail» non c'era risposta nemmeno a
posteriori — non mancava solo l'ACL, mancava la traccia.

Le due dimensioni però ESISTONO già al momento in cui il vault decide, e
arrivano firmate: il principal dal claim `principal` del token, il topic dal
claim `chat`. Nessuna delle due è dichiarabile da un modello. Quello che
mancava non era l'identità: era che il vault la guardasse.

Regola del modello, ed è ciò che rende retrocompatibile il cambiamento:
**chiave assente = qualunque**. Un `vault-policy.yaml` scritto prima di oggi si
comporta esattamente come prima — e il primo test qui sotto è quello.
"""
from __future__ import annotations

import inspect
import json
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import yaml

from . import vault
from . import whitelist


@contextmanager
def _vault_dir():
    with tempfile.TemporaryDirectory() as d:
        with patch.object(vault, "vault_dir", lambda: Path(d)):
            yield Path(d)


@contextmanager
def _come(principal: str | None = None, topic: str | None = None):
    """Il contesto FIRMATO della richiesta: chi, e in che canale.

    `topic` si scrive nella forma che il gateway riceve davvero (la chiave di
    sessione `chan:<tier>:<nome>:<seed>#<n>`), non nella forma già digerita:
    se un giorno cambiasse il modo in cui il canale si deriva dal claim, questi
    test lo devono sentire.
    """
    chat = None
    if topic:
        tier, name = topic.split("/", 1)
        chat = f"chan:{tier}:{name}:clodia#1"
    tp = whitelist.set_current_principal(principal)
    tc = whitelist.set_current_chat(chat)
    try:
        yield
    finally:
        whitelist.reset_current_chat(tc)
        whitelist.reset_current_principal(tp)


def _policy(d: Path, grant: dict) -> None:
    """Scrive store + policy a mano: la forma sul disco è il contratto."""
    (d / "store").mkdir(parents=True, exist_ok=True)
    (d / "store" / "gmail_studio.json").write_text(
        json.dumps({"email": "studio@x.it"}), encoding="utf-8")
    (d / "vault-policy.yaml").write_text(yaml.safe_dump(
        {"credentials": {"gmail_studio": {"type": "oauth2_google",
                                          "grants": [grant]}}}), encoding="utf-8")


def _righe(d: Path) -> list[dict]:
    f = d / "audit.log"
    return [json.loads(r) for r in f.read_text().splitlines() if r.strip()] \
        if f.is_file() else []


class LegacyPolicyIsUntouchedTests(unittest.TestCase):
    """Il test che autorizza tutti gli altri: senza le due chiavi nuove, nulla
    cambia. Un vault già in produzione non deve accorgersi di questo PR."""

    def test_grant_without_the_new_keys_works_for_anyone_anywhere(self):
        with _vault_dir() as d:
            _policy(d, {"agent": "messaggero", "actions": ["fetch"]})
            with _come("davide", "SEAL-1/software-house"):
                self.assertEqual(vault.get_secret("messaggero", "gmail_studio"),
                                 {"email": "studio@x.it"})
            with _come("marta", "SEAL-2/contabilita"):
                self.assertEqual(vault.list_for("messaggero"), ["gmail_studio"])
            with _come():  # nessun contesto: un job, o una shell
                self.assertTrue(vault.get_secret("messaggero", "gmail_studio"))


class PrincipalScopeTests(unittest.TestCase):
    def test_another_person_does_not_get_the_mailbox(self):
        with _vault_dir() as d:
            _policy(d, {"agent": "messaggero", "actions": ["fetch"],
                        "principals": ["davide"]})
            with _come("marta", "SEAL-1/software-house"):
                with self.assertRaises(vault.VaultDenied) as e:
                    vault.get_secret("messaggero", "gmail_studio")
                self.assertEqual(vault.list_for("messaggero"), [])
        self.assertIn("principal", str(e.exception))

    def test_the_person_named_in_the_grant_does(self):
        with _vault_dir() as d:
            _policy(d, {"agent": "messaggero", "actions": ["fetch"],
                        "principals": ["davide"]})
            with _come("davide", "SEAL-1/software-house"):
                self.assertTrue(vault.get_secret("messaggero", "gmail_studio"))
                self.assertEqual(vault.list_for("messaggero"), ["gmail_studio"])


class TopicScopeTests(unittest.TestCase):
    def test_the_wrong_room_does_not_get_the_credential(self):
        with _vault_dir() as d:
            _policy(d, {"agent": "messaggero", "actions": ["fetch"],
                        "topics": ["SEAL-1/studio"]})
            with _come("davide", "SEAL-1/software-house"):
                with self.assertRaises(vault.VaultDenied) as e:
                    vault.get_secret("messaggero", "gmail_studio")
        self.assertIn("topic", str(e.exception))

    def test_the_room_named_in_the_grant_does(self):
        with _vault_dir() as d:
            _policy(d, {"agent": "messaggero", "actions": ["fetch"],
                        "topics": ["SEAL-1/studio"]})
            with _come("davide", "SEAL-1/studio"):
                self.assertTrue(vault.get_secret("messaggero", "gmail_studio"))


class NoContextIsNotAWildcardTests(unittest.TestCase):
    """Una restrizione che non si può verificare NON si concede.

    È il verso in cui si deve sbagliare: se il contesto firmato non dice in che
    topic siamo, un grant ristretto a un topic non vale «ovunque» — varrebbe
    proprio dove nessuno può controllarlo (un job schedulato, un `docker exec`).
    """

    def test_a_restricted_grant_is_denied_without_context(self):
        with _vault_dir() as d:
            _policy(d, {"agent": "messaggero", "actions": ["fetch"],
                        "topics": ["SEAL-1/studio"]})
            with _come():
                with self.assertRaises(vault.VaultDenied):
                    vault.get_secret("messaggero", "gmail_studio")


class TheRefusalSaysWhatFailedTests(unittest.TestCase):
    def test_it_names_the_dimension_and_still_forbids_delegation(self):
        """«Non hai il grant» e «il tuo grant non copre questo topic» mandano a
        fare due cose diverse. E in nessuno dei due casi la mossa è chiedere a
        un altro agente: userebbe la PROPRIA identità, che è esattamente ciò che
        #270 vuole smettere di confondere."""
        with _vault_dir() as d:
            _policy(d, {"agent": "messaggero", "actions": ["fetch"],
                        "principals": ["davide"]})
            with _come("marta", "SEAL-1/software-house"):
                with self.assertRaises(vault.VaultDenied) as e:
                    vault.get_secret("messaggero", "gmail_studio")
        msg = str(e.exception)
        self.assertIn("marta", msg)
        self.assertIn("altro agente", msg)
        self.assertNotIn("davide", msg)  # non si indica a chi delegare


class OneDecisionNotThreeTests(unittest.TestCase):
    """`grants_for`, `list_for` e `get_secret` devono decidere nello stesso
    punto. Tre letture parallele dello stesso dict divergono: è il difetto che
    abbiamo appena pagato su clodia-platform#296, e non si ripete qui."""

    def test_list_and_fetch_agree_in_every_context(self):
        with _vault_dir() as d:
            _policy(d, {"agent": "messaggero", "actions": ["fetch"],
                        "principals": ["davide"], "topics": ["SEAL-1/studio"]})
            for principal, topic in (("davide", "SEAL-1/studio"),
                                     ("davide", "SEAL-1/altro"),
                                     ("marta", "SEAL-1/studio"),
                                     (None, None)):
                with self.subTest(principal=principal, topic=topic):
                    with _come(principal, topic):
                        elencata = "gmail_studio" in vault.list_for("messaggero")
                        try:
                            vault.get_secret("messaggero", "gmail_studio")
                            ottenuta = True
                        except vault.VaultDenied:
                            ottenuta = False
                    self.assertEqual(elencata, ottenuta)


class ContextIsNeverAnArgumentTests(unittest.TestCase):
    """Il principal e il topic si leggono SOLO dal contesto firmato.

    Se un giorno diventassero parametri, un chiamante potrebbe dichiararsi in un
    topic in cui non è — e l'ACL diventerebbe un'autodichiarazione, cioè niente.
    Questa guardia costa una riga e regge quella proprietà nel tempo.
    """

    def test_get_secret_takes_only_agent_and_credential(self):
        self.assertEqual(list(inspect.signature(vault.get_secret).parameters),
                         ["agent", "credential"])


class AuditAnswersOnWhoseBehalfTests(unittest.TestCase):
    def test_every_record_carries_principal_and_topic(self):
        with _vault_dir() as d:
            _policy(d, {"agent": "messaggero", "actions": ["fetch"]})
            with _come("davide", "SEAL-1/software-house"):
                vault.get_secret("messaggero", "gmail_studio")
                vault.set_grant("gmail_studio", "dairio", True)
            righe = _righe(d)
        self.assertTrue(righe)
        for r in righe:
            self.assertEqual(r["principal"], "davide")
            self.assertEqual(r["topic"], "SEAL-1/software-house")

    def test_a_denial_says_it_too(self):
        """Il rifiuto è la riga che si va a cercare dopo: senza le due chiavi
        direbbe che è successo, non a chi."""
        with _vault_dir() as d:
            _policy(d, {"agent": "messaggero", "actions": ["fetch"],
                        "principals": ["davide"]})
            with _come("marta", "SEAL-1/studio"):
                with self.assertRaises(vault.VaultDenied):
                    vault.get_secret("messaggero", "gmail_studio")
            r = _righe(d)[-1]
        self.assertEqual(r["result"], "DENIED")
        self.assertEqual(r["principal"], "marta")
        self.assertEqual(r["topic"], "SEAL-1/studio")


class WritingAndReadingTheScopeTests(unittest.TestCase):
    def test_set_grant_persists_the_restrictions(self):
        with _vault_dir() as d:
            vault.set_grant("gmail_studio", "messaggero", True,
                            principals=["davide"], topics=["SEAL-1/studio"])
            spec = yaml.safe_load((d / "vault-policy.yaml").read_text())
        g = spec["credentials"]["gmail_studio"]["grants"][0]
        self.assertEqual(g["principals"], ["davide"])
        self.assertEqual(g["topics"], ["SEAL-1/studio"])

    def test_set_grant_without_restrictions_writes_no_keys(self):
        """Un grant senza restrizioni non deve scrivere `principals: []`: una
        lista vuota si legge come «nessuno» e sarebbe l'opposto."""
        with _vault_dir() as d:
            vault.set_grant("gmail_studio", "messaggero", True)
            spec = yaml.safe_load((d / "vault-policy.yaml").read_text())
        g = spec["credentials"]["gmail_studio"]["grants"][0]
        self.assertNotIn("principals", g)
        self.assertNotIn("topics", g)

    def test_grant_scope_shows_the_matrix(self):
        with _vault_dir() as d:
            _policy(d, {"agent": "messaggero", "actions": ["fetch"],
                        "principals": ["davide"]})
            del d
            scope = vault.grant_scope("gmail_studio")
        self.assertEqual(scope["messaggero"]["principals"], ["davide"])
        self.assertEqual(scope["messaggero"]["topics"], [])   # = ovunque
        self.assertIn("fetch", scope["messaggero"]["actions"])


class ProfileAclKeepsWorkingTests(unittest.TestCase):
    """`profile.py` riusa i grant del vault per l'ACL dei profili, e non ha
    (né vuole) restrizioni: deve restare identico a prima."""

    def test_a_profile_grant_is_visible_to_its_grantee(self):
        with _vault_dir() as d:
            vault.deposit("profile_dairio", {"fields": {}}, cred_type="profile",
                          grant_agents=["clodia"])
            del d
            vault.set_grant("profile_dairio", "ophelia", True)
            with _come("marta", "SEAL-2/altrove"):
                self.assertIn("profile_dairio", vault.grants_for("ophelia"))


class TheGrantEndpointCanNarrowTests(unittest.TestCase):
    """`POST /internal/connectors/grant` accetta le due chiavi, e **solo se le
    riceve**: il body di oggi concede come oggi, così la UI attuale non cambia."""

    @contextmanager
    def _client(self):
        from starlette.applications import Starlette
        from starlette.testclient import TestClient
        from . import connectors_api as ca
        with _vault_dir() as d:
            with patch.object(ca, "_authorize", lambda _r: ("owner", None)), \
                 patch.object(ca.vault, "email_connectors", lambda: ["studio"]):
                yield TestClient(Starlette(routes=ca.routes)), d

    def test_the_restrictions_reach_the_policy(self):
        with self._client() as (c, d):
            r = c.post("/internal/connectors/grant",
                       json={"agent": "messaggero", "account": "studio",
                             "granted": True, "principals": ["davide"],
                             "topics": ["SEAL-1/studio"]})
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()["scope"]["principals"], ["davide"])
            g = yaml.safe_load((d / "vault-policy.yaml").read_text())
        voce = g["credentials"]["gmail_studio"]["grants"][0]
        self.assertEqual(voce["topics"], ["SEAL-1/studio"])

    def test_the_body_of_today_still_grants_to_everyone(self):
        with self._client() as (c, d):
            r = c.post("/internal/connectors/grant",
                       json={"agent": "messaggero", "account": "studio",
                             "granted": True})
            self.assertEqual(r.status_code, 200)
            g = yaml.safe_load((d / "vault-policy.yaml").read_text())
        voce = g["credentials"]["gmail_studio"]["grants"][0]
        self.assertNotIn("principals", voce)
        self.assertNotIn("topics", voce)

    def test_a_malformed_restriction_is_refused_not_ignored(self):
        """Silenziare un `principals: "davide"` scritto male concederebbe a tutti
        credendo di restringere: il modo peggiore di sbagliare, qui."""
        with self._client() as (c, _d):
            r = c.post("/internal/connectors/grant",
                       json={"agent": "messaggero", "account": "studio",
                             "granted": True, "principals": "davide"})
        self.assertEqual(r.status_code, 400)


if __name__ == "__main__":
    unittest.main()
