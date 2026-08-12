"""A vault grant opens the CREDENTIAL, not the verbs.

What it did before. `_connector_allows` returned True for a granted credential's
whole namespace: holding `google_<account>` conferred `email.*`, `gdrive.*`,
`gdocs.*`, `gsheets.*` and `gcalendar.*` — 23 verbs — **regardless of what the
agent's seed declares**. Measured on venere: granting `messaggero` the account
would have handed it all of Drive, Calendar, Docs and Sheets, none of which its
seed asks for.

Why that mattered beyond the extra verbs. It made the declaration **decorative**
on five namespaces: the per-seed-class verb refactor, `profile_tools`, the whole
"trade" model decided nothing where the grant decided. And the security model
states that a principal's matrix bounds its verbs — on those namespaces that was
simply false.

The original justification was «la delega non dipende da config.yaml (effimero al
rebuild)». That premise no longer holds: `config.yaml` lives on the gateway's
`/gateway-state` bind mount and survives container recreation — verified on
venere.

Both are now required. The tests below pin both halves, because an implementation
that ignored either would pass a suite that only checked one.
"""
from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

from . import main as m

# messaggero: postino — dichiara la posta, NON il Drive.
# impiegato: dichiara gdrive.* esplicitamente.
# spoglio: nessuna dichiarazione.
CFG = {"agents": {
    "messaggero": {"allowed_tools": ["email.*", "topic.open"]},
    "impiegato": {"allowed_tools": ["gdrive.*", "email.send"]},
    "spoglio": {"allowed_tools": []},
}}

GOOGLE = {"google_devnullboxx"}


def _env(grants=GOOGLE, cfg=CFG, seed=None):
    from . import human, whitelist as w
    return (patch.object(w, "CONFIG", cfg),
            patch.object(m, "_vault_grants", lambda _a: set(grants)),
            patch.object(human, "_seed", lambda n: (seed or {}).get(n, {})))


class Base(unittest.TestCase):
    def setUp(self):
        self.ctx = _env()
        for c in self.ctx:
            c.start()
        self.addCleanup(lambda: [c.stop() for c in self.ctx])


class BothHalvesRequiredTests(Base):
    def test_a_declared_verb_with_the_grant_is_allowed(self):
        """La metà che si rompe se l'intersezione è troppo stretta. Senza questo
        test, un'implementazione che nega sempre passerebbe tutti gli altri."""
        self.assertTrue(m._connector_allows("email.send", "messaggero"))

    def test_an_undeclared_verb_with_the_grant_is_refused(self):
        """Il difetto che questa modifica chiude: il Drive arrivava a un postino
        come effetto collaterale di una credenziale concessa per la posta."""
        for verb in ("gdrive.download", "gdrive.share", "gdocs.read",
                     "gsheets.read", "gcalendar.list_events"):
            with self.subTest(verb=verb):
                self.assertFalse(m._connector_allows(verb, "messaggero"))

    def test_a_declared_verb_without_the_grant_is_refused(self):
        """L'altra metà: dichiarare un verbo non crea la credenziale."""
        with patch.object(m, "_vault_grants", lambda _a: set()):
            self.assertFalse(m._connector_allows("email.send", "messaggero"))
            self.assertFalse(m._connector_allows("gdrive.download", "impiegato"))

    def test_an_agent_that_declares_drive_keeps_it(self):
        self.assertTrue(m._connector_allows("gdrive.download", "impiegato"))
        self.assertTrue(m._connector_allows("gdrive.share", "impiegato"))
        # ma NON i namespace che non dichiara, benché la credenziale li copra
        self.assertFalse(m._connector_allows("gcalendar.list_events", "impiegato"))
        self.assertFalse(m._connector_allows("gsheets.read", "impiegato"))

    def test_a_wildcard_declaration_still_gets_the_namespace(self):
        """`gdrive.*` dichiarato deve continuare a coprire i suoi verbi: la
        modifica restringe rispetto al GRANT, non rispetto alla dichiarazione."""
        self.assertTrue(m._connector_allows("gdrive.mkdir", "impiegato"))


class UnregisteredAgentTests(unittest.TestCase):
    """Il caso che questa modifica potrebbe rompere, e non deve.

    `_connector_allows` esisteva per servire gli agenti NON in `config.yaml` — un
    clone per-topic, un responder appena materializzato. Per loro
    `agent_config` solleva KeyError, e un'intersezione ingenua li ridurrebbe a
    zero verbi di connettore: romperebbe precisamente il caso d'uso che la
    funzione doveva coprire.
    """

    def test_an_unregistered_agent_falls_back_to_its_seed(self):
        seed = {"clone-1": {"tool_permissions": ["email.send", "topic.open"]}}
        ctx = _env(cfg={"agents": {}}, seed=seed)
        for c in ctx:
            c.start()
        try:
            self.assertTrue(m._connector_allows("email.send", "clone-1"))
            self.assertFalse(m._connector_allows("gdrive.download", "clone-1"))
        finally:
            [c.stop() for c in ctx]

    def test_an_agent_with_neither_config_nor_seed_gets_nothing(self):
        ctx = _env(cfg={"agents": {}}, seed={})
        for c in ctx:
            c.start()
        try:
            self.assertFalse(m._connector_allows("email.send", "fantasma"))
        finally:
            [c.stop() for c in ctx]


class KillSwitchTests(Base):
    def test_it_is_on_by_default(self):
        """Acceso per default perché la misura lo sostiene: nessuno dei verbi che
        l'intersezione toglie risulta mai usato nella telemetria delle due
        istanze. Un'osservazione preventiva qui avrebbe solo ritardato una
        restrizione a impatto misurato zero."""
        with patch.dict("os.environ", {}, clear=True):
            self.assertTrue(m._connector_intersect_on())
            self.assertFalse(m._connector_allows("gdrive.download", "messaggero"))

    def test_off_restores_the_historical_behaviour(self):
        """Una telemetria è una finestra, non la storia completa: se salta fuori
        un flusso legittimo va sbloccato in un minuto, senza un deploy."""
        with patch.dict("os.environ", {"CLODIA_CONNECTOR_INTERSECT": "off"}):
            self.assertTrue(m._connector_allows("gdrive.download", "messaggero"))

    def test_an_unknown_value_does_not_silently_disable(self):
        with patch.dict("os.environ", {"CLODIA_CONNECTOR_INTERSECT": "forse"}):
            self.assertTrue(m._connector_intersect_on())


class SuperAgentTests(Base):
    def test_supers_are_untouched_because_the_dispatch_short_circuits(self):
        """Misurato prima di implementare, e ha corretto la mia stima
        dell'impatto: per un super-agent il dispatch decide su `_is_super` e non
        arriva mai qui, quindi l'intersezione non gli toglie niente. Il test
        fissa il fatto, così se un domani il corto-circuito venisse rimosso si
        scoprirebbe qui e non in produzione.
        """
        with patch.object(m, "agent_name", lambda: "clodia"), \
             patch.object(m, "is_on_behalf", lambda: False), \
             patch.object(m, "_is_super", lambda _n: True), \
             patch.object(m, "_agent_tool_reachable",
                          side_effect=AssertionError("matrix consulted for super")), \
             patch.object(m, "_unattended_denial", lambda _n: None), \
             patch.object(m.origin, "evaluate", return_value={"action": "allow"}), \
             patch.object(m, "_dispatch_memory", return_value={"files": []}), \
             patch.object(m._taint, "note_verb"), \
             patch.object(m._tlm, "record"):
            result = asyncio.run(m.call_tool("memory.list", {}))

        self.assertIn('"files": []', result[0].text)


if __name__ == "__main__":
    unittest.main()
