"""`agents.grant_tool` non deve dichiarare un esito che non è vero (#304).

Il verbo scriveva nella datadir (`PATCH /api/agents/<n>/caps`) e rispondeva
`{"ok": true}`. Ma l'autorizzazione non si legge dalla datadir: `_agent_may`
guarda `allowed_tools` nella config del GATEWAY, che per progetto è
irraggiungibile dall'agent-server (§3.5). Un permesso concesso restava negato a
ogni chiamata, e nessuno andava a cercarlo — il file mostrava il verbo, l'agente
lo vedeva in lista, e il rifiuto sembrava un problema di ruolo. Costo misurato:
due giorni dell'`avvocato` passati da `sysadmin` per aggirare un grant che
risultava applicato e non lo era.

La revoca è la direzione peggiore, e ha un secondo modo di essere falsa che vale
anche a whitelist aggiornata: togliere un verbo dai `tool_permissions` propri non
toglie ciò che arriva da un antenato o da un wildcard. `ok: true` lì significa
«ho tolto» su un verbo ancora attivo.

Qui si misura una sola cosa, in tutte le direzioni: che la risposta riporti lo
STATO, non l'INTENZIONE — e che lo stato sia letto con la funzione
dell'enforcement, non con una copia della sua regola.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from .tools import agents_admin as AA


AGENTE = {"name": "avvocato", "type": "normal", "immutable": False,
          "tool_permissions": ["topic.open", "topic.write_file"]}


class _Scena:
    """Il mondo intorno al verbo: il backend che scrive la datadir, la whitelist
    del gateway che decide, e la provenienza dei verbi ereditati."""

    def __init__(self, effettivo: bool, prov: dict | None = None,
                 denied: tuple = ()):
        self.effettivo, self.prov, self.denied = effettivo, prov or {}, set(denied)
        self.patched: list[dict] = []
        # Copia PROPRIA e backend che APPLICA la scrittura. Prima il finto
        # backend rispondeva senza toccare lo stato: dal #219 la risposta rilegge
        # il record, e un backend che ignora le scritture modellava proprio il
        # difetto che questi test non stanno misurando. Qui si misura
        # l'ENFORCEMENT, quindi il record dev'essere quello di un backend sano.
        self.agente = {**AGENTE,
                       "tool_permissions": list(AGENTE["tool_permissions"])}

    def __enter__(self):
        def _patch(name: str, body: dict) -> dict:
            self.patched.append(body)
            self.agente.update({k: list(v) for k, v in body.items()})
            return body

        self._p = [
            patch.object(AA, "_all_agents", lambda: [self.agente]),
            patch.object(AA, "_patch_caps", _patch),
        ]
        for p in self._p:
            p.start()
        from . import origin, whitelist
        self._p += [
            patch.object(origin, "_agent_may", lambda n, v: self.effettivo),
            patch.object(whitelist, "reload_config", lambda: {}),
            patch.object(whitelist, "tools_with_provenance", lambda n: self.prov),
            patch.object(whitelist, "agent_denies", lambda v, n=None: v in self.denied),
        ]
        for p in self._p[2:]:
            p.start()
        return self

    def __exit__(self, *a):
        for p in self._p:
            p.stop()
        return False


class GrantTests(unittest.TestCase):
    def test_a_grant_that_did_not_take_is_not_ok(self):
        """Il caso di #304, in una riga: scrittura riuscita, permesso inerte."""
        with _Scena(effettivo=False):
            out = AA.grant_tool("avvocato", "topic.write_document")
        self.assertFalse(out["ok"], "il verbo ha dichiarato un esito che non è vero")
        self.assertIs(out["effective"], False)
        self.assertIn("gateway", out["detail"])

    def test_a_grant_that_took_says_so_and_says_how_long(self):
        with _Scena(effettivo=True, prov={"topic.write_document": "own"}):
            out = AA.grant_tool("avvocato", "topic.write_document")
        self.assertTrue(out["ok"])
        self.assertIs(out["effective"], True)
        # La durata si dice anche quando è andata bene: un grant d'istanza torna
        # indietro al primo Update del pack, e scoprirlo dopo è lo stesso difetto
        # con un ritardo più lungo.
        self.assertEqual(out["persistence"], "instance")
        self.assertIn("seed", out["note"])

    def test_a_grant_blocked_by_a_deny_names_the_deny(self):
        """`denied_tools` batte ogni concessione: dire «non concesso» senza dire
        perché manda a cercare nel posto sbagliato."""
        with _Scena(effettivo=False, denied=("topic.write_document",)):
            out = AA.grant_tool("avvocato", "topic.write_document")
        self.assertFalse(out["ok"])
        self.assertIn("denied_tools", out["detail"])

    def test_the_write_still_happens(self):
        """Misurare non è rinunciare a scrivere: la datadir si aggiorna comunque,
        e l'esito riguarda l'autorizzazione."""
        with _Scena(effettivo=True) as s:
            AA.grant_tool("avvocato", "topic.write_document")
        self.assertIn("topic.write_document", s.patched[0]["tool_permissions"])


class RevokeTests(unittest.TestCase):
    def test_a_revocation_that_did_not_take_is_not_ok(self):
        with _Scena(effettivo=True):
            out = AA.revoke_tool("avvocato", "topic.write_file")
        self.assertFalse(out["ok"], "una revoca che non toglie niente ha detto ok")
        self.assertIs(out["effective"], True)

    def test_an_inherited_verb_names_its_ancestor_and_the_remedy(self):
        """Toglierlo dalla propria lista non lo toglie: il rimedio è `denied_tools`,
        e senza dirlo la revoca manda a modificare un file che non cambia niente."""
        with _Scena(effettivo=True, prov={"topic.write_file": "archseed"}):
            out = AA.revoke_tool("avvocato", "topic.write_file")
        self.assertFalse(out["ok"])
        self.assertEqual(out["inherited_from"], "archseed")
        self.assertIn("denied_tools", out["detail"])

    def test_a_wildcard_that_still_covers_the_verb_is_named(self):
        with _Scena(effettivo=True, prov={"topic.*": "own"}):
            out = AA.revoke_tool("avvocato", "topic.write_file")
        self.assertFalse(out["ok"])
        self.assertEqual(out["granted_by"], "topic.*")
        self.assertIn("topic.*", out["detail"])

    def test_a_revocation_that_took_is_ok(self):
        with _Scena(effettivo=False):
            out = AA.revoke_tool("avvocato", "topic.write_file")
        self.assertTrue(out["ok"])
        self.assertIs(out["effective"], False)


class UnmeasurableIsExplicitTests(unittest.TestCase):
    def test_a_failed_measurement_is_not_an_ok(self):
        """«Non ho potuto misurare» è un caso, non un via libera: è il modo in cui
        una verifica si trasforma in una decorazione."""
        with _Scena(effettivo=True) as s:
            from . import origin
            with patch.object(origin, "_agent_may",
                              side_effect=RuntimeError("config illeggibile")):
                out = AA.grant_tool("avvocato", "topic.write_document")
        self.assertFalse(out["ok"])
        self.assertIs(out["verified"], False)
        self.assertIsNone(out["effective"])
        del s


class TheCheckIsTheEnforcementTests(unittest.TestCase):
    """La verifica deve usare la funzione che poi NEGA, non una seconda lettura
    della matrice: tre lettori disallineati sono già costati un verbo concesso da
    un percorso e negato da un altro (`whitelist.effective_tools`)."""

    def test_the_measure_calls_origin(self):
        import inspect
        src = inspect.getsource(AA._measure)
        self.assertIn("origin", src)
        self.assertIn("agent_may", src)

    def test_the_public_alias_delegates(self):
        """L'alias pubblico non è una seconda implementazione: chiama quella."""
        import inspect
        from . import origin
        self.assertIn("_agent_may(name, verb)", inspect.getsource(origin.agent_may))


if __name__ == "__main__":
    unittest.main()
