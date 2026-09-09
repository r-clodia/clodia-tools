"""Un ingresso `proxy` accende il taint del canale (clodia-platform#262).

La #222 ha consegnato il punto 1: l'etichetta autorevole si scrive dove il
messaggio NASCE (`kind: proxy`, firmato nel token). Il punto 2 restava aperto, ed
è quello che si copre qui: l'etichetta da sola è **soft mitigation** — la nota di
provenienza dipende dal fatto che il modello la rispetti. L'ENFORCEMENT è il
taint, e finché non si accende un sistema terzo può avviare lavoro dentro la
colonia mentre il context gate che scatta leggendo una issue pubblica non scatta
affatto.

Perché in `post_message` e non alla rotta: ci passano TUTTI gli scrittori — la
webui via `/internal/topics`, il verbo MCP del gateway, lo scheduler. Marcare a
una delle due porte lascerebbe l'altra muta, che è la forma esatta del difetto
già visto sull'annuncio SSE (#219).

Perché la sedia NON vale come vaglio: `egress.is_perimeter_source` dichiara
fidato chi è nella stanza, e un proxy È fra i partecipanti — è così che viene
ammesso (`proxy_auth._is_participant`). Ma il proxy non è la fonte: è un tubo che
ripete i byte di un sistema di cui nessuno risponde. La regola del perimetro
resta dov'è, sulla posta, e non si estende a `kind == "proxy"`.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from .. import taint
from .local_fs import LocalFsStorage
from .service import TopicService


class ProxyIngressTaintsTests(unittest.TestCase):
    #: La chiave di sessione di un proxy, coniata da `proxy_auth.token_for`. Il
    #: test legge lo stato DA QUI e non dalla chiave interna: ciò che conta è che
    #: il flag acceso postando sia lo stesso flag che il gate di uscita andrà a
    #: leggere nel turno successivo.
    CHAT = "chan:SEAL-1:ch:crm-esterno"

    def setUp(self) -> None:
        stato = tempfile.TemporaryDirectory()
        self.addCleanup(stato.cleanup)
        p = patch.object(taint, "_path",
                         side_effect=lambda: Path(stato.name) / "taint.json")
        p.start()
        self.addCleanup(p.stop)
        # l'annuncio SSE non c'entra con questa proprietà e non deve uscire
        a = patch("server.tools.runtime.announce_message")
        a.start()
        self.addCleanup(a.stop)
        self.svc = TopicService(LocalFsStorage(tempfile.mkdtemp()))
        with patch("server.instance_profile.topic_default_participants",
                   return_value=[]):
            self.svc.new("P1", "ch", {"title": "Canale", "owner": "owner"})

    def _posta(self, kind: str, author: str = "crm-esterno") -> dict:
        return self.svc.post_message("P1", "ch", author, "lavora su questo",
                                     kind=kind)

    def test_a_proxy_message_taints_the_channel(self) -> None:
        self._posta("proxy")
        self.assertTrue(taint.status(self.CHAT)["tainted"])

    def test_the_source_says_who_spoke(self) -> None:
        """«Il canale è contaminato» non è azionabile, «ha parlato questo proxy»
        sì: senza il riferimento l'umano declassifica alla cieca (#104 §4)."""
        self._posta("proxy")
        src = taint.status(self.CHAT)["sources"][-1]
        self.assertEqual(src["kind"], "message")
        self.assertIn("crm-esterno", src["detail"])

    def test_a_message_from_inside_does_not_taint(self) -> None:
        """L'utente autenticato dall'UI è trusted, e un agente della colonia non
        è una fonte esterna: un flag che si accende su tutto smette di
        discriminare, che è la condizione posta in #77 per non produrre consent
        fatigue."""
        for kind in ("human", "ai", "system"):
            with self.subTest(kind=kind):
                taint._save({})
                self._posta(kind, author="davide")
                self.assertFalse(taint.status(self.CHAT)["tainted"])

    def test_the_flag_is_monotone_once_armed(self) -> None:
        """Proprietà chiesta da @security-engineer in #262: monotono. Un
        messaggio interno dopo quello del proxy non lava il canale — l'unico
        interruttore legittimo è l'atto umano (`taint/clear`)."""
        self._posta("proxy")
        self._posta("human", author="davide")
        self.assertTrue(taint.status(self.CHAT)["tainted"])

    def test_the_message_is_still_written(self) -> None:
        """La misura non deve mangiarsi il messaggio che sta misurando."""
        msg = self._posta("proxy")
        self.assertEqual([m["id"] for m in self.svc.list_messages("P1", "ch")],
                         [msg["id"]])


if __name__ == "__main__":
    unittest.main()
