"""clodia-platform#522 — what stays with the gateway when a connector's
implementation lives in a pack.

1. **reading a topic file.** A `send_file` verb sends a file that lives in a
   topic: the caller names the path, and the compartment check (the caller must
   be a member of THAT topic) and the audit of what crosses the boundary are
   attached to the read. A pack backend reading the topics' filesystem itself
   would skip both. So the manifest declares which arguments are the path and
   the bytes, and the gateway hands over the bytes;
2. **the bound chat.** A `defaults: value: binding` argument is resolved by the
   gateway from its bindings registry, per connector.

Born with Telegram (#522), measured on a generic `chat` connector since
Telegram's removal (#683). The tests fail on what would break SILENTLY: a file
read without the membership check, a path that reaches the backend.
"""
from __future__ import annotations

import base64
import json
import unittest
from unittest.mock import patch

from . import main
from .connectors import manifest as M
from .connectors import resolved

#: The minimal connector declaring a file: this test measures the MECHANISM.
PACK = {
    "name": "chat-pack",
    "connectors": [{
        "id": "chat", "manifest_version": 1, "namespace": "chat",
        "schemes": [{"scheme": "chat", "direction": "both",
                     "forms": [{"pattern": r"-?\d+", "example": "-100"}]}],
        "verbs": [{"verb": "chat.send_file", "direction": "egress",
                   "scheme": "chat", "arg": "chat_id"}],
        "defaults": [{"verb": "chat.send", "arg": "chat_id",
                      "value": "binding"}],
        "files": [{"verb": "chat.send_file", "path_arg": "path",
                   "bytes_arg": "content_b64", "name_arg": "filename",
                   "tier_arg": "tier", "topic_arg": "name",
                   "chat_arg": "chat_id"}],
    }],
}


def _registry(doc=PACK):
    return patch.object(resolved, "registry",
                        lambda: M.build_registry({doc["name"]: doc},
                                                 reserved=frozenset()))


class _Topics:
    """Lo storage dei topic, ridotto a ciò che la consegna usa."""

    def __init__(self, contenuto: bytes = b"ciao"):
        self.contenuto = contenuto
        self.letti: list = []

    def read_file(self, tier, name, path):
        self.letti.append((tier, name, path))
        return self.contenuto


class IlGatewayConsegnaIlFileTests(unittest.TestCase):

    def setUp(self) -> None:
        self.svc = _Topics()
        self.membership: list = []
        patches = [
            patch.object(main, "_topics", lambda: self.svc),
            patch.object(main, "_require_topic_member",
                         lambda svc, tier, name, mutating=False:
                         self.membership.append((tier, name))),
            patch.object(main, "_note_crossing", lambda **k: None),
            patch.object(main, "current_channel", lambda: "SEAL-1/software-house"),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_i_byte_arrivano_e_il_percorso_no(self) -> None:
        """Il backend riceve il contenuto e il nome, mai il percorso del topic:
        un pack che vedesse `local/x` saprebbe cosa chiedere la volta dopo."""
        args = {"path": "local/relazione.pdf", "caption": "ecco"}
        with _registry():
            self.assertTrue(main._fill_declared_file("chat.send_file", args))
        self.assertEqual(base64.b64decode(args["content_b64"]), b"ciao")
        self.assertEqual(args["filename"], "relazione.pdf")
        self.assertNotIn("path", args)
        self.assertNotIn("tier", args)
        self.assertEqual(args["caption"], "ecco")

    def test_la_membership_si_verifica_prima_di_leggere(self) -> None:
        """È il controllo che il pack non potrebbe fare: senza, il percorso
        scelto dal chiamante aprirebbe i file di un topic di cui non è
        partecipante."""
        with _registry():
            main._fill_declared_file("chat.send_file", {"path": "local/x"})
        self.assertEqual(self.membership, [("SEAL-1", "software-house")])
        self.assertEqual(self.svc.letti, [("SEAL-1", "software-house", "local/x")])

    def test_un_rifiuto_di_membership_non_legge_niente(self) -> None:
        def nega(svc, tier, name, mutating=False):
            raise PermissionError("non sei partecipante")
        with _registry(), patch.object(main, "_require_topic_member", nega):
            with self.assertRaises(PermissionError):
                main._fill_declared_file("chat.send_file",
                                         {"path": "local/x"})
        self.assertEqual(self.svc.letti, [])

    def test_il_topic_esplicito_vince(self) -> None:
        with _registry():
            main._fill_declared_file("chat.send_file", {
                "chat_id": "-100", "path": "local/x",
                "tier": "SEAL-2", "name": "altro"})
        self.assertEqual(self.membership, [("SEAL-2", "altro")])

    def test_senza_topic_esplicito_vale_la_chat_legata(self) -> None:
        """Il registro dei binding è del gateway: è la ragione per cui questa
        risoluzione non poteva andare nel pack."""
        legame = {"tier": "SEAL-3", "topic": "riservato"}
        with _registry(), \
                patch("server.tools.channel_bindings.get",
                      lambda conn, chat, **k: legame if conn == "chat" else None):
            main._fill_declared_file("chat.send_file",
                                     {"chat_id": "-100", "path": "local/x"})
        self.assertEqual(self.membership, [("SEAL-3", "riservato")])

    def test_una_chat_senza_binding_non_ricade_sul_canale(self) -> None:
        """Comportamento del codice nativo, conservato: se il chiamante NOMINA
        una chat, il file si legge dal topic di QUELLA chat. Ricadere sul canale
        corrente manderebbe in un gruppo il file di un altro topic — con la
        membership verificata sul topic sbagliato, cioè verificata per finta."""
        with _registry(), \
                patch("server.tools.channel_bindings.get", lambda *a, **k: None):
            with self.assertRaises(ValueError):
                main._fill_declared_file("chat.send_file",
                                         {"chat_id": "-100", "path": "local/x"})
        self.assertEqual(self.svc.letti, [])

    def test_senza_percorso_e_un_errore_non_un_invio_vuoto(self) -> None:
        with _registry():
            with self.assertRaises(ValueError):
                main._fill_declared_file("chat.send_file", {})

    def test_un_verbo_che_non_lo_dichiara_resta_intatto(self) -> None:
        args = {"path": "local/x"}
        with _registry():
            self.assertFalse(main._fill_declared_file("chat.send", args))
        self.assertEqual(args, {"path": "local/x"})

    def test_la_dichiarazione_vale_solo_dentro_il_proprio_namespace(self) -> None:
        """Un pack non si fa consegnare i file di topic per il verbo di un
        altro: sarebbe una lettura con il nome di qualcun altro."""
        doc = json.loads(json.dumps(PACK))
        doc["connectors"][0]["files"][0]["verb"] = "email.send"
        with self.assertRaises(M.ManifestError):
            M.build_registry({"comms-pack": doc}, reserved=frozenset())

    def test_un_manifest_del_gateway_non_puo_dichiararlo(self) -> None:
        with self.assertRaises(M.ManifestError):
            M.parse_connector(
                {"id": "tg2", "manifest_version": 1, "namespace": "tg2",
                 "schemes": [{"scheme": "tg2", "direction": "egress",
                              "forms": [{"pattern": r"\d+", "example": "1"}]}],
                 "verbs": [{"verb": "tg2.send_file", "direction": "egress",
                            "scheme": "tg2", "arg": "chat_id"}],
                 "files": [{"verb": "tg2.send_file", "path_arg": "p",
                            "bytes_arg": "b"}]},
                pack="gateway-chat", builtin=True)

    def test_i_byte_non_possono_sovrascrivere_il_percorso(self) -> None:
        doc = json.loads(json.dumps(PACK))
        doc["connectors"][0]["files"][0]["bytes_arg"] = "path"
        with self.assertRaises(M.ManifestError):
            M.build_registry({"comms-pack": doc}, reserved=frozenset())


class LaChatLegataLaRisolveIlGatewayTests(unittest.TestCase):
    """`defaults:` — il secondo fatto che un backend di pack non ha.

    Il registro dei binding è del gateway: lo scrive il bottone del topic e
    tiene i binding di TUTTI i connettori. Finché a leggerlo era il pack, lo
    faceva con l'uid del gateway e vedeva anche quelli degli altri — la
    scorciatoia che clodia-platform#544 chiude. Qui il valore lo mette il
    gateway, e la regola è l'opposto di quella del contesto: si riempie solo
    ciò che il chiamante ha omesso.
    """

    def setUp(self) -> None:
        p = patch.object(main, "current_channel", lambda: "SEAL-1/software-house")
        p.start()
        self.addCleanup(p.stop)

    def _registro(self, voci: dict):
        return patch("server.tools.channel_bindings.load",
                     lambda conn=None, **k: voci.get(conn, {}))

    def test_un_argomento_omesso_prende_la_chat_del_canale(self) -> None:
        args = {"text": "ciao"}
        with _registry(), self._registro({"chat": {
                "-100999": {"tier": "SEAL-1", "topic": "software-house"}}}):
            main._fill_declared_defaults("chat.send", args)
        self.assertEqual(args["chat_id"], "-100999")

    def test_un_argomento_esplicito_vince(self) -> None:
        """È la differenza con il contesto, e non è un dettaglio: se il default
        sovrascrivesse, non si potrebbe più scrivere a una chat diversa da
        quella legata al topic."""
        args = {"text": "ciao", "chat_id": "-100111"}
        with _registry(), self._registro({"chat": {
                "-100999": {"tier": "SEAL-1", "topic": "software-house"}}}):
            main._fill_declared_defaults("chat.send", args)
        self.assertEqual(args["chat_id"], "-100111")

    def test_il_binding_di_un_altro_connettore_non_vale(self) -> None:
        with _registry(), self._registro({"whatsapp": {
                "-100999": {"tier": "SEAL-1", "topic": "software-house"}}}):
            with self.assertRaises(ValueError):
                main._fill_declared_defaults("chat.send", {"text": "ciao"})

    def test_senza_chat_collegata_l_errore_nomina_la_causa(self) -> None:
        """Lasciare l'argomento vuoto farebbe calcolare al PDP una destinazione
        inesistente: l'agente leggerebbe «destinazione ignota» per un topic che
        semplicemente non ha una chat collegata."""
        with _registry(), self._registro({}):
            with self.assertRaises(ValueError) as e:
                main._fill_declared_defaults("chat.send", {"text": "ciao"})
        self.assertIn("collegala dal pulsante", str(e.exception))

    def test_un_verbo_senza_default_non_viene_toccato(self) -> None:
        """Per VERBO, non per namespace: `chat.inbox` non ha una chat da
        riempire e il suo schema non dichiara quell'argomento."""
        args = {}
        with _registry(), self._registro({"chat": {
                "-100999": {"tier": "SEAL-1", "topic": "software-house"}}}):
            self.assertEqual(main._fill_declared_defaults("chat.inbox", args), [])
        self.assertEqual(args, {})

    def test_un_manifest_del_gateway_non_puo_dichiararli(self) -> None:
        with self.assertRaises(M.ManifestError):
            M.parse_connector(
                {"id": "tg2", "manifest_version": 1, "namespace": "tg2",
                 "schemes": [{"scheme": "tg2", "direction": "egress",
                              "forms": [{"pattern": r"\d+", "example": "1"}]}],
                 "verbs": [{"verb": "tg2.send", "direction": "egress",
                            "scheme": "tg2", "arg": "chat_id"}],
                 "defaults": [{"verb": "tg2.send", "arg": "chat_id",
                               "value": "binding"}]},
                pack="gateway-chat", builtin=True)

    def test_un_valore_inventato_e_rifiutato(self) -> None:
        doc = json.loads(json.dumps(PACK))
        doc["connectors"][0]["defaults"][0]["value"] = "owner"
        with self.assertRaises(M.ManifestError):
            M.build_registry({"comms-pack": doc}, reserved=frozenset())



async def _async(valore):
    return valore


if __name__ == "__main__":
    unittest.main()
