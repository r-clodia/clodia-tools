"""clodia-platform#522 — i due pezzi che restano al gateway quando il connettore se ne va.

Spostata l'implementazione in un pack, due cose NON possono seguirla, e senza di
esse l'interruttore non si può accendere su traffico vero:

1. **leggere un file di topic.** `telegram.send_file` manda un file che sta in un
   topic: il percorso lo sceglie il chiamante, e attaccati alla lettura ci sono
   il compartimento (chi chiama dev'essere partecipante di QUEL topic) e l'audit
   di ciò che attraversa il confine. Un backend di pack che leggesse da sé il
   filesystem dei topic salterebbe entrambi. Quindi il manifest dichiara quali
   argomenti sono il path e i byte, e il gateway consegna i byte;
2. **la porta degli update.** Telegram ammette un solo consumer `getUpdates` per
   bot: se il pack ne ha uno e il gateway pure, i due si rubano i messaggi.
   Quindi le rotte interne del relay, in posizione `pack`, diventano un rinvio
   al backend — e il join per link, che è control-plane e non si è spostato, va
   intercettato lì, sull'unica porta da cui gli update entrano.

I test sono scritti per fallire su ciò che si romperebbe in SILENZIO: un file
letto senza il controllo di membership, un percorso che arriva al backend, un
`/start <token>` che finisce nel topic come un messaggio qualunque.
"""
from __future__ import annotations

import base64
import json
import unittest
from unittest.mock import patch

from . import main, telegram_api
from .connectors import manifest as M
from .connectors import resolved

#: Il connettore minimo che dichiara un file: quello vero (comms-pack) vive
#: nell'altro repo, e questo test misura il MECCANISMO, non quel manifest.
PACK = {
    "name": "comms-pack",
    "connectors": [{
        "id": "telegram", "manifest_version": 1, "namespace": "telegram",
        "schemes": [{"scheme": "tg", "direction": "both",
                     "forms": [{"pattern": r"-?\d+", "example": "-100"}]}],
        "verbs": [{"verb": "telegram.send_file", "direction": "egress",
                   "scheme": "tg", "arg": "chat_id"}],
        "files": [{"verb": "telegram.send_file", "path_arg": "path",
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
            self.assertTrue(main._fill_declared_file("telegram.send_file", args))
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
            main._fill_declared_file("telegram.send_file", {"path": "local/x"})
        self.assertEqual(self.membership, [("SEAL-1", "software-house")])
        self.assertEqual(self.svc.letti, [("SEAL-1", "software-house", "local/x")])

    def test_un_rifiuto_di_membership_non_legge_niente(self) -> None:
        def nega(svc, tier, name, mutating=False):
            raise PermissionError("non sei partecipante")
        with _registry(), patch.object(main, "_require_topic_member", nega):
            with self.assertRaises(PermissionError):
                main._fill_declared_file("telegram.send_file",
                                         {"path": "local/x"})
        self.assertEqual(self.svc.letti, [])

    def test_il_topic_esplicito_vince(self) -> None:
        with _registry():
            main._fill_declared_file("telegram.send_file", {
                "chat_id": "-100", "path": "local/x",
                "tier": "SEAL-2", "name": "altro"})
        self.assertEqual(self.membership, [("SEAL-2", "altro")])

    def test_senza_topic_esplicito_vale_la_chat_legata(self) -> None:
        """Il registro dei binding è del gateway: è la ragione per cui questa
        risoluzione non poteva andare nel pack."""
        legame = {"tier": "SEAL-3", "topic": "riservato"}
        with _registry(), \
                patch("server.tools.channel_bindings.get",
                      lambda conn, chat, **k: legame if conn == "telegram" else None):
            main._fill_declared_file("telegram.send_file",
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
                main._fill_declared_file("telegram.send_file",
                                         {"chat_id": "-100", "path": "local/x"})
        self.assertEqual(self.svc.letti, [])

    def test_senza_percorso_e_un_errore_non_un_invio_vuoto(self) -> None:
        with _registry():
            with self.assertRaises(ValueError):
                main._fill_declared_file("telegram.send_file", {})

    def test_un_verbo_che_non_lo_dichiara_resta_intatto(self) -> None:
        args = {"path": "local/x"}
        with _registry():
            self.assertFalse(main._fill_declared_file("telegram.send", args))
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
                pack="gateway-telegram", builtin=True)

    def test_i_byte_non_possono_sovrascrivere_il_percorso(self) -> None:
        doc = json.loads(json.dumps(PACK))
        doc["connectors"][0]["files"][0]["bytes_arg"] = "path"
        with self.assertRaises(M.ManifestError):
            M.build_registry({"comms-pack": doc}, reserved=frozenset())


class _Req:
    """La richiesta interna minima: `internal_auth` è patchato a parte."""

    def __init__(self, body: dict):
        self._body = body

    async def json(self):
        return self._body


class LaPortaDegliUpdateEUnaSolaTests(unittest.IsolatedAsyncioTestCase):
    """In posizione `pack` le rotte interne rinviano al backend."""

    def setUp(self) -> None:
        p = patch.object(telegram_api, "_authorize", lambda r: ("clodia", None))
        p.start()
        self.addCleanup(p.stop)
        self.chiamate: list = []

    def _pack(self, risposte: dict):
        async def fake(verbo, args):
            self.chiamate.append((verbo, args))
            return risposte.get(verbo, {})
        return patch.object(telegram_api, "_pack", fake)

    def _posizione(self, nativo: bool):
        return patch.object(telegram_api, "_nativo", lambda: nativo)

    async def test_il_poll_passa_dal_backend_del_pack(self) -> None:
        riga = {"chat_id": "-100", "text": "ciao", "chat_type": "supergroup"}
        with self._posizione(False), \
                self._pack({"updates": {"messages": [riga],
                                        "bot_username": "clodiabot"}}):
            r = await telegram_api.poll(_Req({"timeout": 5}))
        self.assertEqual(self.chiamate, [("updates", {"timeout": 5})])
        self.assertEqual(json.loads(r.body)["count"], 1)

    async def test_in_posizione_nativa_il_backend_non_si_tocca(self) -> None:
        with self._posizione(True), self._pack({}), \
                patch.object(telegram_api.tg, "poll_updates", lambda t: []):
            r = await telegram_api.poll(_Req({"timeout": 5}))
        self.assertEqual(self.chiamate, [])
        self.assertEqual(json.loads(r.body)["count"], 0)

    async def test_un_join_per_link_non_finisce_nel_topic(self) -> None:
        """`/start <token>` è un join che aspetta l'owner, non un messaggio da
        riportare. Nel gateway l'intercettazione viveva nel ciclo degli update;
        quel ciclo adesso è del pack, e il join non si è spostato con lui."""
        riga = {"chat_id": "-100", "text": "/start abcdefghijklmnop",
                "chat_type": "supergroup", "from_username": "dadabit"}
        altro = {"chat_id": "-100", "text": "ciao", "chat_type": "supergroup"}
        visti: list = []
        with self._posizione(False), \
                self._pack({"updates": {"messages": [riga, altro],
                                        "bot_username": "clodiabot"}}), \
                patch("server.tools.telegram_join.intercept",
                      lambda msg, bot: visti.append((msg, bot)) or
                      msg["text"].startswith("/start")):
            r = await telegram_api.poll(_Req({}))
        corpo = json.loads(r.body)
        self.assertEqual(corpo["count"], 1)
        self.assertEqual(corpo["messages"][0]["text"], "ciao")
        # L'intercettazione riceve la chat con il suo TIPO: `claim` accetta solo
        # gruppi, e senza il tipo un join in un gruppo verrebbe scartato.
        self.assertEqual(visti[0][0]["chat"]["type"], "supergroup")
        self.assertEqual(visti[0][1], "clodiabot")

    async def test_il_send_interno_passa_dal_pack(self) -> None:
        with self._posizione(False), \
                self._pack({"send": {"ok": True, "message_id": 9}}):
            r = await telegram_api.send(_Req({"chat_id": "-100", "text": "ciao"}))
        self.assertEqual(self.chiamate[0][0], "send")
        self.assertEqual(json.loads(r.body)["message_id"], 9)

    async def test_il_download_passa_dal_pack(self) -> None:
        with self._posizione(False), self._pack({"download": {"size": 3}}):
            r = await telegram_api.download(_Req({"file_id": "F1"}))
        self.assertEqual(self.chiamate[0], ("download", {"file_id": "F1"}))
        self.assertEqual(json.loads(r.body)["size"], 3)

    async def test_il_drenaggio_per_chat_dice_perche_non_c_e(self) -> None:
        """Nel pack non esiste e nessuno lo chiama (il relay usa `poll`). Si
        risponde col motivo invece di inventare un drenaggio che consumerebbe
        la coda condivisa di tutte le chat."""
        with self._posizione(False), self._pack({}):
            r = await telegram_api.updates(_Req({"chat_id": "-100"}))
        self.assertEqual(r.status_code, 501)
        self.assertEqual(self.chiamate, [])

    async def test_un_errore_del_backend_non_diventa_un_risultato(self) -> None:
        """Il backend risponde in testo: un `ERROR: …` letto come JSON sarebbe
        un'eccezione oscura, e letto come successo sarebbe peggio."""
        with patch.object(telegram_api.proxy, "call_proxied",
                          lambda n, a: _async("ERROR: RuntimeError: niente bot")):
            with self.assertRaises(RuntimeError):
                await telegram_api._pack("updates", {})


async def _async(valore):
    return valore


if __name__ == "__main__":
    unittest.main()
