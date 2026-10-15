"""clodia-platform#522 — l'interruttore per istanza, e la parità nelle due posizioni.

La transizione decisa dall'owner (G3) dice che le due implementazioni di
Telegram — quella nativa del gateway e quella del pack — convivono nell'immagine
e che un interruttore sceglie quale è in servizio, così la migrazione si accende
su un'istanza sola, si verifica su traffico vero e si spegne senza un rollback
del codice. Il primo criterio di accettazione è esattamente questo file: **test
di parità verdi con l'interruttore nelle due posizioni**.

Come è scritta la parità, e perché così. Non due elenchi da confrontare a
occhio: una sola funzione — `_risposte()` — fa al gateway le domande che il PDP
gli fa davvero (`check_grantable`, `danger_note`, `spec_for` con l'URI che ne
esce, `taints`, gli schemi concedibili, l'azione di topic, la voce di vault) e
la si esegue due volte, una per posizione dell'interruttore. Le due mappe devono
essere **uguali**. Una differenza compare da sola, col nome della domanda che
l'ha prodotta, invece di nascondersi in un assert che nessuno ha scritto.

Il manifest usato come «pack installato» è l'esempio comms-pack di `SCHEMA.md`,
lo stesso che la fase 1 di #522 ha già pinnato: è la copia leggibile da questo
repo della dichiarazione che vive in comms-pack (clodia-logic). Se le due
divergessero, la parità misurerebbe un pack che non è quello installato — ed è
il motivo per cui questo test va rifatto contro il manifest REGISTRATO il giorno
in cui il gateway lo valida a install time (#519 l'ha reso possibile).

**Cosa questo file NON misura, e va fatto nella PR del pack.** La *copia* della
card Tools (`icon`, `blurb`, `scope`, aggiunti al manifest del gateway da #520)
non è confrontabile da qui: l'esempio di `SCHEMA.md` è un'illustrazione della
grammatica e non le riporta, quindi un confronto darebbe un rosso che parla
dello stand-in e non del gateway. Chi porta l'implementazione in comms-pack deve
allineare il suo `tools_card` a `builtin_manifests/telegram.yaml` campo per
campo e dichiararvi il blocco `context:`, altrimenti la pagina Tools perde la
scheda nel momento in cui l'interruttore si sposta.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from . import egress, instance_profile, main, taint
from .connectors import builtin, resolved
from .connectors import manifest as M
from .connectors.test_manifest import _examples

#: Stringhe di prova, le stesse della fase 1: gruppo, supergruppo, handle buono,
#: handle troppo corto/lungo, wildcard, percorso, handle senza chiocciola, vuoto.
CAMPIONI = (
    "-1001234567890", "123456789", "@dadabit", "@abcd",
    "@" + "a" * 33, "*", "gruppo/sotto", "dadabit", "",
)


def _dichiarazione_del_pack() -> dict:
    """Il solo connettore `telegram` dell'esempio comms-pack di SCHEMA.md.

    Solo quello: l'esempio dichiara anche il vocabolario `mail`, che collide con
    il manifest builtin ancora in servizio e verrebbe rifiutato — rumore che non
    c'entra con la domanda di questo file.
    """
    comms = _examples()["comms-pack"]
    telegram = next(c for c in comms["connectors"] if c["id"] == "telegram")
    return {"name": "comms-pack", "connectors": [telegram]}


class _Istanza:
    """Un'istanza usa e getta: data dir, profilo, pack installati.

    Tocca le stesse strade della produzione — `profile.yaml` letto dal loader
    vero, `packs/<nome>/pack.yaml` letto dal registry vero — perché il punto
    dell'interruttore è proprio che il gateway lo legga da sé.
    """

    def __init__(self, posizione: str | None, installati: dict | None = None):
        self.posizione = posizione
        self.installati = installati or {}
        self._patch: list = []

    def __enter__(self):
        self._tmp = tempfile.TemporaryDirectory()
        data = Path(self._tmp.name)
        if self.posizione:
            (data / instance_profile.PROFILE_FILENAME).write_text(
                yaml.safe_dump({"connectors": {"telegram": self.posizione}}),
                encoding="utf-8")
        for nome, manifest in self.installati.items():
            (data / "packs" / nome).mkdir(parents=True)
            (data / "packs" / nome / "pack.yaml").write_text(
                yaml.safe_dump(manifest), encoding="utf-8")
        self._patch = [
            patch.dict(os.environ, {"CLODIA_DATA": str(data)}),
            patch.object(resolved, "_DATA", data),
            # Nessun backend MCP montato: la proprietà di un namespace di
            # backend è una domanda a sé (#539 §3) e qui falserebbe la misura.
            patch.object(resolved, "_backend_entries", lambda: []),
        ]
        for p in self._patch:
            p.start()
        instance_profile.load(force=True)
        resolved.invalidate()
        return self

    def __exit__(self, *exc):
        for p in reversed(self._patch):
            p.stop()
        self._tmp.cleanup()
        instance_profile._CACHE = None
        instance_profile.load(force=True)
        resolved.invalidate()
        return False


def _concedibile(direzione: str, resto: str) -> bool:
    try:
        egress.check_grantable(direzione, f"tg:{resto}")
    except ValueError:
        return False
    return True


def _risposte() -> dict:
    """Tutto ciò che il gateway sa di Telegram, chiesto come lo chiede il PDP.

    Attraverso le funzioni pubbliche e mai leggendo il registry: una posizione
    dell'interruttore che risponde uguale *a queste* domande è una posizione in
    cui nulla di osservabile è cambiato, che è ciò che «a parità» significa.
    """
    out: dict = {}
    for direzione in ("egress", "ingress"):
        for resto in CAMPIONI:
            out[f"concedibile[{direzione}][{resto}]"] = _concedibile(direzione, resto)
    out["danger"] = egress.danger_note("tg:-1001234567890")
    out["tg è uno schema d'uscita"] = "tg" in egress.egress_schemes()
    out["tg è una fonte"] = "tg" in egress.source_schemes()
    for verbo in ("telegram.send", "telegram.send_file", "telegram.inbox",
                  "telegram.poll", "telegram.listen", "telegram.roster"):
        spec = egress.spec_for(verbo)
        out[f"dtype[{verbo}]"] = spec[0] if spec else None
        out[f"destinazione[{verbo}]"] = (
            spec[1]({"chat_id": "-1001234567890"}) if spec else None)
        out[f"contamina[{verbo}]"] = taint.taints(verbo)
    for verbo in ("telegram.receive", "telegram.pull"):
        out[f"contamina[{verbo}]"] = taint.taints(verbo)
    azione = next((a for a in resolved.registry().topic_actions()
                   if a.id == "telegram-link"), None)
    out["azione c'è"] = azione is not None
    if azione:
        valori = {azione.fields[0].name: "-1001234567890"}
        out["azione ingress"] = [t.format(**valori) for t in azione.adds_ingress]
        out["azione egress"] = [t.format(**valori) for t in azione.adds_egress]
        out["azione binding"] = azione.binding
    connettore = resolved.registry().by_id("telegram")
    out["connettore c'è"] = connettore is not None
    if connettore:
        out["namespace"] = connettore.namespace
        bot = next((p for p in connettore.providers if p.credential), None)
        out["voce di vault"] = bot.credential.vault_entry if bot else None
    return out


class ParityInBothPositionsTests(unittest.TestCase):
    """Criterio 1 di #522: le stesse risposte con l'interruttore nelle due posizioni."""

    def test_the_two_positions_answer_the_same(self):
        with _Istanza("native"):
            nativo = _risposte()
        with _Istanza("pack", {"comms-pack": _dichiarazione_del_pack()}):
            pacchetto = _risposte()
        for domanda, atteso in nativo.items():
            with self.subTest(domanda=domanda):
                self.assertEqual(pacchetto[domanda], atteso)
        self.assertEqual(set(pacchetto), set(nativo))

    def test_the_questions_are_really_answered(self):
        """La parità fra due silenzi è una parità per finta: se il registry
        fosse vuoto in entrambe le posizioni ogni risposta sarebbe None/False e
        il test sopra passerebbe senza misurare niente."""
        with _Istanza("native"):
            r = _risposte()
        self.assertTrue(r["connettore c'è"])
        self.assertTrue(r["azione c'è"])
        self.assertEqual(r["dtype[telegram.send]"], "telegram")
        self.assertEqual(r["destinazione[telegram.send]"], ["tg:-1001234567890"])
        self.assertTrue(r["concedibile[egress][-1001234567890]"])
        self.assertFalse(r["concedibile[egress][dadabit]"])
        self.assertTrue(r["contamina[telegram.inbox]"])
        self.assertFalse(r["contamina[telegram.send]"])

    def test_without_the_pack_the_pack_position_knows_nothing(self):
        """Il contrario della parità, per sapere che l'interruttore agisce: in
        posizione `pack` senza il pack installato il gateway non sa più né dove
        manda `telegram.send` né cosa contamina. È il motivo per cui le due PR
        hanno un ordine (prima il pack, poi l'interruttore) e non è un dettaglio
        di rilascio."""
        with _Istanza("pack"):
            self.assertIsNone(egress.spec_for("telegram.send"))
            self.assertIsNone(resolved.registry().by_id("telegram"))


class TheSwitchMovesTheImplementationTests(unittest.TestCase):
    """Cosa cambia davvero fra le due posizioni: chi implementa."""

    def test_native_position_serves_the_verbs_itself(self):
        with _Istanza("native", {"comms-pack": _dichiarazione_del_pack()}):
            self.assertIn("telegram.send", main.all_native_verb_names())
            connettore = resolved.registry().by_id("telegram")
            self.assertTrue(connettore.builtin)
            # La dichiarazione del pack c'è, ed è ignorata RUMOROSAMENTE finché
            # il gateway implementa il namespace.
            self.assertTrue([p for p in resolved.problems() if "telegram" in p])

    def test_pack_position_hands_the_verbs_over(self):
        with _Istanza("pack", {"comms-pack": _dichiarazione_del_pack()}):
            self.assertNotIn("telegram.send", main.all_native_verb_names())
            self.assertNotIn("telegram", main._native_tool_namespaces())
            connettore = resolved.registry().by_id("telegram")
            self.assertFalse(connettore.builtin)
            self.assertEqual(connettore.pack, "comms-pack")

    def test_pack_position_without_a_backend_has_no_verb_at_all(self):
        """Fail-closed, ed è il controllo che prova che il ramo nativo è
        davvero spento: niente implementazione nativa e nessun backend MCP
        montato ⇒ il verbo non esiste, e `_verb_implemented` lo dice prima di
        qualunque gate (#539 §7). Se il dispatch avesse ancora il suo ramo,
        questo passerebbe comunque e il verbo lo servirebbe il gateway."""
        with _Istanza("pack", {"comms-pack": _dichiarazione_del_pack()}):
            with patch.object(main.proxy, "is_proxied", lambda _n: False):
                self.assertFalse(main._verb_implemented("telegram.send"))
                self.assertTrue(main._verb_implemented("email.send"))

    def test_the_namespace_and_the_vault_prefix_are_freed(self):
        """I due motivi per cui la sola dichiarazione era inerte: `telegram` era
        un namespace riservato (lo derivano i verbi nativi) e `telegram_` un
        prefisso di vault del core. Finché restano, il pack non può né tenere il
        namespace né scrivere la credenziale del bot."""
        with _Istanza("native"):
            self.assertIn("telegram", M.core_namespaces())
            self.assertIn("telegram_", M.core_vault_prefixes())
            self.assertTrue(
                M.vault_entry_problem("telegram_bot_token", "telegram"))
        with _Istanza("pack"):
            self.assertNotIn("telegram", M.core_namespaces())
            self.assertNotIn("telegram_", M.core_vault_prefixes())
            self.assertEqual(
                M.vault_entry_problem("telegram_bot_token", "telegram"), "")

    def test_only_the_migrated_connector_moves(self):
        """L'interruttore nomina UN connettore: gli altri prefissi di vault e
        gli altri namespace restano riservati come ieri."""
        with _Istanza("pack"):
            self.assertIn("google_", M.core_vault_prefixes())
            self.assertIn("github", M.core_namespaces())
            self.assertIsNotNone(egress.spec_for("email.send"))
            self.assertIn("mailto", egress.egress_schemes())

    def test_an_unreadable_position_leaves_the_connector_where_it_was(self):
        """Un refuso nel profilo non migra niente e non spegne il resto del
        profilo: `native` è lo stato di ieri, ed è la direzione sicura."""
        with _Istanza("pacco"):
            self.assertEqual(instance_profile.connector_backend("telegram"),
                             "native")
            self.assertIn("telegram.send", main.all_native_verb_names())
        with _Istanza(None):
            self.assertEqual(instance_profile.connector_backend("telegram"),
                             "native")


class TheGatewayFillsTheContextTests(unittest.TestCase):
    """Il contesto di chiamata di un verbo di pack lo mette il gateway.

    Un connettore nativo legge canale e agente dal claim FIRMATO della sessione;
    il processo di un pack quel claim non ce l'ha. Se il contesto arrivasse come
    argomento del chiamante sarebbe falsificabile, e `telegram.send` senza
    `chat_id` scrive nella chat legata al canale chiamante: dichiarare un altro
    canale vorrebbe dire scrivere nel gruppo di un topic di cui non si è
    partecipanti.
    """

    def setUp(self) -> None:
        self.ctx = (M.ContextArg(arg="channel", value="channel"),
                    M.ContextArg(arg="agent", value="agent"))

    def _riempi(self, argomenti: dict, dichiarati, canale="SEAL-1/software-house",
                agente="messaggero") -> dict:
        with patch.object(main, "current_channel", lambda: canale), \
                patch("server.connectors.resolved.context_arguments",
                      lambda _v: dichiarati):
            main._fill_declared_context("telegram.send", argomenti, agente)
        return argomenti

    def test_a_forged_context_is_overwritten(self):
        argomenti = self._riempi(
            {"text": "ciao", "channel": "SEAL-1/altro-topic", "agent": "clodia"},
            self.ctx)
        self.assertEqual(argomenti["channel"], "SEAL-1/software-house")
        self.assertEqual(argomenti["agent"], "messaggero")
        self.assertEqual(argomenti["text"], "ciao")

    def test_an_absent_context_is_filled(self):
        argomenti = self._riempi({"text": "ciao"}, self.ctx)
        self.assertEqual(argomenti["channel"], "SEAL-1/software-house")
        self.assertEqual(argomenti["agent"], "messaggero")

    def test_no_channel_writes_empty_never_the_caller_value(self):
        """Il caso che un `if not arguments.get(...)` sbaglierebbe: senza canale
        firmato il valore è VUOTO, non quello che il chiamante si è scritto."""
        argomenti = self._riempi({"channel": "SEAL-1/altro-topic"}, self.ctx,
                                 canale=None)
        self.assertEqual(argomenti["channel"], "")

    def test_a_connector_that_declares_nothing_is_left_alone(self):
        argomenti = self._riempi({"channel": "qualunque"}, ())
        self.assertEqual(argomenti, {"channel": "qualunque"})

    def test_the_gateway_refuses_a_context_it_cannot_produce(self):
        """Grammatica chiusa fino in fondo: se un valore sconosciuto arrivasse
        qui, l'argomento NON resta quello del chiamante — la chiamata fallisce."""
        with self.assertRaises(ValueError):
            self._riempi({}, (M.ContextArg(arg="x", value="principal"),))

    def test_native_telegram_takes_no_context_from_the_arguments(self):
        """Posizione `native`: nessun argomento di contesto da riempire. Il
        connettore del gateway il claim ce l'ha, e scrivere nei suoi argomenti
        sovrascriverebbe un parametro di codice nostro."""
        with _Istanza("native"):
            self.assertEqual(resolved.context_arguments("telegram.send"), ())

    def test_pack_telegram_declares_the_two_contexts(self):
        with _Istanza("pack", {"comms-pack": _dichiarazione_del_pack()}):
            dichiarati = resolved.context_arguments("telegram.send")
            self.assertEqual({c.value for c in dichiarati}, {"channel", "agent"})
            # Per NAMESPACE: vale per ogni verbo del connettore, anche quelli
            # che il manifest non mappa (il lease è di un agente, per nome).
            self.assertEqual(resolved.context_arguments("telegram.inbox"),
                             dichiarati)
            self.assertEqual(resolved.context_arguments("email.send"), ())


class TheGrammarOfContextTests(unittest.TestCase):
    """Cosa un manifest può dichiarare come contesto, e cosa no."""

    def _connettore(self, context) -> M.Connector:
        return M.parse_connector(
            {"id": "sms", "manifest_version": 1, "namespace": "sms",
             "schemes": [{"scheme": "sms", "direction": "egress",
                          "forms": [{"pattern": r"\+\d{6,15}", "example": "+391234567"}]}],
             "verbs": [{"verb": "sms.send", "direction": "egress",
                        "scheme": "sms", "arg": "to"}],
             "context": context},
            pack="sms-pack", reserved=())

    def test_the_two_values_load(self):
        c = self._connettore({"channel": "channel", "who": "agent"})
        self.assertEqual({a.arg: a.value for a in c.context},
                         {"channel": "channel", "who": "agent"})

    def test_an_invented_context_is_refused(self):
        for valore in ("principal", "spawn", "token", ""):
            with self.subTest(valore=valore):
                with self.assertRaises(M.ManifestError):
                    self._connettore({"x": valore})

    def test_an_argument_name_must_be_an_argument_name(self):
        with self.assertRaises(M.ManifestError):
            self._connettore({"non valido!": "agent"})

    def test_a_gateway_manifest_may_not_declare_one(self):
        """Rifiutato invece che ignorato: una dichiarazione inerte è una
        promessa che nessuno mantiene."""
        with self.assertRaises(M.ManifestError):
            M.parse_connector(
                {"id": "tg2", "manifest_version": 1, "namespace": "tg2",
                 "schemes": [{"scheme": "tg2", "direction": "egress",
                              "forms": [{"pattern": r"\d+", "example": "1"}]}],
                 "context": {"channel": "channel"}},
                pack="gateway-telegram", builtin=True)

    def test_a_contributor_may_not_declare_one(self):
        """`extends` aggiunge un provider, non un significato: il contesto è dei
        verbi del vocabolario, e chi non li possiede non parla per loro."""
        with self.assertRaises(M.ManifestError):
            M.parse_connector(
                {"id": "sms-altro", "manifest_version": 1, "namespace": "sms2",
                 "extends": "sms", "providers": [{"id": "p"}],
                 "context": {"channel": "channel"}},
                pack="altro-pack", reserved=())


class TheBuiltinDocumentsTests(unittest.TestCase):
    """Il manifest builtin del connettore migrato esce di scena, e solo lui."""

    def test_the_document_is_dropped_whole_in_pack_position(self):
        with _Istanza("pack"):
            self.assertNotIn("gateway-telegram", builtin.manifests())
            self.assertIn("gateway-telegram", builtin.documents())
            self.assertEqual(builtin.migrated_namespaces(), frozenset({"telegram"}))
            self.assertIn("gateway-mail", builtin.manifests())

    def test_nothing_is_dropped_in_native_position(self):
        with _Istanza("native"):
            self.assertEqual(builtin.manifests(), builtin.documents())
            self.assertEqual(builtin.migrated_namespaces(), frozenset())


if __name__ == "__main__":
    unittest.main()
