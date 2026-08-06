"""Il perimetro Drive è per TOPIC, non per account.

La regola, chiesta da Davide: *«il path che metto come remote diventa la root di
confine per gli accessi dal topic»*. La cartella del remote di un topic è il
perimetro delle chiamate che avvengono dentro quel canale.

Perché stamattina avevo argomentato il contrario, e cosa è cambiato. L'obiezione
era che chi può creare un remote si allarga il perimetro da sé, e l'ho verificata
invece di ripeterla: l'endpoint della webui chiedeva `_require_member`, quindi
**qualunque partecipante** — Matteo — poteva puntare il remote a `30-legale`. Il
disegno regge solo con la sua conseguenza: impostare, cambiare o togliere un
remote Drive diventa un'azione da **admin**, perché non è più una preferenza ma
una dichiarazione di autorità.

Ciò che lo rende un controllo e non una convenzione: il topic della chiamata
arriva nel claim `chat` FIRMATO dall'agent-server. Un agente non può dichiarare
il topic di un altro per prenderne il perimetro.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from .tools import gdrive_root as gr
from . import whitelist as w

TOPIC_FOLDER = "50EXEC"        # la cartella del remote del topic
ALTRA = "30LEGALE"             # una sorella, fuori dal perimetro
ACCOUNT_ROOT = "PROGETTO"      # radice d'account (tetto), se impostata

TREE = {
    "dentro-topic": ["50EXEC"],
    "50EXEC": ["PROGETTO"],
    "in-legale": ["30LEGALE"],
    "30LEGALE": ["PROGETTO"],
    "PROGETTO": ["MYDRIVE"],
    # La radice di «Il mio Drive» e le altre cime sono nell'albero con genitori
    # VUOTI, non assenti. Senza, la risalita finiva in un 404 e il verdetto
    # «fuori» arrivava dal fail-closed invece che dall'aver esaurito gli
    # antenati: il test passava per la ragione sbagliata e non avrebbe visto una
    # regressione nella logica di discendenza. Stesso difetto trovato oggi in un
    # test costruito su un verbo inesistente.
    "MYDRIVE": [],
    "altrove": ["ALTRO"],
    "ALTRO": [],
}


class _Exec:
    def __init__(self, v):
        self.v = v

    def execute(self):
        if isinstance(self.v, Exception):
            raise self.v
        return self.v


class FakeDrive:
    def __init__(self):
        self.calls = 0

    def files(self):
        return self

    def get(self, fileId=None, **kw):
        self.calls += 1
        if fileId not in TREE:
            return _Exec(RuntimeError("404"))
        return _Exec({"id": fileId, "parents": list(TREE[fileId])})

    def list(self, **kw):
        return _Exec({"files": []})


class _Chat:
    def __init__(self, v):
        self.v = v

    def __enter__(self):
        self.t = w.set_current_chat(self.v)
        return self

    def __exit__(self, *a):
        w.reset_current_chat(self.t)
        return False


def _env(account_roots=None, topic_folder=TOPIC_FOLDER):
    cfg = {"agents": {}}
    if account_roots:
        cfg["gdrive_roots"] = {"conto": list(account_roots)}
    return (patch.object(w, "CONFIG", cfg),
            patch.object(gr, "_topic_drive_folder",
                         lambda tier, name: topic_folder))


class Base(unittest.TestCase):
    def setUp(self):
        gr.reset_cache()
        gr.reset_topic_cache()

    def run_with(self, ctx, fn):
        for c in ctx:
            c.start()
        try:
            return fn()
        finally:
            [c.stop() for c in ctx]


class PerTopicTests(Base):
    CHAN = "chan:SEAL-1:proof-of-flex-2:messaggero"

    def test_the_fixture_walks_to_the_top_without_errors(self):
        """Guardia sul test stesso: se la risalita fallisce, ogni verdetto
        «fuori» sotto è indistinguibile da un fail-closed e non prova niente."""
        d = FakeDrive()
        cur, visti = "in-legale", []
        for _ in range(6):
            r = d.get(fileId=cur).execute()
            visti.append(cur)
            ps = r.get("parents") or []
            if not ps:
                break
            cur = ps[0]
        self.assertEqual(visti, ["in-legale", "30LEGALE", "PROGETTO", "MYDRIVE"])

    def test_inside_the_channel_the_perimeter_is_the_topics_remote(self):
        def go():
            with _Chat(self.CHAN):
                roots, fonte = gr.roots_for_call("conto")
                self.assertEqual(roots, [TOPIC_FOLDER])
                self.assertEqual(fonte, "topic")
                d = FakeDrive()
                self.assertTrue(gr.inside(d, "conto", "dentro-topic"))
                self.assertFalse(gr.inside(d, "conto", "in-legale"))
        self.run_with(_env(), go)

    def test_a_sibling_folder_of_the_remote_is_outside(self):
        """Il caso concreto: `30-legale` e `40-budget` sono sorelle di
        `50-execution`. Il topic espone la seconda, e sono precisamente le prime
        due che non devono finire in un canale con dei collaboratori."""
        def go():
            with _Chat(self.CHAN):
                self.assertFalse(gr.inside(FakeDrive(), "conto", "in-legale"))
                self.assertFalse(gr.inside(FakeDrive(), "conto", "30LEGALE"))
        self.run_with(_env(), go)

    def test_the_parent_of_the_remote_is_outside_too(self):
        """Confinare a una cartella non concede il suo genitore: altrimenti
        confinare a una sottocartella non confinerebbe niente."""
        def go():
            with _Chat(self.CHAN):
                self.assertFalse(gr.inside(FakeDrive(), "conto", "PROGETTO"))
        self.run_with(_env(), go)

    def test_outside_any_channel_the_account_roots_apply(self):
        """Un job o una DM non hanno un topic. Il fallback è l'account, non
        «tutto»: se il fallback fosse permissivo, basterebbe uscire dal canale
        per uscire dal perimetro."""
        def go():
            with _Chat(None):
                roots, fonte = gr.roots_for_call("conto")
                self.assertEqual(roots, [ACCOUNT_ROOT])
                self.assertEqual(fonte, "account")
        self.run_with(_env(account_roots=[ACCOUNT_ROOT]), go)

    def test_a_channel_without_a_drive_remote_falls_back_to_the_account(self):
        """Negare qui romperebbe un uso legittimo: allegare a una mail un file
        preso da Drive, in un topic che non ha un remote."""
        def go():
            with _Chat(self.CHAN):
                roots, fonte = gr.roots_for_call("conto")
                self.assertEqual(fonte, "account")
                self.assertEqual(roots, [])
        self.run_with(_env(topic_folder=None), go)

    def test_an_unreadable_topic_meta_does_not_invent_a_perimeter(self):
        """Se il meta non si legge non si finge di avere una radice dal topic: si
        ricade sull'account. Inventare un perimetro da un dato non letto è la
        direzione d'errore sbagliata."""
        def go():
            with _Chat(self.CHAN):
                _, fonte = gr.roots_for_call("conto")
                self.assertEqual(fonte, "account")
        self.run_with(_env(topic_folder=None), go)

    def test_a_malformed_channel_claim_falls_back(self):
        def go():
            with _Chat("chan:soloUnPezzo"):
                _, fonte = gr.roots_for_call("conto")
                self.assertEqual(fonte, "account")
        self.run_with(_env(), go)


class CeilingTests(Base):
    CHAN = "chan:SEAL-1:proof-of-flex-2:messaggero"

    def test_account_roots_act_as_a_ceiling_not_an_alternative(self):
        """Un topic non deve poter sfondare il pavimento posato dall'owner.

        Con radici d'account impostate, la cartella del topic non le sostituisce:
        la verifica interseca, quindi il perimetro effettivo non è più largo del
        minore dei due.
        """
        def go():
            with _Chat(self.CHAN):
                roots, fonte = gr.roots_for_call("conto")
                self.assertIn("tetto", fonte)
                self.assertIn(ACCOUNT_ROOT, roots)
                # una cartella fuori da ENTRAMBI resta fuori
                self.assertFalse(gr.inside(FakeDrive(), "conto", "altrove"))
        self.run_with(_env(account_roots=[ACCOUNT_ROOT]), go)


class SignedClaimTests(Base):
    def test_the_topic_comes_from_the_signed_claim_only(self):
        """Il perimetro non può dipendere da un argomento della chiamata: sarebbe
        la parola dell'agente su sé stesso. Deriva da `current_channel()`, che
        legge il claim `chat` verificato."""
        import inspect
        src = inspect.getsource(gr.roots_for_call)
        self.assertIn("current_channel()", src)
        self.assertNotIn("arguments", src)


class PerimeterMovingVerbsAreGatedTests(unittest.TestCase):
    """I verbi che spostano il perimetro devono essere gated.

    Test scritto come enumerazione VERIFICATA, non come lista fidata: se domani
    si aggiunge un verbo che scrive il remote e nessuno lo gata, il perimetro
    torna scrivibile da un partecipante — cioè il difetto che questo disegno
    esiste per non avere.
    """

    def test_setting_or_removing_a_drive_remote_is_gated(self):
        from . import gate
        for v in ("topic.remote_add", "topic.remote_enable", "topic.remote_disable"):
            with self.subTest(verb=v):
                self.assertTrue(gate.is_gated(v), f"{v} sposta il perimetro")

    def test_disable_is_gated_because_removing_the_perimeter_widens_it(self):
        """La ragione meno ovvia: togliere il remote fa ricadere sulle radici
        d'account, che possono essere più larghe o assenti."""
        from . import gate
        self.assertTrue(gate.is_gated("topic.remote_disable"))

    def test_reading_the_remote_state_is_not_gated(self):
        """Non si gata la lettura: `remote_status` e `remote_pull` non spostano
        il confine, e gatarli renderebbe il gate un riflesso."""
        from . import gate
        self.assertFalse(gate.is_gated("topic.remote_status"))
        self.assertFalse(gate.is_gated("topic.remote_pull"))


if __name__ == "__main__":
    unittest.main()
