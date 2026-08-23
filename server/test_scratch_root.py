"""La radice del cortile degli spawn non è una destinazione.

Punto aperto 1 del notebook — «chi scrive i 226 file in cima a `/datadir/spawns`
su marte, e perché lì?» — misurato il 7 ago 2026. Li scrive il **gateway**, per
conto di un agente che passa un `dest` senza una directory di spawn davanti:
`_safe_scratch_path` validava «sotto `spawns/`», e la radice passava il
controllo.

Cosa c'è finito: 226 file `root:root` modo `644` — 91 PDF, 30 DOCX, lettere su
carta intestata, allegati di posta.

Perché contava, e non è disordine (punto aperto 2). La cartella è `drwx--x--x`:
un agente **non può elencarli** — misurato dall'agent-server, `ls` → Permission
denied — ma può traversarla, e `644` significa che chi ne conosce il nome li
legge. Un file finito lì esce dal perimetro del suo scope senza che nulla lo
dica. Il modo silenzioso di sbagliare: l'operazione riesce.

**Cosa questo NON chiude**, e va detto perché la voce 2 promette di più: il
confinamento di uno spawn al PROPRIO scratch. Per esigerlo servirebbe sapere
quale spawn chiama, e il gateway non lo sa — conosce il seed, mentre l'istanza è
`"-"` ovunque. Qui si chiude il caso osservato, non l'accesso di uno spawn allo
scratch di un altro.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

from . import main as M


class RootIsNotADestinationTests(unittest.TestCase):
    def test_a_path_inside_a_spawn_is_allowed(self):
        self.assertTrue(
            M._safe_scratch_path("/datadir/spawns/clodia-1/x.pdf")
            .endswith("/clodia-1/x.pdf"))

    def test_a_deeper_path_is_allowed(self):
        M._safe_scratch_path("/datadir/spawns/clodia-1/out/report.pdf")

    def test_a_file_at_the_root_is_refused(self):
        """Il caso che ha prodotto i 226 file."""
        with self.assertRaises(ValueError) as cm:
            M._safe_scratch_path("/datadir/spawns/FPR_3_25.pdf")
        self.assertIn("RADICE", str(cm.exception))

    def test_the_root_itself_is_refused(self):
        with self.assertRaises(ValueError):
            M._safe_scratch_path("/datadir/spawns")

    def test_the_refusal_shows_the_road(self):
        """Un rifiuto che non dice come procedere insegna solo che il sistema
        dice di no — e qui ci sono due strade, a seconda di cosa si stava
        facendo."""
        with self.assertRaises(ValueError) as cm:
            M._safe_scratch_path("/datadir/spawns/allegato.pdf")
        t = str(cm.exception)
        self.assertIn("<spawn>", t)
        self.assertIn("save_attachment", t)


class EscapeTests(unittest.TestCase):
    """Quello che il controllo già faceva, e che non deve smettere di fare."""

    def test_outside_the_yard_is_refused(self):
        for p in ("/etc/passwd", "/datadir/topics/x", "/secrets/token"):
            with self.subTest(path=p), self.assertRaises(ValueError):
                M._safe_scratch_path(p)

    def test_traversal_out_of_the_yard_is_refused(self):
        with self.assertRaises(ValueError):
            M._safe_scratch_path("/datadir/spawns/clodia-1/../../topics/x")

    def test_a_sibling_prefix_is_not_inside(self):
        """`/datadir/spawns-altro` comincia per `/datadir/spawns` ma non ci sta
        dentro: è il motivo per cui il confronto vuole lo slash."""
        with self.assertRaises(ValueError):
            M._safe_scratch_path("/datadir/spawns-altro/clodia-1/x")

    def test_an_empty_path_is_refused(self):
        with self.assertRaises(ValueError):
            M._safe_scratch_path("")


class RelativeIsNotAPathTests(unittest.TestCase):
    """Un path relativo non è «quasi assoluto»: `realpath` non lo rifiuta, lo
    RISOLVE contro la directory di lavoro del *gateway* — una directory che
    nessun chiamante ha nominato e che il chiamante non conosce.

    Finché la CWD del gateway sta fuori dal cortile il difetto si travestiva da
    rifiuto giusto con un messaggio sbagliato. Ma con la CWD dentro lo scratch
    di uno spawn il controllo **passava**, e i byte finivano lì: di nuovo il
    modo silenzioso di sbagliare del docstring, l'operazione riesce.

    Per questo il test si mette nella condizione in cui il vecchio codice era
    verde per il motivo sbagliato — CWD dentro il cortile — invece di dipendere
    da dove gira la suite. Il vecchio
    `EscapeTests::test_an_empty_path_is_refused` era rosso in locale e verde in
    CI proprio perché il *codice* era CWD-dipendente: non era un test fragile,
    stava segnalando questo.
    """

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        dentro = os.path.join(tmp.name, "spawn-1", "sub")
        os.makedirs(dentro)
        p = mock.patch.object(M, "_SPAWNS_ROOT", tmp.name)
        p.start()
        self.addCleanup(p.stop)
        prima = os.getcwd()
        self.addCleanup(os.chdir, prima)
        os.chdir(dentro)                      # la CWD che rendeva verde il bug

    def test_a_relative_path_is_refused(self):
        with self.assertRaises(ValueError):
            M._safe_scratch_path("out/report.pdf")

    def test_a_bare_filename_is_refused(self):
        with self.assertRaises(ValueError):
            M._safe_scratch_path("report.pdf")

    def test_the_empty_path_is_refused_wherever_the_gateway_runs(self):
        with self.assertRaises(ValueError):
            M._safe_scratch_path("")

    def test_the_refusal_names_the_problem_and_the_road(self):
        """«path non consentito: ` `» non dice a chi legge che il problema è la
        relatività, né come si esce."""
        with self.assertRaises(ValueError) as cm:
            M._safe_scratch_path("out/report.pdf")
        t = str(cm.exception)
        self.assertIn("assoluto", t)
        self.assertIn(M._SPAWNS_ROOT, t)

    def test_an_absolute_path_still_works_from_the_same_cwd(self):
        """Il rifiuto nuovo non deve mangiarsi il caso legittimo."""
        M._safe_scratch_path(
            os.path.join(M._SPAWNS_ROOT, "spawn-1", "out", "report.pdf"))


class CallersTests(unittest.TestCase):
    def test_every_file_the_gateway_opens_for_writing_has_a_validated_path(self):
        """L'invariante vera: se il GATEWAY apre un file in scrittura, il path o
        è passato di qui, o è una directory che si è costruito da sé.

        Questo test è alla terza forma, e le prime due sbagliavano allo stesso
        modo — guardavano le ASSEGNAZIONI (`dest = …`) e segnalavano due casi
        legittimi: una destinazione costruita con `mkdtemp` più `basename`, e il
        `dest` di `topic.fetch`, che il gateway non scrive affatto (passa da
        `transfer_channel`, e a materializzarlo è l'agent-server dentro lo
        scratch della propria sessione). Un test che segnala il legittimo
        insegna a ignorarlo, che è peggio del non averlo.

        Quindi si guarda il punto in cui i byte toccano il disco.
        """
        import inspect
        import re
        src = inspect.getsource(M)

        scritture = re.findall(r'open\(\s*([A-Za-z_][\w.]*)\s*,\s*["\']wb["\']', src)
        self.assertTrue(scritture, "nessuna scrittura trovata: il test non guarda più nulla")

        assegnazioni = {}
        for var in set(scritture):
            assegnazioni[var] = re.findall(
                r'^\s*%s\s*=\s*(.+)$' % re.escape(var), src, re.M)

        non_validate = []
        for var, righe in assegnazioni.items():
            for r in righe:
                validata = ("_safe_scratch_path(" in r
                            or "_os.path.join(d," in r)   # mkdtemp del gateway
                if not validata:
                    non_validate.append(f"{var} = {r.strip()}")
        self.assertEqual(
            non_validate, [],
            "il gateway apre in scrittura un path che non ha validato")


if __name__ == "__main__":
    unittest.main()


class OwnScratchTests(unittest.TestCase):
    """La seconda metà, e quella che la voce 2 prometteva: uno spawn possiede il
    proprio scratch e non raggiunge quello di un altro.

    Perché non era chiusa prima. Il gateway conosceva il SEED — `agent_name()` —
    e non l'istanza, quindi non poteva distinguere «un clodia» da «questo
    clodia». Il campo `execution_id` esisteva nel token firmato **e nessuno lo
    riempiva**: i quattro punti di conio non lo passavano. Ottava volta in due
    giorni che si trova un campo dichiarato e non trasportato, e questa era
    quella che serviva davvero.
    """

    def setUp(self):
        from . import whitelist as w
        self.w = w
        self.t = w.set_current_spawn("clodia-1")
        self.addCleanup(lambda: w.reset_current_spawn(self.t))

    def test_a_spawn_writes_in_its_own_scratch(self):
        M._safe_scratch_path("/datadir/spawns/clodia-1/x.pdf")

    def test_a_spawn_may_not_write_in_anothers(self):
        with self.assertRaises(ValueError) as cm:
            M._safe_scratch_path("/datadir/spawns/ophelia-2/x.pdf")
        self.assertIn("ophelia-2", str(cm.exception))
        self.assertIn("clodia-1", str(cm.exception))

    def test_not_even_another_spawn_of_the_same_seed(self):
        """`clodia-1` e `clodia-2` sono due esecuzioni distinte, e il compartimento
        è dello spawn — è lo stesso principio della voce 29 applicato al
        filesystem invece che ai topic."""
        with self.assertRaises(ValueError):
            M._safe_scratch_path("/datadir/spawns/clodia-2/x.pdf")

    def test_the_refusal_says_the_road_for_passing_a_file(self):
        """Chi ci arriva vuole quasi sempre consegnare qualcosa a un altro
        spawn, e quella strada esiste: passa dal topic, non dal filesystem."""
        with self.assertRaises(ValueError) as cm:
            M._safe_scratch_path("/datadir/spawns/altro-3/x.pdf")
        self.assertIn("topic del canale", str(cm.exception))

    def test_a_prefix_of_a_spawn_name_is_not_that_spawn(self):
        """`clodia-10` comincia per `clodia-1` e non è lo stesso spawn."""
        with self.assertRaises(ValueError):
            M._safe_scratch_path("/datadir/spawns/clodia-10/x.pdf")


class NoClaimTests(unittest.TestCase):
    def test_without_the_claim_only_the_level_is_required(self):
        """Un chiamante vecchio o un percorso interno non porta
        `execution_id`. Rifiutare qui trasformerebbe l'assenza di un campo nuovo
        in un guasto, e la retrocompatibilità va verso «come prima»."""
        M._safe_scratch_path("/datadir/spawns/chiunque-9/x.pdf")

    def test_the_root_stays_refused_even_without_the_claim(self):
        """Il controllo precedente non deve indebolirsi con l'aggiunta del
        nuovo: sono due condizioni, non una scelta."""
        with self.assertRaises(ValueError):
            M._safe_scratch_path("/datadir/spawns/sciolto.pdf")
