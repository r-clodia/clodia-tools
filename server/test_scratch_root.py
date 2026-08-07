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

import unittest

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
