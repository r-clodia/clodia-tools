"""Test del parser mention (issue clodia-platform#83, D1 + DoD 7-8)."""
from __future__ import annotations

import tempfile
import unittest
from unittest.mock import patch

from .local_fs import LocalFsStorage
from .mentions import (GOLDEN_CASES, cita, extract_mentions, extract_tags,
                       normalizza)
from .service import TopicService


class ExtractMentionsTests(unittest.TestCase):
    def test_only_the_at_sigil_is_a_mention(self) -> None:
        # #391: `$` appartiene agli alias del composer, non è una menzione.
        self.assertEqual(extract_mentions("ciao @davide, senti $mario"), ["davide"])

    def test_dedup_and_lowercase_first_occurrence_order(self) -> None:
        self.assertEqual(extract_mentions("@Davide poi @mario e ancora @davide"), ["davide", "mario"])

    def test_dod7_double_dollar_escape_is_not_mention(self) -> None:
        self.assertEqual(extract_mentions("il letterale $$davide non conta"), [])

    def test_dod8_code_block_does_not_count(self) -> None:
        text = "```\nlog: @davide ha fatto login\n```\nfuori dal blocco @anna"
        self.assertEqual(extract_mentions(text), ["anna"])

    def test_dod8_inline_code_does_not_count(self) -> None:
        self.assertEqual(extract_mentions("usa `@davide` come placeholder"), [])

    def test_dod8_quoted_line_does_not_count(self) -> None:
        self.assertEqual(extract_mentions("> @davide aveva scritto così\nrispondo io: @luca"), ["luca"])

    def test_email_and_path_do_not_count(self) -> None:
        self.assertEqual(extract_mentions("scrivi a d.carboni@gmail.com, log in /var/@web/x"), [])

    def test_open_punctuation_boundary_counts(self) -> None:
        self.assertEqual(extract_mentions("(vedi @davide) e [cc @anna]"), ["davide", "anna"])

    def test_empty_and_none_like(self) -> None:
        self.assertEqual(extract_mentions(""), [])
        self.assertEqual(extract_mentions("nessuna menzione qui"), [])


class OrdinalMentionsTests(unittest.TestCase):
    """Mention con ordinale @agente#N — istanze multi-spawn (issue#94)."""

    def test_ordinal_mention(self) -> None:
        self.assertEqual(extract_mentions("fai tu @fullstack-dev#2"), ["fullstack-dev#2"])

    def test_generic_and_ordinal_are_distinct(self) -> None:
        self.assertEqual(extract_mentions("@fullstack-dev e @fullstack-dev#2"),
                         ["fullstack-dev", "fullstack-dev#2"])

    def test_ordinal_zero_or_hash_alone_not_matched(self) -> None:
        # #0 non è un ordinale valido: la mention resta quella generica.
        self.assertEqual(extract_mentions("@dev#0"), ["dev"])
        self.assertEqual(extract_mentions("@dev# ciao"), ["dev"])

    def test_escaped_ordinal_not_mention(self) -> None:
        self.assertEqual(extract_mentions("il letterale $$dev#2 non conta"), [])

    def test_ordinal_in_code_block_not_mention(self) -> None:
        self.assertEqual(extract_mentions("`@dev#2` placeholder"), [])


class GoldenCasesTests(unittest.TestCase):
    """La tabella condivisa con `clodia-logic` (issue#255).

    Il parser di questo modulo era già corretto; sbagliato era l'altro — le due
    regex del router, senza confine sinistro, che leggevano `foo@bar.com` come
    una menzione di `bar`. Il fix è la convergenza delle due copie, e questa
    tabella è ciò che rende la convergenza verificabile: viaggia dentro
    `mentions.py`, quindi la suite di entrambi i repository la esegue sui propri
    entry point. Se una copia cambia da sola, fa rosso da quel lato.
    """

    def test_extract_mentions_matches_the_shared_rule_set(self) -> None:
        for testo, attesi in GOLDEN_CASES:
            with self.subTest(testo=testo):
                self.assertEqual(attesi, extract_mentions(testo))

    def test_extract_tags_matches_the_shared_rule_set(self) -> None:
        """Dal #391 un solo sigillo: le convocazioni sono le menzioni."""
        for testo, attesi in GOLDEN_CASES:
            with self.subTest(testo=testo):
                self.assertEqual(attesi, extract_tags(testo))


class EmphasisBoundaryTests(unittest.TestCase):
    """clodia-logic#457 · l'enfasi markdown è un confine, non un nascondiglio.

    `**@sysadmin**` valeva `[]`: l'asterisco non era fra i caratteri ammessi
    prima del sigillo. Lato gateway il danno è il campo `mentions` vuoto —
    nessun badge azionabile, nessuna notifica a chi è stato chiamato; lato
    router (l'altra copia) è l'ordine che non parte. Una regola sola, due
    effetti, ed è per questo che il fix va in entrambe le copie.

    I casi vivono in `GOLDEN_CASES` (li esegue anche `clodia-logic`); qui si
    misura l'effetto dove conta per questo repository: il campo strutturato
    scritto da `post_message`.
    """

    def test_bold_and_italic_mentions_are_mentions(self) -> None:
        self.assertEqual(["sysadmin"], extract_mentions("**@sysadmin** guarda"))
        self.assertEqual(["clodia"], extract_mentions("*@clodia* nota"))
        self.assertEqual(["davide"], extract_mentions("***@davide*** decide"))

    def test_the_other_rules_still_hold_inside_emphasis(self) -> None:
        self.assertEqual([], extract_mentions("**scrivi a foo@bar.com**"))
        self.assertEqual([], extract_mentions("**$clodia**"))
        self.assertEqual([], extract_mentions("usa `**@clodia**` come placeholder"))
        self.assertEqual([], extract_mentions("> **@clodia** aveva scritto così"))

    def test_the_dollar_amount_is_not_a_mention(self) -> None:
        """Il caso preesistente citato dalla issue: non cambia."""
        self.assertEqual([], extract_mentions("costa $100 in tutto"))
        self.assertEqual([], extract_mentions("**costa $100 in tutto**"))


class CitazioneInteraTests(unittest.TestCase):
    """clodia-platform#501 · la citazione copre OGNI riga del testo riportato.

    L'incidente sta nell'altra copia (il router non ha aperto nessun turno:
    `@clodia` + `@clodia-354`, due destinatari per un agente solo), ma la regola
    è del parser e quindi vive in entrambe. Qui l'effetto si misura dove conta
    per questo repository: il campo strutturato `mentions`, cioè i badge e le
    notifiche. Con la citazione su una riga sola, un messaggio di sistema
    consegnava un badge a un'istanza che non esiste.
    """

    GOAL = ("clodia-354: i due articoli sono scritti e in cablaggio\n"
            "@clodia-354 riprendiamo il lavoro e pubblichiamo i due articoli")

    def test_every_line_of_a_quoted_text_is_inert(self) -> None:
        self.assertEqual([], extract_mentions(cita(self.GOAL)))
        self.assertEqual([], extract_tags(cita(self.GOAL)))

    def test_an_empty_line_does_not_break_the_quote(self) -> None:
        """Una riga vuota non citata spezzerebbe il blockquote in due, e fra i
        due pezzi il testo torna normale — cioè le `@` tornano vive."""
        self.assertEqual("> a\n>\n> b", cita("a\n\nb"))
        self.assertEqual([], extract_mentions(cita("a\n\n@mario")))

    def test_the_live_part_of_the_message_still_counts(self) -> None:
        """Citare il testo riportato non deve zittire il messaggio che lo
        riporta: il promemoria convoca comunque il suo destinatario."""
        testo = f"@clodia obiettivo ancora aperto.\n\n{cita(self.GOAL)}\n\nStato: `pinned`."
        self.assertEqual(["clodia"], extract_mentions(testo))


class NormalizzaTests(unittest.TestCase):
    """`normalizza` riscrive gli indirizzi dove il parser li legge, e solo lì.

    Chi conosce la mappa seed/spawn è il chiamante (in `clodia-logic` il
    registry): qui si verifica che la riscrittura veda esattamente le stesse
    zone vive di `_scan` — un `@` in un blocco di codice o in una citazione non
    si tocca, se no si riscrive un esempio o la frase di un altro.
    """

    @staticmethod
    def _a_clodia(_nome: str) -> str:
        return "clodia"

    def test_a_live_mention_is_rewritten(self) -> None:
        self.assertEqual("@clodia vai", normalizza("@mario vai", self._a_clodia))

    def test_inert_zones_are_left_alone(self) -> None:
        for testo in ("usa `@mario` come placeholder",
                      "```\n@mario guarda\n```",
                      "> @mario aveva scritto",
                      "Routing: scegli @mario o @anna.",
                      "scrivi a mario@bar.com"):
            with self.subTest(testo=testo):
                self.assertEqual(testo, normalizza(testo, self._a_clodia))

    def test_a_resolver_that_says_nothing_changes_nothing(self) -> None:
        self.assertEqual("@mario vai", normalizza("@mario vai", lambda _n: None))

    def test_rewriting_moves_nobody_in_or_out_of_the_recipients(self) -> None:
        """L'invariante, su tutta la tabella condivisa: chi convocava resta
        convocato (sotto un nome solo), chi non convocava non si sveglia."""
        for testo, attesi in GOLDEN_CASES:
            with self.subTest(testo=testo):
                self.assertEqual(["clodia"] if attesi else [],
                                 extract_mentions(normalizza(testo, self._a_clodia)))


class PostMessageMentionsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.svc = TopicService(LocalFsStorage(tempfile.mkdtemp()))
        with patch("server.instance_profile.topic_default_participants", return_value=[]):
            self.svc.new("SEAL-1", "ch", {"title": "Canale", "owner": "owner"})

    def test_message_carries_structured_mentions(self) -> None:
        msg = self.svc.post_message("SEAL-1", "ch", "owner", "ping @davide e $anna")
        self.assertEqual(msg["mentions"], ["davide"])
        stored = self.svc.list_messages("SEAL-1", "ch")[-1]
        self.assertEqual(stored["mentions"], ["davide"])

    def test_message_without_mentions_has_empty_list(self) -> None:
        msg = self.svc.post_message("SEAL-1", "ch", "owner", "solo testo ordinario")
        self.assertEqual(msg["mentions"], [])

    def test_a_quoted_goal_does_not_reach_the_structured_field(self) -> None:
        """#501 dal lato di questo repository: il promemoria del goal watch
        archiviava `mentions: ['clodia', 'clodia-354']` — un badge per
        un'istanza che non esiste, oltre al turno che non partiva."""
        testo = ("@clodia obiettivo ancora aperto.\n\n"
                 + cita("clodia-354: i due articoli sono in cablaggio\n"
                        "@clodia-354 riprendiamo il lavoro"))
        msg = self.svc.post_message("SEAL-1", "ch", "system", testo)
        self.assertEqual(["clodia"], msg["mentions"])
        self.assertEqual(["clodia"], self.svc.list_messages("SEAL-1", "ch")[-1]["mentions"])

    def test_a_bold_mention_reaches_the_structured_field(self) -> None:
        """#457 dal lato di questo repository: senza il fix il messaggio veniva
        archiviato con `mentions: []` e il destinatario non riceveva il badge."""
        msg = self.svc.post_message("SEAL-1", "ch", "owner", "**@davide** guarda")
        self.assertEqual(msg["mentions"], ["davide"])
        stored = self.svc.list_messages("SEAL-1", "ch")[-1]
        self.assertEqual(stored["mentions"], ["davide"])


if __name__ == "__main__":
    unittest.main()
