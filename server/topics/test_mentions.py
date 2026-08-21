"""Test del parser mention (issue clodia-platform#83, D1 + DoD 7-8)."""
from __future__ import annotations

import tempfile
import unittest
from unittest.mock import patch

from .local_fs import LocalFsStorage
from .mentions import GOLDEN_CASES, extract_mentions, extract_tags
from .service import TopicService


class ExtractMentionsTests(unittest.TestCase):
    def test_basic_sigils(self) -> None:
        self.assertEqual(extract_mentions("ciao @davide, senti $mario"), ["davide", "mario"])

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
        self.assertEqual(extract_mentions("(vedi @davide) e [cc $anna]"), ["davide", "anna"])

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
        for testo, men, _hard, _soft in GOLDEN_CASES:
            with self.subTest(testo=testo):
                self.assertEqual(men, extract_mentions(testo))

    def test_extract_tags_separates_the_two_sigils(self) -> None:
        for testo, _men, hard, soft in GOLDEN_CASES:
            with self.subTest(testo=testo):
                self.assertEqual((hard, soft), extract_tags(testo))

    def test_the_mentions_are_the_ordered_union_of_the_two_sigils(self) -> None:
        """`extract_mentions` non è `hard + soft`: è l'ordine del documento.
        Un badge elenca i destinatari come sono scritti, non per sigillo."""
        self.assertEqual(["mario", "davide"],
                         extract_mentions("$mario avvisa, poi @davide decide"))
        self.assertEqual((["davide"], ["mario"]),
                         extract_tags("$mario avvisa, poi @davide decide"))


class PostMessageMentionsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.svc = TopicService(LocalFsStorage(tempfile.mkdtemp()))
        with patch("server.instance_profile.topic_default_participants", return_value=[]):
            self.svc.new("SEAL-1", "ch", {"title": "Canale", "owner": "owner"})

    def test_message_carries_structured_mentions(self) -> None:
        msg = self.svc.post_message("SEAL-1", "ch", "owner", "ping @davide e $$anna")
        self.assertEqual(msg["mentions"], ["davide"])
        stored = self.svc.list_messages("SEAL-1", "ch")[-1]
        self.assertEqual(stored["mentions"], ["davide"])

    def test_message_without_mentions_has_empty_list(self) -> None:
        msg = self.svc.post_message("SEAL-1", "ch", "owner", "solo testo ordinario")
        self.assertEqual(msg["mentions"], [])


if __name__ == "__main__":
    unittest.main()
