"""Telegram: la dichiarazione del pack dice ESATTAMENTE ciò che il gateway fa oggi.

clodia-platform#522 (epic #527) sposta Telegram in comms-pack. L'epic chiede una
migrazione **a parità**, e una parità affermata non è una parità: #518 cancella
`EGRESS_SCHEMES`, `SOURCE_SCHEMES`, `_TG_GROUP`, `_TG_HANDLE`, `_DANGER`,
`_SPECS` e i prefissi di `taint.py` per sostituirli col registry costruito dai
manifest dei pack, e senza un controllo eseguibile nessuno si accorgerebbe di
una forma accettata in più, di un `dtype` cambiato o di una lettura che smette
di contaminare. Sono tutte differenze **silenziose**: non danno errore, danno un
permesso che prima non c'era o un taint che non si accende più.

Quindi qui si fanno due cose, e in quest'ordine:

1. **si pinna il comportamento di oggi**, attraverso le funzioni pubbliche
   (`check_grantable`, `danger_note`, `spec_for`, `taints`) e non leggendo le
   tabelle — se una tabella sparisce il test deve continuare a misurare la
   stessa domanda, che è il punto;
2. **si chiede alla dichiarazione le stesse domande**, e le risposte devono
   coincidere. Non confronto fra due regex, che potrebbero essere scritte
   diversamente e valere lo stesso: una batteria di stringhe passata ai due
   lati, e nessuna deve essere accettata da uno e rifiutata dall'altro.

Il manifest letto qui è l'esempio Telegram di `SCHEMA.md`. La copia che vale in
produzione è il blocco `connectors:` di comms-pack (clodia-logic, PR #515 della
fase 1 di #522): sta nell'altro repo perché è il pack a portarla, e questo test
non può vederla finché #519 non fa validare i manifest al gateway a install
time. Quando quel giro esisterà, questo test dovrà misurare il manifest
installato: è l'unico punto in cui i due possono divergere senza dirlo.
"""
from __future__ import annotations

import unittest

from .. import egress, taint
from . import manifest as M
from .test_manifest import NO_RESERVED, _examples

#: Stringhe di prova, una per caso che si è già visto sbagliare: gruppo,
#: supergruppo, handle buono, handle troppo corto/troppo lungo, wildcard,
#: percorso, handle senza chiocciola, vuoto.
CAMPIONI = (
    "-1001234567890", "123456789", "@dadabit", "@abcd",
    "@" + "a" * 33, "*", "gruppo/sotto", "dadabit", "",
)


def _telegram() -> M.Connector:
    reg = M.build_registry(_examples(), reserved=NO_RESERVED)
    c = reg.by_id("telegram")
    assert c is not None, "SCHEMA.md non documenta più il connettore telegram"
    return c


def _accettato_dal_gateway(direzione: str, resto: str) -> bool:
    try:
        egress.check_grantable(direzione, f"tg:{resto}")
    except ValueError:
        return False
    return True


def _accettato_dalla_dichiarazione(resto: str) -> bool:
    scheme = _telegram().schemes[0]
    return any(f.matches(resto) for f in scheme.forms)


class TodayIsPinnedTests(unittest.TestCase):
    """Il comportamento che #518 deve conservare, misurato senza le tabelle."""

    def test_the_two_forms_are_grantable_and_nothing_else_is(self):
        atteso = {"-1001234567890": True, "123456789": True, "@dadabit": True,
                  "@abcd": False, "@" + "a" * 33: False, "*": False,
                  "gruppo/sotto": False, "dadabit": False, "": False}
        for resto, ok in atteso.items():
            with self.subTest(resto=resto):
                self.assertIs(_accettato_dal_gateway("egress", resto), ok)

    def test_the_form_is_checked_in_both_directions(self):
        """È una proprietà dello SCHEMA, non della direzione: in ingresso un
        wildcard spegnerebbe il taint su tutto Telegram, in uscita una voce mai
        combaciabile sarebbe approvata e inefficace — e il sintomo («l'ho messa
        in lista e chiede ancora») non nominerebbe la causa."""
        for resto in CAMPIONI:
            with self.subTest(resto=resto):
                self.assertIs(_accettato_dal_gateway("egress", resto),
                              _accettato_dal_gateway("ingress", resto))

    def test_the_danger_note_is_this_sentence(self):
        """La frase che l'owner legge al gate PRIMA di concedere. Riscriverla
        durante una migrazione cambierebbe ciò su cui ha dato il consenso."""
        self.assertEqual(egress.danger_note("tg:-1001234567890"),
                         "una chat su Telegram, cioè su un'infrastruttura non tua.")

    def test_the_pdp_constrains_exactly_two_verbs(self):
        self.assertEqual(egress.spec_for("telegram.send")[0], "telegram")
        self.assertEqual(egress.spec_for("telegram.send_file")[0], "telegram")
        self.assertEqual(egress.spec_for("telegram.send")[1]({"chat_id": "-100"}),
                         ["tg:-100"])
        for verbo in ("telegram.inbox", "telegram.poll", "telegram.listen",
                      "telegram.roster"):
            with self.subTest(verbo=verbo):
                self.assertIsNone(egress.spec_for(verbo))

    def test_which_telegram_reads_taint_a_channel(self):
        for verbo in ("telegram.inbox", "telegram.receive", "telegram.pull"):
            with self.subTest(verbo=verbo):
                self.assertTrue(taint.taints(verbo))
        for verbo in ("telegram.send", "telegram.send_file", "telegram.listen"):
            with self.subTest(verbo=verbo):
                self.assertFalse(taint.taints(verbo))


class TheDeclarationSaysTheSameTests(unittest.TestCase):
    """Le stesse domande, fatte al manifest."""

    def setUp(self) -> None:
        self.c = _telegram()
        self.scheme = self.c.schemes[0]

    def test_it_accepts_exactly_what_the_gateway_accepts(self):
        """Il controllo che vale: non due regex a confronto — due RISPOSTE.
        Una forma accettata qui e rifiutata di là sarebbe un permesso nuovo che
        entra con una migrazione dichiarata a parità."""
        for resto in CAMPIONI:
            with self.subTest(resto=resto):
                self.assertIs(_accettato_dalla_dichiarazione(resto),
                              _accettato_dal_gateway("egress", resto))

    def test_the_scheme_speaks_in_both_directions(self):
        """`tg:` è fonte E destinazione (clodia-platform#363): è il relay
        conversazionale a chiederlo, e perderlo come fonte spegnerebbe il
        vaglio del mittente senza che nessun invio fallisca."""
        self.assertEqual(self.scheme.name, "tg")
        self.assertTrue(self.scheme.is_source and self.scheme.is_egress)
        self.assertIn("tg", egress.EGRESS_SCHEMES)
        self.assertIn("tg", egress.SOURCE_SCHEMES)

    def test_it_carries_the_same_danger_sentence(self):
        self.assertEqual(self.scheme.danger, egress.danger_note("tg:123"))

    def test_its_verbs_build_the_destination_the_pdp_builds(self):
        """Verbo per verbo: stesso `dtype` e stesso URI a partire dallo stesso
        argomento. Un `arg` sbagliato darebbe destinazione vuota, cioè — per la
        regola fail-closed di #119 — un rifiuto su ogni invio."""
        dichiarati = {v.verb: v for v in self.c.verbs if v.direction == "egress"}
        self.assertEqual(set(dichiarati), {"telegram.send", "telegram.send_file"})
        for verbo, v in dichiarati.items():
            with self.subTest(verbo=verbo):
                dtype, estrattore = egress.spec_for(verbo)
                self.assertEqual(v.dtype, dtype)
                self.assertEqual([v.uri_for("-1001234567890")],
                                 estrattore({v.arg: "-1001234567890"}))

    def test_it_declares_the_reads_that_taint_today(self):
        """Nessuna in più (una lettura che smette di contaminare non fallisce:
        tace) e nessuna in meno."""
        self.assertTrue(self.c.taint_prefixes)
        for prefisso in self.c.taint_prefixes:
            with self.subTest(prefisso=prefisso):
                self.assertTrue(taint.taints(prefisso))

    def test_the_topic_button_writes_the_two_uris_the_route_writes(self):
        """`topics_api.telegram_link` mette `tg:<chat_id>` in USCITA e in
        INGRESSO, e crea il binding del canale. Senza l'ingresso il mittente non
        è vagliato; senza il binding il messaggero non riporta nulla pur con la
        whitelist scritta (sintomo del 23 set 2026)."""
        azione = next(a for a in self.c.topic_actions if a.id == "telegram-link")
        campo = azione.fields[0].name
        valori = {campo: "-1001234567890"}
        self.assertEqual([t.format(**valori) for t in azione.adds_ingress],
                         ["tg:-1001234567890"])
        self.assertEqual([t.format(**valori) for t in azione.adds_egress],
                         ["tg:-1001234567890"])
        self.assertEqual(azione.binding, "channel")

    def test_the_credential_is_the_vault_entry_in_use_today(self):
        """`tools_api` dichiara Telegram connesso se quella voce è nel vault: un
        nome diverso nel manifest darebbe un connettore eternamente da
        configurare, con la credenziale depositata accanto."""
        bot = next(p for p in self.c.providers if p.credential)
        self.assertEqual(bot.credential.vault_entry, "telegram_bot_token")
        self.assertTrue(all(f.secret for f in bot.credential.fields
                            if f.name == "token"))


if __name__ == "__main__":
    unittest.main()
