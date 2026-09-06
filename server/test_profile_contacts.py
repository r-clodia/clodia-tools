"""Il profilo PII non è una seconda casa per i recapiti (clodia-platform#200).

Il campo libero del profilo («+ aggiungi campo») accettava `telegram`. Il
contatto dell'owner è finito lì, il campo della scheda agente è rimasto `None`,
e da quel momento la piattaforma si è comportata come se il recapito non
esistesse: il lookup in ingresso non riconosceva i suoi messaggi e l'ultimo
gradino di R4 non aveva dove mandare la notifica.

Due case scrivibili per lo stesso fatto, una sola letta. Qui se ne chiude una,
in scrittura soltanto: la lettura resta, e `None` continua a passare — è come
si toglie un valore finito qui per sbaglio, e vietarlo lo terrebbe prigioniero
del vault per sempre.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import profile as P


class RefuseFixedContactsTests(unittest.TestCase):
    def test_telegram_is_refused(self):
        with self.assertRaises(ValueError) as e:
            P._refuse_fixed_contacts({"telegram": "76632169"})
        self.assertIn("scheda dell'agente", str(e.exception))

    def test_the_refusal_names_where_the_value_belongs(self):
        with self.assertRaises(ValueError) as e:
            P._refuse_fixed_contacts({"telegram": "@davide_c"})
        self.assertIn("/api/agents/", str(e.exception))

    def test_the_same_fact_under_another_name_is_the_same_fact(self):
        """`telegram_id`, `chat_id`, `Telegram-ID`: chi vuole scriverlo qui non
        si ferma alla prima chiave rifiutata, prova la variante."""
        for k in ("telegram_id", "telegram_handle", "chat_id", "Telegram-ID", " TELEGRAM "):
            with self.subTest(k=k):
                with self.assertRaises(ValueError):
                    P._refuse_fixed_contacts({k: "76632169"})

    def test_removing_a_stray_value_stays_possible(self):
        """`None` = «togli questa chiave». Vietarlo insieme alla scrittura
        lascerebbe il valore sbagliato dov'è, senza modo di ripulirlo."""
        P._refuse_fixed_contacts({"telegram": None})

    def test_the_real_pii_fields_are_untouched(self):
        P._refuse_fixed_contacts({"email": "d@example.com", "iban": "IT60X...",
                                  "telefono": "+39 333 1234567"})


class SetFieldsTests(unittest.TestCase):
    """Il rifiuto sta nel percorso di scrittura vero, non solo nell'helper: è
    `set_fields` che ogni chiamante attraversa (webui, verbo `profile.set`)."""

    def setUp(self):
        self.deposited = []
        for p in (patch.object(P, "can_write", lambda c, t: True),
                  patch.object(P.vault, "has_credential", lambda c: False),
                  patch.object(P.vault, "deposit",
                               lambda c, b, **kw: self.deposited.append(b)),
                  patch.object(P, "get", lambda c, t: {"agent": t, "fields": {}})):
            p.start()
            self.addCleanup(p.stop)

    def test_a_contact_does_not_reach_the_vault(self):
        with self.assertRaises(ValueError):
            P.set_fields("davide", "davide", {"telegram": "76632169"})
        self.assertEqual([], self.deposited, "il recapito è stato depositato lo stesso")

    def test_a_profile_still_saves(self):
        P.set_fields("davide", "davide", {"iban": "IT60X..."})
        self.assertEqual([{"fields": {"iban": "IT60X..."}, "tier": "SEAL-2"}],
                         self.deposited)

    def test_one_bad_key_refuses_the_whole_write(self):
        """Salvare metà di una form e rifiutare l'altra metà in silenzio è il
        modo di far credere che sia andata."""
        with self.assertRaises(ValueError):
            P.set_fields("davide", "davide",
                         {"iban": "IT60X...", "telegram": "76632169"})
        self.assertEqual([], self.deposited)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
