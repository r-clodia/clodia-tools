"""On-behalf: la whitelist di DESTINAZIONE vale anche per una persona (#148).

Fino al 23 ago 2026 il dispatch aveva due esenzioni scritte così — `if not
is_on_behalf():` — una sul M-gate e una sulla whitelist di destinazione, con la
motivazione «l'utente autenticato dall'UI è trusted (§2)».

L'esenzione era sicura finché l'unica persona era l'owner, che è admin. Non lo è
più appena esiste un ruolo `user`, e il tetto che sembrava trattenerla non la
trattiene: `scoped_ceiling_allows` per progetto dichiarato non è un tetto quando
il claim manca, e su questo percorso manca SEMPRE — `gateway_pdp._token` conia il
token on-behalf senza `scoped_tools`. Risultato misurato: una persona con ruolo
`user` dalla webui raggiungeva ogni destinazione, senza gate e senza whitelist.

La decisione (decision record 38, approvata il 23 ago 2026) separa le due metà:

  - il **M-gate** resta esente per i ruoli **admin** — chiedere a chi agisce di
    confermare la propria azione è consent fatigue, non controllo;
  - la **whitelist di destinazione** si applica a TUTTI, perché *dove* i dati
    escono è perimetro e non segnale: non dipende da chi ha premuto il tasto.

Questi test guardano il comportamento del dispatch, non il testo del codice: il
caso centrale (`test_a_plain_user_cannot_reach_an_unlisted_destination`) passa
la chiamata per `call_tool` e verifica che il connettore NON venga raggiunto.
Prima della modifica quello stesso caso spedisce.
"""
from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

from . import egress
from . import main as M
from . import whitelist


class _Persona:
    """Il contesto di una chiamata ON-BEHALF, per la durata del blocco.

    Nessun `scoped_tools`: è il token vero della webui, ed è esattamente ciò che
    rende la riga misurabile invece di teorica.
    """

    def __init__(self, ruolo="user", chi="giovanni", on_behalf=True):
        self._c = (ruolo, chi, on_behalf)

    def __enter__(self):
        ruolo, chi, ob = self._c
        self._tok = (whitelist.set_current_on_behalf(ob),
                     whitelist.set_current_human_role(ruolo),
                     whitelist.set_current_principal(chi))
        return self

    def __exit__(self, *a):
        ob, hr, pr = self._tok
        whitelist.reset_current_principal(pr)
        whitelist.reset_current_human_role(hr)
        whitelist.reset_current_on_behalf(ob)
        return False


def _send(to, *, ruolo="user", destinazioni=(), on_behalf=True, modo="on"):
    """Prova a spedire una mail come una persona, e riferisce cosa è successo.

    Ritorna `(testo, spedito, gate)`: il testo che il dispatch restituisce (i
    rifiuti tornano come contenuto, non come eccezione), se il connettore è stato
    raggiunto, e le chiavi di gate richieste. `spedito` è la misura che conta —
    un rifiuto arrivato DOPO l'invio non è un rifiuto.
    """
    spediti: list = []
    gate: list = []

    async def _gate_consent(agent, key, **kw):
        # Un gate in test non si attende: si registra e si nega, così un
        # controllo che scatta è visibile e non blocca la suite per 180s.
        gate.append((key, kw.get("reason") or ""))
        raise PermissionError(f"GATE {key}")

    with _Persona(ruolo=ruolo, on_behalf=on_behalf), \
            patch.object(M, "agent_name", lambda: "clodia"), \
            patch.object(M, "_unattended_denial", lambda _n: None), \
            patch.object(M.origin, "evaluate", return_value={"action": "allow"}), \
            patch.object(M, "_require_gate_consent", _gate_consent), \
            patch.object(M, "_cross_topic_gate_key", lambda *a: None), \
            patch.object(M, "_topic_attachments", lambda *a: ([], None)), \
            patch.object(M, "_email_account", lambda _a: "casella"), \
            patch.object(egress, "mode", lambda: modo), \
            patch.object(egress, "effective_uris",
                         lambda _d="egress", *a, **kw: list(destinazioni)), \
            patch.object(M.email, "send",
                         lambda *a, **kw: spediti.append(a) or {"sent": True}), \
            patch.object(M._taint, "note_verb"), \
            patch.object(M._tlm, "record"):
        out = asyncio.run(M.call_tool(
            "email.send", {"to": to, "subject": "s", "body": "b"}))
    return out[0].text, bool(spediti), gate


class TheDestinationWhitelistAppliesToPeopleTests(unittest.TestCase):
    def test_a_plain_user_cannot_reach_an_unlisted_destination(self):
        """Il caso che dà il senso alla modifica: rosso prima del fix."""
        testo, spedito, _ = _send("estraneo@example.com")
        self.assertFalse(spedito,
                         f"una persona con ruolo `user` ha spedito comunque: {testo}")
        self.assertIn("DENIED", testo)

    def test_an_admin_is_not_exempt_either(self):
        """L'esenzione dal gate riguarda il consenso, non il perimetro: l'owner
        non si fa confermare la propria mail, ma non per questo la manda dove
        nessuno ha censito."""
        testo, spedito, gate = _send("estraneo@example.com", ruolo="admin")
        self.assertFalse(spedito, f"admin esente anche dal perimetro: {testo}")
        self.assertEqual([], gate, "all'admin è stato chiesto un M-gate")

    def test_a_listed_destination_still_goes_out(self):
        """Il controllo circoscrive, non chiude: senza questo caso la modifica
        potrebbe essere «nega sempre» e sembrare corretta."""
        testo, spedito, _ = _send("collega@clodia.dev", ruolo="admin",
                                  destinazioni=["mailto:collega@clodia.dev"])
        self.assertTrue(spedito, f"destinazione censita e rifiutata: {testo}")

    def test_the_agent_branch_is_unchanged(self):
        """Il ramo che già funzionava continua a funzionare come prima."""
        testo, spedito, _ = _send("estraneo@example.com", on_behalf=False)
        self.assertFalse(spedito, f"whitelist inefficace per un agente: {testo}")


class TheCardSaysWhoIsAskingTests(unittest.TestCase):
    """Il M-gate ora scatta anche per una persona non-admin, e allora la card
    deve dire di chi è la richiesta.

    Onestà su quanto vale questo mezzo: chi approva un gate è un principal
    autenticato qualunque (`gate_api._authorize` non guarda il ruolo), quindi per
    un non-admin questo gate compra VISIBILITÀ e traccia, non impedimento — la
    metà che impedisce è la whitelist di destinazione, testata sopra. Se un
    giorno l'approvazione dovrà richiedere un admin, è lì che va scritto, in un
    punto solo.
    """

    def test_the_reason_names_the_person_not_only_the_carrier(self):
        _t, spedito, gate = _send("collega@clodia.dev",
                                  destinazioni=["mailto:collega@clodia.dev"])
        self.assertTrue(gate, "una persona con ruolo `user` non ha visto nessun gate")
        _key, reason = gate[0]
        self.assertIn("giovanni", reason)
        self.assertIn("user", reason)

    def test_an_admin_sees_no_card_for_their_own_action(self):
        """L'altra metà del decision record 38: chiedere all'owner di confermare
        la propria azione è consent fatigue, non controllo."""
        _t, _s, gate = _send("collega@clodia.dev", ruolo="admin",
                             destinazioni=["mailto:collega@clodia.dev"])
        self.assertEqual([], gate)


class TheMgateExemptionFollowsTheRoleTests(unittest.TestCase):
    """`_mgate_exempt` in isolamento: è la regola, il resto la applica."""

    def test_an_admin_is_exempt(self):
        for ruolo in ("admin", "superadmin"):
            with self.subTest(ruolo=ruolo), _Persona(ruolo=ruolo):
                self.assertTrue(M._mgate_exempt())

    def test_a_plain_user_is_not(self):
        with _Persona(ruolo="user"):
            self.assertFalse(M._mgate_exempt())
        with _Persona(ruolo=None):
            self.assertFalse(M._mgate_exempt(), "ruolo assente = `user`, non admin")

    def test_an_agent_call_was_never_exempt(self):
        with _Persona(ruolo="admin", on_behalf=False):
            self.assertFalse(M._mgate_exempt())

    def test_the_switch_restores_the_old_rule(self):
        """La maniglia di rientro, verificata: senza un test è una promessa."""
        with _Persona(ruolo="user"), \
                patch.dict(M._os.environ, {"CLODIA_ONBEHALF_TRUSTED": "on"}):
            self.assertTrue(M._mgate_exempt())
        with _Persona(ruolo="user"), \
                patch.dict(M._os.environ, {"CLODIA_ONBEHALF_TRUSTED": "off"}):
            self.assertFalse(M._mgate_exempt())

    def test_the_switch_also_restores_the_egress_exemption(self):
        """Le due metà tornano indietro INSIEME: una maniglia che rimette solo
        una delle due esenzioni lascia uno stato che nessuno ha mai testato."""
        with patch.dict(M._os.environ, {"CLODIA_ONBEHALF_TRUSTED": "on"}):
            _t, spedito, _g = _send("estraneo@example.com")
        self.assertTrue(spedito)


class TheRoleCheckLivesInOnePlaceTests(unittest.TestCase):
    """La domanda «questa persona è admin?» ora ha due lettori. Con due copie
    divergerebbe, ed è già divergiuta una volta su questa esatta riga (il
    `== "admin"` che escludeva `superadmin`, 7 ago 2026)."""

    def test_the_gate_exemption_does_not_re_implement_the_role_check(self):
        import inspect
        src = inspect.getsource(M._mgate_exempt)
        self.assertIn("_human_is_admin", src)
        self.assertNotIn("_ADMIN_ROLES", src,
                         "seconda copia della regola: usa `_human_is_admin`")


if __name__ == "__main__":
    unittest.main()
