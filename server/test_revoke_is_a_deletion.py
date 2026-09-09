"""Una revoca deve TOGLIERE, e chi la registra deve sapere CHI l'ha chiesta (#219).

Due difetti sulla stessa strada — `agents.grant_*` / `agents.revoke_*` — che si
sommano nel modo peggiore: la revoca non toglie e l'audit non sa dirlo.

1. **La revoca dichiara invece di misurare.** `_modify` calcola l'insieme nuovo,
   lo manda in PATCH (un UPSERT: si scrive il set completo, non si cancella una
   riga) e poi risponde `{"ok": true, <campo>: <insieme che voleva>}`. La
   risposta è l'INTENZIONE del gateway, non lo stato del backend: se l'upsert
   non applica la sottrazione — o la applica a metà — il chiamante legge
   `capabilities: []` mentre la riga è ancora lì. È la stessa classe di difetto
   già corretta per `grant_tool` (#304), rimasta su skill e rule.

2. **L'audit del vault attribuisce ogni revoca alla shell.**
   `vault._caller_hint()` chiedeva `whitelist.agent_name_safe()`, che in
   `whitelist` non esiste (sta in `main`): l'`AttributeError` finiva nell'`except`
   e ogni chiamata senza principal umano — un job, un agente che agisce per sé —
   veniva registrata come `shell`. Cioè proprio la distinzione che quella
   funzione era stata scritta per fare («l'ha tolto la UI» contro «l'ha tolto
   qualcuno dal guscio») restava sempre dalla parte sbagliata, e in silenzio.

Un permesso che sparisce senza traccia è peggio di un permesso mancante: il
secondo si vede. Uno che NON sparisce ma risulta tolto è peggio di entrambi.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from .tools import agents_admin as AA


def _agente(**campi) -> dict:
    base = {"name": "avvocato", "type": "normal", "immutable": False,
            "capabilities": [], "rules": [], "tool_permissions": []}
    base.update(campi)
    return base


class _Backend:
    """Un agent-server finto con la semantica di scrittura che gli si chiede.

    `applica=True` è l'upsert che fa il suo lavoro; `applica=False` è l'upsert
    che risponde OK e lascia la riga dov'era — il caso del #219.
    """

    def __init__(self, stato: dict, applica: bool = True):
        self.stato, self.applica = stato, applica
        self.patched: list[dict] = []

    def __enter__(self):
        def _patch(name: str, body: dict) -> dict:
            self.patched.append(body)
            if self.applica:
                self.stato.update({k: list(v) for k, v in body.items()})
            return {"ok": True}

        self._p = [patch.object(AA, "_all_agents", lambda: [self.stato]),
                   patch.object(AA, "_patch_caps", _patch)]
        for p in self._p:
            p.start()
        return self

    def __exit__(self, *e):
        for p in self._p:
            p.stop()
        return False


class RevocaMisurata(unittest.TestCase):
    """La risposta riporta lo stato RILETTO dal backend, non quello inviato."""

    def test_una_revoca_non_applicata_non_dice_ok(self):
        stato = _agente(capabilities=["ricerca-giuridica"])
        with _Backend(stato, applica=False):
            r = AA.revoke_skill("avvocato", "ricerca-giuridica")
        self.assertFalse(r["ok"], "la riga è ancora lì: `ok: true` è una bugia")
        # E non deve mostrare l'insieme che VOLEVA, che è il modo in cui la
        # bugia diventa invisibile a chi rilegge la risposta.
        self.assertEqual(r["capabilities"], ["ricerca-giuridica"])
        self.assertIn("ricerca-giuridica", r.get("detail", ""))

    def test_una_revoca_applicata_dice_cosa_ha_tolto(self):
        stato = _agente(capabilities=["ricerca-giuridica", "redazione-atti"])
        with _Backend(stato, applica=True):
            r = AA.revoke_skill("avvocato", "ricerca-giuridica")
        self.assertTrue(r["ok"])
        self.assertEqual(r["removed"], ["ricerca-giuridica"])
        self.assertEqual(r["capabilities"], ["redazione-atti"])

    def test_revocare_cio_che_non_c_era_e_un_no_op_dichiarato(self):
        """Idempotente, ma non muto: `removed: []` distingue «tolto» da «non
        c'era», e sono due risposte diverse per chi sta verificando un audit."""
        stato = _agente(capabilities=["redazione-atti"])
        with _Backend(stato, applica=True):
            r = AA.revoke_skill("avvocato", "ricerca-giuridica")
        self.assertTrue(r["ok"])
        self.assertEqual(r["removed"], [])

    def test_un_grant_non_applicato_non_dice_ok(self):
        """Stessa misura nell'altra direzione: `_modify` è il punto condiviso."""
        stato = _agente(rules=[])
        with _Backend(stato, applica=False):
            r = AA.grant_rule("avvocato", "tono-formale")
        self.assertFalse(r["ok"])
        self.assertEqual(r["rules"], [])

    def test_se_la_rilettura_fallisce_non_si_finge_un_esito(self):
        """«Non ho potuto verificare» è un caso esplicito, non un `ok` di default."""
        stato = _agente(capabilities=["ricerca-giuridica"])
        with _Backend(stato, applica=True):
            with patch.object(AA, "_readback", lambda name, field: None):
                r = AA.revoke_skill("avvocato", "ricerca-giuridica")
        self.assertFalse(r["ok"])
        self.assertFalse(r["verified"])

    def test_revoke_tool_conserva_il_verdetto_dell_enforcement(self):
        """Su `tool_permissions` l'ultima parola resta di `_measure`, che legge la
        whitelist del gateway: è lì che si decide, e un verbo ereditato resta
        attivo anche dopo una cancellazione riuscita dalla lista propria."""
        stato = _agente(tool_permissions=["topic.open"])
        with _Backend(stato, applica=True):
            with patch.object(AA, "_measure",
                              lambda n, t, atteso: {"ok": False, "effective": True,
                                                    "verified": True,
                                                    "detail": "ereditato da un antenato"}):
                r = AA.revoke_tool("avvocato", "topic.open")
        self.assertFalse(r["ok"])
        self.assertEqual(r["detail"], "ereditato da un antenato")
        # La cancellazione dalla lista PROPRIA è comunque avvenuta e si vede.
        self.assertEqual(r["removed"], ["topic.open"])


class AuditNominaChiHaTolto(unittest.TestCase):
    """`vault._caller_hint()` deve saper dire «l'agente X», non sempre «shell»."""

    def test_un_agente_senza_principal_umano_non_e_la_shell(self):
        from . import vault, whitelist
        whitelist.CONFIG.setdefault("agents", {}).setdefault("avvocato", {"allowed_tools": []})
        tok = whitelist.set_current_agent("avvocato")
        try:
            self.assertEqual(vault._caller_hint(), "avvocato")
        finally:
            whitelist.reset_current_agent(tok)

    def test_il_principal_umano_ha_la_precedenza(self):
        from . import vault, whitelist
        whitelist.CONFIG.setdefault("agents", {}).setdefault("avvocato", {"allowed_tools": []})
        ta = whitelist.set_current_agent("avvocato")
        tp = whitelist.set_current_principal("davide")
        try:
            self.assertEqual(vault._caller_hint(), "davide")
        finally:
            whitelist.reset_current_principal(tp)
            whitelist.reset_current_agent(ta)

    def test_un_solo_lettore_dell_identita(self):
        """Il vault DELEGA, non reimplementa.

        Il difetto è nato da un secondo lettore scritto in un altro modulo, che
        chiamava una funzione che lì non esisteva. Un terzo lettore rifarebbe lo
        stesso errore da capo, e nessuno lo vedrebbe finché un audit non nomina
        la persona sbagliata.
        """
        import inspect
        from . import vault, whitelist
        self.assertTrue(hasattr(whitelist, "caller_hint"))
        self.assertIn("caller_hint()", inspect.getsource(vault._caller_hint))
        self.assertNotIn("current_principal", inspect.getsource(vault._caller_hint))

    def test_senza_nessuna_identita_resta_la_shell(self):
        """Un `docker exec` a mano non ha né principal né agente: va detto, non
        attribuito a qualcuno."""
        import os
        from . import vault, whitelist
        ta = whitelist.set_current_agent(None)
        try:
            with patch.dict(os.environ, {"MCP_AGENT_NAME": ""}):
                self.assertEqual(vault._caller_hint(), "shell")
        finally:
            whitelist.reset_current_agent(ta)


if __name__ == "__main__":
    unittest.main()
