"""Un messaggio che entra da un PROXY non è un messaggio umano (#248).

`kind` è scelto all'ingresso, e l'ingresso è qui. Finché la scelta era «token
on-behalf → `human`», un sistema terzo si persisteva come una persona: un token
di proxy **è** on-behalf, perché parla per conto di un principal ammesso nella
stanza. `clodia-logic` poteva solo coercire in lettura (r-clodia/clodia-logic#315),
che è un ponte e non una correzione — ogni lettore futuro deve ricordarsene, e
quello che se ne dimentica riapre il difetto.

Le due direzioni d'errore contano entrambe, e per questo sono due test:

* un proxy che si scrive `human` **disattiva in silenzio** le regole che poggiano
  su quel campo (una menzione a una persona non instrada un'AI; solo i messaggi
  umani accodano una notifica Telegram) applicandole a un terzo;
* una persona che si scrive `proxy` le disattiva **per chi ne ha diritto**, che è
  il modo in cui un eccesso di zelo diventa il difetto successivo.
"""
from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from . import human_mcp, main as M, pki_mint, whitelist
from .topics import service as topics_service


class _Sessione:
    """Una sessione on-behalf, come la conia il gateway. `kind` è il claim
    firmato: nel token, non nel corpo della richiesta."""

    def __init__(self, chi="giovanni", kind=None, chat="chan:SEAL-1:acme:giovanni"):
        self._v = (chi, kind, chat)

    def __enter__(self):
        chi, kind, chat = self._v
        self._t = (whitelist.set_current_on_behalf(True),
                   whitelist.set_current_principal(chi),
                   whitelist.set_current_principal_kind(kind),
                   whitelist.set_current_chat(chat),
                   whitelist.set_current_clearance("SEAL-1"),
                   whitelist.set_current_agent("clodia"))
        return self

    def __exit__(self, *a):
        ob, pr, pk, ch, cl, ag = self._t
        whitelist.reset_current_agent(ag)
        whitelist.reset_current_clearance(cl)
        whitelist.reset_current_chat(ch)
        whitelist.reset_current_principal_kind(pk)
        whitelist.reset_current_principal(pr)
        whitelist.reset_current_on_behalf(ob)
        return False


class _Svc:
    def __init__(self):
        self.posted = None

    def open(self, tier, name):
        return {"meta": META}

    def post_message(self, tier, name, author, text, kind="human", **k):
        self.posted = {"author": author, "kind": kind, "text": text}
        return dict(self.posted, id="m1")


META = {"tier": "SEAL-1", "owner": "davide",
        "participants": {"davide": "owner", "giovanni": "member",
                         "crm-esterno": "member"}}


def _posta(testo="ciao"):
    svc = _Svc()
    with patch.object(M, "_topics", lambda: svc), \
         patch.object(M, "runtime", MagicMock()):
        M._dispatch_topic("topic.post_message",
                          {"tier": "SEAL-1", "name": "acme", "text": testo})
    return svc.posted


class TheKindIsChosenAtIngressTests(unittest.TestCase):

    def test_a_proxy_message_is_not_persisted_as_human(self):
        with _Sessione(chi="crm-esterno", kind="proxy"):
            self.assertEqual(_posta()["kind"], "proxy")

    def test_a_proxy_still_signs_with_its_own_name(self):
        """L'autore resta il nome del sistema terzo: `kind` dice *che natura*
        ha chi parla, non lo nasconde."""
        with _Sessione(chi="crm-esterno", kind="proxy"):
            self.assertEqual(_posta()["author"], "crm-esterno")

    def test_a_person_is_still_human(self):
        with _Sessione(chi="giovanni", kind="human"):
            self.assertEqual(_posta()["kind"], "human")

    def test_a_person_without_the_claim_is_still_human(self):
        """Retro-compatibilità: il token di una persona lo conia `clodia-logic`,
        che non scrive il claim. Coercire a `proxy` in sua assenza spegnerebbe
        le due regole per chi ne ha diritto."""
        with _Sessione(chi="giovanni", kind=None):
            self.assertEqual(_posta()["kind"], "human")

    def test_an_agent_is_still_ai(self):
        tok = whitelist.set_current_agent("ophelia")
        try:
            with patch.object(M, "_require_topic_member", lambda *a, **k: None):
                self.assertEqual(_posta()["kind"], "ai")
        finally:
            whitelist.reset_current_agent(tok)


class TheLabelTravelsInTheTokenTests(unittest.TestCase):
    """La natura del principal non si deduce a valle: si firma a monte.

    Il gateway è l'**unico** che conia i token di proxy (`proxy_auth.token_for`);
    marcarli lì rende la distinzione disponibile a ogni lettore senza che nessuno
    debba consultare un registro, e firmata, quindi non rimovibile da chi la porta.
    """

    def test_the_mint_carries_the_principal_kind(self):
        import json as _json
        from base64 import urlsafe_b64decode

        with patch.object(pki_mint, "_agent_key_path") as kp, \
             patch.object(pki_mint, "_load_private") as lp:
            kp.return_value = MagicMock(is_file=lambda: True)
            lp.return_value = MagicMock(sign=lambda b: b"firma")
            tok = pki_mint.mint_session_token("clodia", principal="crm-esterno",
                                              on_behalf=True, principal_kind="proxy")
        body = tok.split(".")[1]
        payload = _json.loads(urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        self.assertEqual(payload.get("principal_kind"), "proxy")

    def test_a_session_without_the_claim_is_read_as_human(self):
        self.assertEqual(human_mcp.principal_kind_of({"agent": "clodia"}), "human")

    def test_a_seat_admitted_proxy_is_recognised_without_the_claim(self):
        """Difesa in profondità per i token coniati prima di questa modifica:
        `participant:` lo scrive soltanto `proxy_auth`, quindi quell'
        `execution_id` è già la prova che la sessione è di un proxy."""
        self.assertEqual(
            human_mcp.principal_kind_of({"agent": "clodia",
                                         "execution_id": "participant:SEAL-1/acme"}),
            "proxy")


class TheInternalApiIsNotAProxyDoorTests(unittest.TestCase):
    """`/internal/topics` è la porta del runner di `clodia-logic`, non di un terzo.

    Un token di proxy porta nel claim `agent` il **carrier** (di norma `clodia`),
    che è esattamente il principal privilegiato che questa API ammette: senza una
    guardia, un sistema terzo entra da qui e si scrive `kind: human` nel corpo
    della richiesta, scavalcando la scelta fatta all'ingresso MCP.
    """

    def _richiesta(self, payload):
        from starlette.requests import Request
        scope = {"type": "http", "method": "POST", "path": "/internal/topics",
                 "headers": [(b"authorization", b"Bearer ckt1.x.y")]}
        # La verifica del bearer vive ora in `internal_auth`, un posto solo per
        # tutte le rotte interne (clodia-platform#261): il punto da sostituire
        # nel test si è spostato con lei.
        with patch("server.internal_auth.verify_session_token", lambda t: payload):
            from . import topics_api
            return topics_api._authorize(Request(scope))

    def test_a_proxy_token_is_refused(self):
        _, err = self._richiesta({"agent": "clodia", "principal": "crm-esterno",
                                  "principal_kind": "proxy", "on_behalf": True})
        self.assertIsNotNone(err)
        self.assertEqual(err.status_code, 403)

    def test_the_backend_runner_still_gets_in(self):
        agente, err = self._richiesta({"agent": "clodia"})
        self.assertIsNone(err)
        self.assertEqual(agente, "clodia")


class AnInventedKindIsRefusedTests(unittest.TestCase):
    """Il campo ha un insieme chiuso di valori, e il posto dove si verifica è
    quello attraversato da OGNI chiamante — non un controllo per porta."""

    def test_the_service_refuses_an_unknown_kind(self):
        svc = topics_service.TopicService.__new__(topics_service.TopicService)
        with patch.object(topics_service.TopicService, "_read_meta",
                          lambda self, t, n: ({"tier": t}, "v1")), \
             patch.object(topics_service.TopicService, "_assert_content_available",
                          lambda self, m: None):
            with self.assertRaises(topics_service.TopicError):
                svc.post_message("SEAL-1", "acme", "chi", "testo", kind="umano")

    def test_proxy_is_a_known_kind(self):
        self.assertIn("proxy", topics_service.MESSAGE_KINDS)

    def test_the_telegram_relay_keeps_working(self):
        """Guardia contro l'eccesso di zelo: `telegram` è un valore in uso oggi
        (`clodia-logic/api/channel_relay.py`). Un insieme chiuso che lo escluda
        romperebbe il drenaggio di un gruppo al primo messaggio."""
        self.assertIn("telegram", topics_service.MESSAGE_KINDS)


if __name__ == "__main__":
    unittest.main()
