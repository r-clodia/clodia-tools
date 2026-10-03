"""L'elenco dei topic ha UNA porta, non due (clodia-platform#418, punti 1-3).

`topic.list`/`topic.search` applicano tre filtri in fila: need-to-know del seed
**con la clearance** (`_filter_member_rows`), la stanza da cui parte la chiamata
(`_scope_rows_to_this_room`) e — per un token di PERSONA legato a una stanza —
la restrizione a quella stanza. `runtime.topics` restituisce gli stessi metadati
e ne applicava **uno solo**: la membership del seed, dentro
`server/tools/runtime.py`. Da quell'asimmetria nascono tutti e tre i punti
dell'issue, che quindi non sono tre difetti ma tre sintomi dello stesso:

1. una sessione NON presidiata (un job) riceveva l'elenco intero: `topic.*` le è
   negato a monte, `runtime.topics` no, e fuori da una stanza il filtro di
   stanza non restringe per disegno;
2. un token umano senza claim di stanza veniva filtrato sulla membership del
   CARRIER — in esercizio `clodia`, che partecipa a tutto;
3. `include_restricted=True` restituiva i metadati SEAL-3/4 a prescindere dalla
   clearance di chi chiedeva.

La prova che vale davvero non è «ogni verbo risponde bene ai suoi casi», è che i
due verbi rispondono **la stessa cosa nelle stesse condizioni**: finché le due
risposte coincidono non esiste la maniglia che rifà ciò che l'altra ha chiuso.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import main, whitelist


def _row(tier, name, participants=("clodia",), owner="davide"):
    return {"tier": tier, "name": name, "title": name,
            "tldr": f"segreto di {name}", "owner": owner,
            "participants": list(participants)}


class _Claims:
    """I claim firmati della richiesta: chat, principal, on_behalf, ruolo."""

    def __init__(self, chat=None, principal=None, on_behalf=False,
                 human_role=None, unattended=False):
        self._v = (chat, principal, on_behalf, human_role, unattended)

    def __enter__(self):
        chat, principal, on_behalf, ruolo, unatt = self._v
        self._t = (whitelist.set_current_chat(chat),
                   whitelist.set_current_principal(principal),
                   whitelist.set_current_on_behalf(on_behalf),
                   whitelist.set_current_human_role(ruolo),
                   whitelist.set_current_unattended(unatt))
        return self

    def __exit__(self, *a):
        ch, pr, ob, ru, un = self._t
        whitelist.reset_current_unattended(un)
        whitelist.reset_current_human_role(ru)
        whitelist.reset_current_on_behalf(ob)
        whitelist.reset_current_principal(pr)
        whitelist.reset_current_chat(ch)
        return False


class Base(unittest.TestCase):
    """Le righe sono le stesse per i due verbi: è l'unico modo di confrontarli."""

    ROWS: list = []

    def setUp(self):
        self._env("on")
        for p in (patch.object(main, "agent_name", lambda: "clodia"),
                  patch.object(main, "current_clearance", lambda: self.clearance)):
            p.start()
            self.addCleanup(p.stop)
        self.clearance = "SEAL-3"

    def _env(self, modo):
        p = patch.dict("os.environ", {"CLODIA_SPAWN_COMPARTMENT": modo})
        p.start()
        self.addCleanup(p.stop)

    def _svc(self, rows):
        class _Svc:
            def list(self, tier=None, include_archived=False):
                return list(rows)

            def search(self, query, mode="lexical"):
                return list(rows)
        return _Svc()

    def topic_list(self, rows, verb="list"):
        with patch.object(main, "_topics", lambda: self._svc(rows)):
            a = {"query": "x"} if verb == "search" else {}
            out = main._dispatch_topic(f"topic.{verb}", a)
        return [r["name"] for r in out]

    def runtime_topics(self, rows, include_restricted=True):
        with patch.object(main.runtime, "topics",
                          lambda include_restricted=False: {
                              "count": len(rows), "topics": list(rows)}):
            out = main._dispatch_runtime(
                "runtime.topics", {"include_restricted": include_restricted}, "clodia")
        return [t["name"] for t in out["topics"]], out["count"]


class SessioneNonPresidiataTests(Base):
    """Punto 1. Un job non accede ai dati dei topic (decisione 2 ago 2026,
    clodia-platform#104): `_unattended_denial` lo applica ai verbi `topic.*`,
    ma `runtime.topics` non è un verbo `topic.*` e passava.

    Il job non ha un «qui» — `fire_job` apre la sessione con un chat_id suo, non
    `chan:…` — quindi il filtro di stanza, che fuori da una stanza non restringe
    per disegno, lo lasciava passare intero: nome, titolo e tldr di ogni topic
    del seed. Su un seed participant di 135 topic su 157 è la mappa della
    colonia consegnata a un turno che nessuno sta guardando.
    """

    ROWS = [_row("SEAL-1", "topic-a"), _row("SEAL-1", "topic-b")]

    def test_un_job_non_riceve_lelenco_dei_topic(self):
        with _Claims(chat="job:7", unattended=True):
            self.assertEqual(self.runtime_topics(self.ROWS), ([], 0))

    def test_nemmeno_quando_il_job_dichiara_una_stanza(self):
        """La stanza non è un'attenuante: ciò che manca è qualcuno davanti al
        turno, non il «qui». Se un giorno un job nascesse legato a una stanza,
        la regola non deve allentarsi da sola."""
        with _Claims(chat="chan:SEAL-1:topic-b:clodia", unattended=True):
            self.assertEqual(self.runtime_topics(self.ROWS), ([], 0))

    def test_nemmeno_con_un_token_di_persona_legato_a_una_stanza(self):
        """Il ramo del token legato a una stanza esce PRIMA del filtro di
        stanza: finché il taglio dei job stava dentro `_scope_rows_to_this_room`
        questo caso lo scavalcava e si riprendeva la sua riga. Il fail-closed
        sta in testa a `_visible_topic_rows` per questo — là sopra non c'è
        nessun ramo da cui uscire prima.
        """
        with _Claims(chat="chan:SEAL-1:topic-b:giovanni", principal="giovanni",
                     on_behalf=True, unattended=True):
            self.assertEqual(self.runtime_topics(self.ROWS), ([], 0))
            self.assertEqual(self.topic_list(self.ROWS), [])
            self.assertEqual(self.topic_list(self.ROWS, "search"), [])

    def test_il_blocco_non_dipende_dalla_maniglia_di_rollout(self):
        """`CLODIA_SPAWN_COMPARTMENT` governa il compartimento per-spawn (#382),
        non il blocco dei job (#104). Legarli significherebbe che una ritirata
        dall'uno riapre l'altro, senza che nessuno lo abbia deciso."""
        for modo in ("off", "report", "on"):
            with self.subTest(modo=modo):
                with patch.dict("os.environ", {"CLODIA_SPAWN_COMPARTMENT": modo}), \
                        _Claims(chat="job:7", unattended=True):
                    self.assertEqual(self.runtime_topics(self.ROWS), ([], 0))

    def test_una_sessione_presidiata_fuori_stanza_continua_a_vedere(self):
        """La contro-prova: il difetto è «non presidiata», non «fuori stanza».
        Una chat della webui è un umano che chiede quali topic esistono."""
        with _Claims(chat="dm:davide"):
            self.assertEqual(self.runtime_topics(self.ROWS)[0],
                             ["topic-a", "topic-b"])


class ClearanceTests(Base):
    """Punto 3. `include_restricted=True` non è una clearance: è la richiesta di
    includere anche i tier alti, che resta subordinata a fin dove arriva chi
    chiede. Senza il filtro, il verbo consegnava i metadati di un SEAL-3 a chi
    non può aprirlo — e i metadati portano il `tldr`, cioè la prima riga del
    summary.
    """

    ROWS = [_row("SEAL-1", "normale"), _row("SEAL-3", "riservato")]

    def test_include_restricted_non_scavalca_la_clearance(self):
        self.clearance = "SEAL-1"
        with _Claims(chat="dm:davide"):
            self.assertEqual(self.runtime_topics(self.ROWS)[0], ["normale"])

    def test_chi_ha_la_clearance_non_perde_niente(self):
        """La correzione stringe, non neutralizza: il verbo serve ancora."""
        self.clearance = "SEAL-4"
        with _Claims(chat="dm:davide"):
            self.assertEqual(self.runtime_topics(self.ROWS)[0],
                             ["normale", "riservato"])

    def test_il_conteggio_segue_le_righe(self):
        """Un `count` che non corrisponde racconta comunque quante stanze
        esistono: il numero è già informazione."""
        self.clearance = "SEAL-1"
        with _Claims(chat="dm:davide"):
            nomi, count = self.runtime_topics(self.ROWS)
            self.assertEqual(count, len(nomi))


class TokenDiPersonaTests(Base):
    """Punto 2. Il token di un client MCP umano porta `on_behalf` e il nome
    della persona; il CARRIER resta un agente (in esercizio `clodia`, che
    partecipa a tutto). Filtrare sul carrier significa rispondere a Giovanni con
    l'elenco dei topic di Clodia — non i contenuti, ma la mappa delle stanze, e
    una perdita che non somiglia a un errore perché una lista di titoli sembra
    sempre plausibile.

    L'intersezione non è un ampliamento al contrario: la membership umana non ha
    mai allargato l'elenco (`_filter_member_rows`), e ora non lo allarga né lo
    lascia intatto — lo restringe. Decisione dell'owner, 3 ott 2026: **nessuna
    esenzione per il ruolo `admin`**; chi deve vedere tutto ha un canale
    amministrativo, non un elenco più largo di quello che gli compete.
    """

    ROWS = [_row("SEAL-1", "suo", participants=("clodia", "giovanni")),
            _row("SEAL-1", "altrui", participants=("clodia", "davide"))]

    def test_una_persona_vede_le_sue_stanze_non_quelle_del_carrier(self):
        with _Claims(chat="dm:giovanni", principal="giovanni", on_behalf=True):
            self.assertEqual(self.runtime_topics(self.ROWS)[0], ["suo"])

    def test_lo_stesso_vale_per_topic_list_e_topic_search(self):
        """Il punto 2 dell'issue nomina entrambi i verbi: il ramo umano del
        dispatch copre il token LEGATO a una stanza, non quello senza."""
        with _Claims(chat="dm:giovanni", principal="giovanni", on_behalf=True):
            self.assertEqual(self.topic_list(self.ROWS), ["suo"])
            self.assertEqual(self.topic_list(self.ROWS, "search"), ["suo"])

    def test_un_admin_non_e_esentato(self):
        with _Claims(chat="dm:giovanni", principal="giovanni", on_behalf=True,
                     human_role="admin"):
            self.assertEqual(self.runtime_topics(self.ROWS)[0], ["suo"])

    def test_on_behalf_senza_principal_non_apre_niente(self):
        """Fail closed: un token che dice «per conto di una persona» senza dire
        quale non è un token di agente, è un token che non si può valutare."""
        with _Claims(chat="dm:ignoto", on_behalf=True):
            self.assertEqual(self.runtime_topics(self.ROWS), ([], 0))

    def test_la_persona_non_amplia_oltre_il_seed(self):
        """Intersezione, non sostituzione: un topic della persona ma non del
        seed resta fuori — altrimenti il token umano diventerebbe la via per
        far leggere a un agente una stanza che non è sua."""
        rows = [_row("SEAL-1", "solo-suo", participants=("giovanni",))]
        with _Claims(chat="dm:giovanni", principal="giovanni", on_behalf=True):
            self.assertEqual(self.runtime_topics(rows), ([], 0))

    def test_un_token_legato_a_una_stanza_resta_in_quella_stanza(self):
        """Il ramo che già esisteva per `topic.list`, ora anche di qua."""
        rows = [_row("SEAL-1", "suo", participants=("clodia", "giovanni")),
                _row("SEAL-1", "altro-suo", participants=("clodia", "giovanni"))]
        with _Claims(chat="chan:SEAL-1:suo:giovanni", principal="giovanni",
                     on_behalf=True):
            self.assertEqual(self.runtime_topics(rows)[0], ["suo"])
            self.assertEqual(self.topic_list(rows), ["suo"])


class UnaPortaSolaTests(Base):
    """L'invariante che tiene insieme i tre punti: nelle stesse condizioni i due
    verbi rispondono la stessa cosa. È ciò che impedisce che la prossima
    correzione su uno dei due lasci l'altro indietro — che è esattamente come
    sono nati questi tre punti.
    """

    ROWS = [_row("SEAL-1", "topic-a"), _row("SEAL-1", "topic-b"),
            _row("SEAL-3", "riservato"), _row("SEAL-1", "altrui",
                                              participants=("commercialista",))]

    CASI = {
        "spawn in una stanza": _Claims(chat="chan:SEAL-1:topic-b:clodia"),
        "sessione webui": _Claims(chat="dm:davide"),
        "persona fuori stanza": _Claims(chat="dm:davide", principal="davide",
                                        on_behalf=True),
        "persona in una stanza": _Claims(chat="chan:SEAL-1:topic-a:davide",
                                         principal="davide", on_behalf=True),
    }

    def test_runtime_topics_risponde_come_topic_list(self):
        for etichetta, claims in self.CASI.items():
            for clearance in ("SEAL-1", "SEAL-3"):
                with self.subTest(caso=etichetta, clearance=clearance):
                    self.clearance = clearance
                    with claims:
                        self.assertEqual(self.runtime_topics(self.ROWS)[0],
                                         self.topic_list(self.ROWS))

    def test_la_nota_di_release_arriva_dove_l_operatore_la_legge(self):
        """Punto 7. «`on` è meno stretto fuori da una stanza che dentro» era la
        frase da spiegare in una nota di release. La nota utile non è in un file
        che nessuno rilegge: è nella riga che il gateway dichiara all'avvio sul
        logger che `logs.tail(source="gateway")` sa leggere, accanto alla
        modalità effettiva e alla sua origine."""
        _, msg = main.spawn_compartment_declaration()
        self.assertIn("fuori da una stanza", msg)
        self.assertIn("non presidiate", msg)
        self.assertIn("token umani", msg)

    def test_il_filtro_vive_in_una_funzione_sola(self):
        """Tre copie della stessa regola sono tre posti in cui dimenticarne una
        — ed è la storia di questo file."""
        import inspect
        for f in (main._dispatch_topic, main._dispatch_runtime):
            self.assertIn("_visible_topic_rows", inspect.getsource(f))
