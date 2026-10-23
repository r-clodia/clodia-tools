from __future__ import annotations

"""clodia-platform#500 — `rag.search` risponde `DENIED: impossibile verificare
i grant RAG` a ogni guasto transitorio della lettura live dei grant dal core.

Il controllo è fail-closed SOLO per decisione, non per guasto: un timeout di
mint, un loop del gateway bloccato per qualche secondo (l'episodio del
3/10/2026) equivale a un diniego, e il messaggio non dice se il grant è
assente o se la verifica non è stata fatta. Qui si prova che:

1. un guasto transitorio, seguito dal core che torna a rispondere, NON nega;
2. un guasto ancora vivo non nega se SUBITO prima il core rispondeva: lo
   snapshot di ultimo-buono SOLO di questo agente supporta la lettura fallita,
   per una finestra di due minuti al massimo, e MAI al posto della live;
3. il messaggio di diniego infrastrutturale è DIVERSO da quello di grant
   assente (il «impossibile risolvere» di `runtime.rag_grants` passa intatto),
   e il fail-closed resta.
"""

import unittest
from unittest.mock import patch

from . import main


class RagGrantReadResilienceTests(unittest.TestCase):
    """Retry con backoff + snapshot breve su `_rag_grants` (clodia-platform#500)."""

    GRANTS = {"rag_read": {"eu-normativa"}, "rag_write": set()}

    def setUp(self) -> None:
        # stato di modulo: nessuno snapshot deve attraversare i test (pre-fix
        # l'attributo non esiste: un dizionario vuoto è comunque lo stato giusto)
        main._rag_grants_snapshots = {}

    def _base_patches(self, rag_grants):
        return (
            patch.object(main, "agent_name", return_value="esperto-bandi"),
            patch.object(main, "_is_super", return_value=False),
            patch.object(main, "current_clearance", return_value="SEAL-2"),
            patch.object(main.instance_profile, "rag_check_collection"),
            patch.object(main.eu_corpus, "collection_tier", return_value="SEAL-1"),
            # retry istantanei nel test: il backoff reale non interessa qui
            # (create=True: pre-fix l'attributo non esiste e va creato mock)
            patch.object(main, "_RAG_GRANT_RETRY_PAUSES", (0.0,), create=True),
            patch.object(main.runtime, "rag_grants", rag_grants),
        )

    def test_transient_core_glitch_then_success_is_not_denied(self) -> None:
        """Il 3/10/2026 (~11:09, ~11:16): core momentaneamente irraggiungibile,
        poi di nuovo su. Prima del fix la prima lettura fallita negava."""
        calls = []

        def flaky(agent):
            calls.append(agent)
            if len(calls) == 1:
                raise RuntimeError("mint PKI in timeout (transitorio)")
            return dict(self.GRANTS)

        p = self._base_patches(flaky)
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6]:
            main._rag_authorize("eu-normativa", write=False)
        self.assertEqual(len(calls), 2)

    def test_persistent_failure_but_fresh_snapshot_still_allows(self) -> None:
        """Rilettura live ancora fallita, ma due minuti prima il CORE rispondeva:
        lo snapshot DI QUESTO agente sostiene la richiesta, non la nega."""
        calls = []

        def then_dead(agent):
            calls.append(agent)
            if len(calls) == 1:
                return dict(self.GRANTS)
            raise RuntimeError("core giù (loop bloccato)")

        p = self._base_patches(then_dead)
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6]:
            main._rag_authorize("eu-normativa", write=False)   # warm-up live
            main._rag_authorize("eu-normativa", write=False)   # core morto → snapshot
        # warm-up + (retry… e poi snapshot): la live non è MAI saltata
        self.assertEqual(len(calls), 3)

    def test_no_snapshot_fails_closed_with_an_infra_message(self) -> None:
        """Niente snapshot, core giù: fallisce CHIUSO — e il messaggio dice che
        è un GUASTO INFRASTRUTTURALE, non un grant assente."""
        p = self._base_patches(
            RuntimeError("core unavailable"))
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6]:
            with self.assertRaises(PermissionError) as ctx:
                main._rag_authorize("eu-normativa", write=False)
        msg = str(ctx.exception)
        self.assertIn("guasto infrastrutturale", msg)
        self.assertIn("impossibile verificare i grant RAG", msg)

    def test_snapshot_too_stale_fails_closed(self) -> None:
        """Uno snapshot antico non maschera un core giù da più di due minuti:
        la revoca di grant non resta nascosta a tempo indeterminato."""
        calls = []

        def warm_then_dead(agent):
            calls.append(agent)
            if len(calls) == 1:
                return dict(self.GRANTS)
            raise RuntimeError("core giù da troppo")

        p = self._base_patches(warm_then_dead)
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6]:
            main._rag_authorize("eu-normativa", write=False)   # warm-up
            # invecchia lo snapshot oltre il TTL
            import time as _time
            with patch.object(main, "_time_monotonic",
                              side_effect=lambda: _time.monotonic() + 3600.0,
                              create=True):
                with self.assertRaises(PermissionError):
                    main._rag_authorize("eu-normativa", write=False)

    def test_live_success_never_serves_the_snapshot(self) -> None:
        """La lettura LIVE resta la decisione: una revoca letta live dai
        grant chiude l'accesso ANCHE nella stessa finestra in cui uno
        snapshot esiste — la cache non prevale mai su una lettura riuscita."""
        calls = []

        def revoked(agent):
            calls.append(agent)
            if len(calls) == 1:
                return {"rag_read": {"eu-normativa"}, "rag_write": set()}
            return {"rag_read": set(), "rag_write": set()}   # revoca immediata

        p = self._base_patches(revoked)
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6]:
            main._rag_authorize("eu-normativa", write=False)   # subito: concesso
            with self.assertRaises(PermissionError):
                main._rag_authorize("eu-normativa", write=False)   # poi: revocata

    def test_unknown_agent_is_never_retried_and_message_distinct(self) -> None:
        """`PermissionError` di runtime (agent non esistente) è una DECISIONE:
        passa intatta, senza retry, con un messaggio diverso da quello dei
        guasti (clodia-platform#500 «il messaggio non distingue»)."""
        calls = []

        def unknown(agent):
            calls.append(agent)
            raise PermissionError(
                "impossibile risolvere i grant RAG dell'agent 'fantasma-1'")

        p = self._base_patches(unknown)
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6]:
            with self.assertRaises(PermissionError) as ctx:
                main._rag_authorize("eu-normativa", write=False)
        self.assertEqual(len(calls), 1)          # niente tentativi in cascata
        self.assertNotIn("guasto infrastrutturale", str(ctx.exception))

    def test_snapshot_never_serves_a_different_agent(self) -> None:
        """Lo snapshot è per agent: nessuna entry di un altro agente, nessun mix."""
        calls = []

        def vacillante(agent):
            calls.append(agent)
            if agent == "esperto-bandi":
                raise RuntimeError("core giù")
            return dict(self.GRANTS)

        p = self._base_patches(vacillante)
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6]:
            with self.assertRaises(PermissionError):
                main._rag_authorize("eu-normativa", write=False)


if __name__ == "__main__":
    unittest.main()
