"""La risposta di un backend MCP montato non entra nel contesto senza un tetto.

I tre verbi di lettura del gateway (`topic.read_file`, `profile.read_file`,
`memory.read`) e `web.fetch` consegnano una finestra di 64 KB e dicono come
chiedere il resto. `call_proxied` no: qualunque cosa un backend MCP di terzi
metta nel `content` finiva nel turno per intero. Un `github.get_file_contents`
su un lockfile, un `search_code` su un repository grande, un backend che sbaglia
paginazione: sono megabyte che nessuno ha chiesto, e che non si pagano una volta
— restano nel contesto e vengono riletti a ogni azione successiva del turno.

Qui il taglio è **irreversibile**: `call_proxied` non ha offset e non può
paginare, perché la seconda metà della risposta di un backend non è
richiedibile (non c'è cursore, e la connessione è per-chiamata). Da cui le due
proprietà che i campi da soli non darebbero:

  1. la nota deve dire che il resto NON arriva richiamando, e indicare la
     strada che funziona (`github.clone` e i file nella scratch);
  2. deve avvertire che un JSON tagliato NON è JSON: senza l'avviso, chi riceve
     un oggetto mozzato lo passa a un parser e legge l'errore come un guasto del
     backend, non come un taglio del gateway.

E il taglio cade su un confine UTF-8: una finestra indecodificabile
trasformerebbe una risposta di testo valida in un errore che dipende da dove
capita l'accento.
"""
from __future__ import annotations

import asyncio
import contextlib
import unittest
from unittest.mock import patch

from . import proxy as P
from .tools import web_fetch


class _Testo:
    type = "text"

    def __init__(self, text: str) -> None:
        self.text = text


class _Risultato:
    def __init__(self, content: list) -> None:
        self.content = content


class _SessioneFinta:
    """Un backend che risponde quello che gli si dice, senza processi né rete."""

    def __init__(self, testo: str | None) -> None:
        #: `None` = il backend risponde senza nessun blocco testuale.
        self._contenuto = [] if testo is None else [_Testo(testo)]
        self.chiamate: list[tuple[str, dict]] = []

    async def call_tool(self, name: str, arguments: dict) -> _Risultato:
        self.chiamate.append((name, arguments))
        return _Risultato(self._contenuto)


def _chiama(testo: str | None, verbo: str = "github.get_file_contents") -> str:
    """Percorre `call_proxied` per davvero, con un backend finto al posto del
    processo MCP: il tetto va provato sulla strada che gli agenti usano, non su
    un helper chiamato a parte."""
    sessione = _SessioneFinta(testo)

    @contextlib.asynccontextmanager
    async def _sessione(_b):
        yield sessione

    with patch.object(P, "_backends", lambda: {"github": {"name": "github"}}), \
            patch.object(P, "_session", _sessione):
        return asyncio.run(P.call_proxied(verbo, {}))


class IlRitornoProxatoHaUnTetto(unittest.TestCase):
    #: 300 KB di testo con dentro dei capi a riga, come una risposta vera.
    GROSSO = "\n".join(f"riga {i}: " + "x" * 60 for i in range(4600))

    def test_una_risposta_enorme_non_entra_intera_nel_contesto(self) -> None:
        """IL CASO: senza tetto, il turno si porta dietro tutto il file."""
        self.assertGreater(len(self.GROSSO.encode("utf-8")), 250 * 1024,
                           "il fixture non è più grande del tetto: non prova niente")
        out = _chiama(self.GROSSO)
        # il tetto vale sui BYTE consegnati; la nota è il sovrapprezzo di dire
        # che il taglio è avvenuto, e sta fuori dalla finestra.
        self.assertLess(len(out.encode("utf-8")),
                        P.MAX_RESULT_BYTES + 2000)
        self.assertTrue(out.startswith(self.GROSSO[:1000]),
                        "il taglio deve tenere il PRINCIPIO della risposta")

    def test_la_nota_dice_che_il_taglio_non_si_recupera_richiamando(self) -> None:
        out = _chiama(self.GROSSO)
        coda = out[-800:]
        self.assertIn("github.clone", coda,
                      "la nota deve indicare la strada che consegna il contenuto "
                      "intero, o l'unica mossa che resta è richiamare a vuoto")
        self.assertIn("JSON", coda,
                      "un JSON tagliato non è JSON: senza avviso finisce in un "
                      "parser e l'errore sembra del backend")

    def test_la_nota_indica_di_stringere_la_query_sui_verbi_di_ricerca(self) -> None:
        """Per un verbo di ricerca/elenco non c'è uno «scarica tutto» come
        `github.clone`: l'unica via d'uscita è restringere la query."""
        out = _chiama(self.GROSSO)
        coda = out[-800:]
        self.assertIn("query", coda)

    def test_la_nota_dice_quanto_e_stato_consegnato_e_quanto_c_era(self) -> None:
        out = _chiama(self.GROSSO)
        self.assertIn(str(len(self.GROSSO.encode("utf-8"))), out[-800:],
                      "senza la dimensione originale non si sa se manca una riga "
                      "o il 90% della risposta")

    def test_una_risposta_dentro_il_tetto_passa_intatta(self) -> None:
        """Il rischio opposto: una nota su ogni risposta corta è rumore, e un
        `\\n\\n[...]` appeso a un JSON valido lo romperebbe."""
        piccolo = "risposta breve del backend"
        self.assertEqual(_chiama(piccolo), piccolo)

    def test_il_taglio_cade_su_un_confine_utf8(self) -> None:
        """Testo accentato: il taglio non deve produrre caratteri di sostituzione."""
        accentato = ("però àèìòù — verità di città, società e libertà. " * 4000)
        self.assertGreater(len(accentato.encode("utf-8")), P.MAX_RESULT_BYTES)
        out = _chiama(accentato)
        self.assertNotIn("�", out)

    def test_un_backend_senza_contenuto_testuale_non_cambia_comportamento(self) -> None:
        """Il tetto non deve inghiottire il messaggio che spiega il vuoto."""
        self.assertEqual(_chiama(None), "(nessun contenuto testuale)")


class IlNumeroEQuelloDegliAltriVerbi(unittest.TestCase):
    def test_il_tetto_e_lo_stesso_di_web_fetch(self) -> None:
        """Una decisione sola per tutto ciò che entra nel contesto da fuori: un
        secondo numero qui andrebbe giustificato a parte e diverrebbe l'unico a
        non essere aggiornato quando il primo cambia."""
        self.assertEqual(P.MAX_RESULT_BYTES, web_fetch.DEFAULT_RESPONSE_BYTES)


if __name__ == "__main__":
    unittest.main()
