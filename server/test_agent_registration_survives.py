"""Registrare un agente nella whitelist deve funzionare, e nessuno se ne accorgeva.

`gated_in_channel` è stato ritirato il 7 ago 2026. Il ritiro ha tolto il parametro
da `whitelist.upsert_agent` — e `test_gate_in_channel_retired` lo verifica, e
passa — ma ha lasciato `agents_api.register` che continuava a passarlo. Il kwarg
orfano sollevava `TypeError` **dentro** l'handler: ogni POST a
`/internal/agents/whitelist` rispondeva 500.

Conseguenza misurata su venere l'11 ago: un agente installato da un pack
(`content-creator`) non entrava mai nella config del gateway. E un agente non
registrato non ottiene «meno verbi»: `list_tools` chiama `agent_config()`, che
solleva `PermissionError`, e la lista torna **vuota**. In chat l'agente diceva di
non avere nessun tool `topic.*`; il seed li dichiarava tutti, e la scheda glieli
mostrava. Due ore di diagnosi hanno cercato il guasto nella sessione, nel
provider e nei permessi — mai nel punto in cui una registrazione era fallita
scrivendo `WARNING` e proseguendo.

Il test vecchio guardava **un capo** della catena (la firma). Questo guarda che i
due capi si parlino: ogni keyword passata a `upsert_agent`, in qualunque punto
del gateway, deve esistere nella sua firma. È il controllo che il ritiro a metà
non poteva superare.
"""
from __future__ import annotations

import ast
import asyncio
import inspect
import json
import pathlib
import unittest
from unittest.mock import patch

from . import agents_api
from . import whitelist as w


class _Req:
    """Richiesta minima: solo ciò che `register` legge."""

    def __init__(self, body: dict):
        self._body = body
        self.headers = {"authorization": "Bearer tok"}
        self.path_params = {}

    async def json(self):
        return self._body


class CallSitesMatchTheSignatureTests(unittest.TestCase):
    """Statico: nessun chiamante passa a `upsert_agent` un kwarg che non esiste.

    Statico e non dinamico perché il difetto stava in un ramo che i test non
    percorrevano: l'unico modo di vedere una riga mai eseguita è leggerla.
    """

    def test_no_orphan_keyword_reaches_upsert_agent(self):
        ammessi = set(inspect.signature(w.upsert_agent).parameters)
        base = pathlib.Path(__file__).parent
        orfani: list[str] = []
        for p in sorted(base.rglob("*.py")):
            if p.name.startswith("test_") or "__pycache__" in str(p):
                continue
            for n in ast.walk(ast.parse(p.read_text())):
                if not isinstance(n, ast.Call):
                    continue
                f = n.func
                nome = (f.attr if isinstance(f, ast.Attribute)
                        else f.id if isinstance(f, ast.Name) else "")
                if nome != "upsert_agent":
                    continue
                for kw in n.keywords:
                    if kw.arg and kw.arg not in ammessi:
                        orfani.append(f"{p.name}:{n.lineno} → {kw.arg}=")
        self.assertEqual(orfani, [],
                         "kwarg che la firma non accetta: la chiamata solleva "
                         "TypeError e la registrazione risponde 500")


class TheEndpointRegistersTests(unittest.TestCase):
    def _register(self, body: dict, cfg: dict | None = None):
        config = {"agents": cfg if cfg is not None else {}}
        with patch.object(agents_api, "_authorize", lambda r: ("clodia", None)), \
                patch.object(w, "CONFIG", config), \
                patch.object(w, "reload_config", lambda: None), \
                patch.object(w, "save_config", lambda: None):
            r = asyncio.run(agents_api.register(_Req(body)))
        return r, config

    def test_a_new_agent_lands_in_the_config(self):
        r, config = self._register({"agent": "content-creator",
                                    "allowed_tools": ["topic.open", "topic.files"]})
        self.assertEqual(r.status_code, 200)
        self.assertIn("content-creator", config["agents"])
        self.assertEqual(config["agents"]["content-creator"]["allowed_tools"],
                         ["topic.open", "topic.files"])

    def test_a_retired_field_in_the_body_does_not_break_the_registration(self):
        """Un chiamante vecchio manda ancora `gated_in_channel`: si ignora.

        Rifiutare la registrazione per un campo morto sarebbe lo stesso guasto
        con un codice di errore più educato — l'agente resterebbe comunque senza
        verbi.
        """
        r, config = self._register({"agent": "content-creator",
                                    "allowed_tools": ["topic.open"],
                                    "gated_in_channel": ["email.send"]})
        self.assertEqual(r.status_code, 200)
        self.assertIn("content-creator", config["agents"])
        self.assertNotIn("gated_in_channel", config["agents"]["content-creator"])

    def test_the_response_does_not_advertise_the_retired_field(self):
        r, _ = self._register({"agent": "x", "allowed_tools": []})
        self.assertNotIn("gated_in_channel", json.loads(r.body))


class AnUnregisteredAgentGetsNothingTests(unittest.TestCase):
    """Perché il 500 era grave: la config mancante non degrada, spegne.

    Questo fissa la ragione per cui una registrazione fallita non può restare un
    `WARNING`: il sintomo a valle non somiglia affatto alla causa.
    """

    def test_agent_config_refuses_an_unknown_agent(self):
        # Identità impostata come in esercizio (contextvar del token PKI), non
        # sostituendo `agent_name`: è proprio lì dentro che sta il rifiuto.
        tok = w.set_current_agent("content-creator")
        try:
            with patch.object(w, "CONFIG", {"agents": {"clodia": {}}}):
                with self.assertRaises(PermissionError):
                    w.agent_config()
        finally:
            w.reset_current_agent(tok)


if __name__ == "__main__":
    unittest.main()
