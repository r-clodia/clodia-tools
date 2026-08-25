"""La superficie hook non esiste più, e non torna per distrazione.

clodia-platform#223 (step 3 di #222). Lo step 1 aveva smesso di *creare* hook —
sull'istanza viva ne restavano 12, `uses: 0` su tutti — e questo step toglie il
resto: il verbo `topic.invoke_hook`, i due proxy in `tools.runtime` e il flag
`meta.hook_enabled`, che dopo l'uscita del gate da `invoke_local` era diventato
un interruttore che non interrompeva più niente.

Il file prima verificava «l'hook non nasce da solo». Ora che l'hook non nasce
affatto, quella domanda non ha più un soggetto: la domanda che resta è se la
superficie **rimane** rimossa. Sono guardie di non-ritorno, come
`check-no-telegram-panel` lato web — la cosa che si rompe se qualcuno
reintroduce metà del meccanismo senza accorgersene.
"""
from __future__ import annotations

import asyncio
import tempfile
import unittest
from unittest.mock import patch

from . import main as M
from . import topics_api, whitelist
from .tools import runtime
from .topics.local_fs import LocalFsStorage
from .topics.service import TopicService


def _svc() -> TopicService:
    return TopicService(LocalFsStorage(tempfile.mkdtemp(prefix="clodia-hook-test-")))


class TheMetaFieldIsGoneTests(unittest.TestCase):
    def test_a_new_topic_has_no_hook_field_at_all(self):
        self.assertNotIn("hook_enabled", _svc().new(None, "stanza-nuova"))

    def test_an_explicit_request_does_not_resurrect_it(self):
        """Il caso che un `del meta["hook_enabled"]` non coprirebbe.

        Un client vecchio (o un pack non aggiornato) continua a spedire
        `hook_enabled: True`. Se il servizio lo lasciasse passare nel meta, il
        campo tornerebbe a esistere sui topic nuovi — con l'aggravante di
        sembrare una scelta di chi ha creato la stanza, mentre non abilita più
        nulla da nessuna parte.
        """
        meta = _svc().new(None, "stanza-con-hook", {"hook_enabled": True})
        self.assertNotIn("hook_enabled", meta)


class TheVerbIsGoneTests(unittest.TestCase):
    def test_the_gateway_declares_no_hook_verb(self):
        hookish = [n for n in M.all_native_verb_names() if "hook" in n]
        self.assertEqual(hookish, [])

    def test_the_dispatch_refuses_the_old_verb(self):
        """Il catalogo e il dispatch sono due elenchi: togliere dal primo e
        lasciare il ramo nel secondo lascerebbe un verbo invocabile e non
        dichiarato — il peggiore dei due stati, perché non compare da nessuna
        parte e funziona lo stesso."""
        tok = whitelist.set_current_agent("sysadmin")
        try:
            with patch.object(M, "_topics", _svc):
                with self.assertRaises(Exception):
                    M._dispatch_topic(
                        "topic.invoke_hook",
                        {"tier": "SEAL-1", "name": "stanza", "payload": "ciao"})
        finally:
            whitelist.reset_current_agent(tok)

    def test_runtime_has_no_hook_proxies(self):
        for fn in ("ensure_topic_hook", "invoke_topic_hook"):
            with self.subTest(fn=fn):
                self.assertFalse(hasattr(runtime, fn))


class _Request:
    """Il minimo che `create_topic` legge da una richiesta."""

    def __init__(self, body: dict):
        self._body = body

    async def json(self):
        return self._body


class TheTopicsApiTests(unittest.TestCase):
    def _post(self, body: dict):
        svc = _svc()
        with patch.object(topics_api, "_authorize", lambda _r: ("davide", None)), \
             patch.object(topics_api, "_service", lambda: svc), \
             patch.object(topics_api.instance_profile,
                          "topic_creation_check", lambda _n: None):
            return asyncio.run(topics_api.create_topic(_Request(body)))

    def test_the_api_path_creates_a_topic_without_a_hook(self):
        res = self._post({"name": "stanza-api"})
        self.assertEqual(res.status_code, 200)

    def test_the_api_path_ignores_an_explicit_yes(self):
        """`hook_enabled: True` dal body non deve più provisionare niente né
        finire nel meta: è una chiave sconosciuta come un'altra."""
        res = self._post({"name": "stanza-api-hook",
                          "hook_enabled": True, "ensure_hook": True})
        self.assertEqual(res.status_code, 200)
        import json
        meta = json.loads(bytes(res.body).decode())["meta"]
        self.assertNotIn("hook_enabled", meta)


if __name__ == "__main__":
    unittest.main()
