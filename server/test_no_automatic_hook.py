"""Un topic nuovo non nasce con una porta pubblica e un segreto da custodire.

clodia-platform#222 step 1 (clodia-tools#211): sull'istanza viva la creazione
automatica ha prodotto **8 hook, 0 invocazioni** — uno per topic creato fra il
13 e il 15 agosto, nessuno mai chiamato. Ogni riga è una porta e un segreto,
creati per nessuno.

Il punto misurato qui non è il valore del flag in sé: è che sui due percorsi di
creazione (verbo MCP `topic.new` e API `POST /topics`) **nessuna** `ensure`
parte da sola. L'hook resta possibile, ma solo se qualcuno lo chiede.

Gli hook già esistenti non li tocca nessuno: la loro cancellazione è lo step 4
(clodia-platform#223), e tenere gli step separati è ciò che li rende revertibili.
"""
from __future__ import annotations

import asyncio
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from . import main as M
from . import topics_api, whitelist
from .topics.local_fs import LocalFsStorage
from .topics.service import TopicService


def _svc() -> TopicService:
    return TopicService(LocalFsStorage(tempfile.mkdtemp(prefix="clodia-hook-test-")))


class TheMetaDefaultTests(unittest.TestCase):
    def test_a_new_topic_is_born_without_a_hook(self):
        meta = _svc().new(None, "stanza-nuova")
        self.assertIs(meta["hook_enabled"], False)

    def test_an_explicit_request_is_still_recorded(self):
        """Il default cambia, la richiesta esplicita no: chi chiede l'hook lo
        ottiene, e il meta continua a dire il vero su quel topic."""
        meta = _svc().new(None, "stanza-con-hook", {"hook_enabled": True})
        self.assertIs(meta["hook_enabled"], True)


class TheMcpVerbTests(unittest.TestCase):
    def _new(self, args: dict):
        rt = MagicMock()
        tok = whitelist.set_current_agent("clodia")
        try:
            with patch.object(M, "_topics", _svc), \
                 patch.object(M, "runtime", rt), \
                 patch.object(M.instance_profile,
                              "topic_creation_check", lambda _n: None):
                meta = M._dispatch_topic("topic.new", args)
        finally:
            whitelist.reset_current_agent(tok)
        return meta, rt

    def test_topic_new_provisions_nothing(self):
        meta, rt = self._new({"name": "stanza-nuova"})
        rt.ensure_topic_hook.assert_not_called()
        self.assertIs(meta["hook_enabled"], False)

    def test_topic_new_still_honours_an_explicit_yes(self):
        meta, rt = self._new({"name": "stanza-con-hook", "hook_enabled": True})
        rt.ensure_topic_hook.assert_called_once()
        self.assertIs(meta["hook_enabled"], True)


class _Request:
    """Il minimo che `create_topic` legge da una richiesta."""

    def __init__(self, body: dict):
        self._body = body

    async def json(self):
        return self._body


class TheTopicsApiTests(unittest.TestCase):
    def _post(self, body: dict):
        rt = MagicMock()
        svc = _svc()
        with patch.object(topics_api, "_authorize", lambda _r: ("davide", None)), \
             patch.object(topics_api, "_service", lambda: svc), \
             patch.object(topics_api.instance_profile,
                          "topic_creation_check", lambda _n: None), \
             patch("server.tools.runtime.ensure_topic_hook", rt.ensure_topic_hook):
            res = asyncio.run(topics_api.create_topic(_Request(body)))
        return res, rt

    def test_the_api_path_provisions_nothing(self):
        res, rt = self._post({"name": "stanza-api"})
        self.assertEqual(res.status_code, 200)
        rt.ensure_topic_hook.assert_not_called()

    def test_the_api_path_still_honours_an_explicit_yes(self):
        _, rt = self._post({"name": "stanza-api-hook", "hook_enabled": True})
        rt.ensure_topic_hook.assert_called_once()


if __name__ == "__main__":
    unittest.main()
