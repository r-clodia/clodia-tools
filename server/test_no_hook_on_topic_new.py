"""Creare un topic non conia un segreto (clodia-platform#222, step 1).

Sull'istanza viva `hooks.json` conteneva DIECI righe, non le otto censite
all'apertura della issue: `risoluzione-issue-clodia` (18 ago) e
`bando-camcom-2026` (19 ago) sono nate DOPO, una per topic, con `uses: 0` su
tutte. Non e' igiene arretrata: e' un registro che si riempie da solo, e ogni
riga e' materiale segreto a riposo per una porta che #300 ha gia' chiuso.

Il punto misurato qui e' il piu' a monte dei quattro: `topic.new`. Il flag
`meta.hook_enabled` resta — e' l'interruttore dell'invocazione locale, che non
usa segreti — ma non deve piu' tirarsi dietro la creazione della riga.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import main


class _Svc:
    """Servizio topic finto: registra la meta con cui e' stato creato."""

    def __init__(self) -> None:
        self.created: list[tuple] = []

    def new(self, tier, name, meta):
        self.created.append((tier, name, meta))
        return {"tier": tier or "SEAL-0", "name": name, **meta}


class TopicNewMintsNoSecretTests(unittest.TestCase):
    def _new(self, args: dict):
        svc = _Svc()
        with patch("server.main._topics", return_value=svc), \
             patch("server.main.instance_profile.topic_creation_check"), \
             patch("server.main.agent_name", return_value="clodia"), \
             patch("server.main.runtime") as rt:
            meta = main._dispatch_topic("topic.new", args)
        return svc, rt, meta

    def test_topic_new_does_not_ensure_a_hook(self):
        svc, rt, _ = self._new({"tier": "SEAL-1", "name": "pratica-x"})
        rt.ensure_topic_hook.assert_not_called()
        self.assertEqual(len(svc.created), 1)

    def test_hook_enabled_true_still_mints_nothing(self):
        """Il default e' `true` e resta `true`: e' il flag dell'invocazione
        locale, non un ordine di coniare un segreto. Il caso esplicito e' quello
        che regrediva prima, quindi va misurato a parte dal default."""
        _, rt, meta = self._new({"tier": "SEAL-1", "name": "pratica-y",
                                 "hook_enabled": True})
        rt.ensure_topic_hook.assert_not_called()
        self.assertIs(meta["hook_enabled"], True)

    def test_the_flag_survives_in_meta(self):
        """`hook_enabled: false` deve restare leggibile sul topic: e' cosi' che
        una stanza spegne `topic.invoke_hook` (letto in hooks/api.py)."""
        _, _, meta = self._new({"tier": "SEAL-1", "name": "pratica-z",
                                "hook_enabled": False})
        self.assertIs(meta["hook_enabled"], False)

    def test_the_gateway_no_longer_exposes_the_ensure_proxy(self):
        """Il proxy verso `/clodia/hooks/internal/ensure` non ha piu' chiamanti.
        Lasciarlo vivo e' l'invito a richiamarlo: la rotta a valle sopravvive
        una release come 200 inerte, il proxy no."""
        from .tools import runtime
        self.assertFalse(hasattr(runtime, "ensure_topic_hook"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
