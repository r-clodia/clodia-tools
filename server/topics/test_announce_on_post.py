"""Chi posta annuncia, chiunque sia (clodia-platform#219).

`TopicService.post_message` è il punto in cui un messaggio del topic NASCE: ci
passano tutti gli scrittori — la webui via `/internal/topics`, il verbo MCP del
gateway (proxy, messaggero, client MCP di una persona), lo scheduler. Fino a
oggi l'evento `channel_message` sul bus SSE lo pubblicava solo una delle due
porte, dentro `clodia-logic`: un messaggio scritto **attraverso il gateway**
veniva persistito e non annunciato a nessuno.

Qui si copre esattamente quel caso, più la proprietà che lo rende innocuo
quando l'agent-server non risponde: un messaggio nella stanza non dipende dalla
raggiungibilità di un servizio esterno.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from .local_fs import LocalFsStorage
from .service import TopicService


class AnnounceOnPostTests(unittest.TestCase):
    def setUp(self) -> None:
        self.svc = TopicService(LocalFsStorage(tempfile.mkdtemp()))
        with patch("server.instance_profile.topic_default_participants",
                   return_value=[]):
            self.svc.new("P1", "ch", {"title": "Canale", "owner": "owner"})

    def test_a_message_written_through_the_gateway_is_announced(self) -> None:
        with patch("server.tools.runtime.announce_message") as annuncia:
            msg = self.svc.post_message("P1", "ch", "messaggero",
                                        "@clodia guarda qui", kind="ai")

        annuncia.assert_called_once()
        tier, name, annunciato = annuncia.call_args.args
        # tier NORMALIZZATO: la rotta dell'agent-server lo riceve nel path, e un
        # `P1` legacy lì sarebbe un secondo nome per lo stesso canale
        self.assertEqual((tier, name), ("SEAL-1", "ch"))
        # si annuncia il messaggio PERSISTITO, non il testo in ingresso: `id`,
        # `ts` e `mentions` nascono qui e sono ciò che i consumatori del bus
        # leggono
        self.assertEqual(annunciato["id"], msg["id"])
        self.assertEqual(annunciato["ts"], msg["ts"])
        self.assertEqual(annunciato["author"], "messaggero")
        self.assertEqual(annunciato["kind"], "ai")
        self.assertEqual(annunciato["mentions"], msg["mentions"])

    def test_an_unreachable_announcer_does_not_lose_the_message(self) -> None:
        with patch("server.tools.runtime.announce_message",
                   side_effect=RuntimeError("agent-server giù")):
            msg = self.svc.post_message("P1", "ch", "owner", "ciao", kind="human")

        self.assertEqual([m["id"] for m in self.svc.list_messages("P1", "ch")],
                         [msg["id"]])


class AnnounceVerbTests(unittest.TestCase):
    """La chiamata verso l'agent-server: rotta, payload e riconoscimento."""

    def _chiama(self, *, secret: str | None) -> MagicMock:
        from ..tools import runtime

        client = MagicMock()
        risposta = MagicMock()
        risposta.status_code = 200
        risposta.json.return_value = {"announced": True}
        client.post.return_value = risposta
        contesto = MagicMock()
        contesto.__enter__.return_value = client

        env = {k: v for k, v in os.environ.items()
               if k != "CLODIA_ORCHESTRATOR_SECRET"}
        if secret:
            env["CLODIA_ORCHESTRATOR_SECRET"] = secret
        with patch.dict(os.environ, env, clear=True), \
                patch.object(runtime.httpx, "Client", return_value=contesto):
            runtime.announce_message("SEAL-1", "software-house", {
                "id": "20260907-120000-abc", "author": "messaggero",
                "kind": "ai", "ts": "2026-09-07T12:00:00.000100+00:00",
                "text": "@clodia guarda qui", "mentions": ["clodia"],
                # campo che NON deve viaggiare: il payload è esplicito, così
                # aggiungere una colonna allo store non la pubblica sul bus
                "attachments": ["report.md"],
            })
        return client

    def test_the_announcement_carries_the_shared_secret(self) -> None:
        from ..tools import runtime

        client = self._chiama(secret="s3cr3t")
        url, = client.post.call_args.args
        self.assertEqual(
            url,
            f"{runtime.AGENT_SERVER_URL}"
            "/clodia/channels/SEAL-1/software-house/announce/internal")
        self.assertEqual(
            client.post.call_args.kwargs["headers"].get("X-Orchestrator-Secret"),
            "s3cr3t")

    def test_the_payload_is_explicit_and_carries_no_extra_fields(self) -> None:
        client = self._chiama(secret=None)
        inviato = client.post.call_args.kwargs["json"]

        self.assertEqual(set(inviato), {"id", "author", "kind", "ts", "text",
                                        "mentions"})
        self.assertEqual(inviato["id"], "20260907-120000-abc")
        self.assertEqual(inviato["text"], "@clodia guarda qui")
        # nessun secret configurato → nessun header inventato
        self.assertNotIn("X-Orchestrator-Secret",
                         client.post.call_args.kwargs["headers"])


if __name__ == "__main__":
    unittest.main()
