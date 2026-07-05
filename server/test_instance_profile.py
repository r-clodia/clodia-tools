"""Test del lettore gateway del profilo d'istanza (Modular Distro F1b)."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from . import instance_profile as ip


class InstanceProfileGatewayTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self._old_env = os.environ.get("CLODIA_DATA")
        os.environ["CLODIA_DATA"] = self.tmp.name
        ip._CACHE = None

    def tearDown(self) -> None:
        if self._old_env is None:
            os.environ.pop("CLODIA_DATA", None)
        else:
            os.environ["CLODIA_DATA"] = self._old_env
        ip._CACHE = None
        self.tmp.cleanup()

    def _write(self, text: str) -> None:
        (Path(self.tmp.name) / ip.PROFILE_FILENAME).write_text(text, encoding="utf-8")
        ip.load(force=True)

    def test_absent_is_full_everything_allowed(self) -> None:
        ip.load(force=True)
        self.assertEqual(ip.rag_mode(), "full")
        ip.rag_check_collection("qualunque")          # non solleva
        ip.integrations_check("qualunque")            # non solleva
        ip.topic_creation_check("nuovo-topic")        # non solleva

    def test_rag_off_blocks_all(self) -> None:
        self._write("features: {rag: off}\n")
        self.assertFalse(ip.rag_enabled())
        with self.assertRaises(PermissionError):
            ip.rag_check_collection("eu-normativa")

    def test_rag_single_allows_only_profile_collection(self) -> None:
        self._write("features: {rag: single}\nrag: {collection: acme-kb}\n")
        ip.rag_check_collection("acme-kb")            # ok
        with self.assertRaises(PermissionError):
            ip.rag_check_collection("eu-normativa")

    def test_integrations_off_and_fixed(self) -> None:
        self._write("features: {integrations: off}\n")
        with self.assertRaises(PermissionError):
            ip.integrations_check("normattiva")
        self._write("features: {integrations: fixed}\nintegrations: {allowed: [normattiva]}\n")
        ip.integrations_check("normattiva")           # in whitelist
        with self.assertRaises(PermissionError):
            ip.integrations_check("github")
        # allow_manual_mcp: paste manuale permesso anche fuori whitelist
        self._write("features: {integrations: fixed}\nintegrations: {allowed: [], allow_manual_mcp: true}\n")
        ip.integrations_check("qualunque")

    def test_topics_single_allows_workspace_and_dms(self) -> None:
        self._write("features: {topics: single}\n")
        ip.topic_creation_check("workspace")          # workspace unico
        ip.topic_creation_check("dm-davide--clodia")  # DM sempre permessi
        with self.assertRaises(PermissionError):
            ip.topic_creation_check("altro-progetto")

    def test_connectors_gating(self) -> None:
        ip.load(force=True)                       # profilo assente
        self.assertIsNone(ip.connectors_allowed())
        ip.connector_check("gmail")               # tutti permessi
        self._write("integrations: {connectors: [mailboxes]}\n")
        self.assertEqual(ip.connectors_allowed(), ["mailboxes"])
        ip.connector_check("mailboxes")
        with self.assertRaises(PermissionError):
            ip.connector_check("gmail")

    def test_unknown_feature_key_ignored_not_fallback(self) -> None:
        # Chiave sconosciuta (schema più nuovo lato agent-server): warning e
        # ignora — il gating delle chiavi note DEVE restare attivo.
        self._write("features: {rag: off, chiave_futura: true}\n")
        self.assertEqual(ip.rag_mode(), "off")

    def test_topic_default_participants(self) -> None:
        ip.load(force=True)
        self.assertEqual(ip.topic_default_participants(), ["clodia"])
        self._write("topics_defaults: {participants: [clodia, commercialista]}\n")
        self.assertEqual(ip.topic_default_participants(), ["clodia", "commercialista"])

    def test_invalid_falls_back_full(self) -> None:
        self._write("features: {rag: banana}\n")
        self.assertEqual(ip.rag_mode(), "full")


if __name__ == "__main__":
    unittest.main()
