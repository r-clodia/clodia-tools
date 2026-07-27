from __future__ import annotations

import types
import unittest
from unittest.mock import patch

from . import gate, main


def _service(meta: dict):
    return types.SimpleNamespace(open=lambda _tier, _name: {"meta": meta})


class CrossTopicGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.meta = {
            "tier": "SEAL-2",
            "owner": "davide",
            "participants": ["davide", "clodia"],
        }

    def test_human_membership_no_longer_skips_gate_request(self) -> None:
        with patch.object(main, "_topics", return_value=_service(self.meta)), \
                patch.object(main, "current_principal", return_value="davide"):
            key = main._cross_topic_gate_key(
                "topic.read_document",
                {"tier": "SEAL-2", "name": "confidential"},
                "esperto-bandi",
            )
        self.assertEqual(key, "topic-access:SEAL-2/confidential")

    def test_agent_membership_needs_no_gate(self) -> None:
        self.meta["participants"].append("esperto-bandi")
        with patch.object(main, "_topics", return_value=_service(self.meta)):
            key = main._cross_topic_gate_key(
                "topic.read_document",
                {"tier": "SEAL-2", "name": "confidential"},
                "esperto-bandi",
            )
        self.assertIsNone(key)

    def test_dispatch_denies_human_only_membership_without_consent(self) -> None:
        with patch.object(main, "agent_name", return_value="esperto-bandi"), \
                patch.object(main, "current_principal", return_value="davide"), \
                patch.object(main, "current_clearance", return_value="SEAL-3"), \
                patch.object(gate, "active", return_value=False):
            with self.assertRaises(PermissionError):
                main._require_topic_member(
                    _service(self.meta), "SEAL-2", "confidential")

    def test_dispatch_accepts_explicit_cross_topic_consent(self) -> None:
        with patch.object(main, "agent_name", return_value="esperto-bandi"), \
                patch.object(main, "current_principal", return_value="davide"), \
                patch.object(main, "current_clearance", return_value="SEAL-3"), \
                patch.object(gate, "active", return_value=True):
            main._require_topic_member(
                _service(self.meta), "SEAL-2", "confidential")

    def test_topic_list_does_not_expand_to_human_memberships(self) -> None:
        rows = [
            {**self.meta, "name": "human-only"},
            {"name": "agent-topic", "owner": "davide",
             "participants": ["davide", "esperto-bandi"]},
        ]
        with patch.object(main, "current_principal", return_value="davide"):
            visible = main._filter_member_rows(rows, "esperto-bandi")
        self.assertEqual([row["name"] for row in visible], ["agent-topic"])


if __name__ == "__main__":
    unittest.main()
