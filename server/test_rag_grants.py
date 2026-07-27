from __future__ import annotations

import unittest
from unittest.mock import patch

from . import main


class RagGrantEnforcementTests(unittest.TestCase):
    def _base_patches(self):
        return (
            patch.object(main, "agent_name", return_value="esperto-bandi"),
            patch.object(main, "_is_super", return_value=False),
            patch.object(main, "current_clearance", return_value="SEAL-2"),
            patch.object(main.instance_profile, "rag_check_collection"),
            patch.object(main.eu_corpus, "collection_tier", return_value="SEAL-1"),
        )

    def test_read_grant_authorizes_search(self) -> None:
        patches = self._base_patches()
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patch.object(main.runtime, "rag_grants", return_value={
                    "rag_read": {"eu-normativa"}, "rag_write": set(),
                }):
            main._rag_authorize("eu-normativa", write=False)

    def test_write_grant_implies_read_but_read_does_not_imply_write(self) -> None:
        patches = self._base_patches()
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patch.object(main.runtime, "rag_grants", return_value={
                    "rag_read": set(), "rag_write": {"eu-normativa"},
                }):
            main._rag_authorize("eu-normativa", write=False)
            main._rag_authorize("eu-normativa", write=True)

        patches = self._base_patches()
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patch.object(main.runtime, "rag_grants", return_value={
                    "rag_read": {"eu-normativa"}, "rag_write": set(),
                }):
            with self.assertRaises(PermissionError):
                main._rag_authorize("eu-normativa", write=True)

    def test_core_failure_denies_access(self) -> None:
        patches = self._base_patches()
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patch.object(main.runtime, "rag_grants",
                             side_effect=RuntimeError("core unavailable")):
            with self.assertRaises(PermissionError):
                main._rag_authorize("eu-normativa", write=False)

    def test_collections_are_filtered_with_live_core_grants(self) -> None:
        with patch.object(main, "agent_name", return_value="esperto-bandi"), \
                patch.object(main, "_is_super", return_value=False), \
                patch.object(main.instance_profile, "rag_enabled", return_value=True), \
                patch.object(main.instance_profile, "rag_mode", return_value="multi"), \
                patch.object(main.runtime, "rag_grants", return_value={
                    "rag_read": {"eu-normativa"}, "rag_write": set(),
                }), \
                patch.object(main.eu_corpus, "collections", return_value={
                    "collections": [
                        {"collection": "eu-normativa"},
                        {"collection": "segreta"},
                    ],
                }):
            result = main._dispatch_rag("rag.collections", {})
        self.assertEqual(
            [row["collection"] for row in result["collections"]],
            ["eu-normativa"],
        )


if __name__ == "__main__":
    unittest.main()
