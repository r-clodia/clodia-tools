"""Collegare GitHub non concede un namespace intero.

`github_connect` aggiungeva `github.*` agli `allowed_tools` di clodia. Una
wildcard su un backend esterno concede anche ciò che quel backend aggiungerà
domani: il 17 ago 2026 `delete_repository`, `force_push` e `delete_branch`
risultavano concessi a chi la aveva.
"""
from __future__ import annotations

import unittest

from . import tools_api


class GrantOnConnectTests(unittest.TestCase):
    def test_the_granted_list_has_no_wildcard(self):
        src = tools_api.__file__
        with open(src, encoding="utf-8") as f:
            code = f.read()
        blocco = code.split("_GH_CONCESSI = [", 1)[1].split("]", 1)[0]
        self.assertNotIn("github.*", blocco)

    def test_nothing_irreversible_is_granted(self):
        with open(tools_api.__file__, encoding="utf-8") as f:
            blocco = f.read().split("_GH_CONCESSI = [", 1)[1].split("]", 1)[0]
        for v in ("delete_repository", "force_push", "delete_branch",
                  "delete_file", "merge_pull_request", "create_repository"):
            self.assertNotIn(v, blocco, f"{v} non deve essere concesso: è irreversibile")

    def test_the_verbs_that_publish_are_there(self):
        with open(tools_api.__file__, encoding="utf-8") as f:
            blocco = f.read().split("_GH_CONCESSI = [", 1)[1].split("]", 1)[0]
        for v in ("github.push", "github.pull_request", "github.clone"):
            self.assertIn(v, blocco)


if __name__ == "__main__":
    unittest.main()
