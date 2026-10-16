"""clodia-platform#545 §2 — one spelling of a backend name, in both checks.

The 409 of #539 §4 («this backend is already mounted by somebody else»)
compared RAW slugs, while ownership (`connectors.resolved._norm`, which decides
whether a pack may claim a namespace) compares names with `-` and `_` equated.
Two comparisons, two answers: an admin's hand-edited `mcp_backends` entry named
`norm_attiva` — config.yaml is a file, nothing slugifies what is typed in it —
did not look like a previous mount of the `norm attiva` a pack mounts (slug
`norm-attiva`), so the mount was accepted; and from then on the pack owned the
one name both entries normalise to.

So: the conflict is looked up on the normalised name, and so is the dedup that
replaces the entry — otherwise an accepted remount would leave two rows that
mean the same backend and ownership would depend on which one is read first.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from . import proxy, tools_api, whitelist
from .connectors import resolved


class NormalisedBackendNameTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        env = patch.dict(os.environ, {
            "CLODIA_DATA": str(Path(tmp.name) / "datadir"),
            "CLODIA_VAULT_DIR": str(Path(tmp.name) / "vault"),
            "CLODIA_AUDIT_DIR": str(Path(tmp.name) / "audit"),
            "CLODIA_AUDIT_KEY_DIR": str(Path(tmp.name) / "k"),
        })
        env.start()
        self.addCleanup(env.stop)

    def _mount(self, cfg, server_name, pack):
        spec = {"command": "python3", "args": ["/srv/server.py"]}
        with patch.object(whitelist, "CONFIG", cfg), \
                patch.object(whitelist, "save_config", lambda: None), \
                patch.object(whitelist, "reload_config", lambda: None), \
                patch.object(proxy, "clear_cache", lambda: None), \
                patch("server.instance_profile.integrations_check", lambda s: None):
            return tools_api.register_mcp_core({"mcpServers": {server_name: spec}},
                                               pack=pack)

    def test_a_hand_written_admin_name_is_the_same_backend(self) -> None:
        """`norm_attiva` (hand-edited) vs `norm attiva` → slug `norm-attiva`."""
        admin = {"name": "norm_attiva", "label": "norm_attiva",
                 "transport": "stdio", "command": "python3",
                 "args": ["/opt/normattiva.py"]}
        cfg = {"mcp_backends": [dict(admin)]}
        with self.assertRaises(tools_api.McpRegisterError) as e:
            self._mount(cfg, "norm attiva", "legal-pack")
        self.assertEqual(409, e.exception.status)
        # Nothing mounted, nothing replaced: the admin's entry is untouched.
        self.assertEqual([admin], cfg["mcp_backends"])

    def test_the_two_comparisons_agree(self) -> None:
        """The property, not the example: whatever the 409 lets through must
        not be a backend ownership already considers the same one."""
        for admin_name, mounted in (("norm_attiva", "norm attiva"),
                                    ("norm-attiva", "norm_attiva"),
                                    ("Norm_Attiva", "norm.attiva")):
            with self.subTest(admin=admin_name, mounted=mounted):
                cfg = {"mcp_backends": [{"name": admin_name, "label": admin_name,
                                         "transport": "stdio",
                                         "command": "python3", "args": ["/a.py"]}]}
                try:
                    self._mount(cfg, mounted, "legal-pack")
                except tools_api.McpRegisterError as exc:
                    self.assertEqual(409, exc.status)
                    continue
                nomi = {resolved._norm(str(b.get("name") or ""))
                        for b in cfg["mcp_backends"]}
                self.assertEqual(len(nomi), len(cfg["mcp_backends"]),
                                 "two entries normalise to the same backend")

    def test_a_different_backend_still_mounts(self) -> None:
        cfg = {"mcp_backends": [{"name": "norm_attiva", "label": "norm_attiva",
                                 "transport": "stdio", "command": "python3",
                                 "args": ["/a.py"]}]}
        out = self._mount(cfg, "altro servizio", "legal-pack")
        self.assertEqual(["altro-servizio"], out["registered"])
        self.assertEqual(2, len(cfg["mcp_backends"]))

    def test_the_owner_may_still_remount_its_own(self) -> None:
        cfg = {"mcp_backends": [{"name": "norm-attiva", "label": "norm attiva",
                                 "pack": "legal-pack", "transport": "stdio",
                                 "command": "python3", "args": ["/old.py"]}]}
        self._mount(cfg, "norm attiva", "legal-pack")
        self.assertEqual(1, len(cfg["mcp_backends"]))
        self.assertEqual(["/srv/server.py"], cfg["mcp_backends"][0]["args"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
