"""clodia-platform#563 — a disabled pack counts as absent.

The agent-server disables a pack by writing `disabled: true` in its installed
`pack.yaml`. The gateway must then treat it exactly like a removed pack: its
connectors are gone (verbs fail closed on `pack`, no topic buttons), its
gateway component is not declared (unloaded at the next reconcile). Its file
still counts for seniority, so enabling it again does not turn it into the
newcomer of a clash it was first in.
"""
from __future__ import annotations

import json
import unittest

from . import resolved
from .test_522_pack_switch import _comms_pack, _Istanza


class DisabledPackTests(_Istanza):
    def _write(self, **extra) -> None:
        (self.dir / "packs" / "comms-pack" / "pack.yaml").write_text(
            json.dumps({**_comms_pack(), **extra}), encoding="utf-8")
        resolved.invalidate()

    def test_a_disabled_pack_is_not_a_manifest(self) -> None:
        self.assertIn("comms-pack", resolved.manifests())
        self._write(disabled=True)
        self.assertNotIn("comms-pack", resolved.manifests())
        self._write(disabled=False)
        self.assertIn("comms-pack", resolved.manifests())

    def test_its_connector_is_gone_on_pack(self) -> None:
        self.posizione("pack")
        self.assertEqual(resolved.registry().by_id("telegram").pack, "comms-pack")
        self._write(disabled=True)
        telegram = resolved.registry().by_id("telegram")
        self.assertTrue(telegram is None or telegram.pack != "comms-pack",
                        "a disabled pack must not hold its connector")

    def test_only_a_true_boolean_disables(self) -> None:
        # A string is not a decision: "false" must not switch a pack off.
        for v in ("true", "false", 1, "yes"):
            self._write(disabled=v)
            self.assertIn("comms-pack", resolved.manifests(), v)

    def test_its_file_keeps_its_seniority(self) -> None:
        before = resolved.seniority().get("comms-pack")
        self._write(disabled=True)
        self.assertIn("comms-pack",
                      [p.parent.name for p in resolved._manifest_files()])
        self._write(disabled=False)
        self.assertEqual(resolved.seniority().get("comms-pack"), before)


class McpListNamesThePackTests(unittest.TestCase):
    def test_the_owning_pack_is_listed(self) -> None:
        from unittest.mock import patch
        from .. import whitelist
        from ..tools import runtime
        cfg = {"mcp_backends": [{"name": "acme", "transport": "stdio", "pack": "acme-pack",
                                 "command": "secret-cmd"},
                                {"name": "mine", "transport": "http"}]}
        with patch.dict(whitelist.CONFIG, cfg):
            rows = {r["name"]: r for r in runtime.mcp_servers()["mcp_backends"]}
        self.assertEqual(rows["acme"].get("pack"), "acme-pack")
        self.assertNotIn("pack", rows["mine"])
        self.assertNotIn("command", rows["acme"])   # still names only

    def test_a_mount_records_the_hash_of_its_config(self) -> None:
        import hashlib
        import json as _json
        from unittest.mock import patch
        from .. import proxy, tools_api, whitelist
        spec = {"command": "acme-server", "args": ["--x"], "env": {"K": "${K}"}}
        cfg = {"mcp_backends": []}
        with patch.object(whitelist, "CONFIG", cfg), \
             patch.object(whitelist, "save_config", lambda: None), \
             patch.object(whitelist, "reload_config", lambda: None), \
             patch.object(proxy, "clear_cache", lambda: None), \
             patch("server.instance_profile.integrations_check", lambda s: None):
            tools_api.register_mcp_core({"mcpServers": {"acme": spec}}, pack="acme-pack")
        (entry,) = [b for b in cfg["mcp_backends"] if b.get("name") == "acme"]
        self.assertEqual(entry["config_sha256"], hashlib.sha256(
            _json.dumps(spec, sort_keys=True, default=str).encode("utf-8")).hexdigest())


if __name__ == "__main__":
    unittest.main()


from . import first_party_fixture as _stamp


def setUpModule() -> None:
    # The mount-stamp declaration check is #641's own test; here every test
    # pack «declares» the servers it mounts (see the fixture's docstring).
    _stamp.any_pack_declares_any_backend()


def tearDownModule() -> None:
    _stamp.restore_backend_declarations()
