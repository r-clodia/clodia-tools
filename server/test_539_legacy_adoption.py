"""clodia-platform#539 §4 — a pack adopts its OWN legacy (unstamped) backend.

Backends that packs mounted before clodia-tools 2.90.0 carry no `pack`. Under
the §4 guard they read as admin-mounted, so once clodia-logic passes `pack` on
import/update a trusted pack re-mounting its own backend got 409 and pack
Updates broke. The adoption rule lets pack P take over an unstamped stdio
backend only when the process it starts lives inside one of P's own plugin
directories; everything else stays reserved.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from . import proxy, tools_api, whitelist


class LegacyAdoptionTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        # resolve(): on macOS the temp dir sits behind the /var -> /private/var
        # symlink, and the rule compares resolved paths.
        self.data = Path(tmp.name).resolve() / "datadir"
        self.vault_dir = Path(tmp.name) / "vault"
        env = patch.dict(os.environ, {
            "CLODIA_DATA": str(self.data),
            "CLODIA_VAULT_DIR": str(self.vault_dir),
            "CLODIA_AUDIT_DIR": str(Path(tmp.name) / "audit"),
            "CLODIA_AUDIT_KEY_DIR": str(Path(tmp.name) / "k"),
        })
        env.start()
        self.addCleanup(env.stop)
        # The layout of terra: plugin name == pack name, and a pack whose
        # plugin has another name.
        self._pack("business-pack", ["business-pack"])
        self._pack("studio-commercialista", ["assetti-contabili", "due-diligence"])
        self._pack("studio-legale", ["studio-legale"])

    # ── fixtures ────────────────────────────────────────────────────────────
    def _pack(self, name: str, plugins: list[str]) -> None:
        d = self.data / "packs" / name
        d.mkdir(parents=True, exist_ok=True)
        (d / "pack.yaml").write_text(yaml.safe_dump({"name": name, "plugins": plugins}))
        for pl in plugins:
            (self.data / "plugins" / pl / "mcp").mkdir(parents=True, exist_ok=True)

    def _script(self, plugin: str, name: str = "server_mcp.py") -> str:
        f = self.data / "plugins" / plugin / "mcp" / name
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("# mcp server\n")
        return str(f)

    @staticmethod
    def _legacy(slug: str, *args: str, command: str = "python3") -> dict:
        return {"name": slug, "label": slug, "transport": "stdio",
                "command": command, "args": list(args)}

    def _mount(self, cfg, slug, pack, *, secrets=None, args=None):
        spec = {"command": "python3", "args": args or ["/new/server.py"],
                "env": {"TOKEN": "${token}"}}
        with patch.object(whitelist, "CONFIG", cfg), \
                patch.object(whitelist, "save_config", lambda: None), \
                patch.object(whitelist, "reload_config", lambda: None), \
                patch.object(proxy, "clear_cache", lambda: None), \
                patch("server.instance_profile.integrations_check", lambda s: None):
            return tools_api.register_mcp_core({"mcpServers": {slug: spec}},
                                               secrets=secrets, pack=pack)

    def _seed_secret(self, slug: str, value: str) -> None:
        from . import vault
        vault.deposit(f"mcp_{slug}_token", {"value": value},
                      cred_type="mcp_secret", grant_agents=[])

    def _vault_bytes(self) -> dict:
        if not self.vault_dir.exists():
            return {}
        return {str(f.relative_to(self.vault_dir)): f.read_bytes()
                for f in sorted(self.vault_dir.rglob("*"))
                if f.is_file() and "audit" not in f.name}

    def _assert_refused(self, cfg, slug, pack, before_entry) -> None:
        self._seed_secret(slug, "OWNER-SECRET")
        prima = self._vault_bytes()
        with self.assertRaises(tools_api.McpRegisterError) as e:
            self._mount(cfg, slug, pack, secrets={"token": "INTRUDER"})
        self.assertEqual(409, e.exception.status)
        self.assertEqual(prima, self._vault_bytes())
        self.assertEqual([before_entry], cfg["mcp_backends"])

    # ── adopted ─────────────────────────────────────────────────────────────
    def test_a_pack_adopts_its_own_legacy_backend(self) -> None:
        cfg = {"mcp_backends": [self._legacy("sedia", self._script("business-pack"))]}
        out = self._mount(cfg, "sedia", "business-pack", secrets={"token": "NEW"})
        self.assertEqual(["sedia"], out["registered"])
        [entry] = cfg["mcp_backends"]
        self.assertEqual("business-pack", entry["pack"])
        self.assertEqual(["/new/server.py"], entry["args"])

    def test_a_pack_adopts_a_legacy_backend_of_a_plugin_with_another_name(self) -> None:
        """`studio-commercialista` carries `assetti-contabili`: the backend
        lives in the plugin's dir, not in one named after the pack."""
        cfg = {"mcp_backends": [self._legacy(
            "contabilita", self._script("assetti-contabili", "contabilita_mcp.py"))]}
        self._mount(cfg, "contabilita", "studio-commercialista")
        self.assertEqual("studio-commercialista", cfg["mcp_backends"][0]["pack"])

    def test_after_adoption_the_entry_is_owned(self) -> None:
        """Adoption is a one-off: once stamped, the §4 guard applies as usual."""
        cfg = {"mcp_backends": [self._legacy("sedia", self._script("business-pack"))]}
        self._mount(cfg, "sedia", "business-pack")
        with self.assertRaises(tools_api.McpRegisterError) as e:
            self._mount(cfg, "sedia", "studio-legale")
        self.assertEqual(409, e.exception.status)

    # ── refused ─────────────────────────────────────────────────────────────
    def test_another_packs_legacy_backend_is_refused_and_its_secret_untouched(self) -> None:
        entry = self._legacy("normattiva", self._script("studio-legale", "normattiva_mcp.py"))
        cfg = {"mcp_backends": [dict(entry)]}
        self._assert_refused(cfg, "normattiva", "business-pack", entry)

    def test_an_admin_backend_outside_plugin_dirs_is_refused(self) -> None:
        outside = self.data / "tools" / "sedia_mcp.py"
        outside.parent.mkdir(parents=True)
        outside.write_text("#\n")
        entry = self._legacy("sedia", str(outside))
        cfg = {"mcp_backends": [dict(entry)]}
        self._assert_refused(cfg, "sedia", "business-pack", entry)

    def test_an_http_backend_is_refused(self) -> None:
        entry = {"name": "sedia", "label": "sedia", "transport": "http",
                 "url": f"file://{self._script('business-pack')}"}
        cfg = {"mcp_backends": [dict(entry)]}
        self._assert_refused(cfg, "sedia", "business-pack", entry)

    def test_a_backend_with_no_path_is_refused(self) -> None:
        entry = self._legacy("sedia", "-m", "sedia_mcp", command="python3")
        cfg = {"mcp_backends": [dict(entry)]}
        self._assert_refused(cfg, "sedia", "business-pack", entry)

    def test_dot_dot_traversal_is_refused(self) -> None:
        other = self._script("studio-legale", "normattiva_mcp.py")
        sneaky = str(self.data / "plugins" / "business-pack" / ".." / "studio-legale"
                     / "mcp" / "normattiva_mcp.py")
        self.assertTrue(Path(sneaky).resolve() == Path(other))
        entry = self._legacy("sedia", sneaky)
        cfg = {"mcp_backends": [dict(entry)]}
        self._assert_refused(cfg, "sedia", "business-pack", entry)

    def test_a_symlink_out_of_the_plugin_dir_is_refused(self) -> None:
        target = self.data / "elsewhere" / "evil.py"
        target.parent.mkdir(parents=True)
        target.write_text("#\n")
        link = self.data / "plugins" / "business-pack" / "mcp" / "sedia_mcp.py"
        link.symlink_to(target)
        entry = self._legacy("sedia", str(link))
        cfg = {"mcp_backends": [dict(entry)]}
        self._assert_refused(cfg, "sedia", "business-pack", entry)

    def test_a_plugin_dir_that_is_a_symlink_is_refused(self) -> None:
        self._pack("rogue-pack", [])
        real = self.data / "plugins" / "studio-legale"
        (self.data / "plugins" / "rogue").symlink_to(real)
        self._pack("rogue-pack", ["rogue"])
        script = self._script("studio-legale", "normattiva_mcp.py")
        via_link = str(self.data / "plugins" / "rogue" / "mcp" / "normattiva_mcp.py")
        self.assertTrue(Path(via_link).resolve() == Path(script))
        entry = self._legacy("normattiva", via_link)
        cfg = {"mcp_backends": [dict(entry)]}
        self._assert_refused(cfg, "normattiva", "rogue-pack", entry)

    def test_a_path_spanning_two_plugin_dirs_is_refused(self) -> None:
        entry = self._legacy("sedia", self._script("business-pack"),
                             "--data=" + self._script("studio-legale"))
        cfg = {"mcp_backends": [dict(entry)]}
        self._assert_refused(cfg, "sedia", "business-pack", entry)

    def test_a_shell_line_is_refused(self) -> None:
        entry = self._legacy("sedia", "-c", f"{self._script('business-pack')}; true",
                             command="sh")
        cfg = {"mcp_backends": [dict(entry)]}
        self._assert_refused(cfg, "sedia", "business-pack", entry)

    def test_a_relative_path_is_refused(self) -> None:
        entry = self._legacy("sedia", "plugins/business-pack/mcp/server_mcp.py")
        cfg = {"mcp_backends": [dict(entry)]}
        self._assert_refused(cfg, "sedia", "business-pack", entry)

    def test_a_plugin_claimed_by_two_packs_belongs_to_neither(self) -> None:
        """A pack whose `pack.yaml` lists somebody else's plugin does not get
        to share its backends: ambiguity is refused for both."""
        self._pack("copycat-pack", ["business-pack"])
        entry = self._legacy("sedia", self._script("business-pack"))
        cfg = {"mcp_backends": [dict(entry)]}
        self._assert_refused(cfg, "sedia", "copycat-pack", entry)
        self._assert_refused(cfg, "sedia", "business-pack", entry)

    def test_an_admin_remount_of_an_unstamped_backend_is_unchanged(self) -> None:
        """No pack, no adoption: the admin re-mounting its own stays legal."""
        cfg = {"mcp_backends": [self._legacy("sedia", self._script("business-pack"))]}
        self._mount(cfg, "sedia", None)
        self.assertNotIn("pack", cfg["mcp_backends"][0])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()


from .connectors import first_party_fixture as _stamp


def setUpModule() -> None:
    # The mount-stamp declaration check is #641's own test; here every test
    # pack «declares» the servers it mounts (see the fixture's docstring).
    _stamp.any_pack_declares_any_backend()


def tearDownModule() -> None:
    _stamp.restore_backend_declarations()
