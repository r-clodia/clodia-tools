from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from . import datastores


def _write_manifest(root: Path, pack: str, datastores_list: list[dict]) -> None:
    import yaml
    pdir = root / "plugins" / pack
    pdir.mkdir(parents=True, exist_ok=True)
    (pdir / "plugin.yaml").write_text(
        yaml.safe_dump({"name": pack, "datastores": datastores_list}), encoding="utf-8")


class DeclaredTests(unittest.TestCase):
    def test_fields_round_trip(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_manifest(root, "base-pack", [
                {"path": "data/contacts.db", "purpose": "CRM contatti", "pii": True,
                 "backup": True, "clearance": "SEAL-1", "seeds": ["messaggero", "clodia"]},
            ])
            with patch.object(datastores, "DATADIR", str(root)):
                found = datastores.declared()
            self.assertEqual(len(found), 1)
            entry = found[0]
            self.assertEqual(entry["pack"], "base-pack")
            self.assertEqual(entry["name"], "contacts")
            self.assertEqual(entry["clearance"], "SEAL-1")
            self.assertEqual(entry["seeds"], ["messaggero", "clodia"])
            self.assertTrue(entry["abs_path"].endswith("data/contacts.db"))

    def test_missing_clearance_and_seeds_default_to_most_restrictive(self) -> None:
        """Un datastore dichiarato prima che questi campi esistessero non
        concede nulla finché qualcuno non li scrive esplicitamente."""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_manifest(root, "tomato", [{"path": "data/leads.db"}])
            with patch.object(datastores, "DATADIR", str(root)):
                found = datastores.declared()
            self.assertEqual(found[0]["clearance"], "SEAL-4")
            self.assertEqual(found[0]["seeds"], [])

    def test_name_defaults_to_path_stem(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_manifest(root, "tomato", [{"path": "data/leads.db"}])
            with patch.object(datastores, "DATADIR", str(root)):
                found = datastores.declared()
            self.assertEqual(found[0]["name"], "leads")

    def test_find_matches_pack_and_name(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_manifest(root, "base-pack", [{"path": "data/contacts.db"}])
            _write_manifest(root, "tomato", [{"path": "data/leads.db"}])
            with patch.object(datastores, "DATADIR", str(root)):
                self.assertIsNotNone(datastores.find("base-pack", "contacts"))
                self.assertIsNone(datastores.find("tomato", "contacts"))


class ParseKeyTests(unittest.TestCase):
    def test_splits_pack_and_name(self) -> None:
        self.assertEqual(datastores.parse_key("base-pack/contacts"), ("base-pack", "contacts"))

    def test_rejects_missing_separator(self) -> None:
        with self.assertRaises(ValueError):
            datastores.parse_key("contacts")

    def test_rejects_empty_halves(self) -> None:
        for bad in ("/contacts", "base-pack/", "/"):
            with self.subTest(key=bad):
                with self.assertRaises(ValueError):
                    datastores.parse_key(bad)


if __name__ == "__main__":
    unittest.main()
