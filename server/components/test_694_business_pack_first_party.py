"""business-pack is a first-party pack with a gateway component
(clodia-platform#694: the Jev decision verbs `jev.*`).

What the entry in `FIRST_PARTY_SOURCES` admits is narrow: business-pack's
component, from `r-clodia/clodia-packs`, under `packs/business-pack/`. The same
pack name from another repository, or a path outside the pack's directory, is
still refused.
"""
from __future__ import annotations

import unittest

from ..connectors import builtin
from . import trust
from .grammar import parse_components


def _manifest(repo: str = "r-clodia/clodia-packs",
              path: str = "packs/business-pack/gateway") -> dict:
    return {
        "name": "business-pack",
        "first_party": True,
        "connectors": [{"id": "jev", "manifest_version": 1, "namespace": "jev"}],
        "components": [{
            "id": "jev", "target": "gateway",
            "source": {"repo": repo, "path": path, "ref": "main"},
            "entry": "jev_component",
            "connectors": ["jev"],
            "credentials": ["jev_api_key"],
        }],
    }


def _component(**kw):
    m = _manifest(**kw)
    (c,), _ = parse_components(m, pack=m["name"])
    return c


class BusinessPackFirstPartyTests(unittest.TestCase):
    def test_known_as_first_party(self) -> None:
        self.assertIn("business-pack", builtin.FIRST_PARTY_PACKS)
        self.assertEqual(builtin.FIRST_PARTY_SOURCES["business-pack"],
                         ("r-clodia/clodia-packs", "packs/business-pack/"))

    def test_its_gateway_directory_is_its_source(self) -> None:
        self.assertEqual(trust.source_problem(_component()), "")

    def test_another_repository_is_refused(self) -> None:
        self.assertIn("is not the upstream",
                      trust.source_problem(_component(repo="r-clodia/clodia-logic")))

    def test_another_pack_directory_is_refused(self) -> None:
        self.assertIn("is outside the directory",
                      trust.source_problem(_component(path="packs/it-pack/gateway")))

    def test_jev_credential_is_inside_the_namespace(self) -> None:
        self.assertEqual(trust.credential_problem(_component(), "jev_api_key"), "")


if __name__ == "__main__":
    unittest.main()
