"""The git host API of a gateway component (clodia-platform#525).

it-pack's component serves `github.clone/pull/push/pull_request` on
`github: pack`. The decisions around a call stay the gateway's and are reached
through the host, per call: the approved repository of the room the call comes
from (`host.perimeter.require_approved_repo`) and the room's git token
(`host.git_credential`, only while the component serves `github`).
"""
from __future__ import annotations

import types
import unittest
from unittest.mock import patch

from .. import main, whitelist
from ..topics.service import TopicService
from .host import Host, HostError, Perimeter

APPROVED = "https://github.com/r-clodia/tools"


def _host(namespaces=("github", "openai"), reserved=()):
    comp = types.SimpleNamespace(key="it-pack/it", pack="it-pack", id="it",
                                 namespaces={n: n for n in namespaces})
    return Host(comp, native_names=lambda: [], reserved_namespaces=lambda: reserved,
                taken=lambda name: None)


class RequireApprovedRepoTests(unittest.TestCase):
    def setUp(self):
        for p in (patch.object(main, "_current_topic", lambda: ("SEAL-1", "acme")),
                  patch.object(whitelist, "CONFIG", {"egress_allow": [APPROVED]})):
            p.start()
            self.addCleanup(p.stop)

    def test_an_approved_repository_comes_back_canonical(self):
        for form in ("r-clodia/tools", "https://github.com/r-clodia/tools.git",
                     "git@github.com:r-clodia/tools"):
            with self.subTest(form=form):
                self.assertEqual(Perimeter().require_approved_repo(form), APPROVED)

    def test_another_repository_is_refused(self):
        with self.assertRaises(HostError):
            Perimeter().require_approved_repo("r-clodia/other")

    def test_not_a_repository_is_refused(self):
        for bad in ("", "/datadir/vault", "file:///datadir/x", "https://github.com/x"):
            with self.subTest(bad=bad), self.assertRaises(HostError):
                Perimeter().require_approved_repo(bad)

    def test_outside_a_room_nothing_is_approved(self):
        with patch.object(main, "_current_topic", lambda: (None, None)), \
                self.assertRaises(HostError):
            Perimeter().require_approved_repo(APPROVED)

    def test_the_room_is_the_claims_never_an_argument(self):
        seen = []
        real = TopicService._require_approved_repo

        def spy(url, tier, name):
            seen.append((tier, name))
            return real(url, tier, name)
        with patch.object(TopicService, "_require_approved_repo", staticmethod(spy)):
            Perimeter().require_approved_repo(APPROVED)
        self.assertEqual(seen, [("SEAL-1", "acme")])


class GitCredentialTests(unittest.TestCase):
    def setUp(self):
        self.asked = []
        svc = types.SimpleNamespace(
            git_credential=lambda tier, name: self.asked.append((tier, name)) or ("tok", "scope"))
        for p in (patch.object(main, "_current_topic", lambda: ("SEAL-2", "beta")),
                  patch.object(main, "_topics", lambda: svc)):
            p.start()
            self.addCleanup(p.stop)

    def test_the_rooms_token(self):
        self.assertEqual(_host().git_credential(), "tok")
        self.assertEqual(self.asked, [("SEAL-2", "beta")])

    def test_only_while_serving_github(self):
        for host in (_host(namespaces=("openai",)), _host(reserved=("github",))):
            with self.subTest(), self.assertRaises(HostError):
                host.git_credential()
        self.assertEqual(self.asked, [])

    def test_outside_a_room_no_token(self):
        with patch.object(main, "_current_topic", lambda: (None, None)), \
                self.assertRaises(HostError):
            _host().git_credential()
        self.assertEqual(self.asked, [])


if __name__ == "__main__":
    unittest.main()
