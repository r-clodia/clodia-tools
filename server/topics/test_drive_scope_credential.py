"""La cartella Drive la monta l'owner con la PROPRIA credenziale (§2.7).

Il salto è più grande che su git. Un PAT fine-grained raggiunge un repository;
la credenziale Drive di piattaforma è un **account Google intero**. Usarla per
uno scope significa dare a quello scope tutto il Drive di quell'account — che è
la domanda che Davide ha posto il 7 agosto («in pratica lo scope diventa capace
di modificare qualunque file dell'account dell'owner?»), e la risposta era sì.

Due cose, quindi, e la seconda è quella che si dimentica:

  1. se il mount ha la sua credenziale, si usa quella;
  2. **la cache non deve sopravvivere al cambio.** Il client Drive è tenuto per
     thread: senza la provenienza nella chiave, il primo client costruito con
     l'account di piattaforma continuerebbe a servire lo scope anche dopo che
     l'owner ha collegato il proprio. Un privilegio che sopravvive alla revoca è
     peggio che non averlo mai tolto, perché la schermata dice il contrario.

Nessuna chiamata a Google: si osserva CON QUALE credenziale il client sarebbe
costruito, che è la decisione presa qui. Chiamare Google verificherebbe Google.
"""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from .local_fs import LocalFsStorage
from .service import TopicService

BUNDLE = {"refresh_token": "RT-OWNER", "client_id": "cid", "client_secret": "sec"}


class FakeVault:
    def __init__(self):
        self.store = {}

    def read_internal(self, cred):
        if cred not in self.store:
            raise FileNotFoundError(cred)
        return dict(self.store[cred])

    def deposit(self, cred, bundle, *, cred_type="opaque", grant_agents=None, actions=None):
        self.store[cred] = dict(bundle)

    def remove(self, cred):
        return self.store.pop(cred, None) is not None


class Base(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="drivecred-"))
        self.svc = TopicService(LocalFsStorage(str(self.root)))
        self.svc.new("SEAL-1", "acme", {"title": "Acme", "owner": "davide"})
        self.vault = FakeVault()
        import server.vault as _v
        self._orig = {k: getattr(_v, k, None)
                      for k in ("read_internal", "deposit", "remove")}
        for k in ("read_internal", "deposit", "remove"):
            setattr(_v, k, getattr(self.vault, k))
        self._v = _v

    def tearDown(self):
        for k, v in self._orig.items():
            if v is not None:
                setattr(self._v, k, v)
        shutil.rmtree(self.root, ignore_errors=True)


class ResolutionTests(Base):
    def test_without_one_the_platform_account_is_used_and_it_says_so(self):
        b, fonte = self.svc.drive_credential("SEAL-1", "acme", "drive")
        self.assertIsNone(b)
        self.assertEqual(fonte, "platform")

    def test_the_mount_credential_wins(self):
        self.svc.set_drive_credential("SEAL-1", "acme", BUNDLE, "contratti")
        b, fonte = self.svc.drive_credential("SEAL-1", "acme", "contratti")
        self.assertEqual(b["refresh_token"], "RT-OWNER")
        self.assertEqual(fonte, "mount")

    def test_two_mounts_do_not_share_it(self):
        """È il caso per cui esistono due mount: due cartelle, due proprietari."""
        self.svc.set_drive_credential("SEAL-1", "acme", BUNDLE, "contratti")
        self.assertEqual(self.svc.drive_credential("SEAL-1", "acme", "bilanci")[1],
                         "platform")

    def test_a_bundle_without_a_refresh_token_is_not_a_credential(self):
        """Depositare mezza credenziale renderebbe `credential_source: mount`
        vero sulla card e falso al primo uso."""
        out = self.svc.set_drive_credential("SEAL-1", "acme", {"client_id": "x"}, "c")
        self.assertIsNone(out["credential"])
        self.assertEqual(self.svc.drive_credential("SEAL-1", "acme", "c")[1], "platform")

    def test_removing_it_says_what_it_fell_back_to(self):
        self.svc.set_drive_credential("SEAL-1", "acme", BUNDLE, "contratti")
        out = self.svc.set_drive_credential("SEAL-1", "acme", None, "contratti")
        self.assertEqual(out["source"], "platform")

    def test_git_and_drive_do_not_collide_in_the_vault(self):
        """Stesso topic, stesso mount, due credenziali di natura diversa: se il
        nome coincidesse, depositare l'una cancellerebbe l'altra."""
        self.svc.set_drive_credential("SEAL-1", "acme", BUNDLE, "m")
        self.svc.set_git_credential("SEAL-1", "acme", "PAT", "m")
        self.assertEqual(self.svc.drive_credential("SEAL-1", "acme", "m")[1], "mount")
        self.assertEqual(self.svc.git_credential("SEAL-1", "acme", "m"),
                         ("PAT", "mount"))


class TheCacheDoesNotOutliveTheCredentialTests(Base):
    """Il difetto silenzioso."""

    def _backend(self, mount):
        """Costruisce il backend osservando con quale bundle nasce il client."""
        visti = []

        def finto_service(account, bundle=None):
            visti.append(bundle)
            return object()

        with patch.object(self.svc, "_drive_service", finto_service), \
             patch("server.topics.drive_fs.DriveStorage", lambda svc, folder: object()):
            self.svc._drive_backend_for("SEAL-1", "acme", {"folder": "FID"}, mount)
        return visti

    def test_the_platform_client_is_not_reused_after_the_owner_connects(self):
        primo = self._backend("contratti")
        self.assertEqual(primo, [None])          # nasce con la piattaforma
        self.svc.set_drive_credential("SEAL-1", "acme", BUNDLE, "contratti")
        secondo = self._backend("contratti")
        self.assertEqual(len(secondo), 1)        # non è stato riusato dalla cache
        self.assertEqual(secondo[0]["refresh_token"], "RT-OWNER")

    def test_the_owners_client_is_not_reused_after_a_revocation(self):
        """L'altra direzione, che è la più grave: revocare e continuare a
        lavorare con la credenziale revocata."""
        self.svc.set_drive_credential("SEAL-1", "acme", BUNDLE, "contratti")
        self._backend("contratti")
        self.svc.set_drive_credential("SEAL-1", "acme", None, "contratti")
        dopo = self._backend("contratti")
        self.assertEqual(dopo, [None])

    def test_two_mounts_on_the_same_folder_do_not_share_a_client(self):
        self.svc.set_drive_credential("SEAL-1", "acme", BUNDLE, "uno")
        self._backend("uno")
        due = self._backend("due")
        self.assertEqual(due, [None])


class BuildTests(unittest.TestCase):
    def test_an_incomplete_bundle_fails_naming_what_is_missing(self):
        from .service import TopicError
        with self.assertRaises(TopicError) as ctx:
            TopicService._drive_build({"refresh_token": "x"})
        self.assertIn("client_id", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
