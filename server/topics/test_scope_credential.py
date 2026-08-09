"""La credenziale git appartiene allo SCOPE, non alla piattaforma.

Com'era, misurato il 7 ago 2026:

    def _github_token(self):
        return (vault.read_internal("github_pat") or {}).get("value")

`read_internal` significa nessun controllo di grant — è una credenziale di
infrastruttura, UNA, iniettata in ogni remote git di ogni topic. Quindi un token
raggiungeva tutti i repository per cui ha scope, **da qualunque stanza**.

È l'asse risorsa nella sua forma più pura: qui la risorsa è selezionata dalla
credenziale, e la credenziale era globale. Una credenziale di scope ne raggiunge
uno — e i PAT fine-grained di GitHub si limitano a un repository, quindi il
restringimento è reale.

Due proprietà che i test qui sotto tengono ferme, e sono quelle che fanno
abbandonare o fallire un meccanismo di sicurezza:

  1. **il ripiego è visibile.** Senza credenziale propria si usa quella di
     piattaforma — e chi guarda deve poterlo sapere, perché un ripiego silenzioso
     costruisce la convinzione di un isolamento che non c'è;
  2. **si può ruotare.** Una credenziale per topic significa N rotazioni: senza
     una via per cambiarla, diventano N credenziali che nessuno rinnova più.
"""
from __future__ import annotations

import unittest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch

from .local_fs import LocalFsStorage
from .service import TopicService


class FakeVault:
    """Il vault ridotto a ciò che serve qui: un dizionario con la stessa
    semantica di deposit/read_internal/remove."""

    def __init__(self, iniziali=None):
        self.store = dict(iniziali or {})
        self.grants = {}

    def read_internal(self, cred):
        if cred not in self.store:
            raise FileNotFoundError(cred)
        return {"value": self.store[cred]}

    def deposit(self, cred, bundle, *, cred_type="opaque",
                grant_agents=None, actions=None):
        self.store[cred] = bundle["value"]
        self.grants[cred] = list(grant_agents or [])

    def remove(self, cred):
        return self.store.pop(cred, None) is not None


class Base(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="scopecred-"))
        self.svc = TopicService(LocalFsStorage(str(self.root)))
        self.svc.new("SEAL-1", "acme", {"title": "Acme", "owner": "davide"})
        self.vault = FakeVault({"github_pat": "PAT-DI-PIATTAFORMA"})
        self.p = patch.dict("sys.modules", {})
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


class FallbackTests(Base):
    def test_without_its_own_credential_the_platform_one_is_used(self):
        tok, fonte = self.svc.git_credential("SEAL-1", "acme")
        self.assertEqual(tok, "PAT-DI-PIATTAFORMA")
        self.assertEqual(fonte, "platform")

    def test_the_scope_credential_wins(self):
        self.svc.set_git_credential("SEAL-1", "acme", "PAT-SOLO-DI-ACME")
        tok, fonte = self.svc.git_credential("SEAL-1", "acme")
        self.assertEqual(tok, "PAT-SOLO-DI-ACME")
        self.assertEqual(fonte, "scope")

    def test_two_topics_do_not_share_a_scope_credential(self):
        """Il punto dell'esercizio: il confinamento."""
        self.svc.new("SEAL-1", "beta", {"title": "Beta", "owner": "davide"})
        self.svc.set_git_credential("SEAL-1", "acme", "PAT-ACME")
        self.assertEqual(self.svc.git_credential("SEAL-1", "acme")[0], "PAT-ACME")
        self.assertEqual(self.svc.git_credential("SEAL-1", "beta")[0],
                         "PAT-DI-PIATTAFORMA")

    def test_with_no_platform_credential_either_there_is_none(self):
        self.vault.store.pop("github_pat")
        tok, fonte = self.svc.git_credential("SEAL-1", "acme")
        self.assertIsNone(tok)
        self.assertEqual(fonte, "platform")


class RotationTests(Base):
    """Il costo ricorrente di questo disegno. Senza una via per cambiarla, una
    credenziale per topic diventa una credenziale che nessuno rinnova."""

    def test_a_credential_can_be_replaced(self):
        self.svc.set_git_credential("SEAL-1", "acme", "VECCHIO")
        self.svc.set_git_credential("SEAL-1", "acme", "NUOVO")
        self.assertEqual(self.svc.git_credential("SEAL-1", "acme")[0], "NUOVO")

    def test_removing_it_falls_back_instead_of_breaking(self):
        self.svc.set_git_credential("SEAL-1", "acme", "TEMPORANEO")
        self.svc.set_git_credential("SEAL-1", "acme", "")
        tok, fonte = self.svc.git_credential("SEAL-1", "acme")
        self.assertEqual(tok, "PAT-DI-PIATTAFORMA")
        self.assertEqual(fonte, "platform")


class NamingTests(Base):
    def test_the_name_is_derived_from_the_scope_not_chosen(self):
        """Se il nome fosse libero, due topic potrebbero puntare alla stessa
        credenziale senza che nessuno lo veda, e il confinamento sarebbe una
        convenzione invece di una proprietà."""
        a = TopicService.scope_credential_name("SEAL-1", "acme")
        b = TopicService.scope_credential_name("SEAL-1", "beta")
        c = TopicService.scope_credential_name("SEAL-2", "acme")
        self.assertNotEqual(a, b)
        self.assertNotEqual(a, c)

    def test_legacy_tier_aliases_name_the_same_credential(self):
        """`P1` e `SEAL-1` sono lo stesso posto: nomi diversi qui creerebbero due
        credenziali per un topic solo, e una delle due resterebbe orfana."""
        self.assertEqual(TopicService.scope_credential_name("P1", "acme"),
                         TopicService.scope_credential_name("SEAL-1", "acme"))


class NoAgentGrantTests(Base):
    def test_no_agent_can_read_a_scope_credential(self):
        """È legata allo SCOPE, non a un agente: la usa il gateway eseguendo un
        verbo remote per quel topic. Concederla a un agente la trasformerebbe in
        ciò da cui stiamo uscendo — una credenziale che segue chi la porta invece
        della stanza in cui serve."""
        self.svc.set_git_credential("SEAL-1", "acme", "PAT")
        cred = TopicService.scope_credential_name("SEAL-1", "acme")
        self.assertEqual(self.vault.grants[cred], [])


class VisibleFallbackTests(Base):
    def test_status_says_which_credential_is_in_use(self):
        meta, ver = self.svc._read_meta("SEAL-1", "acme")
        meta["remote"] = {"type": "git", "config": {"url": "https://github.com/x/y.git"}}
        self.svc._write_meta("SEAL-1", "acme", meta, base_version=ver)
        with patch.object(self.svc, "_remote_for", lambda *a, **k: None):
            st = self.svc.remote_status("SEAL-1", "acme")
        self.assertEqual(st.get("credential_source"), "platform")
        self.svc.set_git_credential("SEAL-1", "acme", "PAT")
        with patch.object(self.svc, "_remote_for", lambda *a, **k: None):
            st2 = self.svc.remote_status("SEAL-1", "acme")
        self.assertEqual(st2.get("credential_source"), "scope")

    def test_status_never_exposes_the_value(self):
        """Si mostra la PROVENIENZA, mai il segreto."""
        self.svc.set_git_credential("SEAL-1", "acme", "PAT-SEGRETISSIMO")
        meta, ver = self.svc._read_meta("SEAL-1", "acme")
        meta["remote"] = {"type": "git", "config": {"url": "https://github.com/x/y.git"}}
        self.svc._write_meta("SEAL-1", "acme", meta, base_version=ver)
        with patch.object(self.svc, "_remote_for", lambda *a, **k: None):
            st = self.svc.remote_status("SEAL-1", "acme")
        self.assertNotIn("PAT-SEGRETISSIMO", str(st))


if __name__ == "__main__":
    unittest.main()


class PerMountTests(Base):
    """Voce 33: la credenziale la mette l'OWNER al momento del mount.

    Con più mount la credenziale non può più essere dello scope. Due mount dello
    stesso topic possono appartenere a owner diversi — è esattamente il caso per
    cui esistono — e una credenziale sola li riporterebbe nello stesso
    perimetro, cioè annullerebbe la ragione della modifica.
    """

    def test_the_credential_belongs_to_the_mount(self):
        self.svc.set_git_credential("SEAL-1", "acme", "PAT-CONTRATTI", "contratti")
        tok, fonte = self.svc.git_credential("SEAL-1", "acme", "contratti")
        self.assertEqual(tok, "PAT-CONTRATTI")
        self.assertEqual(fonte, "mount")

    def test_two_mounts_of_the_same_topic_do_not_share_it(self):
        """Il confinamento, un livello più in basso di ieri."""
        self.svc.set_git_credential("SEAL-1", "acme", "PAT-CONTRATTI", "contratti")
        self.svc.set_git_credential("SEAL-1", "acme", "PAT-CODICE", "codice")
        self.assertEqual(self.svc.git_credential("SEAL-1", "acme", "contratti")[0],
                         "PAT-CONTRATTI")
        self.assertEqual(self.svc.git_credential("SEAL-1", "acme", "codice")[0],
                         "PAT-CODICE")

    def test_a_mount_without_one_falls_back_to_the_scope(self):
        """La credenziale già depositata sui topic esistenti non è del mount:
        se smettesse di valere, i remote git in esercizio ricadrebbero sul PAT
        di piattaforma — che raggiunge più repo, non meno. Il ripiego va nella
        direzione giusta solo se passa prima da qui."""
        self.svc.set_git_credential("SEAL-1", "acme", "PAT-STORICO")
        tok, fonte = self.svc.git_credential("SEAL-1", "acme", "drive")
        self.assertEqual(tok, "PAT-STORICO")
        self.assertEqual(fonte, "scope")

    def test_the_narrowest_wins(self):
        """Ordine: mount → scope → piattaforma. L'ordine inverso userebbe il
        token che raggiunge più repository anche avendone uno più stretto."""
        self.svc.set_git_credential("SEAL-1", "acme", "PAT-STORICO")
        self.svc.set_git_credential("SEAL-1", "acme", "PAT-DEL-MOUNT", "codice")
        self.assertEqual(self.svc.git_credential("SEAL-1", "acme", "codice")[0],
                         "PAT-DEL-MOUNT")

    def test_removing_a_mount_credential_says_what_is_underneath(self):
        """Togliere non lascia scoperto: sotto c'è ancora lo scope, e sotto
        ancora la piattaforma. Chi toglie deve leggere su cosa è ricaduto —
        dedurlo è il modo in cui si crede di aver revocato un accesso."""
        self.svc.set_git_credential("SEAL-1", "acme", "PAT-STORICO")
        self.svc.set_git_credential("SEAL-1", "acme", "PAT-DEL-MOUNT", "codice")
        out = self.svc.set_git_credential("SEAL-1", "acme", None, "codice")
        self.assertEqual(out["source"], "scope")
        self.assertEqual(self.svc.git_credential("SEAL-1", "acme", "codice")[0],
                         "PAT-STORICO")

    def test_the_vault_name_is_derived_not_chosen(self):
        """Se il nome fosse libero, due mount potrebbero puntare alla stessa
        credenziale senza che nessuno lo veda."""
        a = TopicService.scope_credential_name("SEAL-1", "acme", "git", "codice")
        b = TopicService.scope_credential_name("SEAL-1", "acme", "git", "contratti")
        self.assertNotEqual(a, b)
        self.assertEqual(
            TopicService.scope_credential_name("SEAL-1", "acme", "git"),
            "scope_git__seal1__acme")

    def test_a_mount_name_cannot_forge_another_topics_credential(self):
        """Il nome del mount entra in una chiave del vault: se non fosse
        normalizzato, un mount chiamato `x__seal1__beta` sceglierebbe il nome
        della credenziale di un altro topic."""
        cred = TopicService.scope_credential_name("SEAL-1", "acme", "git",
                                                  "../../seal1__beta")
        self.assertTrue(cred.startswith("scope_git__seal1__acme__"))
        self.assertNotIn("/", cred)
