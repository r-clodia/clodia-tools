"""Un repository è una voce di whitelist, non un remote.

Voce 31 (Davide, 7 ago 2026): il concetto di remote git su un topic sparisce; un
repository remoto è solo una **voce nella whitelist dello scope**, e pull, push
e pull request le fa il gateway.

Finché il remote git esiste — la voce 31 lo fa sparire, ed è la #28 — questo è
il perimetro: chi può collegare un remote non deve poterlo puntare ovunque
arrivi la credenziale di piattaforma.

**Per repository, non per host.** Un cap per host direbbe solo «github sì», che
con una credenziale di piattaforma significa ogni repository che quel token
raggiunge: il perimetro sarebbe nominale. E per la stessa ragione una voce di
solo host non approva niente — `https` sta in lista anche per il web, e un
`https://github.com/` ammesso per una fetch approverebbe altrimenti *ogni*
repository di quell'host.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import whitelist as w
from .topics.service import TopicService as T, TopicError


def _cfg(**kw):
    return patch.object(w, "CONFIG", dict(kw))


APPROVATO = "https://github.com/r-clodia/clodia-tools"


class ApprovalTests(unittest.TestCase):
    def test_an_approved_repository_passes(self):
        with _cfg(egress_allow=[APPROVATO]):
            T._require_approved_repo(APPROVATO, "SEAL-1", "acme")

    def test_the_dot_git_suffix_is_the_same_repository(self):
        with _cfg(egress_allow=[APPROVATO]):
            T._require_approved_repo(APPROVATO + ".git", "SEAL-1", "acme")

    def test_another_repository_is_refused(self):
        with _cfg(egress_allow=[APPROVATO]):
            with self.assertRaises(TopicError) as cm:
                T._require_approved_repo("https://github.com/altri/segreto",
                                         "SEAL-1", "acme")
            self.assertIn("segreto", str(cm.exception))

    def test_the_refusal_names_the_real_risk(self):
        """Non «non è in lista», ma cosa succederebbe: il perimetro si
        allargherebbe fino a tutto ciò che la credenziale raggiunge."""
        with _cfg(egress_allow=[APPROVATO]):
            with self.assertRaises(TopicError) as cm:
                T._require_approved_repo("https://github.com/altri/x", "SEAL-1", "acme")
            self.assertIn("credenziale", str(cm.exception))

    def test_a_prefix_that_is_not_a_path_boundary_does_not_match(self):
        """`clodia-tools-segreto` non sta dentro `clodia-tools`. Con un
        `startswith` nudo ci sarebbe entrato."""
        with _cfg(egress_allow=[APPROVATO]):
            with self.assertRaises(TopicError):
                T._require_approved_repo(APPROVATO + "-segreto", "SEAL-1", "acme")

    def test_a_subpath_of_an_approved_repository_is_inside(self):
        with _cfg(egress_allow=[APPROVATO]):
            T._require_approved_repo(APPROVATO + "/tree/main", "SEAL-1", "acme")


class HostEntryTests(unittest.TestCase):
    def test_a_host_only_entry_does_not_widen_a_declared_perimeter(self):
        """Il buco che questa forma chiude. Con un perimetro dichiarato, un
        `https://github.com/` ammesso per una fetch approverebbe altrimenti
        *ogni* repository di quell'host."""
        with _cfg(egress_allow=[APPROVATO, "https://github.com/"]):
            with self.assertRaises(TopicError):
                T._require_approved_repo("https://github.com/chiunque/x",
                                         "SEAL-1", "acme")

    def test_a_website_allowed_for_the_web_is_not_a_repository_perimeter(self):
        """Una voce di solo sito non ha forma di repository, quindi non
        dichiara un perimetro: qui non si confina, come prima. Un sito ammesso
        per il web non deve NÉ approvare repository né chiuderli."""
        with _cfg(egress_allow=["https://example.com/"]):
            T._require_approved_repo("https://github.com/x/y", "SEAL-1", "acme")


class BackwardCompatibilityTests(unittest.TestCase):
    def test_with_no_repository_declared_nothing_is_refused(self):
        """Nessun perimetro dichiarato = come prima. Rifiutare qui romperebbe
        ogni remote esistente al primo deploy, e un controllo che rompe il
        lavoro viene spento — allora non protegge niente."""
        with _cfg():
            T._require_approved_repo("https://github.com/qualunque/x", "SEAL-1", "acme")

    def test_an_empty_url_is_not_a_refusal(self):
        with _cfg(egress_allow=[APPROVATO]):
            T._require_approved_repo(None, "SEAL-1", "acme")
            T._require_approved_repo("", "SEAL-1", "acme")


class WiringTests(unittest.TestCase):
    def test_the_check_runs_where_the_remote_is_declared(self):
        import inspect
        src = inspect.getsource(T.remote_enable)
        self.assertIn("_require_approved_repo", src)

    def test_it_runs_before_the_credential_is_stored(self):
        """Se l'abilitazione viene rifiutata non deve restare in giro una
        credenziale per un remote che non esiste — la stessa ragione per cui
        `set_git_credential` era già stato messo prima di abilitare."""
        import inspect
        src = inspect.getsource(T.remote_enable)
        self.assertLess(src.index("_require_approved_repo"),
                        src.index("self.set_git_credential"))


class ScopeTests(unittest.TestCase):
    def test_a_repository_approved_for_one_room_confines_only_that_room(self):
        """Conseguenza da guardare in faccia. Il perimetro nasce dalle voci IN
        VIGORE per la chiamata: in una stanza che non ne ha e senza voci
        globali, non c'è perimetro e il controllo non confina.

        È il prezzo della direzione scelta — «nessun perimetro dichiarato = come
        prima» — ed è preferibile all'alternativa: un'approvazione data nella
        stanza A che confina la stanza B imporrebbe a B un perimetro che nessuno
        ha scelto per lei. Il rimedio, quando serve, è una voce globale: da quel
        momento ogni stanza è confinata."""
        from . import whitelist as _w
        with _cfg(scope_egress_allow={"SEAL-1/acme": [APPROVATO]}):
            t = _w.set_current_chat("chan:SEAL-2:altro:clodia")
            try:
                T._require_approved_repo("https://github.com/chiunque/x",
                                         "SEAL-2", "altro")
            finally:
                _w.reset_current_chat(t)

    def test_a_global_entry_confines_every_room(self):
        from . import whitelist as _w
        with _cfg(egress_allow=[APPROVATO]):
            t = _w.set_current_chat("chan:SEAL-2:altro:clodia")
            try:
                with self.assertRaises(TopicError):
                    T._require_approved_repo("https://github.com/chiunque/x",
                                             "SEAL-2", "altro")
            finally:
                _w.reset_current_chat(t)


if __name__ == "__main__":
    unittest.main()
