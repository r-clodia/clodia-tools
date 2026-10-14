"""#520 — la superficie dei connettori che il BROWSER può chiamare.

Il registry di #518 e le rotte generiche di #519 sono completi, ma stanno tutti
sotto `/internal/`, che il proxy della webui non inoltra per costruzione: al
gateway arriva `/tools`, e nient'altro. Finché è così la pagina Tools non può
leggere il registry, cioè la cosa per cui il registry è stato scritto.

Qui si verificano le quattro cose che #520 chiede a questo lato:

1. le due rotte rispondono anche sotto `/tools`, con la STESSA funzione — se un
   giorno l'autorizzazione si restringe (ed è ciò che #539 §5 sta facendo),
   l'ingresso nuovo si restringe con lei perché non ne ha uno suo;
2. il listing dice se una credenziale c'è, con un BOOLEANO e nient'altro;
3. `admin_only` sopravvive al giro: la regola «la casella di sistema la collega
   un admin» viveva in un `if` sul nome del connettore nella webui, e renderla
   generica senza questo campo la cancellerebbe in silenzio;
4. l'azione di topic canonicalizza ciò che una persona incolla — e NON ciò che
   una persona inventa: le guardie di #360 restano tutte a valle.
"""
from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from starlette.applications import Starlette
from starlette.testclient import TestClient

from . import connectors_api, internal_auth, pki_verify, tools_api, topics_api, vault
from . import egress as eg
from .tools import telegram_bindings as tb
from .connectors import actions as ca
from .connectors import manifest as cm
from .connectors import resolved

_H = {"Authorization": "Bearer ckt1.finto"}


class _Session:
    """Una sessione verificata con questi claim, attraverso i controlli VERI.

    Copiato da `test_519_review_fixes`, con in più la neutralizzazione di
    `_is_human_admin`: legge `agent.yaml` dalla data dir REALE della colonia,
    che in uno scratch non è leggibile (PermissionError). È ambiente, non
    autorizzazione — un agente qualunque non è admin né qui né in CI.
    """

    def __init__(self, claims: dict):
        self.claims = claims

    def __enter__(self):
        self._ps = [
            patch.object(pki_verify, "verify_session_token",
                         lambda tok: dict(self.claims)),
            patch.object(internal_auth, "verify_session_token",
                         lambda tok: dict(self.claims)),
            patch.object(internal_auth, "principals",
                         lambda: frozenset({"clodia"})),
            patch.object(internal_auth, "refuse_if_revoked",
                         lambda *a, **k: None),
            patch.object(tools_api, "_revocata", lambda p: False),
            patch.object(tools_api, "_is_human_admin", lambda ag: False),
            patch.object(tools_api, "_UI_TOKEN", None),
        ]
        for p in self._ps:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in reversed(self._ps):
            p.stop()


class _NoPacks(unittest.TestCase):
    """Registry dei soli connettori builtin: i pack installati sull'istanza
    reale non devono entrare nelle asserzioni di un test."""

    def setUp(self):
        resolved.invalidate()
        self.addCleanup(resolved.invalidate)
        p = patch.object(resolved, "manifests", dict)
        p.start()
        self.addCleanup(p.stop)
        self.c = TestClient(Starlette(routes=connectors_api.routes))


class WebuiReachableRoutesTests(_NoPacks):
    """Le stesse risposte, all'indirizzo che il browser raggiunge."""

    def test_the_listing_answers_under_tools_too(self):
        with _Session({"agent": "clodia", "principal": "davide",
                       "on_behalf": True, "human_role": "admin"}):
            interna = self.c.get("/internal/connectors", headers=_H)
            esterna = self.c.get("/tools/connectors", headers=_H)
        self.assertEqual(interna.status_code, 200)
        self.assertEqual(esterna.status_code, 200)
        self.assertEqual(interna.json(), esterna.json())

    def test_the_connect_answers_under_tools_too(self):
        """Stessa funzione ⇒ stesso rifiuto per un connettore inesistente.

        Si misura su un 404, non su un deposito: scrivere nel vault non è ciò
        che questo test verifica, e un test che deposita una credenziale per
        provare un instradamento lascia dietro di sé la cosa sbagliata.
        """
        with _Session({"agent": "clodia", "principal": "davide",
                       "on_behalf": True, "human_role": "admin"}):
            interna = self.c.post("/internal/tools/connectors/inesistente/connect",
                                  headers=_H, json={})
            esterna = self.c.post("/tools/connectors/inesistente/connect",
                                  headers=_H, json={})
        self.assertEqual(interna.status_code, 404)
        self.assertEqual(esterna.status_code, esterna.status_code)
        self.assertEqual(interna.json(), esterna.json())

    def test_an_agent_token_is_refused_on_the_new_entrances(self):
        """Il token runtime di un agente non apre la porta nuova.

        È la condizione posta all'approvazione del piano: l'alias non deve
        avere un'autorizzazione propria. `minerva` è un agente qualunque —
        quando #539 §5 toglierà anche `clodia`/`ophelia` da `_authorized`,
        questa rotta lo seguirà senza che nessuno la tocchi, perché chiama
        quella funzione e non una sua copia.
        """
        with _Session({"agent": "minerva"}):
            self.assertEqual(
                self.c.get("/tools/connectors", headers=_H).status_code, 401)
            self.assertEqual(
                self.c.post("/tools/connectors/github/connect",
                            headers=_H, json={}).status_code, 401)

    def test_the_new_entrances_are_the_same_functions(self):
        """Non un controllo sul testo: gli endpoint montati sono gli stessi
        oggetti. Una copia con la sua logica non passerebbe di qui."""
        per_path = {r.path: r.endpoint for r in connectors_api.routes}
        self.assertIs(per_path["/tools/connectors"],
                      per_path["/internal/connectors"])
        self.assertIs(per_path["/tools/connectors/{id}/connect"],
                      per_path["/internal/tools/connectors/{id}/connect"])


class ConnectedIsABooleanTests(_NoPacks):
    def _providers(self) -> list[dict]:
        with _Session({"agent": "clodia", "principal": "davide",
                       "on_behalf": True, "human_role": "admin"}):
            rows = self.c.get("/tools/connectors", headers=_H).json()["connectors"]
        return [p for r in rows for p in r["providers"]]

    def test_every_provider_says_whether_its_credential_is_there(self):
        with patch.object(vault, "has_credential", lambda e: e == "github_pat"):
            providers = self._providers()
        self.assertTrue(providers, "nessun provider builtin: fixture inutile")
        for p in providers:
            with self.subTest(provider=p["id"]):
                self.assertIsInstance(p["connected"], bool)
        connessi = [p["vault_entry"] for p in providers if p["connected"]]
        self.assertEqual(connessi, ["github_pat"])

    def test_the_listing_carries_no_secret(self):
        """Il valore depositato non deve comparire da nessuna parte nel corpo.

        `has_credential` risponde sì/no; se un giorno qualcuno la sostituisse
        con una lettura del bundle «per mostrare l'account», il segreto
        finirebbe nel JSON e nessun altro test se ne accorgerebbe.
        """
        segreto = "ghp_segretissimo_che_non_deve_uscire"
        with patch.object(vault, "has_credential", lambda e: True), \
                patch.object(vault, "read_credential",
                             lambda *a, **k: {"value": segreto}, create=True):
            with _Session({"agent": "clodia", "principal": "davide",
                           "on_behalf": True, "human_role": "admin"}):
                corpo = self.c.get("/tools/connectors", headers=_H).text
        self.assertNotIn(segreto, corpo)
        self.assertNotIn("ghp_", corpo)


class AdminOnlyTravelsTests(_NoPacks):
    def test_the_mailbox_action_is_declared_admin_only(self):
        with _Session({"agent": "clodia", "principal": "davide",
                       "on_behalf": True, "human_role": "admin"}):
            rows = self.c.get("/tools/connectors", headers=_H).json()["connectors"]
        azioni = {(r["id"], a["id"]): a for r in rows for a in r["topic_actions"]}
        self.assertIn(("mail", "mailbox-link"), azioni,
                      "il connettore mail non dichiara più la sua azione")
        self.assertTrue(azioni[("mail", "mailbox-link")]["admin_only"])
        # L'opposto, se no il campo potrebbe essere `true` per tutti e il test
        # verde a vuoto: collegare una chat Telegram resta dell'owner.
        self.assertFalse(azioni[("telegram", "telegram-link")]["admin_only"])

    def test_the_state_of_an_action_carries_it(self):
        """È il campo che l'agent-server legge prima di inoltrare una POST: se
        sparisse di qui, la rotta generica diventerebbe la porta di servizio di
        `mailbox-link`, che in clodia-logic è da admin dal 27 set."""
        svc = MagicMock()
        svc.open.return_value = {"meta": {"tier": "SEAL-1"}}
        with patch.object(topics_api, "_service", lambda: svc), \
                patch.object(eg, "scope_uris", lambda d, s, cfg=None: []), \
                patch.object(tb, "load", dict):
            for cid, aid, atteso in (("mail", "mailbox-link", True),
                                     ("telegram", "telegram-link", False)):
                with self.subTest(connettore=cid):
                    connector, action = ca.find(cid, aid)
                    stato = ca.state(connector, action, "SEAL-1", "stanza")
                    self.assertEqual(stato["admin_only"], atteso)

    def test_an_action_is_not_admin_only_by_default(self):
        azione = cm._parse_topic_action(
            {"id": "x", "label": "X", "fields": [{"name": "v", "label": "V"}],
             "adds": {"egress": ["tg:{v}"]}}, "c.topic_actions[0]")
        self.assertFalse(azione.admin_only)

    def test_a_typo_in_admin_only_is_refused(self):
        with self.assertRaises(cm.ManifestError):
            cm._parse_topic_action(
                {"id": "x", "label": "X", "admin_only": "si",
                 "fields": [{"name": "v", "label": "V"}],
                 "adds": {"egress": ["tg:{v}"]}}, "c.topic_actions[0]")


class DriveActionTests(_NoPacks):
    """La parità del bottone Drive: incollare l'URL deve continuare a valere."""

    def _render(self, valore: str) -> dict:
        connector, action = ca.find("google", "drive-folder")
        valori = ca.resolve_values(action, {"folder": valore})
        uris = ca.render(action, valori)
        ca.check_uris(connector, uris)
        return uris

    def test_google_declares_the_drive_button(self):
        connector, action = ca.find("google", "drive-folder")
        self.assertEqual(sorted(f.name for f in action.fields), ["folder"])
        self.assertEqual(action.binding, "", "Drive non aggancia nessun canale")

    def test_a_bare_folder_id_is_written_in_both_directions(self):
        self.assertEqual(
            self._render("1AbCdEfGhIjKlMnOpQrStUv"),
            {"ingress": ["gdrive:folder/1AbCdEfGhIjKlMnOpQrStUv"],
             "egress": ["gdrive:folder/1AbCdEfGhIjKlMnOpQrStUv"]})

    def test_a_pasted_browser_url_lands_on_the_same_uri(self):
        """È ciò che una persona copia davvero dalla barra del browser."""
        self.assertEqual(
            self._render("https://drive.google.com/drive/folders/1AbCdEfGhIjKlMnOpQrStUv"),
            self._render("1AbCdEfGhIjKlMnOpQrStUv"))

    def test_another_scheme_is_still_refused(self):
        """Il controllo negativo: la canonicalizzazione allarga ciò che si può
        DIGITARE, non ciò che si può scrivere in lista. Un URL che non è di
        Drive resta testo dentro il template e non ha la forma di un
        `gdrive:` — rifiutato, come prima."""
        for valore in ("https://evil.example/esfiltra",
                       "gsheets:1AbCdEfGhIjKlMnOpQrStUv",
                       "*", "../../etc"):
            with self.subTest(valore=valore):
                with self.assertRaises(ca.ActionError):
                    self._render(valore)

    def test_a_degenerate_entry_is_still_refused(self):
        """`gdrive:folder/` aprirebbe tutto Drive: lo nega `check_grantable`,
        che gira DOPO la canonicalizzazione e non è stato spostato."""
        with self.assertRaises(ca.ActionError):
            self._render("gdrive://")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
