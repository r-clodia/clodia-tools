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


class ToolsCardCopyTests(_NoPacks):
    """La card di Tools si descrive da sé.

    Fino a #520 il testo di ogni card («Gmail, Drive, Documenti e Calendar in
    un solo consenso…») stava in una tabella dentro clodia-web, indicizzata per
    NOME del connettore: un connettore arrivato con un pack non aveva modo di
    dire niente di sé, e la pagina poteva solo disegnarlo come una scatola
    senza nome. Il testo è del connettore, quindi arriva con lui.
    """

    def _cards(self) -> dict:
        with _Session({"agent": "clodia", "principal": "davide",
                       "on_behalf": True, "human_role": "admin"}):
            rows = self.c.get("/tools/connectors", headers=_H).json()["connectors"]
        return {r["id"]: r for r in rows}

    def test_the_five_base_cards_describe_themselves(self):
        cards = self._cards()
        for cid in ("google", "mail", "telegram", "github", "openai-images"):
            with self.subTest(connettore=cid):
                self.assertIn(cid, cards, "connettore sparito dal registry")
                card = cards[cid]["tools_card"]
                self.assertIsNotNone(card, f"{cid} non dichiara la propria card")
                self.assertTrue(card["blurb"].strip(), f"{cid}: blurb vuoto")
                self.assertTrue(card["scope"].strip(), f"{cid}: scope vuoto")
                # Il disegno è un asset del frontend, la SCELTA è del
                # connettore: finché la decideva la pagina, la deduceva dal
                # nome — cioè sapeva chi sono i connettori.
                self.assertTrue(card["icon"].strip(), f"{cid}: icona non scelta")

    def test_a_connector_without_a_card_says_so(self):
        """`core` e `datastore` non sono card di Tools: `None` è la risposta
        giusta, e la pagina non deve inventarne una."""
        cards = self._cards()
        for cid in ("core", "datastore"):
            with self.subTest(connettore=cid):
                self.assertIsNone(cards[cid]["tools_card"])


class CredentialFormTests(_NoPacks):
    """I connettori che si collegano con un form lo dichiarano, e il deposito
    resta quello di prima."""

    def test_the_paste_key_connectors_declare_their_field(self):
        with _Session({"agent": "clodia", "principal": "davide",
                       "on_behalf": True, "human_role": "admin"}):
            rows = self.c.get("/tools/connectors", headers=_H).json()["connectors"]
        per_id = {r["id"]: r for r in rows}
        atteso = {"github": ("github_pat", "value"),
                  "telegram": ("telegram_bot_token", "token"),
                  "openai-images": ("openai_api_key", "api_key")}
        for cid, (entry, campo) in atteso.items():
            with self.subTest(connettore=cid):
                provider = per_id[cid]["providers"][0]
                self.assertEqual(provider["kind"], "form")
                self.assertEqual(provider["vault_entry"], entry)
                nomi = [f["name"] for f in provider["fields"]]
                self.assertEqual(nomi, [campo])
                self.assertTrue(provider["fields"][0]["secret"],
                                "una credenziale si digita nascosta")

    def test_a_builtin_credential_is_still_deposited_by_its_own_handler(self):
        """Il nome del campo dichiarato è quello che l'handler nativo legge.

        Attorno al deposito ognuno fa qualcosa che il deposito generico non fa:
        GitHub monta il backend MCP, Telegram valida il token con `getMe` e
        salva l'@username, OpenAI passa per il gating del profilo. Se la rotta
        generica scrivesse da sé, quelle cose sparirebbero e il sintomo
        arriverebbe altrove — un bot connesso senza @username, un MCP non
        montato.
        """
        import inspect
        from . import tools_api
        for cid, atteso in (("github", "github_connect"),
                            ("telegram", "telegram_connect"),
                            ("openai-images", "openai_connect")):
            with self.subTest(connettore=cid):
                nome = connectors_api._LEGACY_CONNECT[cid]
                self.assertEqual(nome, atteso)
                sorgente = inspect.getsource(getattr(tools_api, nome))
                campo = {"github": "pat", "telegram": "token",
                         "openai-images": "api_key"}[cid]
                self.assertIn(f'body.get("{campo}")', sorgente)


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

    def test_a_uri_of_the_scheme_must_keep_the_template_shape(self):
        """Review of #365: a value that is ALREADY a `gdrive:` URI used to
        replace the template outright, so the Drive button — declared for
        `gdrive:folder/{folder}` — could write `gdrive:file/…` or
        `gdrive:doc/…`, i.e. any grantable form of the scheme. A canonical
        value stands for itself only if it has the template's shape."""
        for valore in ("gdrive:file/1AbCdEfGhIjKlMnOpQrStUv",
                       "gdrive:doc/1AbCdEfGhIjKlMnOpQrStUv",
                       "https://drive.google.com/file/d/1AbCdEfGhIjKlMnOpQrStUv/view",
                       "https://docs.google.com/document/d/1AbCdEfGhIjKlMnOpQrStUv/edit"):
            with self.subTest(valore=valore):
                with self.assertRaises(ca.ActionError):
                    self._render(valore)

    def test_a_folder_uri_of_the_right_shape_is_still_accepted(self):
        self.assertEqual(
            self._render("gdrive:folder/1AbCdEfGhIjKlMnOpQrStUv"),
            self._render("1AbCdEfGhIjKlMnOpQrStUv"))


class DocsUrlTests(unittest.TestCase):
    """Review of #365: `tools_card.docs_url` ends up in an `href` on the Tools
    page, where the session token lives in localStorage. A pack may point at
    its documentation, not run script: only `https://` is accepted."""

    @staticmethod
    def _card(docs_url):
        return {"id": "p", "manifest_version": cm.MANIFEST_VERSION,
                "namespace": "p",
                "schemes": [{"scheme": "pp", "direction": "egress"}],
                "tools_card": {"setup_label": "Set up", "docs_url": docs_url}}

    def test_non_https_urls_are_refused_at_parse_time(self):
        for url in ("javascript:alert(document.cookie)",
                    "JavaScript:alert(1)",
                    " javascript:alert(1)",
                    "data:text/html,<script>alert(1)</script>",
                    "http://example.com/docs",
                    "//example.com/docs",
                    "/relative/docs",
                    "https:",
                    "https://"):
            with self.subTest(url=url):
                with self.assertRaises(cm.ManifestError):
                    cm.parse_connector(self._card(url), pack="p")

    def test_https_without_a_host_is_refused(self):
        """clodia-platform#545 §7: `netloc` is not a host.

        `https://@` and `https://:443` have a netloc (`'@'`, `':443'`) and no
        hostname at all, and a NUL byte travels through `urlsplit` untouched:
        all three were accepted here and refused by the web side, which is the
        wrong place to find out. A userinfo is refused with them — the href is
        read by an admin, and `https://docs.pack.io@evil.it` reads like the
        first host and goes to the second.
        """
        for url in ("https://@", "https://@/docs", "https://:443",
                    "https://:443/docs", "https://ex\x00ample.it/docs",
                    "https://\x7f.it/docs", "https://docs.pack.io@evil.it/x",
                    "https://user:pw@evil.it/x"):
            with self.subTest(url=url):
                with self.assertRaises(cm.ManifestError):
                    cm.parse_connector(self._card(url), pack="p")

    def test_a_host_with_a_port_or_an_idn_is_kept(self):
        for url in ("https://example.com:8443/docs", "https://café.fr/docs",
                    "https://[::1]/docs"):
            with self.subTest(url=url):
                c = cm.parse_connector(self._card(url), pack="p")
                self.assertEqual(c.tools_card.docs_url, url)

    def test_an_https_url_is_kept(self):
        c = cm.parse_connector(self._card("https://example.com/docs"), pack="p")
        self.assertEqual(c.tools_card.docs_url, "https://example.com/docs")

    def test_builtin_manifests_carry_no_instance_names(self):
        """The builtin manifests ship in a public repository."""
        import pathlib
        cartella = pathlib.Path(cm.__file__).parent / "builtin_manifests"
        for f in sorted(cartella.glob("*.yaml")):
            with self.subTest(file=f.name):
                self.assertNotIn("wainston", f.read_text().lower())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
