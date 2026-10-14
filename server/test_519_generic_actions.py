"""clodia-platform#519 — azione di topic e credenziale, dal manifest.

Le due rotte di oggi (`telegram-link`, `mailbox-link`) sono diventate alias
sottili di **una** implementazione guidata dal manifest. La prova di parità più
forte non è in questo file: sono i 26 test di `test_telegram_link.py` e
`test_mailbox_link.py`, scritti prima di #519 sulle rotte vecchie, che passano
invariati sull'implementazione nuova. Qui si verifica ciò che quelli non
possono vedere:

* che la rotta **generica** faccia la stessa cosa dell'alias, sugli stessi
  payload — se no «alias» sarebbe un modo gentile di dire «seconda copia»;
* che un campo con un insieme di valori prenda il valore dal GATEWAY e non dal
  corpo della richiesta: è l'invariante per cui l'azione sulle caselle esiste
  («una whitelist scritta da chi ne è soggetto non è una whitelist»);
* che l'azione scriva SOLO ciò che il proprio manifest dichiara;
* che la connessione di una credenziale non restituisca mai ciò che ha scritto.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from starlette.applications import Starlette
from starlette.testclient import TestClient

from . import connectors_api, topics_api, vault
from .connectors import actions as ca
from .connectors import resolved
from .connectors.manifest import OPTION_SETS, OPTION_SET_VALUES

_H = {"Authorization": "Bearer ckt1.finto"}
_HUMAN = {"agent": "clodia", "principal": "davide", "on_behalf": True,
          "human_role": "admin"}

CASELLE = [{"account": "studio", "email": "studio@tomato.blue",
            "send_only": False},
           {"account": "info", "email": "info@tomato.blue", "send_only": True}]


class _Topic:
    """Un topic che esiste, liste di scope in memoria, binding finti."""

    def __init__(self, tier="SEAL-1", name="acme"):
        self.tier, self.name = tier, name
        self.scope = f"{tier}/{name}"
        self.liste: dict[tuple[str, str], list[str]] = {}
        self.bindings: dict[str, dict] = {}

    def __enter__(self):
        from . import egress as eg
        from .tools import email as email_tool
        from .tools import telegram_bindings as tb

        def _allow(direction, scope, uri):
            self.liste.setdefault((direction, scope), [])
            if uri not in self.liste[(direction, scope)]:
                self.liste[(direction, scope)].append(uri)
            return {"ok": True}

        def _revoke(direction, scope, uri):
            voci = self.liste.get((direction, scope), [])
            if uri in voci:
                voci.remove(uri)
            return {"ok": True}

        svc = unittest.mock.MagicMock()
        svc.open.return_value = {"meta": {"tier": self.tier}}
        self._p = [
            patch.object(eg, "scope_allow", _allow),
            patch.object(eg, "scope_revoke", _revoke),
            patch.object(eg, "scope_uris",
                         lambda d, s, cfg=None: list(self.liste.get((d, s), []))),
            patch.object(eg, "mailbox_allowed",
                         lambda direction, email, scope=None: any(
                             email in u for u in self.liste.get(
                                 ("ingress" if direction == "inbox" else "egress",
                                  scope or self.scope), []))),
            patch.object(email_tool, "system_mailboxes", lambda: list(CASELLE)),
            patch.object(tb, "load", lambda: dict(self.bindings)),
            patch.object(tb, "get", lambda c: self.bindings.get(str(c))),
            patch.object(tb, "set_binding",
                         lambda chat, who, tier, topic: self.bindings.__setitem__(
                             str(chat), {"tier": tier, "topic": topic,
                                         "agent": who})),
            patch.object(tb, "remove", lambda c: self.bindings.pop(str(c), None)),
            patch.object(topics_api, "_service", lambda: svc),
            patch.object(topics_api.internal_auth, "authorize",
                         lambda *a, **k: (_HUMAN, None)),
        ]
        for p in self._p:
            p.start()
        resolved.invalidate()
        return self

    def __exit__(self, *exc):
        for p in self._p:
            p.stop()
        resolved.invalidate()
        return False


def _client() -> TestClient:
    return TestClient(Starlette(routes=topics_api.routes))


def _url(t: _Topic, cid: str, action: str) -> str:
    return f"/internal/topics/{t.tier}/{t.name}/connectors/{cid}/{action}"


class TopicActionTests(unittest.TestCase):
    def test_a_declared_action_writes_exactly_its_own_entries(self) -> None:
        with _Topic() as t:
            r = _client().post(_url(t, "telegram", "telegram-link"),
                               json={"action": "connect", "chat": "-100123"},
                               headers=_H)
            self.assertEqual(r.status_code, 200, r.text)
            self.assertEqual(t.liste[("egress", t.scope)], ["tg:-100123"])
            self.assertEqual(t.liste[("ingress", t.scope)], ["tg:-100123"])
            self.assertEqual(t.bindings["-100123"]["topic"], "acme")

    def test_disconnect_takes_back_what_it_wrote(self) -> None:
        with _Topic() as t:
            c = _client()
            c.post(_url(t, "telegram", "telegram-link"),
                   json={"action": "connect", "chat": "-100123"}, headers=_H)
            r = c.post(_url(t, "telegram", "telegram-link"),
                       json={"action": "disconnect"}, headers=_H)
            self.assertEqual(r.status_code, 200, r.text)
            self.assertEqual(t.liste[("egress", t.scope)], [])
            self.assertEqual(t.bindings, {})

    def test_the_generic_route_and_the_alias_do_the_same_thing(self) -> None:
        """«Alias» deve voler dire un comportamento sotto due URL, non due
        implementazioni che un giorno divergono."""
        with _Topic() as t:
            _client().post(_url(t, "telegram", "telegram-link"),
                           json={"action": "connect", "chat": "-100123"},
                           headers=_H)
            generico = dict(t.liste), dict(t.bindings)
        with _Topic() as t:
            _client().post(f"/internal/topics/{t.tier}/{t.name}/telegram-link",
                           json={"action": "connect", "chat_id": "-100123"},
                           headers=_H)
            alias = dict(t.liste), dict(t.bindings)
        self.assertEqual(generico, alias)

    def test_an_undeclared_action_is_refused(self) -> None:
        with _Topic() as t:
            r = _client().post(_url(t, "telegram", "inventata"),
                               json={"action": "connect"}, headers=_H)
            self.assertEqual(r.status_code, 400)
            self.assertIn("telegram-link", r.json()["error"])

    def test_an_unknown_connector_is_refused(self) -> None:
        with _Topic() as t:
            r = _client().post(_url(t, "citofono", "x"),
                               json={"action": "connect"}, headers=_H)
            self.assertEqual(r.status_code, 400)
            self.assertIn("non installato", r.json()["error"])

    def test_the_state_shows_the_fields_and_what_is_written(self) -> None:
        with _Topic() as t:
            c = _client()
            vuoto = c.get(_url(t, "telegram", "telegram-link"),
                          headers=_H).json()
            self.assertFalse(vuoto["connected"])
            self.assertEqual([f["name"] for f in vuoto["fields"]], ["chat"])
            self.assertIn("seal", vuoto)
            c.post(_url(t, "telegram", "telegram-link"),
                   json={"action": "connect", "chat": "-100123"}, headers=_H)
            pieno = c.get(_url(t, "telegram", "telegram-link"),
                          headers=_H).json()
            self.assertTrue(pieno["connected"])
            self.assertEqual(pieno["entries"]["egress"], ["tg:-100123"])


class OptionSetTests(unittest.TestCase):
    """Il valore lo risolve il gateway, non il corpo della richiesta."""

    def test_the_address_comes_from_the_system_not_from_the_body(self) -> None:
        with _Topic() as t:
            r = _client().post(
                _url(t, "mail", "mailbox-link"),
                json={"action": "connect", "account": "studio",
                      # Un client che prova a dettare l'indirizzo: ignorato.
                      "address": "attaccante@fuori.it",
                      "email": "attaccante@fuori.it"},
                headers=_H)
            self.assertEqual(r.status_code, 200, r.text)
            self.assertEqual(t.liste[("ingress", t.scope)],
                             ["inbox:studio@tomato.blue"])
            self.assertEqual(t.liste[("egress", t.scope)],
                             ["outbox:studio@tomato.blue"])

    def test_an_account_the_system_does_not_have_is_refused(self) -> None:
        with _Topic() as t:
            r = _client().post(_url(t, "mail", "mailbox-link"),
                               json={"action": "connect", "account": "fantasma"},
                               headers=_H)
            self.assertEqual(r.status_code, 400)
            self.assertIn("non è fra i valori", r.json()["error"])
            self.assertEqual(t.liste, {})

    def test_the_state_offers_the_choices(self) -> None:
        with _Topic() as t:
            body = _client().get(_url(t, "mail", "mailbox-link"),
                                 headers=_H).json()
        (campo,) = body["fields"]
        self.assertEqual([o["value"] for o in campo["options"]],
                         ["studio", "info"])

    def test_the_declared_option_sets_are_the_implemented_ones(self) -> None:
        self.assertEqual(set(OPTION_SETS), set(ca.OPTION_SETS))

    def test_an_option_set_resolves_the_names_the_grammar_promises(self) -> None:
        """La grammatica convalida `{address}` perché `OPTION_SET_VALUES` dice
        che quell'insieme lo risolve: se il resolver smettesse di produrlo, il
        template passerebbe il caricamento e fallirebbe all'uso."""
        with _Topic():
            for nome, attesi in OPTION_SET_VALUES.items():
                with self.subTest(nome=nome):
                    for opzione in ca.OPTION_SETS[nome]():
                        self.assertEqual(set(opzione["values"]), set(attesi))


#: A pack connector with a form credential under its own namespace, and one
#: with an OAuth credential: the generic connect route is for PACKS.
SMS_PACK = {"name": "sms-pack", "connectors": [{
    "id": "sms", "manifest_version": 1, "namespace": "sms", "label": "SMS",
    "schemes": [{"scheme": "sms", "direction": "egress"}],
    "providers": [
        {"id": "twilio", "label": "Twilio", "credential": {
            "kind": "form", "vault_entry": "sms_twilio",
            "fields": [{"name": "token", "secret": True}]}},
    ]}, {
    "id": "fax", "manifest_version": 1, "namespace": "fax", "label": "Fax",
    "schemes": [{"scheme": "fax", "direction": "egress"}],
    "providers": [
        {"id": "cloud", "label": "Cloud", "credential": {
            "kind": "oauth", "authorize_url": "https://x.example/a",
            "token_url": "https://x.example/t"}}]}]}


class ConnectTests(unittest.TestCase):
    def setUp(self) -> None:
        from . import tools_api
        resolved.invalidate()
        self.addCleanup(resolved.invalidate)
        self.depositi: list[tuple] = []
        self.rimossi: list[str] = []
        for p in (patch.object(tools_api, "_authorized", lambda request: True),
                  patch.object(resolved, "manifests",
                               lambda: {"sms-pack": SMS_PACK}),
                  patch.object(vault, "credential_type", lambda e: None),
                  patch.object(vault, "deposit",
                               lambda e, b, **k: self.depositi.append((e, b, k))),
                  patch.object(vault, "remove",
                               lambda e: self.rimossi.append(e))):
            p.start()
            self.addCleanup(p.stop)
        self.c = TestClient(Starlette(routes=connectors_api.routes))

    def test_a_form_credential_is_deposited_where_the_manifest_says(self) -> None:
        r = self.c.post("/internal/tools/connectors/sms/connect",
                        json={"token": "tw_segretissimo"}, headers=_H)
        self.assertEqual(r.status_code, 200, r.text)
        (entry, bundle, kw), = self.depositi
        self.assertEqual(entry, "sms_twilio")
        self.assertEqual(bundle, {"token": "tw_segretissimo"})
        # Credenziale di infrastruttura: nessun grant per-agente.
        self.assertEqual(kw.get("grant_agents"), [])
        self.assertEqual(kw.get("cred_type"), "connector:sms")

    def test_the_answer_never_carries_the_secret(self) -> None:
        r = self.c.post("/internal/tools/connectors/sms/connect",
                        json={"token": "tw_segretissimo"}, headers=_H)
        self.assertNotIn("tw_segretissimo", r.text)
        self.assertEqual(set(r.json()),
                         {"connected", "connector", "provider", "vault_entry"})

    def test_an_undeclared_field_is_not_written(self) -> None:
        self.c.post("/internal/tools/connectors/sms/connect",
                    json={"token": "x", "sudo": "true"}, headers=_H)
        (_entry, bundle, _kw), = self.depositi
        self.assertEqual(set(bundle), {"token"})

    def test_empty_fields_disconnect(self) -> None:
        r = self.c.post("/internal/tools/connectors/sms/connect",
                        json={"token": ""}, headers=_H)
        self.assertFalse(r.json()["connected"])
        self.assertEqual(self.rimossi, ["sms_twilio"])
        self.assertEqual(self.depositi, [])

    def test_oauth_does_not_pass_through_here(self) -> None:
        """Un consenso OAuth ha credenziali d'applicazione, uno stato fra le due
        gambe e un callback: renderlo generico senza il manifest che lo descrive
        sarebbe riscriverlo. Resta alle rotte del provider."""
        r = self.c.post("/internal/tools/connectors/fax/connect",
                        json={}, headers=_H)
        self.assertEqual(r.status_code, 400)
        self.assertIn("oauth", r.json()["error"].lower())

    def test_a_builtin_without_a_handler_is_refused(self) -> None:
        r = self.c.post("/internal/tools/connectors/google/connect",
                        json={}, headers=_H)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.depositi, [])

    def test_an_unknown_connector_is_a_404(self) -> None:
        r = self.c.post("/internal/tools/connectors/citofono/connect",
                        json={}, headers=_H)
        self.assertEqual(r.status_code, 404)

    def test_the_route_requires_the_admin_check(self) -> None:
        from . import tools_api
        with patch.object(tools_api, "_authorized", lambda request: False):
            self.assertEqual(
                self.c.post("/internal/tools/connectors/sms/connect",
                            json={"token": "x"}).status_code, 401)
        self.assertEqual(self.depositi, [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
