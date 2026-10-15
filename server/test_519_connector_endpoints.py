"""clodia-platform#519 — the generic connector routes, and the install verdict.

Two questions, and they are not the same:

* `POST /internal/connectors/validate` — what a candidate `connectors:` block
  would do here. The verdict has two classes and only one of them stops an
  installation: a manifest that is **wrong** (anywhere, any day) against a
  manifest that is merely **inert** on this instance because the gateway still
  implements that connector itself. Without the split, comms-pack — which
  declares `telegram.` while the native verbs exist — would be uninstallable
  from the moment the check is switched on.
* `GET /internal/connectors` — what is installed, for the webui of #520, with
  the instance profile applied and **no secret in the payload**.

The test that matters most is `test_a_refused_block_is_inert_even_if_it_was_never_validated`:
validation is a courtesy to whoever installs, not the thing that protects the
PDP. The registry refuses a bad manifest on its own, so «the gateway was down
during the install» is not a way around the grammar.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from starlette.applications import Starlette
from starlette.testclient import TestClient

from . import connectors_api, egress, instance_profile
from .connectors import resolved
from .connectors import validate as cv

#: La funzione VERA che legge i manifest dal disco, presa prima di ogni patch:
#: un test che vuole il giro completo (pack registrato → registry) deve poterla
#: rimettere, e `resolved.manifests` a quel punto è già sostituita.
_REAL_MANIFESTS = resolved.manifests

_H = {"Authorization": "Bearer ckt1.finto"}
_HUMAN = {"agent": "clodia", "principal": "davide", "on_behalf": True,
          "human_role": "admin"}

#: Un pack ben formato che NON tocca niente del gateway: vocabolario suo.
SMS = {
    "id": "sms", "manifest_version": 1, "namespace": "sms", "label": "SMS",
    "schemes": [{"scheme": "sms", "direction": "egress",
                 "forms": [{"label": "numero", "pattern": r"\+\d{6,15}",
                            "example": "+393331234567"}]}],
    "providers": [{"id": "twilio", "label": "Twilio",
                   "credential": {"kind": "form", "vault_entry": "sms_token",
                                  "fields": [{"name": "token", "label": "Token",
                                              "secret": True}]}}],
    "verbs": [{"verb": "sms.send", "direction": "egress", "scheme": "sms",
               "arg": "to", "dtype": "sms"}],
}

#: La dichiarazione di comms-pack per #522: ben formata, ma il gateway
#: implementa ancora `telegram.` e `tg:`.
COMMS_TELEGRAM = {
    "id": "telegram-pack", "manifest_version": 1, "namespace": "telegram",
    "label": "Telegram", "schemes": [{"scheme": "tg2", "direction": "both"}],
    "verbs": [{"verb": "telegram.send", "direction": "egress", "scheme": "tg2",
               "arg": "chat_id"}],
}


def _client() -> TestClient:
    return TestClient(Starlette(routes=connectors_api.routes))


class _Auth:
    def __enter__(self):
        from . import tools_api
        self._p = patch.object(tools_api, "_authorized", lambda request: True)
        self._p.start()
        return self

    def __exit__(self, *exc):
        self._p.stop()
        return False


class ValidateTests(unittest.TestCase):
    def setUp(self) -> None:
        resolved.invalidate()
        self.addCleanup(resolved.invalidate)
        p = patch.object(resolved, "manifests", dict)
        p.start()
        self.addCleanup(p.stop)

    def test_a_clean_block_is_accepted_and_described(self) -> None:
        out = cv.validate("sms-pack", [SMS])
        self.assertTrue(out["ok"], out)
        self.assertEqual(out["errors"], [])
        self.assertEqual(out["ignored"], [])
        (row,) = out["connectors"]
        self.assertEqual(row["id"], "sms")
        self.assertEqual([v["verb"] for v in row["verbs"]], ["sms.send"])

    def test_validating_writes_nothing(self) -> None:
        """A preview that installs is not a preview."""
        before = [c.id for c in resolved.registry().connectors]
        cv.validate("sms-pack", [SMS])
        self.assertEqual([c.id for c in resolved.registry().connectors], before)
        self.assertIsNone(egress.spec_for("sms.send"))

    def test_a_malformed_block_refuses_the_install(self) -> None:
        for bad, needle in [
            ({**SMS, "manifest_version": 99}, "manifest_version"),
            ({**SMS, "verbs": [{"verb": "altro.send", "direction": "egress",
                                "scheme": "sms", "arg": "to"}]}, "namespace"),
            ({**SMS, "schemes": [{"scheme": "sms", "direction": "egress",
                                  "forms": [{"label": "x",
                                             "pattern": r"^(a+)+$"}]}]},
             "group"),
            ({**SMS, "verbs": [{"verb": "sms.send", "direction": "egress",
                                "scheme": "inesistente", "arg": "to"}]},
             "inesistente"),
        ]:
            with self.subTest(needle=needle):
                out = cv.validate("sms-pack", [bad])
                self.assertFalse(out["ok"], out)
                self.assertIn(needle, out["errors"][0])

    def test_a_scheme_another_pack_owns_is_an_error(self) -> None:
        with patch.object(resolved, "manifests",
                          lambda: {"first-pack": {"name": "first-pack",
                                                  "connectors": [SMS]}}):
            resolved.invalidate()
            out = cv.validate("second-pack", [{**SMS, "id": "sms2",
                                               "namespace": "sms2",
                                               "verbs": []}])
        self.assertFalse(out["ok"], out)
        self.assertIn("sms", out["errors"][0])

    def test_reinstalling_a_pack_does_not_collide_with_itself(self) -> None:
        """The candidate REPLACES the installed manifest of the same name:
        a pack that declares what it already declared is not two packs."""
        with patch.object(resolved, "manifests",
                          lambda: {"sms-pack": {"name": "sms-pack",
                                                "connectors": [SMS]}}):
            resolved.invalidate()
            out = cv.validate("sms-pack", [SMS])
        self.assertTrue(out["ok"], out)
        self.assertEqual(out["ignored"], [])

    def test_a_connector_the_gateway_still_implements_is_ignored_not_refused(self):
        """The whole point of the two classes: comms-pack installs, and the
        connector stays inactive until the migration of #522 removes the
        builtin file."""
        out = cv.validate("comms-pack", [COMMS_TELEGRAM])
        self.assertTrue(out["ok"], out)
        self.assertEqual(out["errors"], [])
        self.assertEqual(len(out["ignored"]), 1)
        self.assertIn("telegram", out["ignored"][0])
        self.assertEqual(out["connectors"], [])

    def test_the_ignored_connector_really_stays_out_of_the_registry(self) -> None:
        """«Ignored» has to mean inactive, not merely reported: the native
        mapping must still be the one that answers."""
        with patch.object(resolved, "manifests",
                          lambda: {"comms-pack": {"name": "comms-pack",
                                                  "connectors": [COMMS_TELEGRAM]}}):
            resolved.invalidate()
            reg = resolved.registry()
            self.assertEqual([c.id for c in reg.connectors
                              if c.pack == "comms-pack"], [])
            self.assertTrue(reg.refused)
            spec = egress.spec_for("telegram.send")
            self.assertEqual(spec[1]({"chat_id": "-100"}), ["tg:-100"])
            self.assertNotIn("tg2", reg.scheme_names("egress"))

    def test_a_refused_block_is_inert_even_if_it_was_never_validated(self) -> None:
        """Validation is a courtesy to whoever installs; it is NOT what protects
        the instance. If the gateway was unreachable and the pack was registered
        anyway, the registry refuses the manifest on its own — so «gateway down»
        is not a way around the grammar."""
        rotto = {**SMS, "verbs": [{"verb": "altro.send", "direction": "egress",
                                   "scheme": "sms", "arg": "to"}]}
        self.assertFalse(cv.validate("sms-pack", [rotto])["ok"])
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            (data / "packs" / "sms-pack").mkdir(parents=True)
            (data / "packs" / "sms-pack" / "pack.yaml").write_text(
                json.dumps({"name": "sms-pack", "connectors": [rotto]}),
                encoding="utf-8")
            with patch.object(resolved, "_DATA", data), \
                    patch.object(resolved, "manifests", _REAL_MANIFESTS):
                resolved.invalidate()
                self.assertIsNone(egress.spec_for("altro.send"))
                self.assertTrue(resolved.problems())
                # and the gateway's own connectors are untouched
                self.assertIsNotNone(egress.spec_for("email.send"))


class RouteTests(unittest.TestCase):
    def setUp(self) -> None:
        resolved.invalidate()
        self.addCleanup(resolved.invalidate)
        p = patch.object(resolved, "manifests", dict)
        p.start()
        self.addCleanup(p.stop)

    def test_the_listing_describes_the_installed_connectors(self) -> None:
        with _Auth():
            r = _client().get("/internal/connectors", headers=_H)
        self.assertEqual(r.status_code, 200)
        body = r.json()
        ids = {c["id"] for c in body["connectors"]}
        self.assertIn("telegram", ids)
        self.assertIn("mail", ids)
        self.assertIn("tg", body["schemes"]["egress"])
        self.assertIn("mailfrom", body["schemes"]["source"])

    def test_the_listing_carries_no_secret(self) -> None:
        """A provider is described by the NAME of its vault entry and by the
        shape of its form — never by what is stored under it."""
        with _Auth():
            body = _client().get("/internal/connectors", headers=_H).json()
        raw = json.dumps(body)
        for forbidden in ("value", "token\":", "secret_value", "password",
                          "refresh_token", "client_secret"):
            self.assertNotIn(forbidden, raw, forbidden)
        google = next(c for c in body["connectors"] if c["id"] == "google")
        self.assertTrue(google["providers"])
        for p in google["providers"]:
            # `connected` (#520) è un BOOLEANO: dice che sotto quella voce c'è
            # qualcosa, mai cosa. L'insieme resta chiuso apposta — è il
            # controllo che si accorge di una chiave in più il giorno che
            # qualcuno ci mette l'account «per comodità».
            self.assertEqual(set(p) - {"id", "label", "kind", "vault_entry",
                                       "fields", "connected"}, set())
            self.assertIsInstance(p["connected"], bool)

    def test_the_instance_profile_filters_the_listing(self) -> None:
        def _no_telegram(cid: str) -> None:
            if cid == "telegram":
                raise PermissionError("non ammesso su questa istanza")
        with _Auth(), patch.object(instance_profile, "connector_check",
                                   _no_telegram):
            body = _client().get("/internal/connectors", headers=_H).json()
        self.assertNotIn("telegram", {c["id"] for c in body["connectors"]})
        self.assertIn("mail", {c["id"] for c in body["connectors"]})

    def test_the_validate_route_answers_the_two_classes(self) -> None:
        with _Auth():
            c = _client()
            ok = c.post("/internal/connectors/validate",
                        json={"pack": "sms-pack", "connectors": [SMS]},
                        headers=_H).json()
            inert = c.post("/internal/connectors/validate",
                           json={"pack": "comms-pack",
                                 "connectors": [COMMS_TELEGRAM]},
                           headers=_H).json()
            bad = c.post("/internal/connectors/validate",
                         json={"pack": "sms-pack",
                               "connectors": [{**SMS, "manifest_version": 99}]},
                         headers=_H).json()
        self.assertTrue(ok["ok"])
        self.assertTrue(inert["ok"])
        self.assertTrue(inert["ignored"])
        self.assertFalse(bad["ok"])

    def test_an_empty_block_is_accepted(self) -> None:
        """Most packs declare no connector, and «nothing to say» is not «no»."""
        with _Auth():
            r = _client().post("/internal/connectors/validate",
                               json={"pack": "plain-pack"}, headers=_H)
        self.assertTrue(r.json()["ok"])

    def test_both_routes_require_the_internal_auth(self) -> None:
        c = _client()
        self.assertEqual(c.get("/internal/connectors").status_code, 401)
        self.assertEqual(
            c.post("/internal/connectors/validate", json={}).status_code, 401)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
