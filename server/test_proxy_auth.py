"""L'identità di un proxy: una chiave che tiene lui.

Questi test guardano le direzioni di rottura, come quelli del client umano. Un
sistema di autenticazione che concede troppo non fallisce: funziona benissimo,
ed è esattamente il motivo per cui va provato che rifiuti.

Le chiavi qui sono vere (Ed25519 vero, firme vere): l'unica cosa in finta è il
certificato, che nei test è la pubkey caricata direttamente invece che estratta
da un x509 firmato dalla CA — quella catena ha già i suoi test in `pki_verify`.
"""
from __future__ import annotations

import base64
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import human_mcp, proxy_auth


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


class _Datadir:
    def __enter__(self):
        self._d = tempfile.TemporaryDirectory()
        self._p = patch.dict(os.environ, {"CLODIA_DATA": self._d.name})
        self._p.start()
        return Path(self._d.name)

    def __exit__(self, *a):
        self._p.stop()
        self._d.cleanup()
        return False


class _Proxy:
    """Il sistema esterno: tiene la chiave e firma."""

    def __init__(self, name="crm-esterno"):
        self.name = name
        self.key = Ed25519PrivateKey.generate()

    def assertion(self, **over) -> str:
        ora = int(time.time())
        payload = {"principal": self.name, "tier": "SEAL-1", "topic": "acme",
                   "aud": proxy_auth.ASSERTION_AUDIENCE,
                   "iat": ora, "exp": ora + 60,
                   "jti": _b64e(os.urandom(9))}
        payload.update(over)
        body = _b64e(json.dumps(payload, separators=(",", ":")).encode())
        return f"{proxy_auth.ASSERTION_PREFIX}.{body}.{_b64e(self.key.sign(body.encode()))}"


def _mint(agent, **k):
    return "ckt1.fake." + json.dumps({"chat": k.get("chat"),
                                      "scoped_tools": k.get("scoped_tools"),
                                      "principal": k.get("principal"),
                                      "ttl": k.get("ttl_seconds"),
                                      "signed_by": agent})


class _Scena:
    """Un proxy con la sua chiave riconosciuta e un collegamento vivo."""

    def __init__(self, con_grant=True, proxy=None):
        self.proxy = proxy or _Proxy()
        self.con_grant = con_grant

    def __enter__(self):
        self._dd = _Datadir(); self._dd.__enter__()
        if self.con_grant:
            human_mcp.issue("SEAL-1", "acme", self.proxy.name, provider="crm",
                            carrier="clodia", principal_kind="proxy")
        self._p1 = patch.object(proxy_auth.pki_verify, "_agent_public_key",
                                lambda n: self.proxy.key.public_key()
                                if n == self.proxy.name
                                else (_ for _ in ()).throw(
                                    PermissionError(f"nessun certificato per agent '{n}'")))
        self._p2 = patch.object(proxy_auth.pki_mint, "mint_session_token", _mint)
        self._p1.start(); self._p2.start()
        return self.proxy

    def __exit__(self, *a):
        self._p2.stop(); self._p1.stop(); self._dd.__exit__(*a)
        return False


class TheHappyPathTests(unittest.TestCase):
    def test_a_signed_assertion_becomes_a_short_token(self):
        with _Scena() as p:
            res = proxy_auth.token_for(p.assertion())
        self.assertEqual(res["expires_in"], proxy_auth.TOKEN_TTL_SECONDS)
        self.assertLessEqual(res["expires_in"], 3600,
                             "un token di proxy deve essere corto: rinnovarlo "
                             "costa una firma, che il proxy sa fare da solo")
        claims = json.loads(res["token"].split(".", 2)[2])
        self.assertEqual(claims["principal"], "crm-esterno")
        self.assertEqual(claims["chat"], "chan:SEAL-1:acme:crm-esterno")

    def test_the_token_carries_the_proxy_verbs_and_nothing_else(self):
        with _Scena() as p:
            res = proxy_auth.token_for(p.assertion())
        claims = json.loads(res["token"].split(".", 2)[2])
        self.assertEqual(set(claims["scoped_tools"]), set(human_mcp.PROXY_VERBS))


class TheAssertionMustBeFreshAndOursTests(unittest.TestCase):
    def test_a_replayed_assertion_is_refused(self):
        """Una firma valida resta valida: chi la intercetta la rigioca. Senza il
        consumo del jti, la finestra ridurrebbe il problema a pochi minuti
        invece di chiuderlo — e pochi minuti sono una sessione intera."""
        with _Scena() as p:
            a = p.assertion()
            proxy_auth.token_for(a)
            with self.assertRaises(PermissionError) as e:
                proxy_auth.token_for(a)
        self.assertIn("già usata", str(e.exception))

    def test_an_expired_assertion_is_refused(self):
        with _Scena() as p:
            ora = int(time.time())
            with self.assertRaises(PermissionError) as e:
                proxy_auth.token_for(p.assertion(iat=ora - 600, exp=ora - 500))
        self.assertIn("scaduta", str(e.exception))

    def test_a_wide_window_is_refused(self):
        """Un `exp` lontano trasformerebbe l'asserzione in ciò che stiamo
        togliendo: un segreto lungo, solo firmato."""
        with _Scena() as p:
            ora = int(time.time())
            with self.assertRaises(PermissionError) as e:
                proxy_auth.token_for(p.assertion(iat=ora, exp=ora + 86400))
        self.assertIn("troppo larga", str(e.exception))

    def test_an_assertion_for_someone_else_is_refused(self):
        """Senza audience, una firma fatta per noi varrebbe per entrare
        altrove — e viceversa."""
        with _Scena() as p:
            with self.assertRaises(PermissionError) as e:
                proxy_auth.token_for(p.assertion(aud="un-altra-istanza"))
        self.assertIn("audience", str(e.exception))

    def test_an_assertion_without_jti_is_refused(self):
        with _Scena() as p:
            with self.assertRaises(PermissionError) as e:
                proxy_auth.token_for(p.assertion(jti=""))
        self.assertIn("jti", str(e.exception))

    def test_a_little_clock_drift_is_tolerated(self):
        """Un client con dieci secondi di deriva non deve restare fuori per
        sempre con una causa invisibile da entrambi i lati."""
        with _Scena() as p:
            ora = int(time.time())
            res = proxy_auth.token_for(p.assertion(iat=ora + 20, exp=ora + 80))
        self.assertIn("token", res)


class TheSignatureMustBeTheirsTests(unittest.TestCase):
    def test_a_forged_signature_is_refused(self):
        altro = _Proxy("crm-esterno")          # stesso nome, chiave diversa
        with _Scena() as p:
            falsa = altro.assertion()
            with self.assertRaises(PermissionError) as e:
                proxy_auth.token_for(falsa)
        self.assertIn("firma non valida", str(e.exception))
        del p

    def test_a_tampered_payload_is_refused(self):
        """Il caso che rende utile la firma: rifirmare non si può, quindi si
        prova a riscrivere il payload lasciando la firma dov'è."""
        with _Scena() as p:
            prefix, body, sig = p.assertion().split(".")
            payload = json.loads(base64.urlsafe_b64decode(body + "=="))
            payload["topic"] = "una-stanza-a-cui-non-appartiene"
            nuovo = _b64e(json.dumps(payload, separators=(",", ":")).encode())
            with self.assertRaises(PermissionError) as e:
                proxy_auth.token_for(f"{prefix}.{nuovo}.{sig}")
        self.assertIn("firma non valida", str(e.exception))

    def test_a_principal_without_a_certificate_is_told_what_to_do(self):
        """Il caso più comune al primo collegamento: il rimedio non è riprovare,
        è far emettere il certificato dalla propria pubkey."""
        sconosciuto = _Proxy("mai-visto")
        with _Scena():
            with self.assertRaises(PermissionError) as e:
                proxy_auth.token_for(sconosciuto.assertion(principal="mai-visto"))
        self.assertIn("pubkey", str(e.exception))


class TheSignatureIsNotThePermissionTests(unittest.TestCase):
    """Provare chi sei non è provare che puoi entrare. Tenerle separate è ciò
    che permette di revocare senza toccare la chiave, e di ruotare la chiave
    senza chiedere di nuovo il permesso."""

    def test_without_a_grant_and_without_a_seat_there_is_no_token(self):
        with _Scena(con_grant=False) as p:
            with self.assertRaises(PermissionError) as e:
                proxy_auth.token_for(p.assertion())
        self.assertIn("non partecipa", str(e.exception))

    def test_a_valid_signature_for_another_room_gets_nothing(self):
        with _Scena() as p:
            with self.assertRaises(PermissionError) as e:
                proxy_auth.token_for(p.assertion(topic="stanza-altrui"))
        self.assertIn("non partecipa", str(e.exception))

    def test_a_revoked_grant_stops_the_key_from_working(self):
        with _Scena() as p:
            gid = human_mcp.list_grants("SEAL-1", "acme")[0]["id"]
            human_mcp.revoke(gid)
            with self.assertRaises(PermissionError) as e:
                proxy_auth.token_for(p.assertion())
        self.assertIn("non partecipa", str(e.exception))

    def test_an_assertion_without_a_room_is_refused(self):
        """Un token di proxy vale per UNA stanza, e va detto quale: senza, il
        legame `chat` si costruirebbe su un vuoto."""
        with _Scena() as p:
            with self.assertRaises(PermissionError) as e:
                proxy_auth.token_for(p.assertion(topic=""))
        self.assertIn("UNA stanza", str(e.exception))


class TheSeatIsTheAdmissionTests(unittest.TestCase):
    """Sedere fra i partecipanti È l'ammissione: l'owner l'ha già data.

    Prima servivano due atti per la stessa cosa — invitare il proxy nel topic e
    poi coniargli un grant dal pannello MCP — e un proxy invitato, visibile fra
    i partecipanti, restava fuori con un errore che parlava di un «collegamento»
    che nella UI non si capiva dove creare.
    """

    def test_a_participant_proxy_gets_a_token_without_any_grant(self):
        with _Scena(con_grant=False) as p:
            with patch.object(proxy_auth, "_is_participant", lambda *a: True):
                res = proxy_auth.token_for(p.assertion())
        self.assertEqual(res["principal"], p.name)
        claims = json.loads(res["token"].split(".", 2)[2])
        self.assertEqual(set(claims["scoped_tools"]), set(human_mcp.PROXY_VERBS),
                         "la sedia non allarga i verbi: restano quelli del proxy")

    def test_the_tier_ceiling_still_applies_without_a_grant(self):
        """La strada nuova non deve essere anche la più larga: sopra SEAL-2 il
        contenuto uscirebbe verso un sistema che non controlliamo."""
        with _Scena(con_grant=False) as p:
            with patch.object(proxy_auth, "_is_participant", lambda *a: True):
                with self.assertRaises(PermissionError) as e:
                    proxy_auth.token_for(p.assertion(tier="SEAL-3"))
        self.assertIn("SEAL-2", str(e.exception))

    def test_being_removed_from_the_room_removes_the_access(self):
        with _Scena(con_grant=False) as p:
            with patch.object(proxy_auth, "_is_participant", lambda *a: False):
                with self.assertRaises(PermissionError) as e:
                    proxy_auth.token_for(p.assertion())
        self.assertIn("partecipanti", str(e.exception))

    def test_participant_is_read_from_the_room_meta(self):
        """La funzione vera, non il suo doppio: owner o participants del meta."""
        class _Svc:
            def open(self, tier, name):
                return {"meta": {"owner": "davide",
                                 "participants": ["clodia", "crm-esterno"]}}

        with patch("server.topics_api._service", lambda: _Svc()):
            self.assertTrue(proxy_auth._is_participant("crm-esterno", "SEAL-1", "acme"))
            self.assertTrue(proxy_auth._is_participant("davide", "SEAL-1", "acme"))
            self.assertFalse(proxy_auth._is_participant("estraneo", "SEAL-1", "acme"))

    def test_an_unreadable_room_is_not_an_admission(self):
        class _Svc:
            def open(self, tier, name):
                raise RuntimeError("storage giù")

        with patch("server.topics_api._service", lambda: _Svc()):
            self.assertFalse(proxy_auth._is_participant("crm-esterno", "SEAL-1", "acme"))


class TheGrantNoLongerCarriesASecretTests(unittest.TestCase):
    def test_issuing_for_a_proxy_returns_no_bearer(self):
        """Il punto di tutto il cambiamento: non esiste più una stringa che,
        copiata, È quel proxy."""
        with _Datadir():
            res = human_mcp.issue("SEAL-1", "acme", "crm-esterno",
                                  provider="crm", carrier="clodia",
                                  principal_kind="proxy")
        self.assertIsNone(res["token"])
        self.assertEqual(res["auth"], "assertion")

    def test_issuing_for_a_person_still_returns_one(self):
        with _Datadir(), patch.object(human_mcp.pki_mint, "mint_session_token", _mint):
            res = human_mcp.issue("SEAL-1", "acme", "giovanni",
                                  provider="anthropic-api", carrier="clodia")
        self.assertTrue(res["token"])
        self.assertEqual(res["auth"], "bearer")

    def test_a_proxy_gets_no_config_to_paste(self):
        """Una configurazione con l'header vuoto sembrerebbe funzionare fino
        alla prima chiamata."""
        self.assertEqual(human_mcp.client_config("https://x", None, "SEAL-1", "acme"), {})

    def test_the_instructions_say_where_and_what_to_sign(self):
        istr = proxy_auth.client_instructions("https://esempio/", "SEAL-1",
                                              "acme", "crm-esterno")
        self.assertEqual(istr["token_endpoint"], "https://esempio/proxy/token")
        self.assertEqual(istr["mcp_url"], "https://esempio/mcp")
        self.assertEqual(istr["assertion"]["payload"]["aud"],
                         proxy_auth.ASSERTION_AUDIENCE)
        self.assertEqual(set(istr["verbs"]), set(human_mcp.PROXY_VERBS))


class TheReplayRegistryDoesNotGrowForeverTests(unittest.TestCase):
    def test_expired_entries_are_pruned_when_a_new_one_arrives(self):
        """Un registro anti-replay che cresce per sempre diventa il motivo per
        cui qualcuno un giorno lo svuota tutto."""
        with _Scena() as p:
            proxy_auth._remember("vecchio", int(time.time()) - 10)
            proxy_auth.token_for(p.assertion())
            visti = proxy_auth._load_seen()
        self.assertNotIn("vecchio", visti)
        self.assertEqual(len(visti), 1)


if __name__ == "__main__":
    unittest.main()
