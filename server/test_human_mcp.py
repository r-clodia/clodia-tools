"""Il token di un client MCP umano: fin dove arriva, per quanto, come si toglie.

Questi test guardano soprattutto le DIREZIONI DI ROTTURA. Un token che concede
troppo non fallisce: funziona benissimo, ed è il motivo per cui va provato che si
rifiuti.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from . import human_mcp


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


def _mint(*a, **k):
    """Il minter vero firma con una chiave che qui non c'è: quello che questi
    test devono verificare sono i CLAIM, non la crittografia (che ha i suoi)."""
    return "ckt1.fake." + json.dumps({"chat": k.get("chat"),
                                      "scoped_tools": k.get("scoped_tools"),
                                      "principal": k.get("principal"),
                                      "execution_id": k.get("execution_id")})


class TierTests(unittest.TestCase):
    """Il tier della stanza è un tetto sul MOTORE del client, non sulla stanza.

    È la differenza con Telegram, dove esce una notifica. Qui esce il contenuto —
    dentro il contesto del Claude di Giovanni.
    """

    def test_seal_0_and_1_are_allowed(self):
        for t in ("SEAL-0", "SEAL-1"):
            human_mcp._check_tier(t, "anthropic-api", False)  # non solleva

    def test_seal_2_needs_someone_to_take_responsibility(self):
        with self.assertRaises(PermissionError) as e:
            human_mcp._check_tier("SEAL-2", "anthropic-api", False)
        self.assertIn("concessione", str(e.exception))
        human_mcp._check_tier("SEAL-2", "anthropic-api", True)  # concesso → passa

    def test_seal_3_is_refused_even_with_consent(self):
        """Il consenso non compra il livello: sopra SEAL-2 non si conia, e non
        perché manchi un permesso — perché la dichiarazione del provider è sulla
        parola e lì l'errore non è recuperabile."""
        with self.assertRaises(PermissionError):
            human_mcp._check_tier("SEAL-3", "anthropic-api", True)
        with self.assertRaises(PermissionError):
            human_mcp._check_tier("SEAL-4", "scaleway", True)

    def test_an_undeclared_provider_is_refused(self):
        """Non è burocrazia: senza questa riga non sapremmo dire, dopo, dove è
        finito ciò che è stato letto."""
        with self.assertRaises(PermissionError):
            human_mcp._check_tier("SEAL-1", "", False)

    def test_legacy_p_tiers_are_understood(self):
        """`P3` è la vecchia scala, ancora presente in qualche meta. Leggerla
        come SEAL-0 aprirebbe il caso più riservato."""
        with self.assertRaises(PermissionError):
            human_mcp._check_tier("P3", "anthropic-api", True)


class IssueTests(unittest.TestCase):
    def test_the_token_is_bound_to_one_room_and_a_short_verb_list(self):
        with _Datadir(), patch.object(human_mcp.pki_mint, "mint_session_token", _mint):
            res = human_mcp.issue("SEAL-1", "proof-of-flex", "giovanni",
                                  provider="anthropic-api", carrier="clodia")
        claims = json.loads(res["token"].split(".", 2)[2])
        self.assertEqual(claims["chat"], "chan:SEAL-1:proof-of-flex:giovanni")
        self.assertEqual(claims["principal"], "giovanni")
        self.assertEqual(set(claims["scoped_tools"]), set(human_mcp.VERBS))

    def test_the_control_plane_is_not_in_the_verb_list(self):
        """Un token per parlare in una stanza non deve poter spostare i muri
        della stanza. Elencato per NOME e non per prefisso: un `agents.*` che
        rientrasse un giorno passerebbe inosservato a un controllo generico."""
        for v in ("agents.spawn", "jobs.create", "settings.set", "mcp.add",
                  "topic.remote_enable", "topic.telegram_bind",
                  "topic.add_participant", "topic.delete_file",
                  "topic.save_summary", "topic.archive", "email.send"):
            self.assertNotIn(v, human_mcp.VERBS)

    def test_a_token_without_a_person_is_refused(self):
        with _Datadir(), patch.object(human_mcp.pki_mint, "mint_session_token", _mint):
            with self.assertRaises(ValueError):
                human_mcp.issue("SEAL-1", "x", "  ", provider="anthropic-api",
                                carrier="clodia")

    def test_the_ttl_is_bounded(self):
        with _Datadir(), patch.object(human_mcp.pki_mint, "mint_session_token", _mint):
            r = human_mcp.issue("SEAL-0", "x", "g", provider="p", carrier="clodia",
                                ttl_days=9999)
        durata = (r["expires"] - int(__import__("time").time())) / 86400
        self.assertLessEqual(durata, human_mcp.MAX_TTL_DAYS + 1)


class RevocationTests(unittest.TestCase):
    """Una revoca che nessuno legge è peggio di una revoca assente: chiude la
    questione nella testa di chi la usa mentre il token continua a valere."""

    def test_revoking_takes_effect_on_the_next_call(self):
        with _Datadir(), patch.object(human_mcp.pki_mint, "mint_session_token", _mint):
            r = human_mcp.issue("SEAL-1", "x", "giovanni", provider="p",
                                carrier="clodia")
            self.assertFalse(human_mcp.is_revoked(r["id"]))
            human_mcp.revoke(r["id"])
            self.assertTrue(human_mcp.is_revoked(r["id"]))

    def test_an_unknown_mcp_id_fails_closed(self):
        """Un id `mcp_` che non sta nel registro è un grant sparito — dopo un
        ripristino parziale del datadir, per esempio. Rifiutare è l'unica
        direzione sicura."""
        with _Datadir():
            self.assertTrue(human_mcp.is_revoked("mcp_deadbeef"))

    def test_a_normal_agent_token_is_not_touched(self):
        """`execution_id` lo portano TUTTI i token. Se questa funzione dicesse
        `True` per un id qualunque, il gateway smetterebbe di rispondere a ogni
        agente della colonia: il difetto peggiore sarebbe qui."""
        with _Datadir():
            self.assertFalse(human_mcp.is_revoked("exec-1234"))
            self.assertFalse(human_mcp.is_revoked(""))
            self.assertFalse(human_mcp.is_revoked(None))

    def test_the_registry_never_returns_the_token(self):
        """Il valore si consegna una volta. Un registro che lo rilegge è un
        secondo posto da cui può uscire."""
        with _Datadir(), patch.object(human_mcp.pki_mint, "mint_session_token", _mint):
            human_mcp.issue("SEAL-1", "x", "giovanni", provider="p", carrier="clodia")
            righe = human_mcp.list_grants("SEAL-1", "x")
        self.assertEqual(len(righe), 1)
        self.assertNotIn("token", righe[0])
        self.assertEqual(righe[0]["principal"], "giovanni")

    def test_a_revoked_grant_is_hidden_but_not_lost(self):
        with _Datadir(), patch.object(human_mcp.pki_mint, "mint_session_token", _mint):
            r = human_mcp.issue("SEAL-1", "x", "g", provider="p", carrier="clodia")
            human_mcp.revoke(r["id"])
            self.assertEqual(human_mcp.list_grants("SEAL-1", "x"), [])
            self.assertEqual(len(human_mcp.list_grants("SEAL-1", "x",
                                                       include_revoked=True)), 1)


class ConfigTests(unittest.TestCase):
    def test_the_fragment_is_a_url_and_a_header(self):
        cfg = human_mcp.client_config("https://venere:8642/", "ckt1.x.y",
                                      "SEAL-1", "proof-of-flex")
        srv = cfg["mcpServers"]["clodia-proof-of-flex"]
        self.assertEqual(srv["url"], "https://venere:8642/mcp")
        self.assertEqual(srv["headers"]["Authorization"], "Bearer ckt1.x.y")


if __name__ == "__main__":
    unittest.main()
