"""La migrazione one-shot whitelist→ingress prepara richieste, non concede nulla.

clodia-platform#366, ultimo passo dell'epic #359. Dopo la #365 il relay non
legge più il blocco `<!-- telegram-whitelist -->` nella `MEMORY.md` del
messaggero: chi era autorizzato lì smette di esserlo **in silenzio**. Questo
script legge quella lista un'ultima volta e ne ricava il PIANO degli
`topic.ingress_add` da far approvare all'owner.

Le proprietà che devono reggere, e che qui si inchiodano:

- un uid della lista finisce fra le fonti di uno scope SOLO se è riconoscibile
  nella chat legata a quello scope (la whitelist è del SEED, condivisa da tutte
  le istanze `messaggero-N`: riversarla intera su ogni topic legato sarebbe un
  allargamento silenzioso);
- un uid senza handle non è migrabile, e risulta con il suo motivo — non in un
  log, dove si perde;
- il gruppo stesso diventa `tg:<chat_id>`: il binding esistente è il segnale
  che va reso fonte, non la prova che lo sia;
- ciò che è già vagliato è marcato e non riproposto (la migrazione si rilancia);
- **nessuna scrittura**: il piano non tocca le liste né le `MEMORY.md`, che
  restano il dato sorgente e la prova di cosa era autorizzato prima.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from . import egress
from .tools import migrate_telegram_ingress as MIG


_MEMORY = """# Memory del messaggero

Note varie.

<!-- telegram-whitelist -->
```json
{"111": "command", "222": "dialogue", "333": "command"}
```

Altre note.
"""


class MigrateTelegramIngressTests(unittest.TestCase):

    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.datadir = Path(d.name)

        # Un binding solo, salvo dove il test ne aggiunge un secondo.
        self._write_bindings({"-1001": {"instance": "messaggero-1",
                                        "tier": "SEAL-1", "topic": "acme"}})
        self._write_memory("messaggero", _MEMORY)

        from . import whitelist as wl
        self.cfg = {"agents": {}, "egress_allow": [], "source_allow": [],
                    "scope_egress_allow": {}, "scope_source_allow": {}}
        # Roster: 111 è amministratore con handle, 222 amministratore SENZA
        # handle (caso reale: su Telegram lo username è facoltativo).
        self.roster = {"-1001": [
            {"user": {"id": 111, "username": "alfa_utente", "first_name": "Alfa"},
             "status": "administrator"},
            {"user": {"id": 222, "first_name": "Beta"}, "status": "member"},
            {"user": {"id": 999, "username": "bot_qualsiasi", "is_bot": True},
             "status": "administrator"},
        ]}
        for pt in (patch.dict(os.environ, {"CLODIA_DATA": str(self.datadir)}),
                   patch.object(wl, "CONFIG", self.cfg),
                   patch.object(wl, "save_config", lambda: None),
                   patch.object(egress, "perimeter_addresses", lambda scope=None: set()),
                   patch.object(MIG, "_chat_admins", lambda cid: self.roster.get(str(cid), []))):
            pt.start()
            self.addCleanup(pt.stop)

    # ── utilità di scenario ──────────────────────────────────────────────────

    def _write_bindings(self, d: dict) -> None:
        (self.datadir / "telegram-bindings.json").write_text(
            json.dumps(d), encoding="utf-8")

    def _write_memory(self, seed: str, text: str) -> None:
        mdir = self.datadir / "agents" / seed / "memory"
        mdir.mkdir(parents=True, exist_ok=True)
        (mdir / "MEMORY.md").write_text(text, encoding="utf-8")

    def _buffer(self, chat_id: str, messages: list) -> None:
        d = self.datadir / "channel-relay-state"
        d.mkdir(parents=True, exist_ok=True)
        (d / f"chat_{chat_id}.json").write_text(
            json.dumps({"seen": [], "buffer": messages}), encoding="utf-8")

    def _uris(self, plan: dict, scope: str) -> list:
        for s in plan["scopes"]:
            if s["scope"] == scope:
                return [e["uri"] for e in s["entries"]]
        return []

    def _reasons(self, plan: dict, uid: str) -> list:
        return [n["reason"] for n in plan["not_migrable"] if n["uid"] == str(uid)]

    # ── il caso della issue ──────────────────────────────────────────────────

    def test_handle_risolto_diventa_una_fonte_dello_scope_del_binding(self):
        """IL CASO: uid con handle → `tg:@handle` sullo scope della sua chat."""
        plan = MIG.plan()
        self.assertIn("tg:@alfa_utente", self._uris(plan, "SEAL-1/acme"))

    def test_il_gruppo_stesso_entra_come_fonte(self):
        """Il binding è il segnale che il gruppo VA reso ingress."""
        self.assertIn("tg:-1001", self._uris(plan := MIG.plan(), "SEAL-1/acme"))
        self.assertTrue(any(e["uri"] == "tg:-1001" and e["kind"] == "group"
                            for e in plan["scopes"][0]["entries"]))

    def test_un_uid_senza_handle_non_e_migrabile_e_lo_dice(self):
        """Niente handle → non migrabile, con il motivo. Non un log, una riga."""
        plan = MIG.plan()
        self.assertNotIn("tg:222", str(self._uris(plan, "SEAL-1/acme")))
        reasons = self._reasons(plan, "222")
        self.assertTrue(reasons, "l'uid senza handle deve comparire fra i non migrabili")
        self.assertIn("handle", reasons[0].lower())

    def test_un_uid_mai_visto_non_si_perde(self):
        """333 non è né amministratore né nel buffer: non migrabile, non silenzioso."""
        self.assertTrue(self._reasons(MIG.plan(), "333"))

    def test_il_buffer_del_relay_risolve_chi_non_e_amministratore(self):
        """Seconda fonte per-chat: gli handle AUTENTICATI già visti in chat."""
        self._buffer("-1001", [{"from_id": 333, "from_username": "gamma_utente"}])
        plan = MIG.plan()
        self.assertIn("tg:@gamma_utente", self._uris(plan, "SEAL-1/acme"))
        self.assertFalse(self._reasons(plan, "333"))

    def test_un_uid_di_una_chat_non_autorizza_l_altro_topic(self):
        """La whitelist è del seed: l'attribuzione la fa la chat, non la lista."""
        self._write_bindings({
            "-1001": {"instance": "messaggero-1", "tier": "SEAL-1", "topic": "acme"},
            "-1002": {"instance": "messaggero-2", "tier": "SEAL-1", "topic": "altrove"}})
        self.roster["-1002"] = [
            {"user": {"id": 333, "username": "gamma_utente"}, "status": "member"}]
        plan = MIG.plan()
        self.assertIn("tg:@alfa_utente", self._uris(plan, "SEAL-1/acme"))
        self.assertNotIn("tg:@alfa_utente", self._uris(plan, "SEAL-1/altrove"),
                         "un utente riconosciuto in una chat non è fonte dell'altra")
        self.assertIn("tg:@gamma_utente", self._uris(plan, "SEAL-1/altrove"))

    def test_cio_che_e_gia_vagliato_non_si_ripropone(self):
        """Rilanciabile: la voce già in lista è marcata, non richiesta di nuovo."""
        egress.scope_allow("ingress", "SEAL-1/acme", "tg:@alfa_utente")
        plan = MIG.plan()
        entry = [e for e in plan["scopes"][0]["entries"]
                 if e["uri"] == "tg:@alfa_utente"][0]
        self.assertEqual(entry["status"], "already")
        self.assertNotIn("tg:@alfa_utente", "\n".join(plan["commands"]))

    def test_una_forma_non_concedibile_e_non_migrabile(self):
        """La forma la decide `egress.check_grantable`, non una regex locale."""
        self.roster["-1001"] = [
            {"user": {"id": 111, "username": "ab"}, "status": "member"}]
        plan = MIG.plan()
        self.assertNotIn("tg:@ab", self._uris(plan, "SEAL-1/acme"))
        self.assertTrue(self._reasons(plan, "111"))

    def test_senza_whitelist_il_piano_non_esplode(self):
        """Nessuna lista da migrare: resta il gruppo, nessuna eccezione."""
        self._write_memory("messaggero", "# Memory\n\nsenza blocco\n")
        plan = MIG.plan()
        self.assertEqual(self._uris(plan, "SEAL-1/acme"), ["tg:-1001"])
        self.assertEqual(plan["not_migrable"], [])

    def test_il_roster_irraggiungibile_non_ferma_la_migrazione(self):
        """Un guasto dell'API degrada a «non risolto», non a un crash."""
        def _boom(cid):
            raise RuntimeError("telegram getChatAdministrators HTTP 401")
        with patch.object(MIG, "_chat_admins", _boom):
            self._buffer("-1001", [{"from_id": 111, "from_username": "alfa_utente"}])
            plan = MIG.plan()
        self.assertIn("tg:@alfa_utente", self._uris(plan, "SEAL-1/acme"))
        self.assertTrue(plan["warnings"], "un roster perduto va detto, non ingoiato")

    def test_il_piano_non_scrive_niente(self):
        """Opzione A: prepara le richieste, non le concede."""
        before = json.dumps(self.cfg, sort_keys=True)
        memory = (self.datadir / "agents" / "messaggero" / "memory" / "MEMORY.md")
        mtime = memory.stat().st_mtime
        MIG.plan()
        self.assertEqual(json.dumps(self.cfg, sort_keys=True), before,
                         "il piano ha concesso qualcosa: doveva solo proporlo")
        self.assertEqual(memory.read_text(encoding="utf-8"), _MEMORY)
        self.assertEqual(memory.stat().st_mtime, mtime)

    def test_i_comandi_sono_eseguibili_come_sono(self):
        """Il piano si consegna a un agente: le righe devono bastare a sé."""
        cmds = MIG.plan()["commands"]
        self.assertTrue(any(c.startswith('topic.ingress_add("SEAL-1", "acme", "tg:@alfa_utente")')
                            for c in cmds), cmds)

    def test_il_report_nomina_i_non_migrabili(self):
        """Vanno comunicati esplicitamente: se non sono nel testo, si perdono."""
        p = MIG.plan()
        text = MIG.render(p)
        self.assertIn("222", text)
        self.assertIn("SEAL-1/acme", text)
        for c in p["commands"]:
            self.assertIn(c, text, "un comando del piano non compare nel report")
        self.assertNotIn("nessuno", text.split("## Comandi", 1)[1],
                         "il report dichiara «nessuno» avendo comandi da eseguire")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
