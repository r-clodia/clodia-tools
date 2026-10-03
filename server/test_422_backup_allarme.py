"""Un backup che non verifica più niente e dice «ok» (clodia-platform#422).

Osservato il 27 set 2026 sull'istanza personale: per **14 giorni** il backup
notturno ha prodotto uno snapshot al giorno, e per 14 giorni nessuno ha
verificato né potato il repository. Un lock restic rimasto appeso dal 13
settembre (PID 984 in un container che non esiste più) faceva uscire `check`
con 11 — «repository is already locked» — e con lui `forget --prune`: la
retention non girava e l'integrità non era mai controllata.

Il guasto che è costato i 14 giorni però non è il lock: è che **nessuno l'ha
detto**. `run_backup()` tornava `{"ok": false, "check_rc": 11}` senza sollevare,
il job notturno leggeva una risposta HTTP andata a buon fine e registrava
`last_status: ok`, e la notifica Telegram di errore non partiva mai. Lo stato
diceva `ok: false` ogni notte, il job diceva `ok`.

Tre difetti distinti, tre misure:
  1. un esito non-ok di un verbo logico è un **fallimento dello step** — il job
     deve diventare rosso e la notifica partire;
  2. un lock PROVATAMENTE morto si rimuove e si riprova, invece di restare
     bloccati per settimane (restic rinfresca il lock di un run vivo ogni ~5
     minuti: un lock che non si rinfresca da ore non ha più un proprietario);
     un lock FRESCO invece è un run concorrente e non si tocca — si dice.
  3. un restore-test che non gira da più di 8 giorni è un allarme, non un
     silenzio: il notturno lo controlla ogni notte, perché il settimanale che
     non parte non può accorgersi da solo di non essere partito.

Resta fermo ciò che è stato deciso il 4 set 2026 (`test_backup_incomplete.py`):
uno snapshot INCOMPLETO è tollerato e dichiarato, non è un fallimento.
"""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from . import backup, logic_api


def _cp(rc: int, err: str = "", out: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=["restic"], returncode=rc,
                                       stdout=out, stderr=err)


def _lock(ore_fa: float, hostname: str = "35b58680ee69", pid: int = 984,
          exclusive: bool = False) -> dict:
    t = datetime.now(timezone.utc) - timedelta(hours=ore_fa)
    # restic scrive i nanosecondi: è la forma che il parser deve reggere.
    return {"time": t.strftime("%Y-%m-%dT%H:%M:%S.") + "690411382Z",
            "exclusive": exclusive, "hostname": hostname, "username": "root",
            "pid": pid, "uid": 0, "gid": 0}


class _Restic:
    """restic sostituito, con i lock del repository."""

    def __init__(self, *, backup_rc: int = 0, forget_rc: int = 0, check_rc: int = 0,
                 locks: tuple[dict, ...] = (), unlock_rc: int = 0,
                 check_rc_dopo_unlock: int = 0, err: str = ""):
        self.comandi: list[str] = []
        self.backup_rc, self.forget_rc, self.check_rc = backup_rc, forget_rc, check_rc
        self.check_rc_dopo = check_rc_dopo_unlock
        self.unlock_rc, self.err = unlock_rc, err
        self.locks = {f"{i}" * 64: l for i, l in enumerate(locks)}
        self.sbloccato = False

    def __call__(self, args, cfg, timeout=1800):
        verbo = args[0]
        self.comandi.append(verbo)
        if verbo == "backup":
            return _cp(self.backup_rc, self.err)
        if verbo == "forget":
            return _cp(self.forget_rc)
        if verbo == "check":
            return _cp(self.check_rc_dopo if self.sbloccato else self.check_rc)
        if verbo == "list":
            return _cp(0, out="\n".join(self.locks) + "\n")
        if verbo == "cat":
            return _cp(0, out=json.dumps(self.locks[args[2]]))
        if verbo == "unlock":
            if self.unlock_rc == 0:
                self.sbloccato, self.locks = True, {}
            return _cp(self.unlock_rc)
        if verbo == "snapshots":
            return _cp(0, out="[]")
        return _cp(0)


_CFG = {"backend": "s3", "repository": "s3:esempio", "passphrase": "x", "env": {},
        "retention": {"daily": 7, "weekly": 4, "monthly": 6}, "schedule": "0 3 * * *"}


class _Mondo:
    """restic finto + vault finto. Il vault è un dizionario: nessun test deve
    poter scrivere nella vault vera dell'istanza."""

    def __init__(self, r: _Restic, vault_iniziale: dict | None = None):
        self.r = r
        self.vault: dict = dict(vault_iniziale or {})
        self.registrato: list[tuple] = []

    def __enter__(self):
        def _dep(cred, bundle, **kw):
            self.vault[cred] = bundle

        self._p = [
            patch.object(backup, "_run", self.r),
            patch.object(backup, "_cfg", lambda: _CFG),
            patch.object(backup, "_snapshot_dbs", lambda _c: None),
            patch.object(backup.vault, "has_credential", lambda c: c in self.vault),
            patch.object(backup.vault, "read_internal", lambda c: self.vault[c]),
            patch.object(backup.vault, "deposit", _dep),
            patch.object(backup, "_record_last_run",
                         lambda ok, err="": self.registrato.append((ok, err))),
        ]
        for p in self._p:
            p.start()
        return self

    def __exit__(self, *a):
        for p in self._p:
            p.stop()
        return False


class UnLockMortoNonBloccaPerQuattordiciGiorni(unittest.TestCase):

    def test_il_caso_osservato_lock_vecchio_rimosso_e_check_ritentato(self):
        """13 set → 27 set: `check` usciva 11 ogni notte e nessuno sbloccava."""
        r = _Restic(check_rc=11, locks=(_lock(ore_fa=336),))
        with _Mondo(r) as m:
            res = backup.run_backup()
        self.assertIn("unlock", r.comandi)
        self.assertTrue(res["ok"], res)
        self.assertTrue(res["unlocked"])
        self.assertTrue(m.registrato[-1][0])

    def test_un_run_concorrente_non_viene_sbloccato(self):
        """Un lock FRESCO ha un proprietario vivo: toglierlo è corrompere il
        repository di qualcun altro. Si lascia stare e si dichiara."""
        r = _Restic(check_rc=11, locks=(_lock(ore_fa=0.1, hostname="altro"),))
        with _Mondo(r) as m:
            res = backup.run_backup()
        self.assertNotIn("unlock", r.comandi)
        self.assertFalse(res["ok"])
        self.assertTrue(any(not l["stale"] for l in res["locks"]))

    def test_il_motivo_del_blocco_finisce_nello_stato(self):
        """«check_rc=11» da solo non dice a nessuno cosa fare: serve da quando
        e di chi è il lock."""
        r = _Restic(check_rc=11, locks=(_lock(ore_fa=0.1, hostname="altro"),))
        with _Mondo(r) as m:
            backup.run_backup()
        ok, err = m.registrato[-1]
        self.assertFalse(ok)
        self.assertIn("bloccato", err)
        self.assertIn("altro", err)

    def test_il_percorso_felice_non_tocca_i_lock(self):
        """Nessun `list locks` e nessun `unlock` preventivo: i lock si guardano
        solo quando restic dice davvero di essere bloccato (rc 11)."""
        r = _Restic()
        with _Mondo(r):
            backup.run_backup()
        self.assertEqual(["backup", "forget", "check"], r.comandi)

    def test_anche_forget_viene_sbloccato(self):
        """La retention è la metà del danno: 58 snapshot non potati in 14
        giorni. `forget` prende il lock esclusivo, ed è il primo a cadere."""
        r = _Restic(forget_rc=11, locks=(_lock(ore_fa=336),))
        with _Mondo(r):
            backup.run_backup()
        self.assertEqual(r.comandi.count("unlock"), 1)
        self.assertEqual(r.comandi[-1], "check")

    def test_un_lock_illeggibile_non_fa_esplodere_il_run(self):
        """Diagnostica: se non si riesce a leggere un lock si prosegue, non si
        perde il backup."""
        r = _Restic(check_rc=11, locks=(_lock(ore_fa=336),))

        def _rotto(args, cfg, timeout=1800):
            if args[0] == "cat":
                return _cp(1, err="boom")
            return _Restic.__call__(r, args, cfg, timeout)

        with _Mondo(r):
            with patch.object(backup, "_run", _rotto):
                res = backup.run_backup()
        self.assertFalse(res["ok"])

    def test_il_timestamp_coi_nanosecondi_si_legge(self):
        """restic scrive 9 cifre di frazione: `fromisoformat` non le regge e un
        lock illeggibile tornerebbe «non stale» per sempre."""
        t = backup._parse_restic_time("2026-09-13T21:19:02.690411382Z")
        self.assertIsNotNone(t)
        self.assertEqual((t.year, t.month, t.day, t.hour), (2026, 9, 13, 21))


class UnaRetentionCheNonGiraNonEUnBackupRiuscito(unittest.TestCase):

    def test_forget_fallito_non_passa_per_ok(self):
        """`forget` non applicato = retention non applicata. Era invisibile:
        `ok` guardava solo `check`."""
        with _Mondo(_Restic(forget_rc=1)) as m:
            res = backup.run_backup()
        self.assertFalse(res["ok"])
        self.assertFalse(m.registrato[-1][0])


class IlRestoreTestCheNonGiraDeveFarsiSentire(unittest.TestCase):

    def test_un_restore_test_riuscito_lascia_la_data(self):
        with _Mondo(_Restic()) as m:
            with patch.object(backup, "_restore_test",
                              lambda: {"ok": True, "restored_topics": 168}):
                backup.restore_test()
        self.assertIn(backup.RESTORE_CRED, m.vault)
        self.assertTrue(m.vault[backup.RESTORE_CRED]["ok"])

    def test_un_restore_test_fallito_non_sposta_la_data(self):
        """Se un fallimento resettasse il contatore, 8 settimane di restore-test
        falliti sembrerebbero 8 settimane di restore-test freschi."""
        vecchio = {"time": (datetime.now(timezone.utc) - timedelta(days=30)
                            ).isoformat(timespec="seconds"), "ok": True}
        with _Mondo(_Restic(), {backup.RESTORE_CRED: vecchio}) as m:
            with patch.object(backup, "_restore_test",
                              lambda: {"ok": False, "restored_topics": 0}):
                backup.restore_test()
        self.assertEqual(m.vault[backup.RESTORE_CRED], vecchio)

    def test_senza_nessun_record_il_notturno_scrive_la_baseline_e_non_fallisce(self):
        """Prima notte dopo il deploy: non c'è storia. Non si inventa un
        allarme, si pianta il paletto da cui contare."""
        with _Mondo(_Restic()) as m:
            fr = backup.restore_test_freshness(write_baseline=True)
        self.assertFalse(fr["overdue"])
        self.assertFalse(fr["known"])
        self.assertIn(backup.RESTORE_CRED, m.vault)

    def test_la_lettura_di_stato_non_scrive_la_baseline(self):
        with _Mondo(_Restic()) as m:
            backup.restore_test_freshness()
        self.assertNotIn(backup.RESTORE_CRED, m.vault)

    def test_nove_giorni_senza_restore_test_sono_in_ritardo(self):
        vecchio = {"time": (datetime.now(timezone.utc) - timedelta(days=9)
                            ).isoformat(timespec="seconds"), "ok": True}
        with _Mondo(_Restic(), {backup.RESTORE_CRED: vecchio}):
            fr = backup.restore_test_freshness()
        self.assertTrue(fr["overdue"])
        self.assertGreaterEqual(fr["days"], 8)

    def test_sette_giorni_vanno_bene(self):
        """Il settimanale gira di sabato: la soglia deve lasciargli un giorno di
        slittamento prima di gridare."""
        rec = {"time": (datetime.now(timezone.utc) - timedelta(days=7)
                        ).isoformat(timespec="seconds"), "ok": True}
        with _Mondo(_Restic(), {backup.RESTORE_CRED: rec}):
            self.assertFalse(backup.restore_test_freshness()["overdue"])


class LoStatoDiceQuelCheSta(unittest.TestCase):

    def test_status_dichiara_il_lock_e_da_quando(self):
        r = _Restic(locks=(_lock(ore_fa=336),))
        with _Mondo(r):
            st = backup.status()
        self.assertTrue(st["locks"])
        self.assertTrue(st["locks"][0]["stale"])
        self.assertIn("time", st["locks"][0])

    def test_status_dice_quando_e_andato_l_ultimo_restore_test(self):
        rec = {"time": (datetime.now(timezone.utc) - timedelta(days=9)
                        ).isoformat(timespec="seconds"), "ok": True}
        with _Mondo(_Restic(), {backup.RESTORE_CRED: rec}):
            st = backup.status()
        self.assertTrue(st["restore_test"]["overdue"])


class _Req:
    def __init__(self, body: dict, secret: str = "segreto"):
        self.headers = {"x-orchestrator-secret": secret}
        self._b = body

    async def json(self):
        return self._b


def _logic(verb: str) -> dict:
    os.environ["CLODIA_ORCHESTRATOR_SECRET"] = "segreto"
    resp = asyncio.run(logic_api.logic_run(_Req({"verb": verb})))
    return json.loads(bytes(resp.body))


class IlJobNotturnoDeveDiventareROSSO(unittest.TestCase):
    """IL difetto della issue: 14 notti con `check_rc: 11` e `last_status: ok`."""

    def test_un_backup_non_ok_fa_fallire_lo_step(self):
        with patch.object(backup, "run_backup",
                          lambda: {"ok": False, "check_rc": 11, "backup_rc": 0}):
            with patch.object(backup, "restore_test_freshness",
                              lambda **k: {"known": True, "overdue": False, "days": 1.0}):
                out = _logic("settings.backup_run")
        self.assertFalse(out["ok"])
        self.assertIn("11", out["error"])

    def test_uno_snapshot_incompleto_resta_un_successo(self):
        """La decisione del 4 set 2026 non si tocca: incompleto è tollerato e
        dichiarato, non è un fallimento."""
        with patch.object(backup, "run_backup",
                          lambda: {"ok": True, "incomplete": True,
                                   "skipped": "permission denied: titulon-tech"}):
            with patch.object(backup, "restore_test_freshness",
                              lambda **k: {"known": True, "overdue": False, "days": 1.0}):
                out = _logic("settings.backup_run")
        self.assertTrue(out["ok"])
        self.assertTrue(out["result"]["incomplete"])

    def test_un_restore_test_vecchio_fa_fallire_il_notturno(self):
        """Il settimanale che non parte non può accorgersene da solo: se ne
        accorge il notturno, che parte tutte le notti."""
        with patch.object(backup, "run_backup", lambda: {"ok": True}):
            with patch.object(backup, "restore_test_freshness",
                              lambda **k: {"known": True, "overdue": True, "days": 14.0,
                                           "max_days": 8}):
                out = _logic("settings.backup_run")
        self.assertFalse(out["ok"])
        self.assertIn("restore-test", out["error"])

    def test_senza_storia_il_notturno_non_fallisce_e_pianta_il_paletto(self):
        visto: list[dict] = []

        def _fresh(**kw):
            visto.append(kw)
            return {"known": False, "overdue": False, "baseline_written": True}

        with patch.object(backup, "run_backup", lambda: {"ok": True}):
            with patch.object(backup, "restore_test_freshness", _fresh):
                out = _logic("settings.backup_run")
        self.assertTrue(out["ok"])
        self.assertEqual(visto, [{"write_baseline": True}])

    def test_un_restore_test_fallito_fa_fallire_il_suo_job(self):
        with patch.object(backup, "restore_test",
                          lambda: {"ok": False, "restored_topics": 0}):
            out = _logic("settings.backup_restore_test")
        self.assertFalse(out["ok"])

    def test_un_verbo_che_solleva_resta_un_errore(self):
        with patch.object(backup, "run_backup",
                          lambda: (_ for _ in ()).throw(RuntimeError("niente repo"))):
            out = _logic("settings.backup_run")
        self.assertFalse(out["ok"])
        self.assertIn("niente repo", out["error"])


if __name__ == "__main__":
    unittest.main()
