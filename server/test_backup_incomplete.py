"""Un file che sparisce mentre restic legge non deve buttare via il backup.

Osservato sull'istanza `terra` il 4 set 2026: il backup notturno risultava
FALLITO dal run delle 07:22, con

    error: incomplete metadata for /datadir/spawns/avvocato-27/.agent/memory:
    xattr.list … no such file or directory

Uno spawn (`avvocato-27`) nasce e muore col turno: era nell'elenco quando restic
ha cominciato e non c'era più quando è arrivato a leggerlo. Ma lo snapshot era
stato creato lo stesso — `27fa63c7`, alle 07:21, un minuto prima del «fallito».

Il danno non era il messaggio: restic esce **3** per «snapshot creato, alcuni
file non letti», e il codice trattava qualunque `returncode != 0` come un
fallimento totale. L'eccezione saltava `forget` e `check`, quindi per ogni run
così **la retention non girava e il repository non veniva mai verificato** — e
lo stato diceva che non c'era backup, mentre una copia utilizzabile c'era.

Due misure, perché i difetti sono due:
  1. gli spawn escono dal perimetro — sono copie di lavoro rigenerate, e
     rincorrerle con `xattr` è una gara che si perde;
  2. l'esito 3 è tollerato e DETTO — perché il prossimo file effimero che
     sparisce (una cache, un tmp) non deve rifare lo stesso danno.
"""
from __future__ import annotations

import os
import subprocess
import unittest
from unittest.mock import patch

from . import backup


def _cp(rc: int, err: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=["restic"], returncode=rc,
                                       stdout="", stderr=err)


class _Restic:
    """restic sostituito: si registra COSA gli viene chiesto e in che ordine.

    Il punto della prova è quali comandi vengono eseguiti dopo un backup
    incompleto — `forget` e `check` sono esattamente ciò che il difetto saltava.
    """

    def __init__(self, backup_rc: int = 0, check_rc: int = 0, err: str = ""):
        self.comandi: list[str] = []
        self._rc, self._check_rc, self._err = backup_rc, check_rc, err
        self.excludes: list[str] = []

    def __call__(self, args, cfg, timeout=1800):
        verbo = args[0]
        self.comandi.append(verbo)
        if verbo == "backup":
            self.excludes = [a for i, a in enumerate(args)
                             if i and args[i - 1] == "--exclude"]
            return _cp(self._rc, self._err)
        if verbo == "check":
            return _cp(self._check_rc)
        return _cp(0)


_CFG = {"repository": "s3:esempio", "passphrase": "x", "env": {},
        "retention": {"daily": 7, "weekly": 4, "monthly": 6}}

_ERRORE_REALE = ("error: incomplete metadata for /datadir/spawns/avvocato-27/"
                 ".agent/memory: xattr.list: no such file or directory")


class _Mondo:
    def __init__(self, r: _Restic):
        self.r = r
        self.registrato: list[tuple] = []

    def __enter__(self):
        self._p = [
            patch.object(backup, "_run", self.r),
            patch.object(backup, "_cfg", lambda: _CFG),
            patch.object(backup, "_snapshot_dbs", lambda _c: None),
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


class UnoSnapshotIncompletoEComunqueUnoSnapshot(unittest.TestCase):

    def test_il_run_non_fallisce(self):
        """IL CASO OSSERVATO: uno spawn sparito non è un backup mancato."""
        with _Mondo(_Restic(backup_rc=3, err=_ERRORE_REALE)) as m:
            res = backup.run_backup()
        self.assertTrue(res["ok"])
        self.assertTrue(res["incomplete"])

    def test_retention_e_verifica_girano_lo_stesso(self):
        """È la parte cara del difetto: senza `forget` la retention non gira e
        senza `check` nessuno sa se il repository è integro. Per un file
        effimero si smetteva di fare entrambe."""
        r = _Restic(backup_rc=3, err=_ERRORE_REALE)
        with _Mondo(r):
            backup.run_backup()
        self.assertEqual(["backup", "forget", "check"], r.comandi)

    def test_l_incompletezza_finisce_nello_stato(self):
        """Tollerare non è tacere: se si ripete, si deve poter vedere."""
        with _Mondo(_Restic(backup_rc=3, err=_ERRORE_REALE)) as m:
            backup.run_backup()
        ok, err = m.registrato[-1]
        self.assertTrue(ok)
        self.assertIn("incompleto", err)

    def test_un_fallimento_vero_resta_un_fallimento(self):
        """Il codice 1 è un'altra cosa: niente snapshot, e si solleva."""
        with _Mondo(_Restic(backup_rc=1, err="Fatal: unable to open repository")) as m:
            with self.assertRaises(RuntimeError):
                backup.run_backup()
        self.assertFalse(m.registrato[-1][0])

    def test_un_repository_corrotto_non_passa_per_ok(self):
        """`check` che fallisce è il caso in cui il backup NON è ripristinabile:
        quello deve restare rosso anche con un backup a posto."""
        with _Mondo(_Restic(backup_rc=0, check_rc=1)) as m:
            res = backup.run_backup()
        self.assertFalse(res["ok"])
        self.assertFalse(m.registrato[-1][0])


class GliSpawnEsconoDalPerimetro(unittest.TestCase):

    def test_le_directory_di_spawn_sono_escluse(self):
        r = _Restic()
        with _Mondo(r):
            backup.run_backup()
        import fnmatch
        pattern = backup._spawn_excludes()
        for p in pattern:
            self.assertIn(p, r.excludes)
        self.assertTrue(any(
            fnmatch.fnmatch(os.path.join(backup.DATADIR, "spawns", "avvocato-27"), p)
            for p in pattern))

    def test_il_contatore_degli_ordinali_resta_nel_backup(self):
        """`spawn-seq.json` non è una copia di lavoro: perderlo farebbe
        ripartire la numerazione su nomi già usati. Per questo il pattern
        nomina `<seed>-<n>` e non `spawns/*`."""
        for p in backup._spawn_excludes():
            self.assertFalse(p.endswith(os.path.join("spawns", "*")), p)
            # il pattern non deve poter catturare il file del contatore
            import fnmatch
            self.assertFalse(
                fnmatch.fnmatch(os.path.join(backup.DATADIR, "spawns",
                                             "spawn-seq.json"), p))

    def test_uno_spawn_reale_e_catturato_dal_pattern(self):
        import fnmatch
        pattern = backup._spawn_excludes()
        for nome in ("avvocato-27", "fullstack-dev-111", "clodia-97", "segretario-1"):
            self.assertTrue(
                any(fnmatch.fnmatch(os.path.join(backup.DATADIR, "spawns", nome), p)
                    for p in pattern), nome)

    def test_le_esclusioni_storiche_restano(self):
        r = _Restic()
        with _Mondo(r):
            backup.run_backup()
        for e in backup._EXCLUDES:
            self.assertIn(e, r.excludes)


if __name__ == "__main__":
    unittest.main()
