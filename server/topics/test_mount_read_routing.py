"""Una cartella montata che si naviga si deve anche leggere.

Il difetto, visto sul topic `hedge-iot-new` il 3 set 2026: `topic.files`
elencava `drive/40-budget/…`, e `topic.read_file` / `topic.fetch` /
`topic.read_document` rispondevano `NotFound` su **ogni** file dentro il mount.
Un agente lo ha letto come «i byte non sono materializzati sul gateway», che
sembrava un guasto di sincronizzazione ed era invece un instradamento sbagliato:
`read_file` cadeva nel ramo control-plane e cercava i byte nel filesystem locale
del topic, dove per un mount `live` non ci sono.

La decisione «questo path è albero dati o control-plane?» era scritta a mano in
tre punti, e i tre punti sono divergiti:

    list_files    first in _MOUNTS or first in _mount_names(meta) or files/…
    read_file     first in _MOUNTS                               or files/…
    delete_file   first in _MOUNTS or first == "files"

`_MOUNTS` contiene i due mount STATICI (`local`, `remote`), non quelli
dichiarati nel meta — quindi `drive/x` passava solo dal primo. Il risultato era
un topic **scrivibile e non leggibile**: `put_file` il nome del mount lo
gestiva.

Questi test fissano le tre proprietà: si legge ciò che si elenca, si cancella
ciò che si legge, e il control-plane resta fuori dall'albero dati.
"""
from __future__ import annotations

import tempfile
import unittest

from .local_fs import LocalFsStorage
from .service import TopicService, TopicError


class _FintoMount(LocalFsStorage):
    """Un secondo storage, per distinguere «mount» da «filesystem del topic».

    Serve un backend DIVERSO da quello del topic: se il mount risolvesse sullo
    stesso albero locale, il test passerebbe anche col difetto — i byte si
    troverebbero comunque, e non proverebbe niente.
    """


class MountMontatoAlPrimoLivello(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.remoto = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.remoto.cleanup)
        self.svc = TopicService(LocalFsStorage(self.tmp.name))
        self.svc.new("SEAL-1", "topico", {"title": "t", "owner": "davide",
                                          "participants": ["davide", "avvocato"]})
        # Un mount chiamato `drive`, come sul topic reale, servito da un altro
        # storage: è il caso che il difetto sbagliava.
        meta, ver = self.svc._read_meta("SEAL-1", "topico")
        # `mounts` è una LISTA in radice al meta (vedi `mounts()`): la forma
        # legacy `remote` come oggetto singolo viene tradotta al confine.
        meta["mounts"] = [{"name": "drive", "type": "drive",
                           "config": {"folder": "F", "name": "cartella"},
                           "mode": "live"}]
        self.svc._write_meta("SEAL-1", "topico", meta, base_version=ver)
        self.magazzino = _FintoMount(self.remoto.name)
        self.magazzino.write("radice/40-budget/README.txt", b"contenuto vero")
        self.svc._remote_mount = lambda t, n, m: (self.magazzino, "radice")  # type: ignore[assignment]

    def test_il_file_elencato_si_legge(self) -> None:
        """IL CASO SEGNALATO: navigabile e illeggibile insieme."""
        voci = self.svc.list_files("SEAL-1", "topico", "drive/40-budget")
        self.assertTrue(any("README.txt" in str(v.get("path") or v.get("name"))
                            for v in voci), voci)
        self.assertEqual(b"contenuto vero",
                         self.svc.read_file("SEAL-1", "topico", "drive/40-budget/README.txt"))

    def test_il_notfound_non_arrivava_dal_mount(self) -> None:
        """Col difetto l'errore nominava il path LOCALE del topic — cioè era il
        filesystem del topic a rispondere, non il mount. È il dettaglio che
        distingue «backend giù» da «instradamento sbagliato», e quello che ha
        fatto leggere il guasto come un problema di sincronizzazione."""
        with self.assertRaises(Exception) as ctx:
            self.svc.read_file("SEAL-1", "topico", "drive/40-budget/inesistente.txt")
        self.assertNotIn("SEAL-1/topico/drive", str(ctx.exception))

    def test_scrivibile_e_leggibile_sono_lo_stesso_posto(self) -> None:
        """`put_file` gestiva già il nome del mount: il topic era scrivibile e
        non leggibile, che è il modo più confondente di essere rotto."""
        self.svc.put_file("SEAL-1", "topico", "drive/nota.txt", b"scritto", "agent", "avvocato")
        self.assertEqual(b"scritto",
                         self.svc.read_file("SEAL-1", "topico", "drive/nota.txt"))

    def test_si_cancella_ciò_che_si_legge(self) -> None:
        self.svc.put_file("SEAL-1", "topico", "drive/vecchio.txt", b"x", "agent", "a")
        self.svc.delete_file("SEAL-1", "topico", "drive/vecchio.txt")

    def test_lalias_remote_continua_a_risolvere(self) -> None:
        """Lo schema fino al 12 ago 2026 compare in messaggi già inviati."""
        self.assertEqual(b"contenuto vero",
                         self.svc.read_file("SEAL-1", "topico",
                                            "remote/drive/40-budget/README.txt"))


class IlControlPlaneRestaFuori(unittest.TestCase):
    """Il predicato unico non deve aver allargato ciò che conta come dato."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.svc = TopicService(LocalFsStorage(self.tmp.name))
        self.svc.new("SEAL-1", "topico", {"title": "t", "owner": "davide"})

    def test_il_summary_si_legge_ma_non_e_un_file_dei_dati(self) -> None:
        meta, _ = self.svc._read_meta("SEAL-1", "topico")
        self.assertFalse(self.svc._is_data_path(meta, "summary.md"))
        self.assertFalse(self.svc._is_data_path(meta, "meta.json"))
        self.assertIsInstance(self.svc.read_file("SEAL-1", "topico", "summary.md"), bytes)

    def test_il_summary_non_si_cancella_come_un_file(self) -> None:
        with self.assertRaises(TopicError):
            self.svc.delete_file("SEAL-1", "topico", "summary.md")

    def test_un_path_nudo_resta_control_plane(self) -> None:
        """Spostarlo sull'albero dati cambierebbe in silenzio il bersaglio di
        riferimenti già scritti: un cambio di significato senza errore."""
        meta, _ = self.svc._read_meta("SEAL-1", "topico")
        self.assertFalse(self.svc._is_data_path(meta, "documento.pdf"))

    def test_i_mount_statici_e_files_restano_dati(self) -> None:
        meta, _ = self.svc._read_meta("SEAL-1", "topico")
        for p in ("local/x.txt", "files/x.txt", "files", "remote/drive/x"):
            self.assertTrue(self.svc._is_data_path(meta, p), p)


class UnSoloPuntoDecide(unittest.TestCase):
    """Guard strutturale: il difetto è nato dalla decisione duplicata.

    Rimetterla in linea in uno dei tre punti la fa divergere di nuovo, e la
    divergenza è invisibile finché qualcuno non monta una cartella e prova a
    leggerla — cioè settimane dopo.
    """

    def test_nessuno_controlla_i_mount_a_mano(self) -> None:
        from pathlib import Path
        src = (Path(__file__).parent / "service.py").read_text()
        colpevoli = [i for i, r in enumerate(src.splitlines(), 1)
                     if "in self._MOUNTS" in r and "_is_data_path" not in r
                     and "def _is_data_path" not in r]
        # L'unica occorrenza ammessa è DENTRO `_is_data_path`.
        dentro = [i for i, r in enumerate(src.splitlines(), 1)
                  if r.strip().startswith("return bool(first)")]
        residui = [i for i in colpevoli if not dentro or abs(i - dentro[0]) > 3]
        self.assertEqual([], residui,
                         f"controllo dei mount fatto a mano alle righe {residui}: "
                         "usa _is_data_path, o i punti divergono di nuovo")


if __name__ == "__main__":
    unittest.main()
