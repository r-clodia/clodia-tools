"""`profile.fetch`: i byte di un allegato di profilo su file, non nel contesto.

Il ramo BINARIO di `profile.read_file` era l'unico rimasto senza via d'uscita
(clodia-platform#320): `topic.read_file` sopra soglia rifiuta e indirizza a
`topic.fetch`, `memory.get_document` a `memory.fetch`, ma un PDF allegato a un
profilo — un CV, un estratto conto, una carta d'identità — usciva INTERO come
base64 nella risposta, a qualunque dimensione. E un risultato di tool non si
paga una volta: resta nella sessione e lo si ri-legge a ogni azione successiva
del turno, quando non tronca prima la tool-call.

Le proprietà provate qui:

  1. `profile.fetch` scrive i byte in un file dello scratch e nella risposta
     non ne mette nessuno;
  2. la destinazione passa dalla stessa validazione degli altri trasferimenti
     (niente scritture fuori dal cortile dello spawn);
  3. l'ACL del profilo è quella di `read_file` — `fetch` è un'altra strada per
     gli stessi byte, non una porta di servizio sui PII di un altro;
  4. sopra la soglia `read_file` non consegna più base64: rifiuta e dice di
     usare `profile.fetch` (un rifiuto senza alternativa è un vicolo cieco);
  5. sotto soglia il ramo binario resta identico a prima (compatibilità).
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from . import main as M
from . import profile as prof

#: Un binario riconoscibile e non decodificabile come UTF-8.
PICCOLO = b"%PDF-1.7\n" + bytes(range(256)) * 8
#: Sopra la soglia oltre la quale i byte non devono viaggiare come base64.
GRANDE = b"%PDF-1.7\n" + (bytes(range(256)) * ((M._B64_INLINE_CAP // 256) + 8))


class ProfileFetchPortaIByteSuFile(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        os.makedirs(self.root / "spawn-1", exist_ok=True)
        p = patch.object(M, "_SPAWNS_ROOT", str(self.root))
        p.start()
        self.addCleanup(p.stop)

    def _fetch(self, contenuto: bytes = GRANDE, *, dest: str | None = None,
               agent: str = "tizio", caller: str = "tizio", **extra):
        with patch.object(prof, "read_file", lambda *a, **k: contenuto):
            return M._dispatch_profile(
                "profile.fetch",
                {"agent": agent, "filename": "estratto.pdf",
                 "dest": dest if dest is not None
                 else str(self.root / "spawn-1" / "estratto.pdf"), **extra},
                caller)

    def test_i_byte_finiscono_su_file_e_non_nella_risposta(self) -> None:
        dest = str(self.root / "spawn-1" / "estratto.pdf")
        r = self._fetch(dest=dest)
        self.assertEqual(GRANDE, Path(dest).read_bytes())
        self.assertEqual(len(GRANDE), r["bytes"])
        self.assertEqual(dest, r["dest"])
        for campo in ("data", "content", "encoding"):
            self.assertNotIn(campo, r, "i byte non devono rientrare nella risposta")

    def test_le_cartelle_intermedie_le_crea_il_verbo(self) -> None:
        """Chi riceve il path non ha una shell per fare `mkdir -p` prima."""
        dest = str(self.root / "spawn-1" / "giu" / "ancora" / "estratto.pdf")
        self._fetch(dest=dest)
        self.assertEqual(GRANDE, Path(dest).read_bytes())

    def test_una_destinazione_fuori_dallo_scratch_e_rifiutata(self) -> None:
        fuori = str(self.root / "estratto.pdf")   # la radice del cortile, non uno spawn
        with self.assertRaises(ValueError):
            self._fetch(dest=fuori)
        self.assertFalse(Path(fuori).exists(), "rifiutato ma scritto comunque")

    def test_l_acl_del_profilo_e_quella_di_read_file(self) -> None:
        """`fetch` non deve leggere i PII di un altro senza l'ACL di `read_file`."""
        visti: list[tuple] = []

        def spia(caller, target, filename):
            visti.append((caller, target, filename))
            raise PermissionError("non autorizzato")

        with patch.object(prof, "read_file", spia):
            with self.assertRaises(PermissionError):
                M._dispatch_profile(
                    "profile.fetch",
                    {"agent": "altro", "filename": "estratto.pdf",
                     "dest": str(self.root / "spawn-1" / "estratto.pdf")},
                    "tizio")
        self.assertEqual([("tizio", "altro", "estratto.pdf")], visti)
        self.assertFalse((self.root / "spawn-1" / "estratto.pdf").exists())

    def test_senza_agent_il_profilo_e_il_proprio(self) -> None:
        visti: list[tuple] = []
        with patch.object(prof, "read_file",
                          lambda *a: (visti.append(a), PICCOLO)[1]):
            M._dispatch_profile(
                "profile.fetch",
                {"filename": "estratto.pdf",
                 "dest": str(self.root / "spawn-1" / "estratto.pdf")},
                "tizio")
        self.assertEqual([("tizio", "tizio", "estratto.pdf")], visti)


class ReadFileNonRiversaPiuIBinariGrandi(unittest.TestCase):
    def _read(self, contenuto: bytes, **extra):
        with patch.object(prof, "read_file", lambda *a, **k: contenuto):
            return M._dispatch_profile("profile.read_file",
                                       {"agent": "tizio", "filename": "estratto.pdf",
                                        **extra},
                                       "tizio")

    def test_sopra_soglia_rifiuta_e_indirizza_a_profile_fetch(self) -> None:
        r = self._read(GRANDE)
        self.assertFalse(r["ok"])
        self.assertEqual(len(GRANDE), r["size"])
        self.assertNotIn("data", r)
        self.assertIn("profile.fetch", r["error"])
        self.assertIn("estratto.pdf", r["error"])

    def test_sotto_soglia_il_ramo_binario_resta_come_prima(self) -> None:
        import base64
        r = self._read(PICCOLO)
        self.assertEqual("base64", r["encoding"])
        self.assertEqual(PICCOLO, base64.b64decode(r["data"]))


class IlVerboEIlSuoSchemaEsistono(unittest.TestCase):
    def _tool(self, nome: str):
        return {t.name: t for t in M._PROFILE_TOOLS}[nome]

    def test_profile_fetch_e_dichiarato_col_dest(self) -> None:
        t = self._tool("profile.fetch")
        self.assertIn("dest", t.inputSchema["properties"])
        self.assertIn("filename", t.inputSchema["required"])
        self.assertIn("dest", t.inputSchema["required"])

    def test_la_descrizione_di_read_file_manda_a_fetch_per_i_binari(self) -> None:
        """Chi legge lo schema deve trovare la strada PRIMA di sbatterci."""
        self.assertIn("profile.fetch", self._tool("profile.read_file").description)


if __name__ == "__main__":
    unittest.main()
