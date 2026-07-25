from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from . import memory


class MemoryDocumentIndexTest(TestCase):
    def test_document_metadata_is_synchronized_without_content(self) -> None:
        with TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {"CLODIA_DATA": tmp}), \
                    patch.object(memory, "agent_name", return_value="helper"):
                memory.write("# Memory Index\n\nNota esistente.\n")
                memory.put_document_bytes("report.pdf", b"secret payload")

                index = Path(tmp) / "agents" / "helper" / "memory" / "MEMORY.md"
                body = index.read_text()
                self.assertIn("Nota esistente.", body)
                self.assertIn("## Documenti", body)
                self.assertIn("`report.pdf` — 14 B", body)
                self.assertNotIn("secret payload", body)

                self.assertEqual(
                    memory.list_documents()["documents"],
                    [{"name": "report.pdf", "bytes": 14}],
                )
                self.assertEqual(index.read_text().count("## Documenti"), 1)
                memory.delete_document("report.pdf")
                self.assertNotIn("`report.pdf`", index.read_text())

    def test_memory_write_preserves_generated_document_index(self) -> None:
        with TemporaryDirectory() as tmp:
            with patch.dict("os.environ", {"CLODIA_DATA": tmp}), \
                    patch.object(memory, "agent_name", return_value="helper"):
                memory.put_document_bytes("design.docx", b"123")
                memory.write("# Note\n\nAggiornate.")
                body = memory.read()["content"]
                self.assertIn("Aggiornate.", body)
                self.assertIn("`design.docx` — 3 B", body)
