import unittest

from mcp.types import (
    BlobResourceContents,
    EmbeddedResource,
    TextContent,
    TextResourceContents,
)

from server.proxy import _response_text


class ResponseTextTests(unittest.TestCase):
    def test_includes_embedded_text_resource(self):
        content = [
            TextContent(type="text", text="downloaded"),
            EmbeddedResource(
                type="resource",
                resource=TextResourceContents(
                    uri="repo://owner/repo/file.txt",
                    mimeType="text/plain",
                    text="file contents",
                ),
            ),
        ]

        self.assertEqual(_response_text(content), "downloaded\nfile contents")

    def test_preserves_empty_embedded_text_resource(self):
        content = [
            TextContent(type="text", text="downloaded empty file"),
            EmbeddedResource(
                type="resource",
                resource=TextResourceContents(
                    uri="repo://owner/repo/empty.txt",
                    mimeType="text/plain",
                    text="",
                ),
            ),
        ]

        self.assertEqual(_response_text(content), "downloaded empty file\n")

    def test_ignores_embedded_binary_resource(self):
        content = [
            TextContent(type="text", text="downloaded binary file"),
            EmbeddedResource(
                type="resource",
                resource=BlobResourceContents(
                    uri="repo://owner/repo/file.bin",
                    mimeType="application/octet-stream",
                    blob="AA==",
                ),
            ),
        ]

        self.assertEqual(_response_text(content), "downloaded binary file")

    def test_reports_when_response_has_no_text(self):
        content = [
            EmbeddedResource(
                type="resource",
                resource=BlobResourceContents(
                    uri="repo://owner/repo/file.bin",
                    mimeType="application/octet-stream",
                    blob="AA==",
                ),
            ),
        ]

        self.assertEqual(_response_text(content), "(nessun contenuto testuale)")


if __name__ == "__main__":
    unittest.main()
