from __future__ import annotations

import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import httpx

from . import gate
from .tools import web_post


class WebPostTests(unittest.TestCase):
    def test_web_post_is_always_gated(self):
        self.assertTrue(gate.is_gated("web.post"))

    def test_gate_summary_validates_and_hides_query(self):
        summary = web_post.gate_summary({
            "url": "http://192.168.1.139:8799/hook?token=secret",
            "json": {"event": "deploy"},
            "headers": {"X-Request-ID": "42"},
        })
        self.assertIn("POST http://192.168.1.139:8799/hook", summary)
        self.assertIn("payload=", summary)
        self.assertNotIn("secret", summary)

    def test_post_does_not_follow_redirects_and_audits(self):
        with TemporaryDirectory() as tmp:
            seen = {}
            real_client = httpx.Client

            def handler(request: httpx.Request) -> httpx.Response:
                seen["request"] = request
                return httpx.Response(302, headers={"location": "http://internal/next"},
                                      content=b"stop")

            class Client:
                def __init__(self, **kwargs):
                    seen["kwargs"] = kwargs
                    self._client = real_client(
                        transport=httpx.MockTransport(handler), **kwargs
                    )

                def __enter__(self):
                    return self._client

                def __exit__(self, *args):
                    self._client.close()

            with patch.object(web_post.httpx, "Client", Client), \
                    patch.object(web_post, "_resolved_ips", return_value=["192.168.1.139"]), \
                    patch.dict(os.environ, {"CLODIA_VAULT_DIR": tmp}):
                result = web_post.post({
                    "url": "http://192.168.1.139:8799/hook",
                    "json": {"ok": True},
                }, agent="sysadmin")

            self.assertEqual(result["status"], 302)
            self.assertFalse(seen["kwargs"]["follow_redirects"])
            audit = json.loads((Path(tmp) / "web-post-audit.log").read_text().strip())
            self.assertEqual(audit["agent"], "sysadmin")
            self.assertEqual(audit["action"], "web.post")

    def test_rejects_oversized_body_and_unsafe_headers(self):
        with self.assertRaisesRegex(ValueError, "limite"):
            web_post.gate_summary({"url": "https://example.test", "body": "x" * 65537})
        with self.assertRaisesRegex(ValueError, "header non consentito"):
            web_post.gate_summary({
                "url": "https://example.test", "headers": {"Host": "internal"}
            })


if __name__ == "__main__":
    unittest.main()
