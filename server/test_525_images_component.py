"""#525/#558 — image generation through it-pack's gateway component service."""
from __future__ import annotations

import base64
import unittest
from types import SimpleNamespace as NS
from unittest.mock import patch

from .components import loader
from .tools import image


class ImagesComponentTests(unittest.TestCase):
    def test_the_service_is_used_and_no_key_travels(self) -> None:
        seen = []
        png = b"\x89PNG fake"
        spec = NS(handler=lambda a: seen.append(a) or {"png_b64": base64.b64encode(png).decode()})
        with patch.object(loader, "service", return_value=spec) as svc, \
             patch("server.connectors.resolved.transport_for") as tr:
            out = image._via_transport("generate", "a cat", size="1024x1024",
                                       quality="auto", background="auto")
        svc.assert_called_once_with("it-pack", "imagegen_run")
        tr.assert_not_called()
        self.assertEqual(out, png)
        self.assertNotIn("api_key", seen[0])
        self.assertEqual(seen[0]["op"], "generate")

    def test_a_failing_service_is_an_image_error(self) -> None:
        def boom(a):
            raise RuntimeError("401 bad key sk-SECRET")
        with patch.object(loader, "service", return_value=NS(handler=boom)):
            with self.assertRaises(image.ImageGenError):
                image._via_transport("generate", "x", size="1024x1024",
                                     quality="auto", background="auto")


if __name__ == "__main__":
    unittest.main()
