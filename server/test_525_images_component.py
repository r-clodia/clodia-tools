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
        with patch.object(loader, "service", return_value=spec) as svc:
            out = image._via_component("generate", "a cat", size="1024x1024",
                                       quality="auto", background="auto")
        svc.assert_called_once_with("it-pack", "imagegen_run")
        self.assertEqual(out, png)
        self.assertNotIn("api_key", seen[0])
        self.assertEqual(seen[0]["op"], "generate")

    def test_a_failing_service_is_an_image_error(self) -> None:
        def boom(a):
            raise RuntimeError("401 bad key sk-SECRET")
        with patch.object(loader, "service", return_value=NS(handler=boom)):
            with self.assertRaises(image.ImageGenError):
                image._via_component("generate", "x", size="1024x1024",
                                     quality="auto", background="auto")


class NoComponentTests(unittest.TestCase):
    def test_without_the_component_there_is_no_image_and_it_says_why(self) -> None:
        """The in-process client is gone (#525): no component, no image."""
        with patch.object(loader, "service", return_value=None), \
                patch.object(loader, "state_of", return_value=None):
            with self.assertRaises(image.ImageGenError) as cm:
                image.generate("a cat")
        self.assertIn("it-pack", str(cm.exception))


class StaleTransportTests(unittest.TestCase):
    def test_imagegen_transport_is_retired(self) -> None:
        from .connectors import builtin
        self.assertIn("imagegen-transport", builtin.RETIRED_TRANSPORTS["it-pack"])


if __name__ == "__main__":
    unittest.main()
