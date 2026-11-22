"""clodia-platform#479 — an unexpected files failure must leave its cause."""
from __future__ import annotations

import logging
import unittest
from unittest.mock import patch

from starlette.applications import Starlette
from starlette.testclient import TestClient

from . import topics_api


class _BrokenTopics:
    def list_files(self, _tier: str, _name: str, _path: str):
        raise RuntimeError("storage offline")


class TopicFilesErrorLogTests(unittest.TestCase):
    def test_unexpected_failure_is_logged_with_context_and_traceback(self):
        records: list[logging.LogRecord] = []

        class Capture(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record)

        logger = logging.getLogger("clodia-tools.topics")
        handler = Capture()
        logger.addHandler(handler)
        try:
            with patch.object(topics_api, "_authorize", return_value=("agent-server", None)), \
                 patch.object(topics_api, "_service", return_value=_BrokenTopics()):
                response = TestClient(
                    Starlette(routes=topics_api.routes), raise_server_exceptions=False
                ).get("/internal/topics/SEAL-2/titulon-tech/files?path=local")
        finally:
            logger.removeHandler(handler)

        self.assertEqual(500, response.status_code)
        errors = [record for record in records if record.levelno == logging.ERROR]
        self.assertEqual(1, len(errors), records)
        self.assertIn("SEAL-2/titulon-tech", errors[0].getMessage())
        self.assertIn("path='local'", errors[0].getMessage())
        self.assertIsNotNone(errors[0].exc_info)
        self.assertIs(errors[0].exc_info[0], RuntimeError)


if __name__ == "__main__":
    unittest.main()
