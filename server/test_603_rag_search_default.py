"""#603: without EU_RAG_SEARCH_URL the gateway's RAG verbs reach the
rag-search container of the stack, never a host outside it."""
import importlib
import os
import unittest
from unittest.mock import patch

from server.tools import eu_corpus


class RagSearchDefaultTest(unittest.TestCase):
    def tearDown(self):
        importlib.reload(eu_corpus)

    def test_default_is_the_rag_search_container(self):
        env = {k: v for k, v in os.environ.items() if k != "EU_RAG_SEARCH_URL"}
        with patch.dict(os.environ, env, clear=True):
            mod = importlib.reload(eu_corpus)
        self.assertEqual(mod._BASE, "http://rag-search:7900")

    def test_the_variable_still_wins(self):
        with patch.dict(os.environ, {"EU_RAG_SEARCH_URL": "http://rag.example:7900/"}):
            mod = importlib.reload(eu_corpus)
        self.assertEqual(mod._BASE, "http://rag.example:7900")


if __name__ == "__main__":
    unittest.main()
