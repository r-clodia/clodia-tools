"""Inventario RAG non filtrato per grant (pagina "Databases" della webui).

A differenza del verbo MCP `rag.collections` (`_dispatch_rag` in `main.py`),
che filtra per i grant dell'agente chiamante, questa rotta serve un admin che
deve vedere TUTTE le collection esistenti — comprese quelle orfane. Stesso
principio già applicato a `providers_api.py`.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from starlette.applications import Starlette
from starlette.testclient import TestClient

from . import internal_auth, rag_api
from .tools import eu_corpus

_H = {"Authorization": "Bearer ckt1.finto"}
#: Il runner di clodia-logic: `pki.mint_session_token(_PRINCIPAL, ttl)`, e basta
#: — stesso payload minimale di `providers_api`/`test_internal_authz._RUNNER`.
_RUNNER = {"agent": "clodia"}


def _sessione(payload: dict):
    return patch.object(internal_auth, "verify_session_token", lambda _t: payload)


class ListCollectionsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = Starlette(routes=rag_api.routes)
        self.client = TestClient(self.app)

    def test_returns_all_collections_unfiltered(self) -> None:
        dati = {"collections": [
            {"collection": "eu-normativa", "tier": "SEAL-1", "documents": 12, "chunks": 300},
            {"collection": "corpus-orfano", "tier": "SEAL-0", "documents": 2, "chunks": 9},
        ]}
        with _sessione(_RUNNER), patch.object(eu_corpus, "collections", lambda: dati):
            r = self.client.get("/internal/rag/collections", headers=_H)
        self.assertEqual(200, r.status_code)
        self.assertEqual(dati, r.json())

    def test_eu_rag_search_unreachable_is_502_not_500(self) -> None:
        """Un guasto infra dev'essere distinguibile da un errore del gateway
        stesso: la pagina Databases deve poter dire «servizio giù», non
        confonderlo con un bug qui."""
        def _boom():
            raise RuntimeError("eu-rag-search irraggiungibile (http://x): timeout")
        with _sessione(_RUNNER), patch.object(eu_corpus, "collections", _boom):
            r = self.client.get("/internal/rag/collections", headers=_H)
        self.assertEqual(502, r.status_code)

    def test_missing_token_is_401(self) -> None:
        r = self.client.get("/internal/rag/collections")
        self.assertEqual(401, r.status_code)

    def test_non_privileged_principal_is_403(self) -> None:
        with _sessione({"agent": "looper"}):
            r = self.client.get("/internal/rag/collections", headers=_H)
        self.assertEqual(403, r.status_code)


class ListDocumentsTests(unittest.TestCase):
    """I documenti INIETTATI in una collection (clodia-platform#342).

    `eu_corpus.list_documents` esisteva già e la pagina Databases non aveva da
    dove chiamarla: la lista delle collection usciva, il contenuto no.
    """

    def setUp(self) -> None:
        self.app = Starlette(routes=rag_api.routes)
        self.client = TestClient(self.app)

    def test_returns_the_documents_of_the_collection(self) -> None:
        dati = {"collection": "eu-normativa", "documents": [
            {"name": "GDPR", "version": "2016/679", "status": "indexed", "chunks": 120},
        ]}
        visto = {}

        def _docs(collection):
            visto["collection"] = collection
            return dati

        with _sessione(_RUNNER), patch.object(eu_corpus, "list_documents", _docs):
            r = self.client.get("/internal/rag/documents?collection=eu-normativa",
                                headers=_H)
        self.assertEqual(200, r.status_code)
        self.assertEqual(dati, r.json())
        # La collection chiesta è quella servita: senza questo il test passerebbe
        # anche se la rotta leggesse sempre la collection di default.
        self.assertEqual("eu-normativa", visto["collection"])

    def test_missing_collection_is_400_not_the_default_one(self) -> None:
        """`list_documents` ha un default (`eu-normativa`): una richiesta senza
        `collection` risponderebbe 200 con i documenti di un'ALTRA collection —
        un errore del chiamante travestito da risposta valida."""
        with _sessione(_RUNNER), patch.object(eu_corpus, "list_documents",
                                              lambda collection: {"documents": []}):
            r = self.client.get("/internal/rag/documents", headers=_H)
        self.assertEqual(400, r.status_code)

    def test_eu_rag_search_unreachable_is_502_not_500(self) -> None:
        def _boom(collection):
            raise RuntimeError("eu-rag-search irraggiungibile (http://x): timeout")
        with _sessione(_RUNNER), patch.object(eu_corpus, "list_documents", _boom):
            r = self.client.get("/internal/rag/documents?collection=eu-normativa",
                                headers=_H)
        self.assertEqual(502, r.status_code)

    def test_missing_token_is_401(self) -> None:
        r = self.client.get("/internal/rag/documents?collection=eu-normativa")
        self.assertEqual(401, r.status_code)

    def test_non_privileged_principal_is_403(self) -> None:
        with _sessione({"agent": "looper"}):
            r = self.client.get("/internal/rag/documents?collection=eu-normativa",
                                headers=_H)
        self.assertEqual(403, r.status_code)


if __name__ == "__main__":
    unittest.main()
