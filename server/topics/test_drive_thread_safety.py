"""Il backend Drive non si condivide fra thread (crash del 4 ago 2026).

Il service di `google-api-python-client` NON è thread-safe: l'oggetto http tiene
lo stato della connessione TLS. Con tre topic Drive e il polling della vista file
il gateway ha prodotto `[SSL] record layer failure` seguito da
`free(): invalid next size (normal)` — corruzione dello heap glibc: il processo
aborta con exit 0 e senza traceback, docker lo riavvia, e l'utente vede 503
intermittenti senza nessun errore che spieghi perché.

Il test non riproduce la corruzione (non si può, è undefined behaviour): verifica
l'invariante che la impedisce — due thread non ottengono mai lo stesso oggetto.
"""
from __future__ import annotations

import tempfile
import threading
import unittest

from .local_fs import LocalFsStorage
from .service import TopicService


class DriveThreadCacheTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.svc = TopicService(LocalFsStorage(self.tmp.name))

    def test_each_thread_gets_its_own_cache(self):
        # Si confrontano gli OGGETTI e li si tiene vivi: `id()` è unico solo fra
        # oggetti vivi, e un dict raccolto libera l'indirizzo al successivo — il
        # confronto passerebbe o fallirebbe a caso.
        caches = {}

        def grab(tag):
            caches[tag] = self.svc._drive_thread_cache()

        t1 = threading.Thread(target=grab, args=("a",))
        t2 = threading.Thread(target=grab, args=("b",))
        t1.start(); t2.start(); t1.join(); t2.join()
        self.assertEqual(len(caches), 2)
        self.assertIsNot(caches["a"], caches["b"])

    def test_the_same_thread_reuses_its_cache(self):
        """Per-thread non deve significare per-chiamata: costruire un service a
        ogni `list()` renderebbe la navigazione dei file inutilizzabile."""
        self.assertIs(self.svc._drive_thread_cache(), self.svc._drive_thread_cache())

    def test_clearing_touches_only_the_current_thread(self):
        """I backend degli altri thread sono oggetti loro: toccarli da qui sarebbe
        la stessa condivisione che questo cambio elimina. Uno stantio costa una
        chiamata a vuoto; uno toccato costa un crash."""
        self.svc._drive_thread_cache()["k"] = object()
        other: dict = {}

        def in_other():
            self.svc._drive_thread_cache()["k"] = object()
            other["before"] = len(self.svc._drive_thread_cache())
            self.svc._drive_cache_clear()
            other["after"] = len(self.svc._drive_thread_cache())

        t = threading.Thread(target=in_other)
        t.start(); t.join()
        self.assertEqual((other["before"], other["after"]), (1, 0))
        # la cache di QUESTO thread è intatta
        self.assertEqual(len(self.svc._drive_thread_cache()), 1)


if __name__ == "__main__":
    unittest.main()
