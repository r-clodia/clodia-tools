"""I servizi lungo-vivi dichiarati dai pack (clodia-platform#515).

Fino a oggi il gateway non teneva in piedi nessun processo di pack: i server MCP
si aprono per chiamata (`proxy._session`) e di loro resta in cache solo l'elenco
dei tool. Un connettore che deve *restare* connesso — un listener, un ricevitore
di webhook, un poller — non aveva un posto dove stare.

Qui c'è quel posto. La grammatica `services:` l'ha già fissata #516
(`connectors/manifest.py::Service`): questo package non la riparsa, la consuma.

Tre proprietà che non sono dettagli di implementazione:

* **la verità sta nel registry, non in una lista nostra.** `reconcile()`
  confronta i servizi dichiarati dai pack installati con i processi vivi, e
  quella sola operazione copre l'avvio al boot, l'avvio di un pack appena
  installato e lo spegnimento di un pack rimosso. Non c'è un hook di
  disinstallazione da ricordarsi di chiamare: se il `pack.yaml` non c'è più, il
  servizio non è più dichiarato e viene fermato al giro dopo.
* **l'ambiente si costruisce da zero** (`launch.build_env`), non si filtra
  quello del gateway. Una lista di esclusione dimentica sempre la variabile
  aggiunta domani, e quelle del gateway sono il segreto di bootstrap e il
  percorso della vault.
* **senza isolamento non si parte.** Il drop di privilegi è il comportamento
  predefinito; l'unico modo di avviare un servizio con l'utente del gateway è
  dichiarare `CLODIA_SERVICE_ISOLATION=off`, che esiste per i test e per lo
  sviluppo locale. Un fallback silenzioso a root sarebbe il modo di far
  sembrare funzionante proprio il caso che la issue vuole impedire.
"""
from __future__ import annotations

from .launch import (
    CredentialUnavailable,
    IsolationUnavailable,
    ServiceRefused,
    build_env,
    privileges,
    state_dir,
)
from .supervisor import (
    Supervisor,
    reconcile_loop,
    snapshot,
    stop_all,
    supervisor,
)

__all__ = [
    "CredentialUnavailable",
    "IsolationUnavailable",
    "ServiceRefused",
    "Supervisor",
    "build_env",
    "privileges",
    "reconcile_loop",
    "snapshot",
    "state_dir",
    "stop_all",
    "supervisor",
]
