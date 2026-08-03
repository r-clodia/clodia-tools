"""Modalità OSSERVA: i controlli decidono, registrano e lasciano passare.

Perché esiste. Il modello della trifecta è stato consegnato tutto in un giorno, e
ogni sua taratura — quali destinazioni servono, quante volte scatta un gate, se
`web.fetch` che contamina è troppo aggressivo — è oggi una **congettura mia**, non
un'osservazione. Con i controlli attivi e le whitelist vuote la piattaforma è
usabile ma scomoda, e l'unico modo di scoprire la taratura giusta sarebbe
inciampare in ogni blocco.

Questa modalità invertе il costo: l'owner lavora **come prima**, e ogni punto in
cui un gate *sarebbe* scattato finisce nel registro con `would_gate` /
`would_deny`. Dopo qualche giorno la domanda «quali controlli servono davvero e
con che soglia» si risponde coi numeri.

## Che cosa salta e che cosa NON salta

Salta ciò che chiede a un umano o che nega **in nome della supervisione**:

- i gate sui verbi (M-gate), il gate di contesto, il gate cross-topic;
- il gate sulla destinazione nuova, e il rifiuto quando la destinazione non è in
  whitelist;
- le `denied_tools` per-agente;
- il blocco delle sessioni non presidiate (job).

**NON salta l'autorizzazione**, e la distinzione non è un dettaglio: la whitelist
dei tool, la clearance sul tier, l'appartenenza al topic e il confinamento di rete
restano pieni. Quelli non sono «gate» — sono il confine di ciò che un agente è,
esistevano prima di questo lavoro, e disattivarli non riporterebbe la piattaforma
a «come prima»: la porterebbe in uno stato in cui non è mai stata.

## Perché il nome è brutto

`CLODIA_DANGEROUSLY_SKIP_GATES` si legge male di proposito. Una modalità che
disattiva la supervisione umana non deve poter essere accesa per comodità né
ereditata da un `.env` copiato senza guardare: deve costare una frase che
qualcuno, rileggendo, nota.
"""
from __future__ import annotations

import logging
import os

LOG = logging.getLogger("clodia-tools.observe")

_ENV = "CLODIA_DANGEROUSLY_SKIP_GATES"
_TRUE = ("1", "true", "yes", "on")
_warned = False


def skipping() -> bool:
    """True se i gate sono in sola osservazione."""
    global _warned
    on = (os.environ.get(_ENV) or "").strip().lower() in _TRUE
    if on and not _warned:
        # Una volta per processo, a WARNING: uno stato del genere non deve poter
        # essere in vigore senza che se ne trovi traccia leggendo i log.
        LOG.warning("%s attivo: i gate NON bloccano, vengono solo registrati. "
                    "La whitelist dei tool, la clearance e il confinamento di "
                    "rete restano pieni.", _ENV)
        _warned = True
    return on


def note(kind: str, verb: str, agent: str, *, detail: str = "",
         channel: str | None = None) -> None:
    """Registra un controllo che AVREBBE bloccato, e lascia passare.

    `kind` = `gate` | `deny`. Il record va nella telemetria con esito
    `would_gate`/`would_deny`, così `stats()` risponde a «quali controlli
    sarebbero scattati, quante volte, per chi» — che è l'unica domanda per cui
    questa modalità esiste.
    """
    outcome = "would_gate" if kind == "gate" else "would_deny"
    try:
        from . import telemetry as _tlm
        from .whitelist import current_chat
        _tlm.record(verb, agent, outcome,
                    channel=channel if channel is not None else current_chat(),
                    gated=True, detail=detail)
    except Exception as e:  # noqa: BLE001 — l'osservazione non rompe il turno
        LOG.warning("observe: record non scritto (%s)", str(e)[:120])
    LOG.warning("OBSERVE %s · %s · %s%s", outcome, agent, verb,
                f" · {detail}" if detail else "")
