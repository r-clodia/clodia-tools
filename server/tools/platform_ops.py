"""Platform ops — tool MCP di CONTROLLO (non solo lettura) per l'agente sysadmin.

A differenza di `runtime.*` (introspezione read-only), questi tool MUTANO lo stato
della piattaforma: creano/avviano/fermano/cancellano job, importano/rimuovono pack,
controllano le run dei workflow, mettono in pausa/riattivano i provider, osservano
le integration. Sono un proxy sottile verso gli endpoint admin dell'agent-server
(clodia-logic); l'autorizzazione effettiva è la whitelist `tool_permissions`
per-agent applicata dal gateway (oggi: solo `sysadmin` li riceve).

SICUREZZA (Prima Legge): nessun segreto transita da qui. `providers.pause/resume`
agiscono sullo stato di selezione, non toccano il keystore. Niente topic, niente
dati utente: questi tool non hanno superfici verso `topics/`.
"""
from __future__ import annotations

import os

import httpx

# Stesso agent-server di runtime.py (service-name sulla rete compose).
AGENT_SERVER_URL = os.environ.get("AGENT_SERVER_URL", "http://agent-server:7842")

_TIMEOUT = httpx.Timeout(connect=4.0, read=20.0, write=10.0, pool=4.0)


def _req(method: str, path: str, payload: dict | None = None):
    with httpx.Client(timeout=_TIMEOUT) as c:
        r = c.request(method, f"{AGENT_SERVER_URL}{path}",
                      json=payload if payload is not None else None)
        r.raise_for_status()
        # alcuni endpoint (204/delete) possono non avere body JSON
        if r.status_code == 204 or not (r.content or b"").strip():
            return {"ok": True}
        return r.json()


def _get(path: str):
    return _req("GET", path)


# ── Jobs ────────────────────────────────────────────────────────────────────
# NB: nessuna funzione di CREAZIONE/lifecycle diretta qui. Anche gli agent di
# piattaforma (sysadmin) creano job solo via jobs.propose (gate owner): un job è
# esecuzione autonoma ricorrente → deve confermarlo l'owner (Prima Legge).
# L'osservazione dei job è runtime.jobs; la proposta è runtime.propose_job.


# ── Packs ───────────────────────────────────────────────────────────────────

def packs_list():
    return _get("/clodia/packs")


def packs_show(name: str):
    return _get(f"/clodia/packs/{name}")


def packs_import_url(url: str):
    """Importa un pack da URL (repo pubblico / zip). L'import da file .zip caricato
    resta un'operazione della UI (upload multipart)."""
    return _req("POST", "/clodia/packs/import-url", {"url": url})


def packs_remove(name: str):
    return _req("DELETE", f"/clodia/packs/{name}")


# ── Workflows ───────────────────────────────────────────────────────────────

def workflows_list():
    return _get("/clodia/workflows")


def workflows_status(run_id: str):
    return _get(f"/clodia/workflows/runs/{run_id}")


def workflows_start(plugin: str, name: str, title: str = "", params: str = ""):
    return _req("POST", f"/clodia/workflows/{plugin}/{name}/start",
                {"title": title, "params": params})


def workflows_cancel(run_id: str, note: str = ""):
    """Ferma/termina una run in esecuzione."""
    return _req("POST", f"/clodia/workflows/runs/{run_id}/cancel", {"note": note})


def workflows_delete_run(run_id: str):
    return _req("DELETE", f"/clodia/workflows/runs/{run_id}")


# ── Providers ───────────────────────────────────────────────────────────────

def providers_list():
    return _get("/api/providers")


def providers_pause(pid: str):
    return _req("POST", f"/api/providers/{pid}/pause")


def providers_resume(pid: str):
    return _req("POST", f"/api/providers/{pid}/resume")


# ── Integrations (connettori) ───────────────────────────────────────────────

def integrations_list():
    """Osserva le integration/connettori e il loro stato di connessione. Non legge
    i dati che veicolano: solo id/nome/provider/connected."""
    return _get("/api/connectors")
