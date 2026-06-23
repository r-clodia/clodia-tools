"""Agent control tools — spawn other agents via the local agent-server REST API.

Per ora supporta solo `spawn`: crea una nuova chat di un agent-type e le
consegna un primo messaggio. Pensato per il pattern `looper` (esecutore
ciclico) che dispatcha task ad altri agent (es. ada).
"""
from __future__ import annotations

import httpx

from ..whitelist import tool_allowed

AGENT_SERVER_URL = "http://127.0.0.1:7842"
_KNOWN_KINDS = {"clodia", "ada", "looper"}


def spawn(agent_type: str, task: str, wait_for_reply: bool = False) -> dict:
    """Spawna una nuova chat dell'agent-type indicato e le consegna `task`
    come primo messaggio utente.

    Default fire-and-forget (wait_for_reply=False): l'agent-server accoda il
    messaggio e ritorna subito; lo spawned agent lo processa in background
    e l'output va a finire negli SSE / history JSONL della sua chat.
    Usato dal looper per dispacciare task ad ada senza bloccare il proprio
    ciclo di 60s.

    Con wait_for_reply=True il caller resta in attesa della risposta
    completa (timeout 10 min lato server) — usalo solo per task brevi
    e quando ti serve davvero il return dell'agent.
    """
    tool_allowed("agent.spawn")
    kind = agent_type.strip().lower()
    if kind not in _KNOWN_KINDS:
        raise ValueError(
            f"unknown agent_type '{agent_type}'; available: {sorted(_KNOWN_KINDS)}"
        )
    if not task or not task.strip():
        raise ValueError("task must be a non-empty string")

    # read timeout: 30s è sufficiente in entrambe le modalità per la creazione
    # chat + l'enqueue (in modalità wait il default era 10min ma in fire-and-
    # forget non aspettiamo il completion). Manteniamo 600s solo per il caso
    # raro wait_for_reply=True.
    read_timeout = 600.0 if wait_for_reply else 30.0
    with httpx.Client(timeout=httpx.Timeout(connect=5.0, read=read_timeout, write=15.0, pool=5.0)) as c:
        # 1. Create chat of the requested kind
        r = c.post(f"{AGENT_SERVER_URL}/clodia/chats", json={"kind": kind})
        r.raise_for_status()
        chat = r.json()
        chat_id = chat["chat_id"]

        # 2. Send first message (fire-and-forget o sync)
        url = f"{AGENT_SERVER_URL}/clodia/chats/{chat_id}/messages"
        if not wait_for_reply:
            url += "?wait=false"
        r2 = c.post(url, json={"content": task})
        r2.raise_for_status()
        result = r2.json()
        out: dict = {
            "ok": True,
            "chat_id": chat_id,
            "kind": kind,
            "title": chat.get("title"),
            "queued": result.get("queued", False),
        }
        if wait_for_reply:
            out["response"] = result.get("response", "")
        return out
