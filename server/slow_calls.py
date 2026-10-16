"""Per-agent cap on concurrent slow tool calls (clodia-platform#553).

Terra, 15 Oct 2026: messaggero fired 50 `email.read` + 16
`email.save_attachment` at once. Each one is an IMAP round trip; the offload
pool went to 32/32 threads and every other caller of the gateway — token
minting, topic reads for the agent-server, other agents' turns — waited behind
one agent's burst.

A burst now queues behind its OWN cap: at most `CAP` slow calls per agent run
at the same time, the rest wait their turn (bounded), and other agents are not
touched. "Slow" means the families that leave the machine: mail, Telegram,
Google, the web.
"""
from __future__ import annotations

import asyncio
import contextlib
import os

#: Families whose calls do network round trips of seconds.
SLOW_PREFIXES = ("email.", "telegram.", "gdrive.", "gdocs.", "gsheets.",
                 "gcalendar.", "web.")


def _int_env(name: str, default: int) -> int:
    try:
        v = int(os.environ.get(name, "") or default)
    except ValueError:
        return default
    return v if v > 0 else default


#: Concurrent slow calls per agent. 4 keeps a burst well under the 32-thread
#: pool while still letting one agent overlap a few round trips.
CAP = _int_env("CLODIA_SLOW_CALLS_PER_AGENT", 4)
#: How long a call may wait for a slot before failing with a clear message.
WAIT_S = float(_int_env("CLODIA_SLOW_CALLS_WAIT_S", 300))

_SEMS: dict[tuple[int, str], asyncio.Semaphore] = {}


def is_slow(verb: str) -> bool:
    return str(verb or "").startswith(SLOW_PREFIXES)


def _sem(agent: str) -> asyncio.Semaphore:
    # Keyed by loop too: a semaphore belongs to the loop it was created on, and
    # tests run several loops in one process.
    key = (id(asyncio.get_running_loop()), agent)
    sem = _SEMS.get(key)
    if sem is None:
        sem = _SEMS[key] = asyncio.Semaphore(CAP)
    return sem


class TooManySlowCalls(RuntimeError):
    """An agent kept more slow calls in flight than its cap for too long."""


@contextlib.asynccontextmanager
async def slot(verb: str, agent: str | None):
    """Hold one of the agent's slow-call slots for the duration of `verb`.

    Non-slow verbs, and calls without an agent identity, pass through."""
    if not agent or not is_slow(verb):
        yield
        return
    sem = _sem(agent)
    try:
        await asyncio.wait_for(sem.acquire(), timeout=WAIT_S)
    except asyncio.TimeoutError:
        raise TooManySlowCalls(
            f"troppe chiamate lente contemporanee per l'agente '{agent}' "
            f"(massimo {CAP} insieme): '{verb}' ha atteso {WAIT_S:.0f}s senza "
            "un posto libero. Fai le chiamate a gruppi più piccoli, una dopo "
            "l'altra.") from None
    try:
        yield
    finally:
        sem.release()
