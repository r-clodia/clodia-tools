"""Audit trail of the gateway (clodia-platform#425, #431).

The one door through which the platform certifies what happened:

    from server import audit
    audit.emit("tool.call", action="execute", resource="topic.put",
               scope={"topic": "titulon-tech", "tier": "SEAL-2"},
               tool={"name": "topic.put", "parameters_hash": audit.content_hash(raw)})

`emit` builds the canonical record (#425 §1.3), chains and signs it, and
appends it to the store in the gateway STATE directory — the volume the
agent-server does not mount. Content never enters the trail: pass hashes
(`content_hash`), not text.

Failure policy. An audit write that fails is never silent: it is logged at
ERROR, counted, and shown by `status()`. With `CLODIA_AUDIT_FAIL_CLOSED=1` it
also raises `AuditWriteError`, so the caller can refuse the action it could
not record. The default is fail-loud rather than fail-closed, because turning
every verb off on a full disk is a decision for the owner, not a default.
"""
from __future__ import annotations

import asyncio
import contextvars
import logging
import os
import threading
from pathlib import Path

from .. import state_paths
from . import checkpoint as _cp
from . import record
from .keys import Signer
from .record import RecordError, content_hash  # noqa: F401 - public API
from .store import AuditStore

LOG = logging.getLogger("clodia-tools.audit")

DEFAULT_CHECKPOINT_SECONDS = 900


class AuditWriteError(RuntimeError):
    """An audit event could not be recorded (only raised when fail-closed)."""


_lock = threading.Lock()
_store: AuditStore | None = None
_store_root: Path | None = None
_failures = 0
_last_error: str | None = None


def root_dir() -> Path:
    """The store directory. `CLODIA_AUDIT_DIR` overrides (tests, dev)."""
    explicit = (os.environ.get("CLODIA_AUDIT_DIR") or "").strip()
    return Path(explicit) if explicit else state_paths.state_dir() / "audit"


def key_dir() -> Path:
    explicit = (os.environ.get("CLODIA_AUDIT_KEY_DIR") or "").strip()
    return Path(explicit) if explicit else state_paths.state_dir() / "audit-key"


def fail_closed() -> bool:
    return (os.environ.get("CLODIA_AUDIT_FAIL_CLOSED") or "").strip().lower() in ("1", "true", "yes", "on")


def _gateway_version() -> str:
    try:
        from .. import __version__
        return __version__
    except Exception:  # noqa: BLE001
        return "unknown"


def store() -> AuditStore:
    """The process-wide store, re-created if the directory changes (tests)."""
    global _store, _store_root
    root = root_dir()
    with _lock:
        if _store is None or _store_root != root:
            _store = AuditStore(root, Signer(key_dir(), root))
            _store_root = root
        return _store


def emit(event_type: str, *, identity: str = "claims", **fields) -> dict | None:
    """Record one canonical event. Returns it, or None if it could not be written.

    `identity="claims"` (default): actor, agent and scope come from the
    verified claims of the request being served, overriding the caller's
    (#441). `identity="explicit"`: the caller's identity is recorded as given —
    for events the gateway itself originates (a timer, an expiry, a revocation)
    or attributes on signed evidence other than the session (the `by` of a
    CA-signed capability)."""
    global _failures, _last_error
    from . import identity as _identity
    if identity == "claims":
        fields = _identity.merge(fields)
    elif identity != "explicit":
        raise RecordError(f"identity must be 'claims' or 'explicit', not {identity!r}")
    elif isinstance(fields.get("actor"), dict):
        fields = {**fields, "actor": {**fields["actor"],
                                      "source": fields["actor"].get("source") or "caller"}}
    # The turn this event belongs to (#433), when the request comes from a
    # spawn whose turn the agent-server has announced.
    if not fields.get("trace_id"):
        fields = _with_trace(fields)
    try:
        rec = record.build(event_type, **fields)
    except RecordError:
        # A malformed record is a programming error in the caller: loud, always.
        raise
    try:
        return store().append(rec)
    except Exception as exc:  # noqa: BLE001
        _failures += 1
        _last_error = f"{type(exc).__name__}: {exc}"[:300]
        LOG.error("audit: event %s NOT recorded (%s)", event_type, _last_error)
        if fail_closed():
            raise AuditWriteError(_last_error) from exc
        return None


def _with_trace(fields: dict) -> dict:
    """Trace id, parent span and links of an event that did not bring its own.

    Precedence (#433, #463): the announced turn of the calling spawn — the
    signed `execution_id` — always names the trace. The request's W3C
    `traceparent` is the caller's word: on the same trace it is a closer
    parent (a runtime span under the turn span), on another trace it becomes a
    link (the runtime's own OTel trace), and it names the trace only when no
    spawn is behind the request AND the request authenticated as the
    agent-server or the egress proxy (`trace.request_trusted`)."""
    from . import trace as _trace
    try:
        from .. import whitelist as _wl
        spawn = _wl.current_spawn()
    except Exception:  # noqa: BLE001
        spawn = None
    cur = _trace.current(spawn)
    req = _trace.request_parent()
    fields = dict(fields)
    if cur:
        fields["trace_id"] = cur[0]
        if not fields.get("parent_span_id"):
            fields["parent_span_id"] = req[1] if req and req[0] == cur[0] else cur[1]
    elif req and not spawn and _trace.request_trusted():
        # Only a paired component (agent-server, proxy) may NAME the trace of
        # a spawn-less event; anyone else's header stays a link below.
        fields["trace_id"] = req[0]
        if not fields.get("parent_span_id"):
            fields["parent_span_id"] = req[1]
    if req and req[0] != fields.get("trace_id"):
        links = list(fields.get("links") or [])
        links.append({"trace_id": req[0], "span_id": req[1],
                      "attributes": {"link.source": "traceparent"}})
        fields["links"] = links
    return fields


#: The tier of the RESOURCE the current call touches (e.g. the topic of a
#: crosstopic read), set by the dispatch. It can only raise the tier evidence
#: is filed under, never lower it below the channel's.
_RESOURCE_TIER: "contextvars.ContextVar[str | None]" = contextvars.ContextVar(
    "audit_resource_tier", default=None)


def set_resource_tier(tier: str | None):
    return _RESOURCE_TIER.set(tier)


def reset_resource_tier(token) -> None:
    _RESOURCE_TIER.reset(token)


def _channel_tier() -> str | None:
    try:
        from .. import whitelist as _wl
        parts = str(_wl.current_chat() or "").split(":")
        if len(parts) >= 3 and parts[0] == "chan":
            return parts[1]
        return _wl.current_scope_tier()
    except Exception:  # noqa: BLE001
        return None


def current_tier() -> str | None:
    """The tier evidence of the current request is filed under:
    max(channel tier — signed `chat` claim, else scope tier — , tier of the
    resource the call touches). A SEAL-3 topic read from a SEAL-1 channel is
    SEAL-3 evidence. None (→ SEAL-4) when the channel tier is unknown."""
    from . import evidence
    return evidence.max_tier(_channel_tier(), _RESOURCE_TIER.get())


def keep(data: bytes | str, tier: str | None = None) -> str:
    """Put `data` in the evidence store (#445) and return its content hash.

    The hash is the same as `content_hash(data)`, so the trail can reference
    the evidence. Outside any scope the evidence is filed under the most
    restrictive tier. Keeping never fails the caller: on error the hash is
    still returned, and the failure is logged."""
    from . import evidence
    try:
        return evidence.keep(data, tier or current_tier())
    except Exception as exc:  # noqa: BLE001
        LOG.error("audit: evidence not kept (%s)", type(exc).__name__)
        return content_hash(data)


def checkpoint_now() -> dict | None:
    """Sign a checkpoint of the head and export it, if there is anything new."""
    st = store()
    seq, head_hash = st.head()
    last = _cp.last_local(st.root)
    if seq == 0 or (last and int(last["checkpoint"]["seq"]) >= seq):
        return None
    cp = _cp.make(seq, head_hash, st.signer, _gateway_version())
    exports = []
    for ex in _cp.exporters():
        try:
            ex.export(cp)
            exports.append({**ex.describe(), "ok": True})
        except Exception as exc:  # noqa: BLE001 - one exporter must not stop the others
            exports.append({**ex.describe(), "ok": False, "error": str(exc)[:200]})
            LOG.error("audit: checkpoint %s NOT exported to %s (%s)",
                      seq, ex.describe().get("type"), exc)
    _cp.append_local(st.root, cp, exports)
    return {"checkpoint": cp, "exports": exports}


def _isolated(root: Path) -> bool:
    """True if the store is NOT under the datadir the agent-server mounts."""
    try:
        root.resolve().relative_to(state_paths.shared_dir().resolve())
        return False
    except ValueError:
        return True


def status() -> dict:
    """Health of the trail, in words an owner can act on. No secrets."""
    try:
        st = store()
        seq, head_hash = st.head()
        last = _cp.last_local(st.root)
        exporters = [e.describe() for e in _cp.exporters()]
        last_cp = last["checkpoint"] if last else None
        last_exports = last["exports"] if last else []
        return {
            "ok": _failures == 0,
            "root": str(st.root),
            # False means the store sits on the datadir the agent-server mounts:
            # the trail is then not independent of the subject it records.
            "isolated": _isolated(st.root),
            "key_id": st.signer.key_id,
            "events": seq,
            "head_hash": head_hash if seq else None,
            "last_checkpoint": ({"seq": last_cp["seq"], "timestamp": last_cp["timestamp"]}
                                if last_cp else None),
            "unanchored_events": seq - (int(last_cp["seq"]) if last_cp else 0),
            "exporters": exporters,
            "off_system": any(e.get("ok") for e in last_exports),
            "failures": _failures,
            "last_error": _last_error,
            "fail_closed": fail_closed(),
        }
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:300],
                "failures": _failures, "last_error": _last_error}


async def checkpoint_loop(interval: int | None = None) -> None:
    """Periodic checkpoints, started by the gateway lifespan."""
    every = interval or int(os.environ.get("CLODIA_AUDIT_CHECKPOINT_SECONDS")
                            or DEFAULT_CHECKPOINT_SECONDS)
    while True:
        await asyncio.sleep(every)
        try:
            await asyncio.to_thread(checkpoint_now)
        except Exception as exc:  # noqa: BLE001 - the loop must survive
            LOG.error("audit: periodic checkpoint failed (%s)", exc)


def boot() -> None:
    """Mark the gateway start in the chain, and say what is not yet in place."""
    try:
        from .. import egress as _eg
        egress_mode = _eg.mode()
    except Exception:  # noqa: BLE001
        egress_mode = None
    try:
        from .. import main as _main
        compartment = _main._spawn_compartment_mode()
    except Exception:  # noqa: BLE001
        compartment = None
    skip = (os.environ.get("CLODIA_DANGEROUSLY_SKIP_GATES") or "").strip().lower() in (
        "1", "true", "yes", "on")
    # The modes the reference monitor starts in are control-plane state too
    # (#439): a restart with gates skipped must be visible in the trail.
    emit("audit.start", identity="explicit", action="boot", resource="gateway",
         actor={"type": "service", "id": "clodia-tools"},
         tool={"name": "clodia-tools", "version": _gateway_version()},
         decision={"egress_mode": egress_mode, "compartment_mode": compartment,
                   "gates_skipped": skip})
    s = status()
    if not s.get("isolated"):
        LOG.warning("audit: the store is on the datadir shared with the agent-server "
                    "(CLODIA_TOOLS_STATE_DIR not set): the trail is not independent")
    if not s.get("exporters"):
        LOG.warning("audit: no off-system checkpoint exporter configured "
                    "(CLODIA_AUDIT_EXPORT_DIR or vault '%s'): a cut tail would "
                    "not be detectable", _cp.WORM_CRED)
