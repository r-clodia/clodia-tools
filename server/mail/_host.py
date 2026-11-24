"""What the mail code asks of the gateway, answered by the gateway itself.

The mail code came back from comms-pack's gateway component (clodia-platform
#683). There it reached the gateway only through the component host; here it
is gateway code, so the same calls are answered by the gateway's own modules,
with the same objects where they exist (`components.host.Perimeter`,
`components.host.Topics`), so the facts it reads are the ones it read before.

What changed is the credential scope: `mailbox_<acct>` is the gateway's own
vault entry again, read directly (`vault.*`), no longer through a component's
scoped credentials.

Gmail stays google-pack's: a Google account's credential never comes here.
For it the mail code asks google-pack's gateway component for two services —
`mail_accounts()` (names and addresses, never a secret) and `mail_exec(...)`
(one client run on the account's XOAUTH2 files, which google-pack writes).
When google-pack is not serving, a Google account is unknown here and its
mail is refused: fail closed.
"""
from __future__ import annotations

import logging
from typing import Any

from ..components.host import AuditUnavailable, Perimeter, Topics

LOG = logging.getLogger("clodia-tools.mail")

#: The vault prefix of the IMAP/SMTP mailboxes.
MAILBOX = "mailbox_"
#: The vault prefixes of Google accounts: google-pack's, never read here.
GOOGLE_PREFIXES = ("google_", "gmail_")
#: The pack whose gateway component serves Gmail, and the two services asked.
GOOGLE_PACK = "google-pack"
GMAIL_ACCOUNTS = "mail_accounts"
GMAIL_EXEC = "mail_exec"


#: Config key: the accounts of the mailboxes switched off from Tools (#733).
DISABLED_KEY = "mailboxes_disabled"


class _Gateway:
    """The calls the mail code makes, answered from the gateway's modules."""

    AuditUnavailable = AuditUnavailable

    def __init__(self) -> None:
        self.perimeter = Perimeter()
        self.topics = Topics()
        self.log = LOG

    def agent(self) -> str:
        from ..whitelist import agent_name
        return agent_name()

    def mailbox_disabled(self, account: str) -> bool:
        """Is the mailbox switched off from Tools (clodia-platform#733)? A
        switched-off mailbox is neither read by the courier nor used to send."""
        from ..whitelist import CONFIG
        return str(account or "") in set(CONFIG.get(DISABLED_KEY) or [])

    def set_mailbox_enabled(self, account: str, enabled: bool) -> None:
        """Record the switch in the gateway's config; the caller saves it."""
        from ..whitelist import CONFIG
        spente = {a for a in (CONFIG.get(DISABLED_KEY) or []) if a != account}
        if not enabled:
            spente.add(account)
        if spente:
            CONFIG[DISABLED_KEY] = sorted(spente)
        else:
            CONFIG.pop(DISABLED_KEY, None)

    def current_topic(self) -> tuple[str | None, str | None]:
        from .. import main
        return main._current_topic()

    def scratch_path(self, path: str) -> str:
        from .. import main
        return main._safe_scratch_path(path)

    def note_crossing(self, data: bytes | None = None, *, path: str | None = None,
                      kind: str = "file") -> None:
        from .. import main
        if data is not None:
            main._note_crossing(data=bytes(data), kind=kind)
        else:
            main._note_crossing(path, kind=kind)

    def audit_decision(self, verb: str, kind: str, result: str, *,
                       reason_class: str | None = None) -> None:
        from .. import audit as _audit
        from ..audit import policy as _apol
        try:
            _apol.decision(verb, kind, result, reason_class=reason_class)
        except _audit.AuditWriteError as e:
            raise AuditUnavailable(str(e)) from None

    def service(self, pack: str, name: str):
        """google-pack's `mail_accounts` / `mail_exec`, or None when its
        component is not serving. Nothing else."""
        if (pack, name) not in ((GOOGLE_PACK, GMAIL_ACCOUNTS), (GOOGLE_PACK, GMAIL_EXEC)):
            raise PermissionError(f"mail may not call service '{name}' of '{pack}'")
        from ..components import loader
        spec = loader.service(pack, name)
        return spec.handler if spec is not None else None


_GATEWAY = _Gateway()


def get() -> Any:
    return _GATEWAY


def google_mail_account_exists(account: str) -> bool:
    """Name-only check (never the credential)."""
    try:
        return bool(_GATEWAY.perimeter.google_mail_account_exists(account))
    except Exception:  # noqa: BLE001 — in doubt: treat as Google, refuse
        return True


# ── Gmail: google-pack's component ─────────────────────────────────────────

def google_service(name: str):
    """google-pack's service `name` (a callable), or None when google-pack's
    gateway component is not serving on this instance."""
    try:
        return _GATEWAY.service(GOOGLE_PACK, name)
    except Exception as e:  # noqa: BLE001 — not serving: absent
        LOG.warning("mail: google-pack service %s not reachable (%s)", name,
                    type(e).__name__)
        return None


def google_rows() -> list[dict]:
    """google-pack's rows for the Google mail accounts, or [] when it is not
    serving. Each row: the diagnostics shape plus `email` (the bundle's
    address as written there)."""
    svc = google_service(GMAIL_ACCOUNTS)
    if svc is None:
        return []
    try:
        rows = svc() or []
    except Exception as e:  # noqa: BLE001 — a listing, never a reason to fail
        LOG.error("mail: google-pack mail_accounts failed (%s)", type(e).__name__)
        return []
    return [dict(r) for r in rows if isinstance(r, dict)
            and str(r.get("credential") or "").startswith(GOOGLE_PREFIXES)]


def google_unavailable() -> str:
    """Why Gmail accounts are not served here, or "" when google-pack is."""
    if google_service(GMAIL_ACCOUNTS) is not None:
        return ""
    return ("Gmail accounts are served by google-pack's gateway component, which "
            "is not serving on this instance (not installed or failed — see "
            "GET /internal/components)")


# ── the credentials the mail code sees ─────────────────────────────────────

class _Vault:
    """`has_credential` / `read_internal` / `store_names` / `deposit` /
    `remove`, as the mail code uses them:

    * `mailbox_<acct>` — the gateway's vault, directly;
    * `google_<acct>` / `gmail_<acct>` — google-pack's rows: existence and the
      ADDRESS only. `read_internal` of a Google credential returns
      `{"email": <address>}` and nothing else: the refresh token stays with
      google-pack.
    """

    def _google(self) -> dict[str, dict]:
        return {str(r["credential"]): r for r in google_rows()}

    def has_credential(self, name: str) -> bool:
        from .. import vault
        name = str(name or "")
        if name.startswith(MAILBOX):
            return bool(vault.has_credential(name))
        if name.startswith(GOOGLE_PREFIXES):
            return name in self._google()
        return False

    def read_internal(self, name: str) -> dict:
        from .. import vault
        name = str(name or "")
        if name.startswith(MAILBOX):
            return dict(vault.read_internal(name))
        if name.startswith(GOOGLE_PREFIXES):
            row = self._google().get(name)
            if row is None:
                raise PermissionError(f"credential '{name}' not available")
            return {"email": row.get("email") or ""}
        raise PermissionError(f"'{name}' is not a mail credential")

    def store_names(self) -> list[str]:
        from .. import vault
        return [n for n in vault.store_names() if n.startswith(MAILBOX)] \
            + list(self._google())

    def deposit(self, name: str, bundle: dict, *, cred_type: str,
                grant_agents=()) -> None:
        from .. import vault
        if not str(name or "").startswith(MAILBOX):
            raise PermissionError(f"'{name}' is not a mailbox credential")
        vault.deposit(name, bundle, cred_type=cred_type,
                      grant_agents=list(grant_agents))

    def remove(self, name: str) -> bool:
        from .. import vault
        if not str(name or "").startswith(MAILBOX):
            raise PermissionError(f"'{name}' is not a mailbox credential")
        return bool(vault.remove(name))


vault = _Vault()
