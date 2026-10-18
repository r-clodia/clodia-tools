"""Vault-only diagnostics of the mail-capable credentials (`google_*`,
`gmail_*`, `mailbox_*`): which are complete, which are send-only. Never a
secret value, never a network call.

Kept from the native mail module (`tools/email.py`, removed with
clodia-platform#523) because the Tools card of Google reads it whichever side
serves mail; the mailboxes card on `mail: pack` asks comms-pack's component.
"""
from __future__ import annotations

from .. import vault

_VAULT_PREFIXES = ("google_", "gmail_", "mailbox_")
_REQUIRED_FIELDS = {
    "google": ("client_id", "client_secret", "refresh_token", "email"),
    "gmail": ("client_id", "client_secret", "refresh_token", "email"),
    # Il minimo di una casella è **spedire**. L'IMAP è opzionale, e non per
    # tolleranza: esistono indirizzi che sono alias con SMTP e nessuna casella
    # dietro (team@uncommon-digital.it). Richiedere l'IMAP li dichiarava «non
    # operativi» — un giudizio falso su una configurazione legittima, che poi
    # nascondeva l'account agli agenti come se fosse rotto.
    "mailbox": ("email", "smtp_server", "smtp_port"),
}


def is_send_only(bundle: dict) -> bool:
    """Casella di solo invio: SMTP dichiarato, nessun IMAP.

    È una **forma dichiarata**, non un errore ingoiato, e la differenza conta.
    Se si assorbisse il fallimento IMAP, un guasto vero del server diventerebbe
    indistinguibile da una scelta di configurazione, e una lettura risponderebbe
    «nessun messaggio» — che non è «non posso leggere», è una bugia con la stessa
    forma di una verità.
    """
    return not (bundle.get("imap_server") or "").strip()


def credential_diagnostics() -> list[dict]:
    """Stato materializzabile delle credenziali email, senza valori segreti."""
    rows = []
    for credential in vault.store_names():
        prefix = next((p for p in _VAULT_PREFIXES if credential.startswith(p)), None)
        if prefix is None:
            continue
        kind = prefix[:-1]
        account = credential[len(prefix):]
        missing: list[str] = []
        error = None
        solo_invio = False
        try:
            bundle = vault.read_internal(credential)
            missing = [field for field in _REQUIRED_FIELDS[kind] if not bundle.get(field)]
            if kind == "mailbox":
                if not (bundle.get("password") or bundle.get("app_password")):
                    missing.append("password|app_password")
                solo_invio = is_send_only(bundle)
        except Exception as exc:  # noqa: BLE001 - diagnostica, mai valori
            error = type(exc).__name__
        rows.append({
            "credential": credential,
            "account": account,
            "kind": kind,
            "operational": not missing and error is None,
            # Dichiarato, non dedotto da un fallimento: chi legge questa riga
            # deve sapere che l'account NON si legge, prima di provarci.
            "send_only": solo_invio,
            "missing": missing,
            "error": error,
        })
    return rows
