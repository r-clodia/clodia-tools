"""The Drive perimeter as the gateway's lists declare it: approved folders
(`gdrive:folder/<id>` entries, global plus the room's) and the legacy
per-account `gdrive_roots`.

What enforced it against Drive — climbing a file's parents, the calendar
whitelist, the per-call caches — was the native Google client's, and went with
it (clodia-platform#524): google-pack's gateway component enforces the
perimeter now, reading these same facts through the host
(`host.perimeter.gdrive_roots`, `egress_uris`). The gateway keeps the reading
for its own decisions — which folders a topic may be linked to
(`TopicService._require_approved_folder`).
"""
from __future__ import annotations

import logging

LOG = logging.getLogger("clodia-tools.gdrive-root")

CONFIG_KEY = "gdrive_roots"


def _config() -> dict:
    from .. import whitelist
    cfg = getattr(whitelist, "CONFIG", None) or {}
    raw = cfg.get(CONFIG_KEY) or {}
    return raw if isinstance(raw, dict) else {}


def roots_for(account: str) -> list[str]:
    """Cartelle radice consentite per `account`; lista vuota = non confinato.

    Le voci per l'account e quelle sotto `*` si SOMMANO: `*` è un minimo comune,
    non un default che una voce specifica sostituisce. Sostituirlo sarebbe la
    direzione d'errore sbagliata — chi scrive una radice per un account non si
    aspetta di perdere quella globale.
    """
    cfg = _config()
    out: list[str] = []
    for key in ("*", account):
        v = cfg.get(key)
        if isinstance(v, str):
            v = [v]
        for fid in (v or []):
            fid = str(fid).strip()
            if fid and fid not in out:
                out.append(fid)
    # Le cartelle approvate nelle liste valgono per OGNI account: sono voci di
    # whitelist e non appartengono a un account (voce 32). Se restassero fuori di
    # qui, una cartella approvata sarebbe collegabile a un topic ma poi
    # irraggiungibile — una lista che concede a metà è peggio di nessuna lista,
    # perché chi la legge conclude che funzioni.
    for fid in approved_folders():
        if fid not in out:
            out.append(fid)
    return out


#: Prefisso con cui una cartella Drive compare nelle liste. Il vocabolario
#: esisteva già: `gdrive:folder/<id>` è un URI di egress ammesso da sempre.
FOLDER_URI = "gdrive:folder/"


def approved_folders(scope: str | None = None) -> list[str]:
    """Cartelle Drive **approvate**: voci di whitelist, non un sottoalbero.

    Le voci vengono dalla lista in vigore per la chiamata — globale PIÙ quella
    dello scope (C1) — più, per retrocompatibilità, le vecchie `gdrive_roots`.
    L'unione e non la sostituzione: chi aveva scritto una radice d'account non
    deve perderla al deploy.

    La forma è cambiata il 7 ago 2026 (voce 32). `gdrive_roots` era un TETTO
    D'ACCOUNT — un sottoalbero dentro cui tutto è permesso — e presupponeva che
    un account avesse una radice. Un account condiviso non ce l'ha: le cartelle
    arrivano da «Condivisi con me», ognuna di un proprietario diverso, senza
    antenato comune. La forma giusta è quella già usata per il repository (voce
    31) e per un indirizzo email: una voce di lista.

    Vuota = non si confina. È il comportamento storico, ed è la direzione giusta
    della retrocompatibilità: una lista vuota che chiudesse tutto verrebbe spenta
    il giorno stesso, e allora non proteggerebbe niente.
    """
    out: list[str] = []
    try:
        from .. import egress as _eg
        for u in _eg.effective_uris("egress", scope):
            s = str(u).strip()
            if s.lower().startswith(FOLDER_URI):
                fid = s[len(FOLDER_URI):].strip().strip("/")
                if fid and fid not in out:
                    out.append(fid)
    except Exception as e:  # noqa: BLE001 — senza liste non si approva nulla
        LOG.warning("lettura delle cartelle approvate fallita (%s)", type(e).__name__)
    # Le vecchie `gdrive_roots` NON entrano qui. Sono per account per
    # costruzione, e portarle dentro renderebbe la radice dell'account A un
    # perimetro anche per B — cioè confinerebbe un account che oggi non lo è,
    # rompendo la compatibilità che marte richiede. Restano dove sono, dentro
    # `roots_for`, per l'account cui appartengono.
    return out
