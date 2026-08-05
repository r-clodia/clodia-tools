"""gdrive_root — confinamento delle credenziali Google a un sottoalbero di Drive.

Perché esiste. Il connettore Workspace chiede lo scope `auth/drive` PIENO: il
token nel vault raggiunge tutto ciò che quell'account vede. Va bene quando
l'account è dedicato e non contiene nient'altro — lì il confine lo applica l'ACL
di Google. Non va bene quando l'owner ha solo account Google gratuiti e non può
creare un Drive condiviso: collegare il suo account significherebbe dare a
*qualunque* utente della webui, attraverso un agente, la lettura di *tutto* il
suo Drive. Il confine allora deve stare qui.

Cosa lo rende un controllo difendibile e non un cerotto. Il refresh token vive
nel vault e **solo il gateway lo usa**: un agente non ha la credenziale, quindi
non può aggirare questo modulo con un client suo, una shell o un `curl`. Questo
è l'unico percorso verso l'API. Il rischio residuo è un difetto in questo file,
non una via alternativa — a differenza di un filtro applicato *dopo* che i dati
sono già usciti.

Cosa NON è. Non è lo scope OAuth: il token resta pieno, e chi ottiene il
contenuto del vault (root sull'host) ha tutto Drive. È una riduzione
dell'autorità *concessa agli agenti*, non della potenza del segreto.

Semantica. `gdrive_roots` in config.yaml (volume del gateway, non raggiungibile
da un agente — lo stesso punto in cui vivono i gate):

    gdrive_roots:
      ceouncommoncreative: ["1AbC…"]   # per account
      "*": ["1XyZ…"]                    # per tutti gli account

Account SENZA voce → non confinato (comportamento storico). Account CON voce →
ogni id che entra in un verbo Google deve avere un antenato nella lista, e ogni
id che esce da un elenco viene filtrato allo stesso modo.

Tre trappole, tutte chiuse qui e nessuna ovvia:

1. **Le scorciatoie sono un reindirizzamento.** Una scorciatoia *dentro* la
   cartella che punta fuori renderebbe raggiungibile il bersaglio se risolta.
   Non si seguono mai: un file che è una scorciatoia viene rifiutato, e la
   risalita non passa mai per il suo bersaglio.
2. **Una query Drive è arbitraria.** Non si può confinare aggiungendo clausole a
   una stringa che il chiamante controlla: il confinamento sta nel filtro degli
   id restituiti, non nella query.
3. **`errore == fuori`.** Se la risalita non si completa (errore API, profondità,
   ciclo) la risposta è «fuori». La direzione opposta è l'unica che questo
   controllo non può permettersi.
"""
from __future__ import annotations

import logging
import time
from typing import Optional

LOG = logging.getLogger("clodia-tools.gdrive-root")

CONFIG_KEY = "gdrive_roots"
SHORTCUT_MIME = "application/vnd.google-apps.shortcut"
MAX_DEPTH = 32          # risalite più profonde di così non sono un albero reale
_PARENTS_TTL = 30.0     # secondi; vedi «finestra di autorità stantia» sotto
_parents_cache: dict[tuple[str, str], tuple[float, tuple[str, ...], bool]] = {}


class OutsideRoot(PermissionError):
    """Un id Google fuori dal sottoalbero consentito.

    PermissionError e non ValueError perché è un rifiuto d'autorità, e il
    dispatch dei tool lo riporta come tale.
    """


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
    return out


def confined(account: str) -> bool:
    return bool(roots_for(account))


def _parents(svc, account: str, file_id: str) -> tuple[tuple[str, ...], bool]:
    """(parents, is_shortcut) di un file, con cache breve.

    La cache è una **finestra di autorità stantia**: un file spostato fuori dalla
    cartella resta raggiungibile fino a `_PARENTS_TTL`. È un compromesso
    consapevole — senza cache un elenco di 50 righe costa 50 chiamate API — e la
    finestra è tenuta a 30s perché è il tempo entro cui uno spostamento manuale
    non è realisticamente parte di un attacco.
    """
    key = (account, file_id)
    now = time.time()
    hit = _parents_cache.get(key)
    if hit and (now - hit[0]) < _PARENTS_TTL:
        return hit[1], hit[2]
    meta = svc.files().get(fileId=file_id, fields="id, parents, shortcutDetails",
                           supportsAllDrives=True).execute()
    parents = tuple(meta.get("parents") or ())
    is_shortcut = bool(meta.get("shortcutDetails"))
    _parents_cache[key] = (now, parents, is_shortcut)
    return parents, is_shortcut


def inside(svc, account: str, file_id: str,
           row: Optional[dict] = None) -> bool:
    """Vero se `file_id` ha un antenato fra le radici consentite.

    `row` è la RIGA restituita da un elenco Drive, non solo i suoi genitori, ed è
    una distinzione che ho già sbagliato una volta: passando i soli `parents` il
    percorso rapido salta la lettura dei metadati e quindi **non vede più che il
    file è una scorciatoia**, che è precisamente il modo numero uno di uscire dal
    perimetro. Il contratto è «tutti i campi che decidono, o nessuno»: chi ha una
    riga dell'API la passa intera (e `_FIELDS` garantisce che contenga
    `shortcutDetails`), chi non l'ha non passa niente e paga una chiamata.

    «Un qualunque cammino raggiunge la radice» è la semantica giusta per la
    LETTURA: un file con più genitori, uno dei quali dentro la cartella, è
    legittimamente nella cartella. Per lo SPOSTAMENTO conta la destinazione, che
    è un controllo separato in `move`.
    """
    roots = roots_for(account)
    if not roots:
        return True
    if file_id in roots:
        return True
    seen: set[str] = {file_id}
    try:
        if row is not None and _row_is_conclusive(row):
            if _row_is_shortcut(row):
                LOG.info("gdrive_root: rifiutata scorciatoia %s (da elenco)", file_id)
                return False
            frontier = list(row.get("parents") or ())
        else:
            parents, is_shortcut = _parents(svc, account, file_id)
            if is_shortcut:
                # Una scorciatoia è un reindirizzamento: non si segue mai.
                LOG.info("gdrive_root: rifiutata scorciatoia %s", file_id)
                return False
            frontier = list(parents)
        for _ in range(MAX_DEPTH):
            if not frontier:
                return False
            if any(p in roots for p in frontier):
                return True
            nxt: list[str] = []
            for p in frontier:
                if p in seen:
                    continue          # guardia sui cicli
                seen.add(p)
                pp, is_shortcut = _parents(svc, account, p)
                if is_shortcut:
                    continue
                nxt.extend(pp)
            frontier = nxt
        return False
    except Exception as e:                      # noqa: BLE001 — fail-closed
        # `errore == fuori`. Una risalita incompleta non deve concedere niente.
        LOG.warning("gdrive_root: risalita di %s non conclusa (%s) → fuori",
                    file_id, type(e).__name__)
        return False


def _row_is_shortcut(row: dict) -> bool:
    """Due segnali indipendenti, entrambi da campi che chiediamo sempre."""
    return bool(row.get("shortcutDetails")) or row.get("mimeType") == SHORTCUT_MIME


def _row_is_conclusive(row: dict) -> bool:
    """Vero se la riga può DIMOSTRARE di non essere una scorciatoia.

    Il difetto che questo chiude: una riga priva di `shortcutDetails` è
    indistinguibile da una riga in cui quel campo non è stato chiesto, e fidarsi
    dell'assenza fa passare esattamente la trappola che il campo doveva chiudere.
    Il percorso rapido vale solo per righe che portano almeno uno dei due campi
    che decidono; le altre pagano la chiamata all'API invece di essere credute.
    """
    return "shortcutDetails" in row or "mimeType" in row


def _refusal(account: str, verb: str, file_id: str) -> OutsideRoot:
    roots = roots_for(account)
    return OutsideRoot(
        f"{verb}: '{file_id}' è fuori dalla cartella consentita per l'account "
        f"'{account}'. Questa credenziale è confinata a {roots} e a tutto ciò che "
        f"sta sotto: puoi leggere e scrivere là dentro, e nient'altro dell'account "
        f"è raggiungibile da un agente. Se il file ti serve, va spostato nella "
        f"cartella da chi ne ha i diritti — il confine non è aggirabile da qui.")


def assert_inside(svc, account: str, file_id: str, verb: str,
                  row: Optional[dict] = None) -> None:
    """Solleva `OutsideRoot` se `file_id` non è nel sottoalbero consentito."""
    if not (file_id or "").strip():
        raise ValueError(f"{verb}: id vuoto")
    if not inside(svc, account, file_id.strip(), row):
        raise _refusal(account, verb, file_id)


def keep_inside(svc, account: str, rows: list[dict]) -> list[dict]:
    """Filtra le righe di un elenco tenendo solo quelle nel sottoalbero.

    Passa la riga INTERA alla verifica: contiene già `parents` e
    `shortcutDetails`, quindi il figlio diretto della radice non costa nessuna
    chiamata in più e la scorciatoia viene comunque riconosciuta.
    """
    if not roots_for(account):
        return rows
    out = []
    for r in rows:
        fid = r.get("id")
        if fid and inside(svc, account, fid, r):
            out.append(r)
    return out


def default_parent(account: str) -> Optional[str]:
    """Cartella da usare quando il chiamante non ne indica una.

    Senza questo, `upload`/`mkdir` senza `folder_id` scriverebbero nella radice
    di «Il mio Drive» — fuori dal confine, e per un verbo di SCRITTURA il
    rifiuto secco sarebbe una regressione gratuita: la destinazione ovvia esiste.
    """
    roots = roots_for(account)
    return roots[0] if len(roots) == 1 else None


def assert_writable_parent(svc, account: str, parent_id: Optional[str],
                           verb: str) -> Optional[str]:
    """Valida (o sceglie) la cartella di destinazione di una scrittura."""
    if not roots_for(account):
        return parent_id
    if not (parent_id or "").strip():
        dp = default_parent(account)
        if dp:
            return dp
        raise OutsideRoot(
            f"{verb}: indica la cartella di destinazione. Questa credenziale è "
            f"confinata a {roots_for(account)} e senza destinazione il file "
            f"finirebbe fuori; con più radici consentite non posso indovinare "
            f"quale intendi.")
    assert_inside(svc, account, parent_id, verb)
    return parent_id.strip()


def guard_calendar(account: Optional[str], verb: str) -> None:
    """Come `assert_not_confined`, ma risolve l'account da sé (comodo per
    gcalendar, che non ne ha uno in mano prima di costruire il client)."""
    if not _config():
        return
    from . import gdrive
    try:
        acct = gdrive._resolve_account(account)
    except RuntimeError:
        return           # nessun account: l'errore vero lo dà il client dopo
    assert_not_confined(acct, verb)


def assert_not_confined(account: str, verb: str) -> None:
    """Rifiuta i verbi che una radice di Drive NON può confinare.

    Il calendario non è un oggetto di Drive: nessuna cartella dice qualcosa su
    di esso. Se lasciassimo passare `gcalendar.*` su una credenziale confinata,
    l'affermazione «l'agente vede solo quella cartella» sarebbe **falsa** —
    l'agenda dell'account sarebbe leggibile. Il confinamento va scelto sapendo
    che costa questi verbi.
    """
    if roots_for(account):
        raise OutsideRoot(
            f"{verb}: non disponibile su '{account}'. Questa credenziale è "
            f"confinata a una cartella di Drive, e il calendario non sta in una "
            f"cartella: non c'è modo di limitarlo allo stesso perimetro, quindi "
            f"è chiuso invece di essere concesso per intero. Per il calendario "
            f"serve un account non confinato.")


def reset_cache() -> None:
    """Svuota la cache dei genitori (test, e cambio di configurazione)."""
    _parents_cache.clear()


def guard_id(account: Optional[str], file_id: str, verb: str) -> None:
    """Controlla un id per i moduli che NON hanno un client Drive in mano
    (gdocs, gsheets): un Doc e uno Sheet *sono* file di Drive, e il loro id è un
    id di Drive.

    Percorso rapido deliberato: se nessuna radice è configurata questa funzione
    non costruisce niente e non fa nessuna chiamata. Un account non confinato non
    paga il confinamento — altrimenti la misura si farebbe togliere per lentezza.
    """
    if not _config():
        return          # nessuna radice configurata: non toccare nemmeno il vault
    from . import gdrive
    acct = gdrive._resolve_account(account)
    if not roots_for(acct):
        return
    svc, _ = gdrive._service(acct)
    assert_inside(svc, acct, file_id, verb)


def adopt(account: Optional[str], file_id: str, verb: str) -> Optional[str]:
    """Sposta dentro la radice un file appena creato dalle API Docs/Sheets.

    Docs e Sheets creano SEMPRE nella radice di «Il mio Drive»: non accettano un
    genitore. Rifiutare la creazione toglierebbe un verbo utile; lasciarla fuori
    romperebbe il perimetro. Quindi si crea e si adotta subito.

    Ritorna la cartella in cui è finito, o None se l'account non è confinato.
    Se l'adozione FALLISCE il file resta fuori: l'errore viene propagato, perché
    un «creato» silenzioso su un file non confinato sarebbe la bugia peggiore.
    """
    if not _config():
        return None
    from . import gdrive
    acct = gdrive._resolve_account(account)
    dest = default_parent(acct)
    if not roots_for(acct):
        return None
    if not dest:
        raise OutsideRoot(
            f"{verb}: con più cartelle consentite su '{acct}' non posso scegliere "
            f"dove creare. Crea il file con gdrive.upload nella cartella che vuoi.")
    svc, _ = gdrive._service(acct)
    cur = svc.files().get(fileId=file_id, fields="parents",
                          supportsAllDrives=True).execute()
    svc.files().update(fileId=file_id, addParents=dest,
                       removeParents=",".join(cur.get("parents") or ()) or None,
                       fields="id", supportsAllDrives=True).execute()
    reset_cache()
    return dest
