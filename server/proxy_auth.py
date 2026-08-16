"""L'identità di un PROXY: una chiave che tiene lui, non un segreto che gli diamo.

Un proxy è un sistema terzo ammesso in una stanza. Fino al 14 ago 2026 la sua
credenziale era un `ckt1` a novanta giorni, **firmato con l'identity key di
Clodia** e con il nome del proxy scritto dentro come semplice claim:

    mint_session_token(carrier="clodia", principal="crm-esterno", on_behalf=True)

Il gateway quindi verificava il certificato di *Clodia* e poi si fidava di un
campo. Tre conseguenze, tutte misurabili e nessuna voluta: chi copiava quella
stringa **era** quel proxy; non c'era niente da revocare per il singolo proxy
tranne il record del grant; e il segreto restava valido per mesi.

Era anche l'unica delle tre nature senza chiave propria. Un agente ha il suo
certificato e il gateway ne verifica la firma; una persona genera Ed25519 nel
browser e la CA le emette il certificato. Il proxy no — non perché si fosse
deciso così, ma perché non l'aveva ancora usato nessuno.

## Come funziona adesso

La privkey sta **dal sistema esterno**, e ce ne prova il possesso ogni volta:

    1. il proxy firma un'ASSERZIONE breve (`cpa1`) con la sua chiave;
    2. la manda a `POST /proxy/token`;
    3. il gateway la verifica col certificato che gli ha emesso — lo stesso
       `_agent_public_key` che usa per gli agenti — e conia un `ckt1` che dura
       **quindici minuti**;
    4. con quello il proxy chiama `/mcp` come prima.

Il grant nel registro non porta più un segreto: dice *che* quel proxy può
ottenere token per quella stanza, fino a quella data. È l'autorizzazione, e
resta revocabile. Il segreto lungo non esiste più da nessuna parte.

## Le due cose che un'asserzione firmata sbaglia se non le si guarda

**Il replay.** Una firma valida resta valida: chi la intercetta la rigioca.
Per questo l'asserzione ha una finestra stretta (`exp` obbligatorio, al massimo
`_MAX_LIFETIME`) e un `jti` che si consuma — visto una volta, non più accettato.
Senza il `jti` la finestra ridurrebbe il problema a pochi minuti invece di
chiuderlo, e «pochi minuti» è comunque una sessione intera.

**L'audience.** Un'asserzione senza destinatario dichiarato è una firma che
qualcuno può presentare altrove. `aud` è obbligatoria e verificata: una firma
fatta per questa istanza non serve a entrare in un'altra.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import time
from pathlib import Path

from . import human_mcp, pki_mint, pki_verify

LOG = logging.getLogger("clodia-tools.proxy_auth")

#: Prefisso dell'asserzione. Diverso da `ckt1` di proposito: sono due cose che
#: viaggiano in direzioni opposte — una la firma il client, l'altro noi — e un
#: prefisso condiviso invita a passare l'una per l'altro.
ASSERTION_PREFIX = "cpa1"

#: Destinatario dichiarato. Una firma fatta per noi non deve valere altrove.
ASSERTION_AUDIENCE = "clodia-proxy-token"

#: Quanto può durare al massimo un'asserzione. Non è la durata del token: è la
#: finestra entro cui la firma è spendibile.
_MAX_LIFETIME = 300

#: Tolleranza sull'orologio del sistema esterno. Senza, un client con dieci
#: secondi di deriva non si autentica mai e la causa è invisibile da entrambi
#: i lati.
_CLOCK_SKEW = 60

#: Durata del token coniato. Corta per costruzione: rinnovarlo costa una firma,
#: che il proxy sa fare da solo.
TOKEN_TTL_SECONDS = 900


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _seen_file() -> Path:
    return Path(os.environ.get("CLODIA_DATA", "/datadir")) / "proxy-assertions.json"


def _load_seen() -> dict[str, int]:
    try:
        return json.loads(_seen_file().read_text()).get("jti", {})
    except Exception:  # noqa: BLE001
        return {}


def _remember(jti: str, exp: int) -> None:
    """Consuma un `jti`, e nel farlo butta via quelli scaduti.

    La potatura vive QUI e non in un job: un registro anti-replay che cresce
    per sempre diventa il motivo per cui qualcuno un giorno lo svuota tutto.
    Un `jti` oltre la propria scadenza non serve più — l'asserzione sarebbe
    rifiutata dalla finestra temporale anche se la si riproponesse.
    """
    ora = int(time.time())
    visti = {k: v for k, v in _load_seen().items() if v > ora}
    visti[jti] = exp
    f = _seen_file()
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps({"jti": visti}, separators=(",", ":")))
    try:
        os.chmod(f, 0o600)
    except OSError:
        pass


def _live_grant(principal: str, tier: str, topic: str) -> dict | None:
    """Il grant vivo di questo proxy per questa stanza, se c'è.

    L'autorizzazione resta un fatto dell'owner: la firma prova CHI sei, non che
    tu possa entrare. Separarle è ciò che permette di revocare senza toccare la
    chiave, e di ruotare la chiave senza chiedere di nuovo il permesso.
    """
    for g in human_mcp.list_grants(tier, topic):
        if g.get("principal") == principal and not g.get("expired"):
            return g
    return None


def _is_participant(principal: str, tier: str, topic: str) -> bool:
    """Il proxy siede fra i partecipanti della stanza?

    **È questa l'ammissione.** Aggiungere un proxy ai partecipanti manda la
    conversazione di quella stanza a un sistema terzo: è già l'atto sulle mura
    che il notebook attribuisce all'owner (A11), ed è già solo l'owner a poterlo
    fare. Chiedere in più un grant dal pannello MCP era una seconda porta per la
    stessa ammissione — con l'effetto che un proxy invitato in un topic, e
    visibile fra i partecipanti, non riusciva a entrare e l'errore parlava di un
    «collegamento» che nella UI non era chiaro dove si creasse.

    Non allarga niente: i verbi restano `PROXY_VERBS` (parla e legge il canale,
    nient'altro) e il tetto di tier resta quello di `human_mcp`. Toglie una
    porta, non un controllo — e la revoca diventa quella che chiunque cercherebbe
    per prima: togliere il proxy dai partecipanti.
    """
    from .topics_api import _service

    try:
        meta = _service().open(tier, topic).get("meta") or {}
    except Exception:  # noqa: BLE001 — topic illeggibile → nessuna ammissione
        return False
    return (principal == meta.get("owner")
            or principal in (meta.get("participants") or []))


def verify_assertion(assertion: str) -> dict:
    """Verifica l'asserzione e ritorna il suo payload. Solleva `PermissionError`.

    L'ordine dei controlli è quello del costo: forma, finestra, destinatario,
    firma, replay. La firma è la verifica cara e sta dopo quelle che scartano
    una richiesta malformata; il replay è per ultimo perché è l'unico che
    SCRIVE, e non deve consumare un `jti` per un'asserzione che sarebbe stata
    rifiutata comunque.
    """
    try:
        prefix, body, sig = assertion.strip().split(".")
        if prefix != ASSERTION_PREFIX:
            raise ValueError(f"prefisso sconosciuto: atteso {ASSERTION_PREFIX}")
        payload = json.loads(_b64d(body))
    except PermissionError:
        raise
    except Exception as e:  # noqa: BLE001
        raise PermissionError(f"asserzione malformata: {e}")

    principal = str(payload.get("principal") or "").strip()
    if not principal:
        raise PermissionError("asserzione senza principal")
    if payload.get("aud") != ASSERTION_AUDIENCE:
        raise PermissionError(
            f"audience errata: un'asserzione per questa istanza dichiara "
            f"'{ASSERTION_AUDIENCE}'")

    ora = int(time.time())
    try:
        iat, exp = int(payload["iat"]), int(payload["exp"])
    except Exception:  # noqa: BLE001
        raise PermissionError("asserzione senza iat/exp: servono entrambi")
    if exp <= ora - _CLOCK_SKEW:
        raise PermissionError("asserzione scaduta")
    if iat > ora + _CLOCK_SKEW:
        raise PermissionError("asserzione datata nel futuro: orologi disallineati")
    if exp - iat > _MAX_LIFETIME:
        raise PermissionError(
            f"finestra troppo larga: al massimo {_MAX_LIFETIME}s fra iat ed exp")

    try:
        pub = pki_verify._agent_public_key(principal)
    except PermissionError as e:
        # Il caso più comune al primo collegamento, e va detto per nome: senza
        # certificato non c'è nulla contro cui verificare, e il rimedio non è
        # riprovare ma far emettere il certificato dalla propria pubkey.
        raise PermissionError(f"{e} — il proxy va creato con la sua pubkey")
    try:
        pub.verify(_b64d(sig), body.encode())
    except Exception:  # noqa: BLE001
        raise PermissionError(f"firma non valida per '{principal}'")

    jti = str(payload.get("jti") or "").strip()
    if not jti:
        raise PermissionError("asserzione senza jti: senza, una firma si rigioca")
    if jti in _load_seen():
        raise PermissionError("asserzione già usata")
    return payload


def token_for(assertion: str) -> dict:
    """Asserzione firmata → token di sessione breve. Il percorso completo."""
    payload = verify_assertion(assertion)
    principal = str(payload["principal"]).strip()
    tier = str(payload.get("tier") or "").strip()
    topic = str(payload.get("topic") or "").strip()
    if not tier or not topic:
        raise PermissionError("asserzione senza tier/topic: un token di proxy "
                              "vale per UNA stanza, e va detto quale")
    grant = _live_grant(principal, tier, topic)
    if grant is None:
        # Nessun grant esplicito: vale la sedia. Se il proxy è fra i
        # partecipanti l'owner l'ha già ammesso, e chiedergli di ripetersi da un
        # secondo pannello è la porta in più che teneva fuori un proxy invitato.
        if not _is_participant(principal, tier, topic):
            raise PermissionError(
                f"'{principal}' non partecipa a {tier}/{topic}: la firma prova "
                "chi sei, non che tu possa entrare — l'owner deve aggiungere il "
                "proxy ai partecipanti della stanza (o te ne ha tolto)")
        # Il tetto di tier è quello dei client MCP e vale qui come là: il
        # contenuto esce verso un sistema che non controlliamo. Il grant lo
        # applicava al momento della coniazione; senza grant va applicato ora,
        # altrimenti la strada nuova sarebbe anche la più larga.
        human_mcp._check_tier(tier, provider=f"proxy:{principal}", consenso=True,
                              principal_kind="proxy")
        grant = {"id": f"participant:{tier}/{topic}", "carrier": "clodia"}
        LOG.info("proxy %s: ammesso su %s/%s dalla lista partecipanti "
                 "(nessun grant esplicito)", principal, tier, topic)

    verbi = human_mcp.verbs_for("proxy")
    token = pki_mint.mint_session_token(
        grant.get("carrier") or "clodia",
        execution_id=grant["id"],
        ttl_seconds=TOKEN_TTL_SECONDS,
        principal=principal,
        clearance=tier,
        on_behalf=True,
        human_role="user",
        chat=f"chan:{tier}:{topic}:{principal}",
        scoped_tools=list(verbi),
    )
    # Consumato SOLO ora: se qualcosa fosse fallito dopo la verifica, un `jti`
    # bruciato costringerebbe a rifirmare per un errore non suo.
    _remember(str(payload["jti"]), int(payload["exp"]))
    LOG.info("proxy %s: token coniato per %s/%s (%ds, %d verbi)",
             principal, tier, topic, TOKEN_TTL_SECONDS, len(verbi))
    return {"token": token, "expires_in": TOKEN_TTL_SECONDS,
            "verbs": list(verbi), "principal": principal,
            "tier": tier, "topic": topic}


def client_instructions(base_url: str, tier: str, name: str,
                        principal: str) -> dict:
    """Cosa consegnare all'operatore del sistema esterno.

    Non una configurazione da incollare: quella conterrebbe un segreto, ed è
    proprio ciò che non esiste più. È il contratto — dove si chiede il token,
    cosa si firma, dove si parla.
    """
    base = base_url.rstrip("/")
    return {
        "token_endpoint": f"{base}/proxy/token",
        "mcp_url": f"{base}/mcp",
        "algorithm": "Ed25519",
        "assertion": {
            "format": f"{ASSERTION_PREFIX}.<base64url(payload)>.<base64url(firma)>",
            "payload": {"principal": principal, "tier": tier, "topic": name,
                        "aud": ASSERTION_AUDIENCE, "iat": "<epoch>",
                        "exp": f"<epoch + max {_MAX_LIFETIME}s>",
                        "jti": "<stringa casuale, mai riusata>"},
            "signature": "firma dei byte di <base64url(payload)> con la privkey del proxy",
        },
        "token_ttl_seconds": TOKEN_TTL_SECONDS,
        "verbs": list(human_mcp.verbs_for("proxy")),
    }
