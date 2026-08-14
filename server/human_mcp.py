"""Un client MCP di una PERSONA, legato a una sola stanza.

Giovanni apre Claude Code, incolla una configurazione, e da lì parla nel topic
**come Giovanni** e chiede se lo hanno chiamato. La domanda naturale è «con quale
autenticazione?», e la risposta migliore che questo modulo dà è: **nessuna
nuova**.

Il gateway verifica già, a ogni chiamata, un token `ckt1` firmato che porta
`principal` (chi), `on_behalf` (decidi sul ruolo umano, non sul carrier), `chat`
(quale stanza), `clearance` (fin dove) e `scoped_tools` (quali verbi). Un client
umano è quindi **un token coniato per una persona** invece che per un agente.
Aggiungere una API key parallela avrebbe significato avere due modi di dire chi
sei, e il secondo sarebbe stato quello senza PKI, senza scadenza e senza revoca.

Qui dentro ci sono solo le tre cose che il minting esistente non sapeva:

1. **fin dove può arrivare** — il tier della stanza, letto come un obbligo che
   segue il dato e non come una proprietà della stanza (vedi `_check_tier`);
2. **per quanto** — una scadenza, perché un token senza scadenza è una chiave
   che non torna indietro;
3. **come si toglie** — un registro consultabile. Un token che non si può
   vedere non si può revocare, e «revocabile in teoria» è indistinguibile da
   non revocabile.
"""
from __future__ import annotations

import json
import os
import secrets
import time
from pathlib import Path

from . import pki_mint

#: I verbi di una persona. Piccolo e deliberato: non è «l'agente Giovanni», è
#: Giovanni — quello che fa già dalla webui. Legge, cerca fra i file, parla.
#:
#: `topic.post_message` copre anche il CHIEDERE: `@fullstack-dev puoi guardare?`
#: passa dal routing del canale, con lo stesso tetto «risponde uno solo» e la
#: stessa regola «una menzione a una persona non instrada un'AI». Un `topic.ask`
#: sarebbe una seconda porta sulla stessa stanza, e la seconda porta è sempre
#: quella che dimentica una regola.
#:
#: Fuori resta tutto il control plane — `agents.*`, `jobs.*`, `settings.*`,
#: `topic.remote_*`, `topic.telegram_bind`. Un token per parlare in una stanza
#: non deve poter spostare i muri della stanza.
VERBS: tuple[str, ...] = (
    "topic.open",
    "topic.messages",
    "topic.post_message",
    "topic.my_mentions",
    "topic.mark_seen",
    "topic.files",
    "topic.read_file",
    "topic.read_document",
    "topic.search",
    "topic.put",
)

#: I verbi di un PROXY: un sistema terzo ammesso in una stanza. Parla e legge
#: quella stanza, e nient'altro — niente file, niente ricerca, niente scrittura.
#:
#: La differenza con una persona non è di grado ma di natura: Giovanni è un
#: partecipante che porta con sé un'autorità (la sua clearance, il suo ruolo);
#: un proxy è una presenza senza autorità, che esiste per dialogare. Legge il
#: canale perché un partecipante che non può leggere le risposte non dialoga —
#: è un webhook — ma la sua superficie di lettura finisce dove finisce la chat.
#:
#: Deve restare allineato a `_PROXY_ALLOWED_TOOLS` nel modello del seed
#: (clodia-logic): quello dichiara, questo conia, e se divergono si riapre il
#: buco per cui il seed prometteva un verbo e il token ne consegnava dieci.
PROXY_VERBS: tuple[str, ...] = (
    "topic.post_message",
    "topic.messages",
    "topic.my_mentions",
    "topic.mark_seen",
)


def verbs_for(principal_kind: str | None) -> tuple[str, ...]:
    """I verbi che spettano a questo tipo di principal.

    Un tipo sconosciuto prende quelli del proxy, non quelli della persona: se un
    giorno arriva una terza natura, deve nascere con la superficie più piccola e
    farsi allargare apposta.
    """
    return VERBS if (principal_kind or "human").strip().lower() == "human" else PROXY_VERBS


#: Tier oltre il quale un client MCP umano non si conia in nessun caso.
TIER_MAX = 2
#: Tier oltre il quale serve la concessione esplicita di chi lo emette.
TIER_LIBERO = 1

DEFAULT_TTL_DAYS = 30
MAX_TTL_DAYS = 90


def _rank(tier: str | None) -> int:
    u = str(tier or "SEAL-0").strip().upper()
    if u.startswith("P") and u[1:].isdigit():
        u = f"SEAL-{u[1:]}"
    try:
        return int(u.replace("SEAL-", "").strip())
    except ValueError:
        return 0


def _store() -> Path:
    return Path(os.environ.get("CLODIA_DATA", "/datadir")) / "human-mcp-grants.json"


def _load() -> list[dict]:
    try:
        return json.loads(_store().read_text()).get("grants", [])
    except Exception:  # noqa: BLE001
        return []


def _save(grants: list[dict]) -> None:
    p = _store()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"grants": grants}, indent=2, ensure_ascii=False))
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass


def _check_tier(tier: str, provider: str, consenso: bool,
                principal_kind: str = "human") -> None:
    """Il tier della stanza è un tetto sul MOTORE DI INFERENZA del client.

    È il punto che rende questa funzione diversa da Telegram, dove esce una
    notifica e basta. Qui, quando Giovanni legge un file del topic dal suo Claude
    Code, quel contenuto **entra nel suo motore di inferenza**. Se un topic
    SEAL-3 si lascia leggere da un client che gira su un provider SEAL-1, il tier
    non è stato violato da un attacco: è stato **svuotato da una comodità**.

    Il provider però qui è **autocertificato** — Giovanni scrive quello che vuole.
    Per questo la scala si ferma prima del dato che non tollera errori: sopra
    SEAL-2 non si conia, e SEAL-2 richiede che qualcuno si assuma quella
    dichiarazione firmandola con la propria (`consenso`).

    Non è un limite tecnico: è il punto in cui ci fermiamo finché la
    dichiarazione è sulla parola. Il giorno in cui un client dichiara il proprio
    provider in modo verificabile, questa funzione cambia — e il commento sopra
    dice perché era com'era.
    """
    # Per un proxy la sostanza della regola non cambia — il contenuto esce
    # verso un sistema che non controlliamo e che si dichiara da sé — ma il
    # nome di quel sistema sì: un proxy non ha un motore di inferenza, e dirgli
    # che ce l'ha manda a cercare la cosa sbagliata.
    dove = ("il motore di inferenza del client" if (principal_kind or "human") == "human"
            else "il sistema esterno che porta il proxy")
    r = _rank(tier)
    if r > TIER_MAX:
        raise PermissionError(
            f"topic {tier}: nessun client MCP sopra SEAL-{TIER_MAX}. Il "
            f"contenuto finirebbe in {dove}, che noi non "
            "controlliamo e che oggi si dichiara da sé. Resta la webui, dove il "
            "dato non esce dal perimetro.")
    if r > TIER_LIBERO and not consenso:
        raise PermissionError(
            f"topic {tier}: serve una concessione esplicita. Il provider "
            f"dichiarato ('{provider or 'non dichiarato'}') non è verificabile: "
            "chi emette il token si assume quella dichiarazione.")
    if not (provider or "").strip():
        raise PermissionError(
            f"dichiara qual è {dove} (es. 'anthropic-api', oppure il nome del "
            "sistema): resta scritto nel token, e serve a sapere dove è finito "
            "ciò che è stato letto.")


def issue(tier: str, name: str, principal: str, *, provider: str,
          carrier: str, human_role: str = "user", clearance: str | None = None,
          ttl_days: int = DEFAULT_TTL_DAYS, by: str = "",
          tier_consent: bool = False, principal_kind: str = "human") -> dict:
    """Conia il token di un client MCP per (principal, topic). Ritorna il token
    IN CHIARO una sola volta: nel registro resta solo il suo id.

    `principal_kind` decide la superficie: una PERSONA porta `VERBS`, un PROXY
    porta `PROXY_VERBS`. Chi sia il principal lo sa la registry, che sta a monte
    — qui arriva già stabilito, come già arriva già autorizzato.
    """
    principal = (principal or "").strip()
    if not principal:
        raise ValueError("principal mancante: un token umano è di qualcuno")
    verbi = verbs_for(principal_kind)
    proxy = (principal_kind or "human").strip().lower() == "proxy"
    _check_tier(tier, provider, tier_consent, principal_kind)
    giorni = max(1, min(int(ttl_days or DEFAULT_TTL_DAYS), MAX_TTL_DAYS))
    gid = "mcp_" + secrets.token_hex(6)
    # Un PROXY non riceve un segreto: riceve un'autorizzazione. Il grant dice
    # CHE può ottenere token per questa stanza fino a questa data; il token se
    # lo conia lui firmando un'asserzione con la propria chiave (`proxy_auth`).
    # Finché qui usciva un bearer a novanta giorni, l'identità del proxy era
    # una stringa copiabile e la firma era di Clodia, non sua.
    token = None if proxy else pki_mint.mint_session_token(
        carrier,
        execution_id=gid,
        ttl_seconds=giorni * 24 * 3600,
        principal=principal,
        clearance=clearance or tier,
        on_behalf=True,
        human_role=human_role or "user",
        # Lega il token a UNA stanza. È firmato: chi lo porta non può riscriverlo
        # per affacciarsi su un'altra. È questa proprietà — non il nome della
        # persona — a rendere sicuro il ramo umano di `_require_topic_member`.
        chat=f"chan:{tier}:{name}:{principal}",
        scoped_tools=list(verbi),
    )
    grants = _load()
    grants.append({
        "id": gid, "principal": principal, "tier": tier, "topic": name,
        # La natura del principal resta scritta nel registro: chi guarda i
        # collegamenti di una stanza deve poter distinguere una persona da un
        # sistema terzo senza andare a leggere il seed.
        "principal_kind": (principal_kind or "human").strip().lower(),
        "provider": (provider or "").strip(), "carrier": carrier,
        "created": int(time.time()), "expires": int(time.time()) + giorni * 24 * 3600,
        "created_by": by or "", "revoked": False,
    })
    _save(grants)
    return {"id": gid, "token": token, "expires": grants[-1]["expires"],
            "tier": tier, "topic": name, "principal": principal,
            "auth": "assertion" if proxy else "bearer",
            "verbs": list(verbi)}


def list_grants(tier: str | None = None, name: str | None = None,
                include_revoked: bool = False) -> list[dict]:
    """Il registro, **senza token**: il valore non si rilegge, si revoca."""
    now = int(time.time())
    out = []
    for g in _load():
        if tier and g.get("tier") != tier:
            continue
        if name and g.get("topic") != name:
            continue
        if g.get("revoked") and not include_revoked:
            continue
        out.append({**g, "expired": g.get("expires", 0) < now})
    return sorted(out, key=lambda g: g.get("created", 0), reverse=True)


def revoke(gid: str) -> dict:
    grants = _load()
    for g in grants:
        if g.get("id") == gid:
            g["revoked"] = True
            g["revoked_at"] = int(time.time())
            _save(grants)
            return {"id": gid, "revoked": True}
    raise ValueError(f"grant '{gid}' inesistente")


def is_revoked(gid: str | None) -> bool:
    """Consultata a OGNI richiesta dal middleware di auth.

    Senza questa lettura la revoca sarebbe un campo scritto in un file che
    nessuno guarda: il token continuerebbe a valere fino alla scadenza, e la
    schermata direbbe il contrario. Un rimedio che non rimedia è peggio di un
    rimedio assente, perché chiude la questione nella testa di chi lo usa.
    """
    if not gid or not str(gid).startswith("mcp_"):
        return False
    for g in _load():
        if g.get("id") == gid:
            return bool(g.get("revoked"))
    # Un id `mcp_` che non sta nel registro è un token il cui grant è sparito:
    # fail-closed. Vale anche dopo un ripristino parziale del datadir.
    return True


def client_config(base_url: str, token: str | None, tier: str, name: str) -> dict:
    """Il frammento da incollare nel client. Un URL, un header, nient'altro.

    `token=None` (un proxy) non ha un frammento: non esiste un segreto statico
    da incollare, e restituire una configurazione con un header vuoto sarebbe
    la cosa peggiore — sembrerebbe funzionare fino alla prima chiamata.
    """
    if token is None:
        return {}
    return {
        "mcpServers": {
            f"clodia-{name}": {
                "type": "http",
                "url": base_url.rstrip("/") + "/mcp",
                "headers": {"Authorization": f"Bearer {token}"},
            }
        }
    }
