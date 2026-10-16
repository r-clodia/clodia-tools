"""The connectors this gateway still implements itself, read from `builtin/`.

clodia-platform#518 moves the PDP's tables into a connector registry. The
registry of #516/#517 is fed by the manifests of *installed packs* — and the
connectors of this instance are not packs yet: they are gateway code. So the
tables could not simply be deleted; the knowledge in them had to be declared
somewhere first, in the same grammar, or the registry would answer «no mapping»
for `email.send` and the PDP would stop constraining the one verb it exists for.

`builtin_manifests/*.yaml` is that somewhere. Each file is a `pack.yaml`-shaped document
the gateway ships with itself:

    core.yaml       http: https: topic: mcp: — the platform-intrinsic schemes,
                    the only ones the issue leaves in a core manifest. This file
                    stays here forever.
    mail.yaml       → comms-pack with migration #522
    telegram.yaml   → comms-pack with migration #522
    google.yaml     → google-pack with migration #523
    github.yaml     → it-pack with migration #525

A migration deletes its file in the same change that adds the pack, and the
registry notices nothing: the entries simply arrive from the other side. Until
then a pack declaring the same connector id or the same scheme is **refused**
(`build_registry`, `builtin=`): while the gateway is the thing actually sending
the mail, an installed manifest must not be able to redefine where it goes.

These files are code, not input. They live in the image, next to the modules
that implement them, and they are the only manifests allowed to declare the
intrinsic schemes or to span namespaces.
"""
from __future__ import annotations

import logging
from pathlib import Path

LOG = logging.getLogger("clodia-tools.connectors")

DIR = Path(__file__).resolve().parent / "builtin_manifests"


def _all() -> dict[str, dict]:
    """Ogni file di `builtin_manifests/`, senza guardare l'interruttore."""
    import yaml

    out: dict[str, dict] = {}
    for path in sorted(DIR.glob("*.yaml")):
        loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        name = str(loaded.get("name") or path.stem)
        if name in out:
            raise ValueError(f"builtin manifest '{name}' declared twice")
        out[name] = dict(loaded)
    return out


def _packaged() -> frozenset[str]:
    """Gli id che il profilo dell'istanza affida a un pack (#522). Mai
    un'eccezione: un profilo illeggibile lascia il gateway com'era."""
    try:
        from .. import instance_profile
        return instance_profile.packaged_connectors()
    except Exception:  # noqa: BLE001
        return frozenset()


def manifests() -> dict[str, dict]:
    """`{pack name: parsed document}` for every file shipped in `builtin_manifests/`.

    A file that does not parse raises: unlike a pack manifest — which comes from
    a volume the gateway does not own, and whose breakage must not take the
    other connectors down — this one is ours, and a gateway whose own mail
    connector is missing would keep working while silently checking nothing.

    Meno i connettori che il profilo d'istanza affida a un pack
    (clodia-platform#522). È QUI che l'interruttore agisce davvero: finché il
    gateway dichiara `telegram`, `build_registry` rifiuta per collisione il
    connettore omonimo del pack — con la stessa frase che la migrazione cita,
    «becomes effective when that implementation moves into a pack». Togliere il
    file è ciò che la migrazione farà per sempre; l'interruttore lo fa per una
    istanza alla volta, e senza un deploy diverso.
    """
    packaged = _packaged()
    if not packaged:
        return _all()
    out: dict[str, dict] = {}
    for name, doc in _all().items():
        entries = doc.get("connectors")
        if not isinstance(entries, list):
            out[name] = doc
            continue
        kept = [e for e in entries
                if not (isinstance(e, dict) and str(e.get("id") or "") in packaged)]
        if len(kept) == len(entries):
            out[name] = doc
            continue
        if not kept:
            # Un file i cui connettori sono TUTTI passati ai pack non va
            # lasciato come documento vuoto: `build_registry(builtin=…)` lo
            # conterebbe fra i pack builtin e il nome resterebbe occupato.
            continue
        out[name] = {**doc, "connectors": kept}
    return out


#: Memo di `released()`, per insieme di connettori passati ai pack. I file
#: stanno nell'immagine e non cambiano a runtime, mentre `released()` è sul
#: percorso caldo (`main._verb_implemented`, una volta per chiamata): senza
#: memo sarebbero sette YAML riletti a ogni verbo.
_RELEASED: dict[frozenset, tuple[frozenset, frozenset]] = {}


#: The first-party pack each builtin connector moves to (epic #527). The
#: switch `connectors: {<id>: pack}` hands the connector to THIS pack only:
#: without the name, whichever pack was imported first could claim the
#: namespace, the official mount and its credential (review of
#: clodia-tools#379). A connector not listed here cannot be switched to a pack.
RELEASED_TO: dict[str, str] = {
    "telegram": "comms-pack",
    "mail": "comms-pack",
    "github": "it-pack",
    "openai-images": "it-pack",
}


def expected_claims() -> dict[str, str]:
    """`{connector id or namespace: pack}` for the connectors switched to a pack.

    Both keys, because a foreign pack could claim the vocabulary under another
    connector id but the same namespace. Never raises: in doubt, nothing."""
    packaged = _packaged()
    if not packaged:
        return {}
    out: dict[str, str] = {}
    try:
        docs = _all()
    except Exception:  # noqa: BLE001
        return {}
    for doc in docs.values():
        for entry in doc.get("connectors") or []:
            if not isinstance(entry, dict):
                continue
            cid = str(entry.get("id") or "")
            if cid not in packaged or cid not in RELEASED_TO:
                continue
            out[cid] = RELEASED_TO[cid]
            ns = str(entry.get("namespace") or "")
            if ns:
                out["ns:" + ns] = RELEASED_TO[cid]
    return out


def released() -> tuple[frozenset[str], frozenset[str]]:
    """`(namespace, prefissi di vault)` che i connettori passati a un pack lasciano.

    Derivato dai manifest builtin, mai da una seconda lista: un connettore
    rinuncia al proprio namespace e ai prefissi di vault che le credenziali
    DICHIARATE lì dentro occupano. Senza questa resa l'interruttore non
    accenderebbe niente — `check_namespace` continuerebbe a riservare
    `telegram` a nessuno e `vault_entry_problem` rifiuterebbe
    `telegram_bot_token` al pack, cioè il connettore del pack verrebbe caricato
    a metà o per niente.

    Mai un'eccezione: in dubbio non si libera nulla, che è il gateway di ieri.
    """
    packaged = _packaged()
    if not packaged:
        return frozenset(), frozenset()
    memo = _RELEASED.get(packaged)
    if memo is not None:
        return memo
    from .manifest import CORE_VAULT_PREFIXES

    try:
        docs = _all()
    except Exception:  # noqa: BLE001
        return frozenset(), frozenset()
    partiti: tuple[set[str], set[str]] = (set(), set())   # namespace, vault
    restati: tuple[set[str], set[str]] = (set(), set())
    for doc in docs.values():
        for entry in doc.get("connectors") or []:
            if not isinstance(entry, dict):
                continue
            dove = partiti if str(entry.get("id") or "") in packaged else restati
            ns = str(entry.get("namespace") or "")
            if ns:
                dove[0].add(ns)
            for provider in entry.get("providers") or []:
                if not isinstance(provider, dict):
                    continue
                cred = provider.get("credential")
                if isinstance(cred, dict) and cred.get("vault_entry"):
                    dove[1].add(str(cred["vault_entry"]))

    def tocca(prefix: str, dati: tuple[set[str], set[str]]) -> bool:
        stem = prefix.rstrip("_")
        return stem in dati[0] or any(e == stem or e.startswith(prefix)
                                      for e in dati[1])

    # Un prefisso che serve ANCHE a un connettore rimasto nel gateway non si
    # libera: `google_` lo userebbero sia il connettore che migra sia uno che
    # resta, e liberarlo lo consegnerebbe a un pack mentre il gateway ci scrive
    # ancora. Oggi non capita — un prefisso, un connettore — ma la migrazione
    # successiva è di google-pack (#523), che di prefissi ne ha tre.
    prefixes = {p for p in CORE_VAULT_PREFIXES
                if tocca(p, partiti) and not tocca(p, restati)}
    out = (frozenset(partiti[0]), frozenset(prefixes))
    _RELEASED[packaged] = out
    return out


def names() -> tuple[str, ...]:
    """The pack names of the builtin manifests, for `build_registry(builtin=…)`."""
    return tuple(manifests())
