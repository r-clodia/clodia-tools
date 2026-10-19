"""The connectors this gateway still declares itself, read from `builtin_manifests/`.

clodia-platform#518 moved the PDP's tables into a connector registry fed by
the manifests of installed packs. What the gateway itself still owns is
declared here in the same grammar:

    core.yaml       http: https: topic: mcp: — the platform-intrinsic schemes.
    datastore.yaml  datastore: — the gateway's own store.

Both are schema-only: no provider, no tools card. These files are code, not
input: they live in the image and are the only manifests allowed to declare
the intrinsic schemes or to span namespaces.

The connectors the gateway used to implement — mail, Telegram, Google, GitHub,
image generation — are served by first-party packs (epic #527); the per-instance
`native|pack` switch that moved them one at a time is retired (#526). What the
gateway still knows about them is in the tables below (`RELEASED_TO`,
`RELEASED_NAMESPACES`, `ADOPTED_VAULT_ENTRIES`): which pack owns each of them,
so that no other pack can claim their ids, namespaces or credentials.
"""
from __future__ import annotations

import logging
from pathlib import Path

LOG = logging.getLogger("clodia-tools.connectors")

DIR = Path(__file__).resolve().parent / "builtin_manifests"


def _all() -> dict[str, dict]:
    """Every file of `builtin_manifests/`."""
    import yaml

    out: dict[str, dict] = {}
    for path in sorted(DIR.glob("*.yaml")):
        loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        name = str(loaded.get("name") or path.stem)
        if name in out:
            raise ValueError(f"builtin manifest '{name}' declared twice")
        out[name] = dict(loaded)
    return out


def manifests() -> dict[str, dict]:
    """`{pack name: parsed document}` for every file shipped in `builtin_manifests/`.

    A file that does not parse raises: unlike a pack manifest — which comes from
    a volume the gateway does not own, and whose breakage must not take the
    other connectors down — this one is ours, and a gateway whose own
    connectors are missing would keep working while silently checking nothing.
    """
    return _all()


#: The builtin connectors: schema-only (no provider, no card). Never filtered
#: by the edition's `integrations.connectors` (`instance_profile
#: .connector_allowed`): their schemes are what every whitelist is written in.
SCHEMA_ONLY_CONNECTORS: frozenset[str] = frozenset({"core", "datastore"})


#: Connector ids that belong to the family of another (clodia-platform#524).
#: Google is four connectors — one per verb namespace, because a pack
#: connector owns exactly one — but ONE credential and one decision of the
#: owner, and Gmail's provider of the mail vocabulary (`mail-gmail`) rides on
#: the same consent. Read by the edition gating: `integrations.connectors:
#: [google]` admits the whole family (`instance_profile.connector_allowed`).
CONNECTOR_FAMILY: dict[str, str] = {
    "google-sheets": "google",
    "google-docs": "google",
    "google-calendar": "google",
    "mail-gmail": "google",
}


#: The first-party pack that serves each connector the gateway used to
#: implement (epic #527, switch retired by #526). That pack ONLY: without the
#: name, whichever pack was imported first could claim the namespace, the
#: official mount and its credential (review of clodia-tools#379).
RELEASED_TO: dict[str, str] = {
    "telegram": "comms-pack",
    "mail": "comms-pack",
    "github": "it-pack",
    "openai-images": "it-pack",
    # #524: the four Google connectors, and Gmail's provider of the mail
    # vocabulary, which has no builtin counterpart but follows `google`.
    "google": "google-pack",
    "google-sheets": "google-pack",
    "google-docs": "google-pack",
    "google-calendar": "google-pack",
    "mail-gmail": "google-pack",
}


#: The namespace each of those connectors owns — what the gateway's builtin
#: manifests declared for them before the packs took over (#522–#525).
#: `mail-gmail` has none of its own: it `extends:` the mail vocabulary.
RELEASED_NAMESPACES: dict[str, str] = {
    "mail": "email",
    "telegram": "telegram",
    "github": "github",
    "openai-images": "openai",
    "google": "gdrive",
    "google-sheets": "gsheets",
    "google-docs": "gdocs",
    "google-calendar": "gcalendar",
}


#: The vault entry the gateway's own declaration gave a connector, which its
#: pack adopts as is (#568): the credential that pack's backend may read even
#: before its connector is held. Mail and Google have none: their credentials
#: stay in the gateway's custody (`CORE_CREDENTIALS_FOLLOW`).
ADOPTED_VAULT_ENTRIES: dict[str, str] = {
    "telegram": "telegram_bot_token",
    "github": "github_pat",
    "openai-images": "openai_api_key",
}


#: The upstream of every FIRST-PARTY pack (clodia-platform#558):
#: `{pack: (repository, directory prefix of the pack in it)}`. The only packs
#: whose `target: gateway` components this gateway fetches and runs inside the
#: reference monitor, and the only place they may come from. Code, not
#: datadir: `/datadir/packs/<pack>/pack.yaml` is written by the agent-server,
#: so a component's `source` must EQUAL the repository here and its path must
#: lie under the prefix, and the pack's manifest itself is then taken from
#: `<prefix>pack.yaml` at the pinned commit (`components.store`), never from
#: the datadir copy. A pack missing here has no gateway component, whatever its
#: manifest says.
FIRST_PARTY_SOURCES: dict[str, tuple[str, str]] = {
    "google-pack": ("r-clodia/clodia-logic", "catalogs/packs/google-pack/"),
    "comms-pack": ("r-clodia/clodia-logic", "catalogs/packs/comms-pack/"),
    "it-pack": ("r-clodia/clodia-packs", "packs/it-pack/"),
}

#: The packs this gateway knows as first-party: the keys of
#: `FIRST_PARTY_SOURCES`. The `first_party: true` flag of a `pack.yaml` is
#: necessary but not sufficient.
FIRST_PARTY_PACKS: frozenset[str] = frozenset(FIRST_PARTY_SOURCES)


#: Vault prefixes (ending in `_`) and exact entries of the gateway's custody
#: that a GATEWAY COMPONENT of the connector's pack may use (#558):
#: `{prefix or entry: connector id}`. Reachable through `host.credentials`
#: only by the component of the pack `RELEASED_TO` names for that connector.
#:
#: Needed because #524 kept credential custody in the gateway: the Google
#: connectors declare no provider credential, so `released()` frees no Google
#: prefix, and `app_` (the OAuth app client) is no connector's prefix at all. The credentials
#: stay in the gateway vault — no re-consent — and the component that now
#: implements the verbs reaches them through the host, scoped.
#:
#: `mailbox_` follows `mail` for the same reason (#558): mail declares no
#: provider credential either, the IMAP/SMTP mailboxes stay in the gateway
#: vault, and comms-pack's gateway component reaches them through the host.
CORE_CREDENTIALS_FOLLOW: dict[str, str] = {
    "google_": "google",
    "gworkspace_": "google",
    "gmail_": "google",
    "app_google_oauth": "google",
    "mailbox_": "mail",
}


#: Provider transports a first-party pack declared in an earlier version and
#: no longer does (#558: the code became the pack's gateway component). Their
#: backends stay gateway-internal — never listed, an agent's call DENIED —
#: while the pack's own stamped mount survives an Update, until an admin
#: unregisters it (`DELETE /tools/mcp/<name>`).
RETIRED_TRANSPORTS: dict[str, frozenset[str]] = {
    "comms-pack": frozenset({"mail-transport"}),            # comms-pack 1.4.0
    "google-pack": frozenset({"google-transport", "gmail-transport"}),  # 1.0.0
    "it-pack": frozenset({"imagegen-transport"}),           # it-pack ≤ 0.18.x
}


#: Services of ANOTHER pack's gateway component that a component may look up
#: through `host.service(pack, name)` (#558): `{caller pack: {(callee pack,
#: service), …}}`. Code, not datadir, and closed by default: a component calls
#: no other component unless the pair is listed here.
#:
#: comms-pack owns the mail vocabulary and serves `email.*` for every
#: account; a Google account's credential is google-pack's and never in
#: comms-pack's scope, so comms-pack asks google-pack for exactly two
#: things — the Google mail accounts (names and addresses, no secret) and one
#: client run on an account's own XOAUTH2 files, which google-pack writes.
COMPONENT_SERVICES: dict[str, frozenset[tuple[str, str]]] = {
    "comms-pack": frozenset({("google-pack", "mail_accounts"),
                             ("google-pack", "mail_exec")}),
}


#: The browser hosts whose URLs a first-party pack connector may canonicalise
#: into its own schemes (#524, `Registry.canonical`). The builtin Google
#: manifest read `https:` to turn a Drive folder URL copied from the browser
#: into `gdrive:folder/<id>`; a pack may not read a shared scheme, and without
#: this google-pack would silently stop recognising those URLs in whitelists,
#: topic buttons and call destinations. Pinned HERE and not in the pack's
#: manifest: canonicalisation also applies to a call's destination, so a
#: manifest that chose its own hosts could rewrite any URL into an approved
#: folder.
ELECTED_URL_HOSTS: dict[str, frozenset[str]] = {
    "google": frozenset({"drive.google.com", "docs.google.com"}),
}


def released_vault_entries(pack: str) -> set[str]:
    """The vault entries of the connectors `RELEASED_TO` hands to `pack`
    (`ADOPTED_VAULT_ENTRIES`) — the credential a first-party pack's backend may
    read even before its own connector is held (an adoption, #568)."""
    return {entry for cid, entry in ADOPTED_VAULT_ENTRIES.items()
            if pack and RELEASED_TO.get(cid) == pack}


def expected_claims() -> dict[str, str]:
    """`{connector id or "ns:"+namespace: pack}` for every connector of
    `RELEASED_TO`: the only pack that may declare it.

    Both keys, because a foreign pack could claim the vocabulary under another
    connector id but the same namespace."""
    out: dict[str, str] = dict(RELEASED_TO)
    for cid, ns in RELEASED_NAMESPACES.items():
        out["ns:" + ns] = RELEASED_TO[cid]
    return out


#: Memo of `_released_for`, per set of connector ids: the tables are code.
_RELEASED: dict[frozenset, tuple[frozenset, frozenset]] = {}


def released() -> tuple[frozenset[str], frozenset[str]]:
    """`(namespaces, vault prefixes)` that the pack-served connectors take
    out of the gateway's reservation.

    A connector gives up its namespace and the core vault prefixes its
    adopted credential falls under: without this `check_namespace` would keep
    `telegram` reserved for nobody and `vault_entry_problem` would refuse
    `telegram_bot_token` to comms-pack. Who may then claim them is
    `expected_claims` (`resolved._strip_foreign_claims`): their pack, nobody
    else.
    """
    return _released_for(frozenset(RELEASED_TO))


def released_to(pack: str) -> frozenset[str]:
    """The vault prefixes released by the connectors handed to `pack` ONLY
    (#558). A prefix shared with a connector of another pack, or kept by the
    gateway, is not in it."""
    mine = frozenset(c for c, p in RELEASED_TO.items() if p == pack)
    return _released_for(mine)[1] if mine else frozenset()


def follows_to(entry: str, pack: str) -> bool:
    """True when `entry` is a `CORE_CREDENTIALS_FOLLOW` credential whose
    connector is served by `pack` (#558)."""
    cid = CORE_CREDENTIALS_FOLLOW.get(entry)
    return bool(cid) and RELEASED_TO.get(cid) == pack


def _released_for(ids: frozenset[str]) -> tuple[frozenset[str], frozenset[str]]:
    memo = _RELEASED.get(ids)
    if memo is not None:
        return memo
    from .manifest import CORE_VAULT_PREFIXES

    partiti: tuple[set[str], set[str]] = (set(), set())   # namespace, vault
    restati: tuple[set[str], set[str]] = (set(), set())
    for cid in RELEASED_TO:
        dove = partiti if cid in ids else restati
        if RELEASED_NAMESPACES.get(cid):
            dove[0].add(RELEASED_NAMESPACES[cid])
        if ADOPTED_VAULT_ENTRIES.get(cid):
            dove[1].add(ADOPTED_VAULT_ENTRIES[cid])
    for doc in _all().values():
        for entry in doc.get("connectors") or []:
            if not isinstance(entry, dict):
                continue
            if entry.get("namespace"):
                restati[0].add(str(entry["namespace"]))
            for provider in entry.get("providers") or []:
                cred = provider.get("credential") if isinstance(provider, dict) else None
                if isinstance(cred, dict) and cred.get("vault_entry"):
                    restati[1].add(str(cred["vault_entry"]))

    def tocca(prefix: str, dati: tuple[set[str], set[str]]) -> bool:
        stem = prefix.rstrip("_")
        return stem in dati[0] or any(e == stem or e.startswith(prefix)
                                      for e in dati[1])

    # A prefix that ALSO serves a connector of another pack, or one the
    # gateway keeps, is not released: handing it over would give one pack a
    # credential another one (or the gateway) writes.
    prefixes = {p for p in CORE_VAULT_PREFIXES
                if tocca(p, partiti) and not tocca(p, restati)}
    out = (frozenset(partiti[0]), frozenset(prefixes))
    _RELEASED[ids] = out
    return out


def names() -> tuple[str, ...]:
    """The pack names of the builtin manifests, for `build_registry(builtin=…)`."""
    return tuple(manifests())
