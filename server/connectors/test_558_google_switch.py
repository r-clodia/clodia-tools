"""Google implemented by google-pack's gateway component (clodia-platform#558,
superseding the transport design of #524; the `native|pack` switch is retired
by #526 — a profile still saying `native` changes nothing):

- google-pack's four connectors — `google` (owner of `gdrive:`/`gsheets:`/
  `gcal:`, namespace `gdrive`) and the verb-only siblings `google-sheets`/
  `google-docs`/`google-calendar` — supply the vocabulary the PDP reads;
- the 24 `gdrive/gsheets/gdocs/gcalendar` verbs LEAVE the native catalogue and
  dispatch: google-pack's gateway component registers and serves them through
  the same `call_tool` path; nothing serving them is a refusal, never the
  native code (`google_io` refuses in that position);
- the gateway's own Google lookups (confinement API, labels, the pre-PDP parent
  of `gdrive.update`, the Tools card test, the token cache) ask the component's
  services, and fail closed without them;
- Gmail is google-pack's provider of the mail vocabulary (`mail-gmail`,
  `extends: mail`, no transport) and a Google account's `email.*` I/O runs in
  the component's `mail_run` service.

What is pinned here, WITHOUT the real component (a stand-in is installed in
the loader): that the profile changes nothing; every PDP answer about Google
(and that the pins can fail); fail-closed;
routing of the gateway's lookups and of Gmail; foreign packs. The real
component — loaded from a clodia-logic checkout — and the Google suites re-run
against it are in `server/test_558_google_component.py`.
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import copy
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from unittest.mock import patch

import yaml

from .. import egress, instance_profile, proxy, taint
from ..components import loader
from ..components.grammar import GatewayComponent
from ..components.host import ServiceSpec, VerbSpec
from ..tools import google_switch
from . import builtin as B
from . import first_party_fixture as _FP
from . import manifest as M
from . import resolved
from .test_523_mail_provider import _comms_pack

# The PDP tables of #524, moved here from the removed `test_524_google_pins`
# (the native Google client's pins): what the PDP answers about Google is the
# gateway's and stays pinned.
ARGS = {"folder_id": "F", "parent_id": "P", "email": "X@Y.it", "file_id": "FI",
        "document_id": "D", "spreadsheet_id": "S", "calendar_id": "c@x.it"}

_DRIVE_DESTS = ("drive", ["mailto:x@y.it", "gdrive:folder/F", "gdrive:folder/P"])

#: verb → (spec_for(verb) applied to ARGS, source_uri(verb, ARGS), taints(verb))
PDP = {
    "gdrive.list":              (None, None, False),
    "gdrive.search":            (None, None, False),
    "gdrive.mkdir":             (_DRIVE_DESTS, None, False),
    "gdrive.upload":            (_DRIVE_DESTS, None, False),
    "gdrive.update":            (_DRIVE_DESTS, None, False),
    "gdrive.download":          (None, "gdrive:file/FI", True),
    "gdrive.share":             (_DRIVE_DESTS, None, False),
    "gdrive.rename":            (None, None, False),
    "gdrive.move":              (_DRIVE_DESTS, None, False),
    "gcalendar.list_calendars": (None, None, False),
    "gcalendar.list_events":    (None, None, True),
    "gcalendar.create_event":   (None, None, False),
    "gcalendar.update_event":   (None, None, False),
    "gcalendar.delete_event":   (None, None, False),
    "gcalendar.freebusy":       (None, None, False),
    "gdocs.create":             (None, None, False),
    "gdocs.read":               (None, "gdrive:doc/D", True),
    "gdocs.append_text":        (None, None, False),
    "gdocs.replace_text":       (None, None, False),
    "gsheets.list_tabs":        (None, "gsheets:S", True),
    "gsheets.read":             (None, "gsheets:S", True),
    "gsheets.add_tab":          (("gsheets", ["gsheets:S"]), None, False),
    "gsheets.append_rows":      (("gsheets", ["gsheets:S"]), None, False),
    "gsheets.write_range":      (("gsheets", ["gsheets:S"]), None, False),
}

#: Declared reads (`direction: source`) — the verbs whose source can be vetted.
DECLARED_READS = {"gdrive.download", "gdocs.read", "gsheets.list_tabs",
                  "gsheets.read"}

#: raw URI → canonical form, for what a human pastes into a list.
CANONICAL = [
    ("https://drive.google.com/drive/folders/ABC", "gdrive:folder/ABC"),
    ("https://drive.google.com/drive/u/1/folders/ABC?usp=sharing", "gdrive:folder/ABC"),
    ("https://docs.google.com/document/d/D1/edit?tab=t.0", "gdrive:doc/D1"),
    ("https://drive.google.com/file/d/F1/view?usp=drive_link", "gdrive:file/F1"),
    ("https://docs.google.com/spreadsheets/d/S1/edit#gid=0", "gsheets:S1"),
    ("gdrive://ABC", "gdrive:folder/ABC"),
    ("gdrive://folder/ABC/", "gdrive:folder/ABC"),
    ("gsheets://S1/", "gsheets:S1"),
    ("gdrive:file/F", "gdrive:file/F"),
    ("gdrive:doc/D", "gdrive:doc/D"),
    ("gcal:a@b.it", "gcal:a@b.it"),
    ("gcal:primary", "gcal:primary"),
    ("gcal:*@tomato.blue", "gcal:*@tomato.blue"),
    # Oddity carried across on purpose: the scheme is lowercased, the
    # calendar id is not (matching is case-insensitive in `_matches`).
    ("GCAL:A@B.IT", "gcal:A@B.IT"),
]

#: (direction, uri) → canonical uri returned, or None when refused.
GRANTABLE = [
    ("egress", "gdrive:folder/ABC", "gdrive:folder/ABC"),
    ("egress", "gdrive:file/F", "gdrive:file/F"),
    ("egress", "gdrive:doc/D", "gdrive:doc/D"),
    ("egress", "gsheets:S1", "gsheets:S1"),
    ("egress", "gcal:a@b.it", "gcal:a@b.it"),
    ("egress", "gcal:primary", "gcal:primary"),
    ("egress", "gcal:*@x.it", "gcal:*@x.it"),
    ("egress", "https://drive.google.com/drive/folders/ABC", "gdrive:folder/ABC"),
    ("egress", "https://docs.google.com/spreadsheets/d/S1/edit", "gsheets:S1"),
    ("ingress", "gdrive:folder/ABC", "gdrive:folder/ABC"),
    ("ingress", "gdrive:file/F", "gdrive:file/F"),
    ("ingress", "gdrive:doc/D", "gdrive:doc/D"),
    ("ingress", "gsheets:S1", "gsheets:S1"),
    ("ingress", "https://drive.google.com/drive/folders/ABC", "gdrive:folder/ABC"),
    ("ingress", "https://docs.google.com/spreadsheets/d/S1/edit", "gsheets:S1"),
    # Oddity carried across: the `gdrive` forms are documentation for the
    # widget, not a filter — an unknown segment is still grantable.
    ("egress", "gdrive:bogus/x", "gdrive:bogus/x"),
    ("ingress", "gdrive:bogus/x", "gdrive:bogus/x"),
    # Refused.
    ("egress", "gcal:*", None),
    ("egress", "gcal:", None),
    ("egress", "gdrive:folder/", None),
    ("egress", "gsheets:", None),
    ("ingress", "gdrive:folder/", None),
    ("ingress", "gsheets:", None),
    ("ingress", "gcal:a@b.it", None),       # authority over a resource, not a source
    ("ingress", "gcal:primary", None),
    ("ingress", "gcal:*@x.it", None),
]


#: The 24 verbs as google-pack's component registers them: the properties
#: matter (the PDP keeps a caller argument only if the schema offers it — e.g.
#: `gdrive.update` has no `folder_id`), the descriptions do not. The gateway's
#: own schemas went with the native code (#524).
_GOOGLE_PROPS = {
    'gdrive.list': ('folder_id', 'query', 'limit', 'account'),
    'gdrive.search': ('name', 'limit', 'account'),
    'gdrive.mkdir': ('name', 'parent_id', 'account'),
    'gdrive.upload': ('src', 'name', 'folder_id', 'account'),
    'gdrive.update': ('file_id', 'src', 'account'),
    'gdrive.download': ('file_id', 'dest', 'account'),
    'gdrive.share': ('file_id', 'email', 'role', 'account'),
    'gdrive.rename': ('file_id', 'new_name', 'account'),
    'gdrive.move': ('file_id', 'folder_id', 'account'),
    'gcalendar.list_calendars': ('account',),
    'gcalendar.list_events': ('calendar_id', 'time_min', 'time_max', 'query', 'limit', 'account'),
    'gcalendar.create_event': ('summary', 'start', 'end', 'calendar_id', 'description', 'location', 'attendees', 'all_day', 'account'),
    'gcalendar.update_event': ('event_id', 'calendar_id', 'summary', 'start', 'end', 'description', 'location', 'account'),
    'gcalendar.delete_event': ('event_id', 'calendar_id', 'account'),
    'gcalendar.freebusy': ('time_min', 'time_max', 'calendar_id', 'account'),
    'gdocs.create': ('title', 'text', 'account'),
    'gdocs.read': ('document_id', 'account'),
    'gdocs.append_text': ('document_id', 'text', 'account'),
    'gdocs.replace_text': ('document_id', 'find', 'replace', 'match_case', 'account'),
    'gsheets.list_tabs': ('spreadsheet_id', 'account'),
    'gsheets.read': ('spreadsheet_id', 'range', 'tab', 'formulas', 'account'),
    'gsheets.add_tab': ('spreadsheet_id', 'title', 'index', 'account'),
    'gsheets.append_rows': ('spreadsheet_id', 'tab', 'rows', 'account'),
    'gsheets.write_range': ('spreadsheet_id', 'range', 'values', 'account'),
}


def _google_tools():
    from mcp.types import Tool
    return [Tool(name=n, description=n, inputSchema={
        "type": "object", "properties": {p: {} for p in ps}})
        for n, ps in _GOOGLE_PROPS.items()]


PACK = "google-pack"
GOOGLE_IDS = ("google", "google-sheets", "google-docs", "google-calendar")
NAMESPACES = ("gdrive", "gsheets", "gdocs", "gcalendar")

#: Verbs with no egress/source mapping and no taint row: google-pack lists
#: them in `unmapped:` (#558), per connector.
UNMAPPED = {
    "google": ["gdrive.list", "gdrive.search", "gdrive.rename"],
    "google-docs": ["gdocs.create", "gdocs.append_text", "gdocs.replace_text"],
    "google-calendar": ["gcalendar.list_calendars", "gcalendar.create_event",
                        "gcalendar.update_event", "gcalendar.delete_event",
                        "gcalendar.freebusy"],
}


def _verbs() -> tuple[str, ...]:
    from .. import main
    return tuple(sorted(main._GOOGLE_NATIVE_NAMES))


# Browser URLs into `gdrive:`/`gsheets:`, rewritten into the PACK's safe regex
# subset (no quantified group, at most two repeats and two `?`): the builtin's
# `(?:u/\d+/)?` and `(?:[/?#].*)?` become one rule per shape. Same answers on
# every URL of the pinned tables; the `u/<n>/` form covers n < 100.
_GDRIVE_CANON = [
    {"from": r"^gdrive://([\w-]+)/?$", "to": "gdrive:folder/{1}"},
    {"from": r"^gdrive://folder/([\w-]+)/?$", "to": "gdrive:folder/{1}"},
    {"from": r"^https?://drive\.google\.com/drive/folders/([\w-]+)$",
     "to": "gdrive:folder/{1}"},
    {"from": r"^https?://drive\.google\.com/drive/folders/([\w-]+)[/?#].*$",
     "to": "gdrive:folder/{1}"},
    {"from": r"^https?://drive\.google\.com/drive/u/\d\d?/folders/([\w-]+)$",
     "to": "gdrive:folder/{1}"},
    {"from": r"^https?://drive\.google\.com/drive/u/\d\d?/folders/([\w-]+)[/?#].*$",
     "to": "gdrive:folder/{1}"},
    {"from": r"^https?://docs\.google\.com/document/d/([\w-]+)$",
     "to": "gdrive:doc/{1}"},
    {"from": r"^https?://docs\.google\.com/document/d/([\w-]+)[/?#].*$",
     "to": "gdrive:doc/{1}"},
    {"from": r"^https?://drive\.google\.com/file/d/([\w-]+)$", "to": "gdrive:file/{1}"},
    {"from": r"^https?://drive\.google\.com/file/d/([\w-]+)[/?#].*$",
     "to": "gdrive:file/{1}"},
]
_GSHEETS_CANON = [
    {"from": r"^gsheets://([\w-]+)/?$", "to": "gsheets:{1}"},
    {"from": r"^https?://docs\.google\.com/spreadsheets/d/([\w-]+)$",
     "to": "gsheets:{1}"},
    {"from": r"^https?://docs\.google\.com/spreadsheets/d/([\w-]+)[/?#].*$",
     "to": "gsheets:{1}"},
]


def _google_connectors() -> list[dict]:
    """google-pack's four Google connectors: the builtin declarations,
    verbatim, except what a PACK must write differently — the canonicalisation
    in the safe regex subset, and `unmapped:` for the verbs the PDP has nothing
    to read on (a component verb must be classified)."""
    doc = yaml.safe_load((_FP.FORMER_BUILTIN / "google.yaml").read_text(encoding="utf-8"))
    entries = copy.deepcopy(doc["connectors"])
    owner = entries[0]
    assert owner["id"] == "google"
    for s in owner["schemes"]:
        if s["scheme"] == "gdrive":
            s["canonicalise"] = copy.deepcopy(_GDRIVE_CANON)
        if s["scheme"] == "gsheets":
            s["canonicalise"] = copy.deepcopy(_GSHEETS_CANON)
    for e in entries:
        if e["id"] in UNMAPPED:
            e["unmapped"] = list(UNMAPPED[e["id"]])
    return entries


def _gmail_connector() -> dict:
    """Gmail as a provider of the mail vocabulary. Namespace `gdrive`: the
    namespace google-pack holds after the switch (see SCHEMA.md — `google`
    stays reserved with the `google_` vault prefix)."""
    return {"id": "mail-gmail", "manifest_version": 1, "namespace": "gdrive",
            "label": "Gmail", "extends": "mail",
            "providers": [{"id": "gmail", "label": "Gmail"}]}


def _google_pack(*, without: tuple[str, ...] = (), gmail: bool = True,
                 mutate=None) -> dict:
    entries = [e for e in _google_connectors() if e["id"] not in without]
    if gmail:
        entries.append(_gmail_connector())
    if mutate:
        mutate(entries)
    return {"name": PACK, "connectors": entries}


class _FakeComponent:
    """A stand-in for google-pack's gateway component in the loader: its 24
    verbs, and services that record what the gateway asks them."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def _svc(self, name, answer):
        def fn(*args):
            self.calls.append((name, *args))
            return answer(*args) if callable(answer) else answer
        return fn

    def state(self) -> "loader.State":
        from .. import main
        comp = GatewayComponent(
            pack=PACK, id="google", repo="r-clodia/clodia-logic",
            path="catalogs/packs/google-pack/gateway", ref="main",
            entry="google_component", connectors=GOOGLE_IDS,
            credentials=("google_", "gworkspace_", "gmail_", "app_google_oauth"),
            namespaces=dict(zip(GOOGLE_IDS, NAMESPACES)))
        tools = {t.name: t for t in _google_tools()}
        verbs = {n: VerbSpec(component=comp.key, pack=PACK, namespace=n.split(".")[0],
                             tool=t, handler=self._svc("verb", {"from": "component"}),
                             offload=False)
                 for n, t in tools.items()}
        answers = {
            "accounts": ["conto"],
            "describe_folder": lambda a, f: {"id": f, "name": "Cartella",
                                             "is_folder": True},
            "perimeter_changed": None,
            "credential_changed": None,
            "folder_labels": lambda uris: {u: {"url": "U", "name": "N"} for u in uris},
            "pdp_arguments": lambda n, a: {"folder_id": "PARENT", "other": "X"},
            "test_connection": {"ok": True, "detail": "component"},
            "mail_run": lambda payload: {"returncode": 0, "stdout": "[]", "stderr": ""},
        }
        services = {n: ServiceSpec(component=comp.key, pack=PACK, name=n,
                                   handler=self._svc(n, a)) for n, a in answers.items()}
        return loader.State(component=comp, status="loaded", commit="c" * 40,
                            verbs=verbs, services=services)


class _GoogleIstanza:
    """A fake instance with google-pack installed and a stand-in component.

    Mixin. `posizione` writes `profile.yaml` for real: since #526 its
    `connectors:` must change nothing."""

    COMPONENT = True

    GOOGLE = "pack"

    def setUp(self) -> None:  # noqa: D401 — unittest hook
        super().setUp()
        self.addCleanup(self._ricarica)
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.scrivi_pack(PACK, _google_pack())
        self.backends: list[dict] = []
        for p in (patch.dict(os.environ, {"CLODIA_DATA": str(self.dir)}),
                  patch.object(resolved, "_DATA", self.dir),
                  patch.object(resolved, "_first_seen_path",
                               lambda: self.dir / "first-seen.json"),
                  patch.dict(proxy.CONFIG, {"mcp_backends": self.backends})):
            p.start()
            self.addCleanup(p.stop)
        self.component = _FakeComponent()
        self.addCleanup(loader.reset)
        loader.reset()
        if self.COMPONENT:
            self.metti_componente()
        self.posizione(self.GOOGLE)

    def metti_componente(self) -> None:
        loader._STATES[f"{PACK}/google"] = self.component.state()

    def togli_componente(self) -> None:
        loader.reset()

    def scrivi_pack(self, name: str, doc: dict) -> None:
        d = self.dir / "packs" / name
        d.mkdir(parents=True, exist_ok=True)
        (d / "pack.yaml").write_text(json.dumps(doc), encoding="utf-8")
        resolved.invalidate()

    def togli_pack(self, name: str) -> None:
        (self.dir / "packs" / name / "pack.yaml").unlink()
        resolved.invalidate()

    def _ricarica(self) -> None:
        instance_profile.load(force=True)
        resolved.invalidate()

    def posizione(self, google: str | None, **altri: str) -> None:
        righe = ["edition: full"]
        modi = {**({"google": google} if google else {}), **altri}
        if modi:
            righe.append("connectors:")
            righe += [f"  {k}: {v}" for k, v in modi.items()]
        (self.dir / "profile.yaml").write_text("\n".join(righe) + "\n",
                                               encoding="utf-8")
        self._ricarica()


class _Istanza(_GoogleIstanza, unittest.TestCase):
    pass


def _call(name: str, args: dict) -> str:
    from .. import main
    return asyncio.run(main.call_tool(name, args))[0].text


def _call_as_clodia(name: str, args: dict) -> str:
    """A call with a signed claim and a whitelist that lets it through."""
    from unittest.mock import AsyncMock
    from .. import main
    from .. import whitelist as wl
    from ..claims import ClaimsContext
    token = {"agent": "clodia", "execution_id": "clodia-558s", "principal": "davide",
             "chat": "chan:SEAL-2:acme:clodia"}
    cfg = {"agents": {"clodia": {"allowed_tools": ["*"]}}, "egress_allow": []}

    async def go():
        with ClaimsContext(token, "t"), \
                patch.object(main, "_require_gate_consent", AsyncMock(return_value={})), \
                patch.object(wl, "CONFIG", cfg):
            return await main.call_tool(name, args)
    return asyncio.run(go())[0].text


# --------------------------------------------------------------------------
# 1. the switch
# --------------------------------------------------------------------------
class SwitchTests(_Istanza):
    def test_google_pack_holds_the_four_connectors_and_gmail(self):
        for pos in ("pack", "native", None):     # the profile changes nothing
            with self.subTest(posizione=pos):
                self.posizione(pos)
                self.assertNotIn("gateway-google", B.manifests())
                reg = resolved.registry()
                for cid in GOOGLE_IDS + ("mail-gmail",):
                    c = reg.by_id(cid)
                    self.assertEqual((c.pack, c.builtin), (PACK, False), cid)
                for ns in NAMESPACES:
                    self.assertTrue(resolved.held_by_pack(ns))

    def test_the_family_of_google(self):
        for cid in GOOGLE_IDS[1:] + ("mail-gmail",):
            self.assertEqual(B.CONNECTOR_FAMILY[cid], "google")
        for cid in ("google", "mail", "telegram", "github"):
            self.assertNotIn(cid, B.CONNECTOR_FAMILY)

    def test_released_frees_every_namespace_and_no_vault_prefix(self):
        namespaces, prefixes = B.released()
        self.assertTrue(set(NAMESPACES) <= namespaces)
        # Credential custody stays: consent, app client and the per-account
        # bundles are the gateway's.
        for p in ("google_", "gworkspace_", "gmail_", "app_"):
            self.assertNotIn(p, prefixes)
        for ns in ("google", "gworkspace", "gmail", "app"):
            self.assertIn(ns, M.reserved_namespaces())
        self.assertTrue(M.vault_entry_problem("google_conto", "gdrive"))
        with self.assertRaises(M.ManifestError):
            M.check_namespace("google", [])

    def test_released_to_names_google_pack(self):
        for cid in GOOGLE_IDS + ("mail-gmail",):
            self.assertEqual(B.RELEASED_TO[cid], PACK)
        self.posizione("native")                 # ignored
        claims = B.expected_claims()
        for key in GOOGLE_IDS + ("mail-gmail",) + tuple(f"ns:{n}" for n in NAMESPACES):
            self.assertEqual(claims.get(key), PACK, key)

    def test_core_namespaces_never_hold_them(self):
        for pos in ("pack", "native"):
            with self.subTest(posizione=pos):
                self.posizione(pos)
                self.assertFalse(set(NAMESPACES) & M.core_namespaces())


class TheVerbsMoveToTheComponentTests(_Istanza):
    def test_they_are_not_in_the_native_catalogue(self):
        from .. import main
        self.assertEqual(len(_verbs()), 24)
        nomi = {t.name for t in main._all_native_tools()}
        listed = {t.name for t in main._component_tools()}
        for verbo in _verbs():
            with self.subTest(verbo=verbo):
                self.assertNotIn(verbo, main._GATEWAY_RETAINED_VERBS)
                self.assertNotIn(verbo, nomi)
                self.assertIn(verbo, listed)
                self.assertTrue(main._is_packaged_verb(verbo))
                self.assertTrue(main._verb_implemented(verbo))
        for ns in NAMESPACES:
            self.assertNotIn(ns, main._native_tool_namespaces())

    def test_a_profile_saying_native_still_hands_them_to_the_component(self):
        from .. import main
        self.posizione("native")
        for verbo in _verbs():
            with self.subTest(verbo=verbo):
                self.assertTrue(main._is_packaged_verb(verbo))
                self.assertIsNotNone(main._component_verb(verbo))

    def test_a_call_reaches_the_component_not_the_native_code(self):
        from .. import main
        out = _call_as_clodia("gdrive.list", {})
        self.assertEqual(json.loads(out), {"from": "component"}, out)
        self.assertEqual(self.component.calls[0][0], "verb")

    def test_pack_declarations_never_apply_to_the_component_verbs(self):
        """No `context:` on google-pack's connectors: nothing is filled in."""
        from .. import main
        args = {"file_id": "F"}
        self.assertEqual(main._fill_declared_context("gdrive.download", args), args)


# --------------------------------------------------------------------------
# 2. the PDP's answers, the four connectors
# --------------------------------------------------------------------------
def _risposte() -> dict:
    """Every public PDP answer about Google, asked as the pins ask them."""
    def grantable(direzione: str, uri: str):
        try:
            return egress.check_grantable(direzione, uri)
        except ValueError:
            return None

    out: dict = {}
    for verbo in _verbs():
        spec = egress.spec_for(verbo)
        out[f"spec:{verbo}"] = None if spec is None else (spec[0], spec[1](dict(ARGS)))
        out[f"fonte:{verbo}"] = resolved.source_uri(verbo, dict(ARGS))
        out[f"lettura:{verbo}"] = resolved.is_declared_read(verbo)
        out[f"taint:{verbo}"] = taint.taints(verbo)
    for raw, _want in CANONICAL:
        out[f"canonico:{raw}"] = egress.canonical(raw)
    for extra in ("https://drive.google.com/drive/u/12/folders/ABC/view",
                  "https://drive.google.com.evil.example/drive/folders/ABC",
                  "https://evil.example/drive/folders/ABC"):
        out[f"canonico:{extra}"] = egress.canonical(extra)
    for direzione, uri, _want in GRANTABLE:
        out[f"concedibile:{direzione}:{uri}"] = grantable(direzione, uri)
    for uri in ("gdrive:folder/X", "gsheets:S", "gcal:a@b.it"):
        out[f"danger:{uri}"] = egress.danger_note(uri)
    out["schemi"] = (tuple(resolved.registry().scheme_names("egress")),
                     tuple(resolved.registry().scheme_names("source")))
    out["gerarchici"] = tuple(egress.hierarchical(s) for s in ("gdrive", "gsheets", "gcal"))
    google = resolved.registry().by_id("google")
    a = next(a for a in google.topic_actions if a.id == "drive-folder")
    out["azione"] = (a.admin_only, a.binding,
                     tuple(t.format(folder="F1") for t in a.adds_ingress),
                     tuple(t.format(folder="F1") for t in a.adds_egress))
    card = google.tools_card
    out["card"] = (card.icon, card.setup_label, card.blurb, card.scope)
    out["provider"] = tuple((p.id, p.credential.kind, p.credential.scopes)
                            for p in google.providers)
    out["card_altre"] = tuple(c.id for c in resolved.registry().connectors
                              if c.tools_card is not None and c.id in GOOGLE_IDS)
    return out


class AnswersTests(_Istanza):
    """What google-pack's connectors answer. The parity with the former
    builtin (`testdata/former_builtin/google.yaml`) was the acceptance of
    #524/#558; what it agreed on is pinned here and in `PDP`."""

    def test_the_answers_are_pinned(self):
        for pos in ("native", "pack"):           # the profile changes nothing
            with self.subTest(posizione=pos):
                self.posizione(pos)
                r = _risposte()
                self.assertEqual(r["spec:gsheets.append_rows"], ("gsheets", ["gsheets:S"]))
                self.assertEqual(r["fonte:gdocs.read"], "gdrive:doc/D")
                self.assertTrue(r["taint:gcalendar.list_events"])
                self.assertEqual(
                    r["canonico:https://drive.google.com/drive/u/1/folders/ABC?usp=sharing"],
                    "gdrive:folder/ABC")
                self.assertEqual(r["canonico:https://drive.google.com/drive/u/12/"
                                   "folders/ABC/view"], "gdrive:folder/ABC")
                self.assertEqual(r["canonico:https://evil.example/drive/folders/ABC"],
                                 "https://evil.example/drive/folders/ABC")
                self.assertIsNone(r["concedibile:egress:gcal:*"])
                self.assertTrue(r["danger:gcal:a@b.it"])
                self.assertEqual(r["azione"][2], ("gdrive:folder/F1",))
                self.assertEqual(r["card_altre"], ("google",))

    def test_the_pins_tables_hold(self):
        for verb, (spec, src, t) in PDP.items():
            with self.subTest(verb=verb):
                got = egress.spec_for(verb)
                self.assertEqual(None if got is None else (got[0], got[1](dict(ARGS))),
                                 spec)
                self.assertEqual(resolved.source_uri(verb, dict(ARGS)), src)
                self.assertEqual(taint.taints(verb), t)

    def test_the_pins_can_fail(self):
        """A mapping dropped from google-sheets, a taint dropped from
        google-calendar: both show up as differences."""
        nativo = _risposte()

        def rompi(entries):
            for e in entries:
                if e["id"] == "google-sheets":
                    e["verbs"] = [v for v in e["verbs"] if v["verb"] != "gsheets.append_rows"]
                if e["id"] == "google-calendar":
                    e["taint"] = ["gcalendar.list_calendars"]
        self.scrivi_pack(PACK, _google_pack(mutate=rompi))
        rotto = _risposte()
        self.assertNotEqual(nativo["spec:gsheets.append_rows"],
                            rotto["spec:gsheets.append_rows"])
        self.assertNotEqual(nativo["taint:gcalendar.list_events"],
                            rotto["taint:gcalendar.list_events"])


class ElectedCanonicalisationTests(_Istanza):
    """Only the ELECTED pack reads `https:`, and only on Google's hosts: a
    call's destination is canonicalised too, so any other URL becoming an
    approved folder would be an egress bypass."""

    def _con_regola(self, regola: dict) -> None:
        def aggiungi(entries):
            entries[0]["schemes"][0]["canonicalise"].insert(0, regola)
        self.scrivi_pack(PACK, _google_pack(mutate=aggiungi))

    def test_a_rule_on_another_host_is_never_applied(self):
        self._con_regola({"from": r"^https?://evil\.example/([\w-]+)$",
                          "to": "gdrive:folder/{1}"})
        self.assertEqual(egress.canonical("https://evil.example/ROOT"),
                         "https://evil.example/ROOT")

    def test_a_lookalike_host_is_not_googles(self):
        self._con_regola({"from": r"^https://drive\.google\.com[^/]*/([\w-]+)$",
                          "to": "gdrive:folder/{1}"})
        for url in ("https://drive.google.com.evil.example/ROOT",
                    "https://drive.google.com@evil.example/ROOT"):
            with self.subTest(url=url):
                self.assertFalse(egress.canonical(url).startswith("gdrive:"))

    def test_a_pack_that_is_not_elected_cannot_read_https(self):
        doc = {"name": "other-pack", "connectors": [{
            "id": "other", "manifest_version": 1, "namespace": "other",
            "schemes": [{"scheme": "otherx", "direction": "egress",
                         "canonicalise": [{
                             "from": r"^https://drive\.google\.com/x/([\w-]+)$",
                             "to": "otherx:{1}"}]}]}]}
        self.scrivi_pack("other-pack", doc)
        self.assertIsNotNone(resolved.registry().by_id("other"))
        self.assertEqual(egress.canonical("https://drive.google.com/x/A"),
                         "https://drive.google.com/x/A")

    def test_the_hosts_are_pinned_in_the_gateway(self):
        self.posizione("native")                 # ignored
        self.assertEqual(B.ELECTED_URL_HOSTS,
                         {"google": frozenset({"drive.google.com", "docs.google.com"})})
        self.assertEqual(egress.canonical("https://drive.google.com/drive/folders/A"),
                         "gdrive:folder/A")


# --------------------------------------------------------------------------
# 3. fail closed
# --------------------------------------------------------------------------
class FailClosedTests(_Istanza):
    def _tutti_negati(self):
        for verbo in _verbs():
            with self.subTest(verbo=verbo):
                out = _call(verbo, {"file_id": "F"})
                self.assertTrue(out.startswith("DENIED:"), out)

    def test_without_google_pack_the_24_verbs_are_denied(self):
        self.togli_pack(PACK)
        self.assertFalse(any(resolved.held_by_pack(ns) for ns in NAMESPACES))
        self._tutti_negati()
        self.assertEqual([c for c in self.component.calls if c[0] == "verb"], [])

    def test_with_its_manifest_refused_too(self):
        def rompi(entries):
            entries[0]["context"] = [{"arg": "agent", "value": "bogus"}]
        self.scrivi_pack(PACK, _google_pack(mutate=rompi))
        self.assertIsNone(resolved.registry().by_id("google"))
        self._tutti_negati()

    def test_each_namespace_needs_its_own_connector(self):
        """google-pack without `google-calendar`: the calendar verbs are
        refused, the others are not refused for it."""
        from .. import main
        self.scrivi_pack(PACK, _google_pack(without=("google-calendar",)))
        self.assertTrue(_call("gcalendar.list_events", {}).startswith("DENIED:"))
        main._check_pack_connector_held("gdrive.list")      # no exception

    def test_other_egress_is_unaffected(self):
        from .. import main
        self.togli_pack(PACK)
        self.assertEqual(resolved.degraded(), "")
        self.assertIsNotNone(egress.spec_for("email.send"))
        self.assertIsNotNone(egress.spec_for("telegram.send"))
        for verbo in ("email.send", "telegram.send", "web.fetch", "topic.list"):
            main._check_pack_connector_held(verbo)          # no exception

    def test_a_profile_saying_native_does_not_lift_the_refusal(self):
        from .. import main
        self.posizione("native")
        self.togli_pack(PACK)
        for verbo in _verbs():
            with self.subTest(verbo=verbo):
                with self.assertRaises(main._PackVerbRefused):
                    main._check_pack_connector_held(verbo)

    def test_without_the_component_the_24_verbs_are_denied(self):
        """google-pack's connectors held (e.g. google-pack 1.x, or a component
        that did not load): nothing serves the verbs, and that is a refusal
        naming the component, never `unknown tool` or the native code."""
        self.togli_componente()
        for verbo in _verbs():
            with self.subTest(verbo=verbo):
                out = _call(verbo, {"file_id": "F"})
                self.assertTrue(out.startswith("DENIED:"), out)
                self.assertIn("gateway component", out)

    def test_the_gateways_lookups_fail_closed_without_the_component(self):
        self.togli_componente()
        with self.assertRaises(google_switch.ComponentUnavailable) as e:
            google_switch.accounts()
        self.assertIn("google-pack", str(e.exception))
        self.assertEqual(google_switch.folder_labels(["gdrive:folder/X"]), {})
        out = google_switch.component_test_connection()
        self.assertFalse(out["ok"])
        from .. import tools_api
        d = tools_api._describe_folder("conto", "F")
        self.assertFalse(d["is_folder"])


# --------------------------------------------------------------------------
# 4. the gateway's own Google lookups ask the component
# --------------------------------------------------------------------------
class LookupsAskTheComponentTests(_Istanza):
    def test_the_component_answers(self):
        from .. import tools_api
        self.assertEqual(google_switch.accounts(), ["conto"])
        self.assertEqual(tools_api._describe_folder("conto", "F1"),
                         {"id": "F1", "name": "Cartella", "is_folder": True})
        self.assertEqual(google_switch.folder_labels(["gdrive:folder/A"]),
                         {"gdrive:folder/A": {"url": "U", "name": "N"}})
        self.assertEqual(tools_api._test_connector("google"),
                         {"ok": True, "detail": "component"})
        google_switch.perimeter_changed()
        google_switch.credential_changed("google_conto")
        from .. import vault
        vault._forget_google_token("google_conto")
        names = [c[0] for c in self.component.calls]
        self.assertEqual(names, ["accounts", "describe_folder", "folder_labels",
                                 "test_connection", "perimeter_changed",
                                 "credential_changed", "credential_changed"])

    def test_a_profile_saying_native_still_asks_the_component(self):
        self.posizione("native")
        self.assertEqual(google_switch.accounts(), ["conto"])
        self.assertEqual([c[0] for c in self.component.calls], ["accounts"])

    def test_the_pdp_reads_only_mapped_arguments_from_the_component(self):
        from .. import main
        spec = main._component_verb("gdrive.update")
        args = main._component_pdp_arguments(spec, "gdrive.update",
                                             {"file_id": "F", "src": "s"})
        self.assertEqual(args, {"file_id": "F", "src": "s", "folder_id": "PARENT"})
        self.assertEqual(egress.spec_for("gdrive.update")[1](args),
                         ["gdrive:folder/PARENT"])
        # A verb without destination mappings is passed through untouched.
        args = main._component_pdp_arguments(main._component_verb("gdrive.list"),
                                             "gdrive.list", {"query": "q"})
        self.assertEqual(args, {"query": "q"})

    def test_the_agents_folder_id_is_never_kept(self):
        """Review of #383: the agent's `folder_id` survived when the service was
        absent or answered {} — a file outside the perimeter judged by an
        allowed folder. Natively `_drive_parent_of` always overwrote it."""
        from unittest.mock import patch as _p
        from .. import main
        from .. import components as _comp
        spec = main._component_verb("gdrive.update")
        sneaky = {"file_id": "OUTSIDE", "src": "s", "folder_id": "ALLOWED"}
        args = main._component_pdp_arguments(spec, "gdrive.update", dict(sneaky))
        self.assertEqual(args["folder_id"], "PARENT")
        with _p.object(_comp, "service", lambda *a, **k: None):
            args = main._component_pdp_arguments(spec, "gdrive.update", dict(sneaky))
        self.assertNotIn("folder_id", args)
        # …and without a destination the verdict refuses, as natively.
        self.assertEqual(egress.spec_for("gdrive.update")[1](args), [])

    def test_a_failing_pdp_service_refuses_the_call(self):
        from .. import main
        spec = main._component_verb("gdrive.update")
        st = loader._STATES[f"{PACK}/google"]

        def boom(*a):
            raise RuntimeError("drive down")
        st.services["pdp_arguments"] = ServiceSpec(
            component=st.component.key, pack=PACK, name="pdp_arguments", handler=boom)
        with self.assertRaises(PermissionError):
            main._component_pdp_arguments(spec, "gdrive.update", {"file_id": "F"})


# --------------------------------------------------------------------------
# 5. Gmail
# --------------------------------------------------------------------------
GMAIL_BUNDLE = {"client_id": "CID", "client_secret": "CSECRET", "refresh_token": "RT",  # gitleaks:allow — fake test credential
                "email": "studio@gmail.com", "account": "studio"}
IMAP_BUNDLE = {"email": "info@example.it", "smtp_server": "smtp.x", "smtp_port": 587,
               "imap_server": "imap.x", "password": "pw"}


# GmailRoutingTests went with the native mail client (#523): the routing of a
# Gmail account between the native client and google-pack existed only on
# `mail: native`, which has no implementation any more.


class ForeignPackCannotClaimTests(_Istanza):
    def _intruso(self, entries: list[dict]) -> None:
        self.scrivi_pack("evil-pack", {"name": "evil-pack", "connectors": entries})
        resolved.invalidate()

    def _tutto_di_evil(self) -> list[dict]:
        return [copy.deepcopy(e) for e in _google_connectors() + [_gmail_connector()]]

    def test_google_pack_keeps_every_id_and_the_intruder_is_refused(self):
        self._intruso(self._tutto_di_evil())
        for cid in GOOGLE_IDS + ("mail-gmail",):
            self.assertEqual(resolved.registry().by_id(cid).pack, PACK)
        self.assertTrue(any("evil-pack" in p and f"belongs to '{PACK}'" in p
                            for p in resolved.problems()))

    def test_without_google_pack_nobody_holds_them(self):
        self.togli_pack(PACK)
        self._intruso(self._tutto_di_evil())
        for cid in GOOGLE_IDS + ("mail-gmail",):
            self.assertIsNone(resolved.registry().by_id(cid))
        self.assertTrue(_call("gdrive.list", {}).startswith("DENIED:"))

    def test_same_namespace_under_another_id_is_refused_too(self):
        self.togli_pack(PACK)
        self._intruso([{"id": "sheets-clone", "manifest_version": 1,
                        "namespace": "gsheets", "taint": ["gsheets.read"]}])
        self.assertIsNone(resolved.registry().by_id("sheets-clone"))
        self.assertFalse(resolved.held_by_pack("gsheets"))

    def test_a_profile_saying_native_changes_nothing_for_the_intruder(self):
        self.posizione("native")
        self._intruso(self._tutto_di_evil())
        for cid in GOOGLE_IDS + ("mail-gmail",):
            self.assertEqual(resolved.registry().by_id(cid).pack, PACK)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()


class ElectedUrlHostIsTheRawPrefixTests(unittest.TestCase):
    """Review of #381: the host is read from the raw prefix, not urlsplit."""

    def test_tricky_urls_never_elect_a_host(self):
        import re as _re
        for url in ("https://evil.io\\@drive.google.com/z/ROOT",
                    "https://user@drive.google.com/drive/folders/X",
                    "https://drive.google.com:443/drive/folders/X",
                    "https://DRIVE.google.com/drive/folders/X",
                    "https://drive.google.com.evil.io/drive/folders/X"):
            m = _re.match(r"https?://([a-z0-9.-]+)/", url)
            self.assertNotEqual(m.group(1) if m else "", "drive.google.com", url)


def setUpModule() -> None:
    # comms-pack and it-pack as on every instance (#526): `gdrive.upload`
    # shares on `mailto:`, which comms-pack's `mail` declares. google-pack is
    # this module's own (`_GoogleIstanza` writes it).
    _FP.install(without=("google-pack",))


def tearDownModule() -> None:
    _FP.uninstall()
