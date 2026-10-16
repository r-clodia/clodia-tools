"""#525: GitHub and OpenAI images are declared by it-pack; the checks stay here.

clodia-platform#525, design comment of 2026-10-16, gateway side.

GitHub (`connectors: {github: pack}`):

- it-pack declares the `github` connector (credential, verb mappings, taint,
  danger) and mounts the GitHub MCP backend itself; `github` stops being a
  core backend reserved for nobody (`resolved.core_backends`);
- the four git verbs (`github.clone/pull/push/pull_request`) stay
  gateway-served (`main._GATEWAY_RETAINED_VERBS`): room from the claim,
  per-scope repository perimeter, origin written by the gateway, credential;
- `/tools/github/connect` deposits the PAT only and mounts nothing; the
  pack's mount replaces the native connector's leftover unstamped entry
  instead of getting a 409.

OpenAI images (`connectors: {openai-images: pack}`):

- `image.generate` and `/internal/imagegen` stay the gateway's; only the HTTP
  call goes to it-pack's provider `transport` (`imagegen-transport`/`run`),
  with that call's API key; fail closed, never the in-process client.

What is pinned here: the switch positions; parity of the PDP's answers about
GitHub; fail closed (pack connector refused → git verbs DENIED; no transport
→ image generation refused); the 409/adoption path of the `github` backend;
the connect routes and the vault types they keep; the transport hidden from
agents; and the suites that pin the repository perimeter, the dispatch and
the PDP tables, run again in `pack` position — with a declared perimeter,
because with none `_require_approved_repo` allows everything and proves
nothing.
"""
from __future__ import annotations

import asyncio
import base64
import copy
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from .. import egress, instance_profile, proxy, taint, tools_api, vault, whitelist
from .. import test_518_pdp_tables as PDP
from .. import test_gate_perimeter as GP
from .. import test_github_dispatch as GD
from .. import test_push_destination as PD
from .. import test_repo_whitelist as RW
from ..tools import image as IMG
from . import builtin as B
from . import manifest as M
from . import resolved

PACK = "it-pack"
IMG_BACKEND = "imagegen-transport"
IMG_TOOL = "run"
GITHUB_DANGER = "repository su github.com"
APPROVED = "https://github.com/r-clodia/clodia-tools"
OUTSIDE = "https://github.com/altro-owner/segreti"
GIT_VERBS = ("github.clone", "github.pull", "github.push", "github.pull_request")


def _github_connector() -> dict:
    """it-pack's `github` connector: the builtin declaration, verbatim, except
    for what a PACK must write differently — the github.com warning as four
    bounded rules (a pack regex may not quantify a group: `(…)?` is refused),
    matching the same URIs as the builtin's single rule."""
    doc = yaml.safe_load((B.DIR / "github.yaml").read_text(encoding="utf-8"))
    entry = copy.deepcopy(doc["connectors"][0])
    text = entry["danger_uris"][0]["text"]
    entry["danger_uris"] = [{"match": m, "text": text} for m in (
        r"https?://github\.com", r"https?://github\.com[:/].*",
        r"https?://[a-z0-9.-]+\.github\.com",
        r"https?://[a-z0-9.-]+\.github\.com[:/].*")]
    return entry


def _images_connector() -> dict:
    doc = yaml.safe_load((B.DIR / "openai.yaml").read_text(encoding="utf-8"))
    entry = copy.deepcopy(doc["connectors"][0])
    entry["providers"][0]["transport"] = {"backend": IMG_BACKEND, "tool": IMG_TOOL}
    return entry


def _it_pack(github: dict | None = None, images: dict | None = None) -> dict:
    return {"name": PACK, "connectors": [github or _github_connector(),
                                         images or _images_connector()]}


def _backend(name: str, pack: str | None = PACK, **extra) -> dict:
    b = {"name": name, "transport": "http", "url": f"https://{name}.example/mcp"}
    if pack:
        b["pack"] = pack
    b.update(extra)
    return b


def _legacy_core_github() -> dict:
    """The entry `github_connect` writes in `native` position: unstamped."""
    return {"name": "github", "label": "GitHub", "transport": "http",
            "url": tools_api.GITHUB_MCP_URL,
            "headers": {"Authorization": "Bearer ${VAULT:github_pat}"}}


class _ItIstanza:
    """A fake instance with it-pack installed and its two backends mounted.

    Mixin, so that the pinned suites can be run again by subclassing them
    (`setUp` of the original first). The switch is turned by writing
    `profile.yaml` for real, as in test_522/test_523.
    """

    GITHUB = "pack"
    IMAGES = "pack"

    def setUp(self) -> None:  # noqa: D401 — unittest hook
        super().setUp()
        self.addCleanup(self._ricarica)
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.scrivi_pack(_it_pack())
        self.backends = [_backend("github"), _backend(IMG_BACKEND)]
        for p in (patch.dict(os.environ, {"CLODIA_DATA": str(self.dir)}),
                  patch.object(resolved, "_DATA", self.dir),
                  patch.dict(proxy.CONFIG, {"mcp_backends": self.backends})):
            p.start()
            self.addCleanup(p.stop)
        self.transport_calls: list[dict] = []
        fake = patch.object(proxy, "call_backend_tool_sync", self._fake_transport)
        fake.start()
        self.addCleanup(fake.stop)
        self.posizione(self.GITHUB, self.IMAGES)

    def scrivi_pack(self, doc: dict) -> None:
        pack = self.dir / "packs" / PACK
        pack.mkdir(parents=True, exist_ok=True)
        (pack / "pack.yaml").write_text(json.dumps(doc), encoding="utf-8")
        resolved.invalidate()

    def _ricarica(self) -> None:
        instance_profile.load(force=True)
        resolved.invalidate()

    def posizione(self, github: str | None, images: str | None = None) -> None:
        righe = ["edition: full"]
        modi = {k: v for k, v in (("github", github), ("openai-images", images)) if v}
        if modi:
            righe.append("connectors:")
            righe += [f"  {k}: {v}" for k, v in modi.items()]
        (self.dir / "profile.yaml").write_text("\n".join(righe) + "\n",
                                               encoding="utf-8")
        self._ricarica()

    def _fake_transport(self, backend: str, tool: str, arguments: dict,
                        timeout: float) -> str:
        """it-pack's image transport, per the contract: `{png_b64}`."""
        self.transport_calls.append({"backend": backend, "tool": tool,
                                     "arguments": arguments, "timeout": timeout})
        png = b"\x89PNG-" + arguments["op"].encode()
        return json.dumps({"png_b64": base64.b64encode(png).decode()})


class _Istanza(_ItIstanza, unittest.TestCase):
    pass


def _call(name: str, args: dict) -> str:
    from .. import main
    return asyncio.run(main.call_tool(name, args))[0].text


# --------------------------------------------------------------------------
# 1. the switch
# --------------------------------------------------------------------------
class SwitchTests(_Istanza):
    def test_in_pack_position_it_pack_holds_github(self):
        c = resolved.registry().by_id("github")
        self.assertEqual((c.pack, c.builtin, c.namespace), (PACK, False, "github"))
        self.assertTrue(resolved.held_by_pack("github"))
        self.assertNotIn("gateway-github", B.manifests())
        self.assertEqual(resolved.problems(), ())

    def test_the_github_backend_is_no_longer_reserved_for_the_core(self):
        self.assertEqual(resolved.core_backends(), frozenset())
        self.assertIn("github", resolved.backend_owners()[PACK])
        self.assertNotIn("github", resolved.foreign_backends(PACK))

    def test_in_native_position_the_core_keeps_it(self):
        self.posizione("native", "native")
        c = resolved.registry().by_id("github")
        self.assertTrue(c.builtin)
        self.assertEqual(c.pack, "gateway-github")
        self.assertEqual(resolved.core_backends(), frozenset({"github"}))
        self.assertNotIn("github", resolved.backend_owners().get(PACK, ()))
        self.assertFalse(resolved.held_by_pack("github"))
        self.posizione(None)
        self.assertEqual(resolved.core_backends(), frozenset({"github"}))

    def test_an_unreadable_profile_keeps_the_reservation(self):
        with patch.object(instance_profile, "connector_mode",
                          side_effect=RuntimeError("boom")):
            self.assertEqual(resolved.core_backends(), frozenset({"github"}))

    def test_images_follow_their_own_switch(self):
        self.posizione("pack", "native")
        self.assertTrue(resolved.registry().by_id("openai-images").builtin)
        self.assertIsNone(resolved.transport_for("openai-images"))
        self.posizione("native", "pack")
        self.assertEqual(resolved.registry().by_id("openai-images").pack, PACK)
        self.assertEqual(resolved.transport_for("openai-images"),
                         (IMG_BACKEND, IMG_TOOL))


class GitVerbsStayGatewayServedTests(_Istanza):
    def test_listed_and_served_in_both_positions(self):
        from .. import main
        for pos in ("pack", "native"):
            self.posizione(pos)
            nomi = {t.name for t in main._all_native_tools()}
            for verbo in GIT_VERBS:
                with self.subTest(posizione=pos, verbo=verbo):
                    self.assertIn(verbo, nomi)
                    self.assertIn(verbo, main._GATEWAY_RETAINED_VERBS)
                    self.assertFalse(main._is_packaged_verb(verbo))
                    self.assertTrue(main._verb_implemented(verbo))

    def test_the_backend_verbs_belong_to_the_pack_in_pack_position(self):
        from .. import main
        self.assertTrue(main._is_packaged_verb("github.list_issues"))
        self.assertNotIn("github", M.core_namespaces())
        # Still a namespace the gateway serves (its four git verbs, wholly
        # retained like `email`): grantable, while no longer reserved.
        self.assertIn("github", main._native_tool_namespaces())
        self.posizione("native")
        self.assertFalse(main._is_packaged_verb("github.list_issues"))
        self.assertIn("github", M.core_namespaces())
        self.assertIn("github", main._native_tool_namespaces())

    def test_pack_declarations_never_apply_to_the_git_verbs(self):
        """A `context:` the pack declares for `github.*` must not rewrite the
        arguments of a verb the gateway serves."""
        from .. import main
        entry = _github_connector()
        entry["context"] = [{"arg": "agent", "value": "agent"}]
        self.scrivi_pack(_it_pack(github=entry))
        self.assertTrue(resolved.held_by_pack("github"), resolved.problems())
        self.assertTrue(resolved.context_arguments("github.push"))
        for verbo in GIT_VERBS:
            args = {"dir": "x", "agent": "forged"}
            self.assertIs(main._fill_declared_context(verbo, args), args)


# --------------------------------------------------------------------------
# 2. parity of the PDP's answers about GitHub
# --------------------------------------------------------------------------
GITHUB_SPECS = [
    ("github.push", {"repo": "https://github.com/R-Clodia/Tools"}),
    ("github.pull_request", {"repo": "r-clodia/tools"}),
    ("github.create_issue", {"owner": "R-Clodia", "repo": "Tools"}),
    ("github.update_issue", {"owner": "a", "repo": "b"}),
    ("github.delete_file", {"owner": "a", "repo": "b"}),
    ("github.push_files", {"owner": "a", "repo": "b"}),
    ("github.fork_repository", {"owner": "a", "repo": "b"}),
    ("github.merge_pull_request", {"owner": "a", "repo": "b"}),
    ("github.add_issue_comment", {"owner": "a", "repo": "b"}),
    ("github.issue_write", {"owner": "a", "repo": "b"}),
    ("github.pull_request_review_write", {"owner": "a", "repo": "b"}),
    ("github.sub_issue_write", {"owner": "a", "repo": "b"}),
    ("github.request_copilot_review", {"owner": "a", "repo": "b"}),
    ("github.clone", {"repo": "a/b"}),
    ("github.pull", {"dir": "x"}),
    ("github.get_file_contents", {"owner": "a", "repo": "b"}),
]
GITHUB_TAINT = ("github.get_file_contents", "github.list_commits",
                "github.search_code", "github.issue_read",
                "github.pull_request_read", "github.push", "github.clone",
                "github.create_issue")


def _risposte() -> dict:
    def grantable(uri: str) -> bool:
        try:
            egress.check_grantable("egress", uri)
        except ValueError:
            return False
        return True

    out: dict = {
        "taint": {v: taint.taints(v) for v in GITHUB_TAINT},
        "grantable": {u: grantable(u) for u in (
            "https://github.com/r-clodia/", APPROVED, "https://")},
        "danger_github": GITHUB_DANGER in egress.danger_note(
            "https://github.com/a/b"),
        "danger_api": GITHUB_DANGER in egress.danger_note(
            "https://api.github.com/x"),
        "danger_lookalike": GITHUB_DANGER in egress.danger_note(
            "https://evilgithub.com/x"),
        "failsafe": {v: egress._failsafe_denied(v) for v in GIT_VERBS},
    }
    for verbo, args in GITHUB_SPECS:
        spec = egress.spec_for(verbo)
        out[f"spec:{verbo}"] = None if spec is None else (spec[0], tuple(spec[1](args)))
    rules = ["https://github.com/r-clodia/"]
    with patch.object(egress, "effective_uris", lambda *_a, **_k: list(rules)):
        for verbo in ("github.push", "github.pull_request", "github.create_issue"):
            for repo, owner in ((APPROVED, "r-clodia"), (OUTSIDE, "altro-owner")):
                args = ({"owner": owner, "repo": repo.rsplit("/", 1)[1]}
                        if verbo == "github.create_issue" else {"repo": repo})
                d = egress.decide({}, verbo, args)
                out[f"decide:{verbo}:{owner}"] = (d["checked"], d["allowed"])
    return out


class ParityTests(_Istanza):
    def test_every_answer_is_the_same_in_both_positions(self):
        self.posizione("native")
        self.assertTrue(resolved.registry().by_id("github").builtin)
        nativo = _risposte()
        self.posizione("pack")
        self.assertEqual(resolved.registry().by_id("github").pack, PACK)
        da_pack = _risposte()
        self.assertEqual(set(nativo), set(da_pack))
        for chiave in sorted(nativo):
            with self.subTest(domanda=chiave):
                self.assertEqual(nativo[chiave], da_pack[chiave])

    def test_the_answers_are_not_vacuous(self):
        for pos in ("native", "pack"):
            with self.subTest(posizione=pos):
                self.posizione(pos)
                r = _risposte()
                self.assertEqual(r["spec:github.push"],
                                 ("github", ("https://github.com/r-clodia/tools",)))
                self.assertEqual(r["spec:github.create_issue"],
                                 ("github", ("https://github.com/r-clodia/tools",)))
                self.assertIsNone(r["spec:github.clone"])
                self.assertTrue(r["taint"]["github.issue_read"])
                self.assertFalse(r["taint"]["github.push"])
                self.assertTrue(r["danger_github"])
                self.assertFalse(r["danger_lookalike"])
                self.assertEqual(r["decide:github.push:r-clodia"], (True, True))
                self.assertEqual(r["decide:github.push:altro-owner"], (True, False))
                self.assertEqual(r["decide:github.create_issue:altro-owner"],
                                 (True, False))

    def test_the_comparison_can_fail(self):
        self.posizione("native")
        nativo = _risposte()
        entry = _github_connector()
        entry["verbs"] = [v for v in entry["verbs"] if v["verb"] != "github.push"]
        self.scrivi_pack(_it_pack(github=entry))
        self.posizione("pack")
        self.assertNotEqual(nativo["spec:github.push"],
                            _risposte()["spec:github.push"])

    def test_the_elected_pack_adds_to_the_https_warning_never_replaces_it(self):
        self.posizione("native")
        nativo = egress.danger_note("https://github.com/a/b")
        generico = egress.danger_note("https://altro.it/")
        self.posizione("pack")
        nota = egress.danger_note("https://github.com/a/b")
        self.assertTrue(nota.startswith(nativo), nota)
        self.assertIn(generico, nota)
        self.assertEqual(egress.danger_note("https://altro.it/"), generico)

    def test_a_pack_that_is_not_elected_still_cannot_speak_for_https(self):
        """The switch elects the connector `github`; a neighbour with a
        catch-all rule on `https:` gets no say (review of #358 still holds)."""
        entry = _github_connector()
        entry["danger_uris"] = [{"match": r"https://.*", "text": "innocuo"}]
        self.scrivi_pack(_it_pack(github=entry))
        self.posizione("native")     # it-pack's github connector not elected
        self.assertNotIn("innocuo", egress.danger_note("https://altro.it/"))


# --------------------------------------------------------------------------
# 3. fail closed
# --------------------------------------------------------------------------
class FailClosedTests(_Istanza):
    def _rifiuta_il_connettore(self):
        entry = _github_connector()
        entry["context"] = [{"arg": "agent", "value": "bogus"}]
        self.scrivi_pack(_it_pack(github=entry))
        self.assertFalse(resolved.held_by_pack("github"))

    def test_without_the_packs_connector_the_git_verbs_are_denied(self):
        """Without it `github.push` would be unmapped — a push nobody checks."""
        self._rifiuta_il_connettore()
        for verbo in GIT_VERBS + ("github.list_issues",):
            with self.subTest(verbo=verbo):
                self.assertTrue(_call(verbo, {"repo": APPROVED, "dir": "x",
                                              "dest": "x", "head": "h",
                                              "title": "t"}).startswith("DENIED:"))

    def test_without_the_pack_installed_too(self):
        (self.dir / "packs" / PACK / "pack.yaml").unlink()
        resolved.invalidate()
        self.assertEqual(resolved.degraded(), "")
        self.assertTrue(_call("github.push", {"dir": "x"}).startswith("DENIED:"))

    def test_the_legacy_core_mount_keeps_the_pack_connector_refused(self):
        """Until the pack's mount replaces it, an unstamped `github` is not
        it-pack's: its connector is refused and every github verb DENIED."""
        with patch.dict(proxy.CONFIG, {"mcp_backends": [_legacy_core_github()]}):
            resolved.invalidate()
            self.assertFalse(resolved.held_by_pack("github"))
            self.assertTrue(_call("github.push", {"dir": "x"}).startswith("DENIED:"))

    def test_on_native_nothing_is_refused_for_this(self):
        from .. import main
        self.posizione("native")
        self._rifiuta_il_connettore()
        for verbo in GIT_VERBS:
            main._check_pack_connector_held(verbo)   # no exception


class DeclaredPerimeterTests(_Istanza):
    """The acceptance criterion: a push/PR to a repository outside the scope's
    egress is refused as today — through the real `_require_approved_repo`,
    with a perimeter declared, in both positions."""

    def _dispatch(self, verbo: str, repo: str):
        from .. import main
        from ..topics.service import TopicService as T

        class Svc:
            _require_approved_repo = staticmethod(T._require_approved_repo)

        with patch.object(whitelist, "CONFIG", {"egress_allow": [APPROVED]}), \
                patch.object(main, "_current_topic", lambda: ("SEAL-1", "acme")), \
                patch.object(main, "_topics", lambda: Svc()), \
                patch.object(main, "_origin_of", lambda d: repo), \
                patch.object(main, "_safe_scratch_path", lambda p: "/scratch/x"), \
                patch.object(main, "_repo_credential", lambda *a: None), \
                patch("server.tools.github_repo.push", lambda *a, **k: {"ok": True}), \
                patch("server.tools.github_repo.clone", lambda *a, **k: {"ok": True}), \
                patch("server.tools.github_repo.pull_request",
                      lambda *a, **k: {"ok": True}):
            main._check_pack_connector_held(verbo)
            return main._dispatch_github(verbo, {"repo": repo, "dir": "x",
                                                 "dest": "x", "head": "h",
                                                 "title": "t"})

    def test_outside_the_perimeter_is_refused_in_both_positions(self):
        from ..topics.service import TopicError
        for pos in ("native", "pack"):
            for verbo in ("github.push", "github.clone", "github.pull_request"):
                with self.subTest(posizione=pos, verbo=verbo):
                    self.posizione(pos)
                    with self.assertRaises(TopicError):
                        self._dispatch(verbo, OUTSIDE)

    def test_inside_the_perimeter_the_push_goes_through(self):
        for pos in ("native", "pack"):
            with self.subTest(posizione=pos):
                self.posizione(pos)
                self.assertEqual(self._dispatch("github.push", APPROVED), {"ok": True})


# --------------------------------------------------------------------------
# 4. images through the transport
# --------------------------------------------------------------------------
class ImageTransportTests(_Istanza):
    def setUp(self):
        super().setUp()
        for p in (patch.object(IMG, "_api_key", lambda: "sk-test"),
                  patch.object(IMG, "_post_json", self._no_http),
                  patch.object(IMG.urllib.request, "urlopen", self._no_http)):
            p.start()
            self.addCleanup(p.stop)

    def _no_http(self, *a, **k):
        raise AssertionError("the in-process OpenAI client must not run")

    def test_generate_goes_to_the_pack_with_the_contract(self):
        png = IMG.generate("a cat", size="512x512", quality="low",
                           background="transparent")
        self.assertEqual(png, b"\x89PNG-generate")
        (call,) = self.transport_calls
        self.assertEqual((call["backend"], call["tool"], call["timeout"]),
                         (IMG_BACKEND, IMG_TOOL, 300))
        self.assertEqual(call["arguments"], {
            "op": "generate", "prompt": "a cat", "size": "512x512",
            "quality": "low", "background": "transparent", "api_key": "sk-test"})

    def test_edit_carries_the_image(self):
        self.assertEqual(IMG.edit("restyle", b"RAW"), b"\x89PNG-edit")
        args = self.transport_calls[0]["arguments"]
        self.assertEqual(args["op"], "edit")
        self.assertEqual(base64.b64decode(args["image_b64"]), b"RAW")
        self.assertEqual(args["api_key"], "sk-test")

    def test_no_transport_refuses_instead_of_falling_back(self):
        images = _images_connector()
        del images["providers"][0]["transport"]
        self.scrivi_pack(_it_pack(images=images))
        with self.assertRaises(IMG.ImageGenError) as e:
            IMG.generate("a cat")
        self.assertIn("transport provider is not available", str(e.exception))
        self.assertEqual(self.transport_calls, [])

    def test_without_the_pack_too(self):
        (self.dir / "packs" / PACK / "pack.yaml").unlink()
        resolved.invalidate()
        with self.assertRaises(IMG.ImageGenError):
            IMG.edit("x", b"RAW")
        self.assertEqual(self.transport_calls, [])

    def test_a_backend_the_pack_did_not_mount_is_not_used(self):
        for b in (_backend(IMG_BACKEND, pack=None), _backend(IMG_BACKEND, pack="other")):
            with self.subTest(backend=b), \
                    patch.dict(proxy.CONFIG, {"mcp_backends": [_backend("github"), b]}):
                resolved.invalidate()
                with self.assertRaises(IMG.ImageGenError):
                    IMG.generate("a cat")
        self.assertEqual(self.transport_calls, [])

    def test_a_tool_error_is_a_failed_generation(self):
        def esplode(*a, **k):
            raise proxy.BackendToolError("upstream 500")
        with patch.object(proxy, "call_backend_tool_sync", esplode):
            with self.assertRaises(IMG.ImageGenError) as e:
                IMG.generate("a cat")
        self.assertIn("upstream 500", str(e.exception))
        self.assertNotIn("sk-test", str(e.exception))

    def test_an_answer_without_its_shape_is_a_failed_generation(self):
        for testo in ("not json", "{}", '{"png_b64": "%%%"}', '{"png_b64": ""}', "[]"):
            with self.subTest(risposta=testo), \
                    patch.object(proxy, "call_backend_tool_sync",
                                 lambda *a, _t=testo, **k: _t):
                with self.assertRaises(IMG.ImageGenError):
                    IMG.generate("a cat")

    def test_native_position_keeps_the_in_process_client(self):
        self.posizione("pack", "native")
        with patch.object(IMG, "_post_json",
                          lambda url, payload: {"data": [{"b64_json": base64.b64encode(
                              b"NATIVE").decode()}]}):
            self.assertEqual(IMG.generate("a cat"), b"NATIVE")
        self.assertEqual(self.transport_calls, [])

    def test_image_generate_keeps_its_gateway_checks(self):
        """Membership and the topic write stay the gateway's: the verb checks
        the caller is in the topic, then writes the pack's PNG with put_file."""
        from .. import main
        scritti = {}

        class Svc:
            def put_file(self, tier, name, filename, data):
                scritti[(tier, name, filename)] = data

        membri = []
        with patch.object(IMG, "has_key", lambda: True), \
                patch.object(main, "_topics", lambda: Svc()), \
                patch.object(main, "_require_topic_member",
                             lambda svc, t, n: membri.append((t, n))):
            out = asyncio.run(main._dispatch_image(
                {"tier": "SEAL-1", "name": "acme", "prompt": "a cat",
                 "filename": "cat"}))
        self.assertEqual(out, {"ok": True, "path": "files/cat.png",
                               "bytes": len(b"\x89PNG-generate")})
        self.assertEqual(membri, [("SEAL-1", "acme")])
        self.assertEqual(scritti, {("SEAL-1", "acme", "cat.png"): b"\x89PNG-generate"})

    def test_image_generate_refuses_a_non_member_before_any_call(self):
        from .. import main

        def fuori(svc, t, n):
            raise PermissionError("not a participant")
        with patch.object(IMG, "has_key", lambda: True), \
                patch.object(main, "_topics", lambda: object()), \
                patch.object(main, "_require_topic_member", fuori):
            with self.assertRaises(PermissionError):
                asyncio.run(main._dispatch_image(
                    {"tier": "SEAL-1", "name": "acme", "prompt": "a cat"}))
        self.assertEqual(self.transport_calls, [])

    def test_internal_imagegen_keeps_working(self):
        from starlette.applications import Starlette
        from starlette.testclient import TestClient

        from .. import imagegen_api
        with patch.object(imagegen_api, "_authorize", lambda r: ("clodia", None)), \
                patch.object(IMG, "has_key", lambda: True):
            c = TestClient(Starlette(routes=imagegen_api.routes))
            r = c.post("/internal/imagegen", json={"prompt": "avatar"})
            self.assertEqual(r.status_code, 200, r.text)
            self.assertEqual(r.content, b"\x89PNG-generate")
            r = c.post("/internal/imagegen", json={
                "prompt": "avatar", "image_b64": base64.b64encode(b"RAW").decode()})
            self.assertEqual(r.content, b"\x89PNG-edit")


class TransportHiddenTests(_Istanza):
    def test_the_image_transport_is_hidden_in_both_positions(self):
        from .. import main
        for pos in ("pack", "native"):
            with self.subTest(posizione=pos):
                self.posizione(pos, pos)
                self.assertIn(resolved.norm_name(IMG_BACKEND),
                              resolved.transport_backends())
                self.assertTrue(resolved.is_transport_backend(f"{IMG_BACKEND}.{IMG_TOOL}"))
                with patch.object(proxy, "is_proxied", lambda n: True):
                    with self.assertRaises(main._PackVerbRefused):
                        main._check_not_transport(f"{IMG_BACKEND}.{IMG_TOOL}")
                self.assertTrue(_call(f"{IMG_BACKEND}.{IMG_TOOL}", {"op": "generate"})
                                .startswith("DENIED:"))

    def test_the_github_backend_is_not_a_transport(self):
        for pos in ("pack", "native"):
            with self.subTest(posizione=pos):
                self.posizione(pos, pos)
                self.assertFalse(resolved.is_transport_backend("github.list_issues"))


# --------------------------------------------------------------------------
# 5. the github backend: 409 or adoption
# --------------------------------------------------------------------------
class _Config(unittest.TestCase):
    """`whitelist.CONFIG` (the same dict `proxy.CONFIG` is) with no disk I/O."""

    def setUp(self):
        super().setUp()
        for p in (patch.object(whitelist, "save_config", lambda: None),
                  patch.object(whitelist, "reload_config", lambda: None),
                  patch.object(proxy, "clear_cache", lambda: None),
                  patch.object(tools_api, "_authorized", lambda r: True),
                  patch.object(tools_api, "_connector_guard", lambda cid: None),
                  patch.object(instance_profile, "integrations_check",
                               lambda name: None)):
            p.start()
            self.addCleanup(p.stop)


class GithubBackendAdoptionTests(_ItIstanza, _Config):
    def _monta(self, existing: list[dict]):
        mount = {"mcpServers": {"github": {
            "url": tools_api.GITHUB_MCP_URL,
            "headers": {"Authorization": "Bearer ${VAULT:github_pat.value}"}}}}
        with patch.dict(whitelist.CONFIG, {"mcp_backends": list(existing)}):
            out = tools_api.register_mcp_core(mount, pack=PACK)
            return out, list(whitelist.CONFIG["mcp_backends"])

    def test_in_pack_position_the_pack_replaces_the_legacy_core_entry(self):
        out, backends = self._monta([_legacy_core_github()])
        self.assertEqual(out, {"registered": ["github"]})
        (b,) = backends
        self.assertEqual(b["pack"], PACK)
        self.assertEqual(b["headers"]["Authorization"],
                         "Bearer ${VAULT:github_pat.value}")

    def test_in_native_position_it_is_a_409(self):
        self.posizione("native")
        with self.assertRaises(tools_api.McpRegisterError) as e:
            self._monta([_legacy_core_github()])
        self.assertEqual(e.exception.status, 409)

    def test_an_admin_mount_that_only_shares_the_name_is_a_409(self):
        with self.assertRaises(tools_api.McpRegisterError) as e:
            self._monta([{"name": "github", "transport": "http",
                          "url": "https://my-proxy.example/mcp"}])
        self.assertEqual(e.exception.status, 409)

    def test_another_packs_mount_is_a_409(self):
        with self.assertRaises(tools_api.McpRegisterError) as e:
            self._monta([{**_legacy_core_github(), "pack": "other-pack"}])
        self.assertEqual(e.exception.status, 409)

    def test_an_admin_cannot_take_it_back_unstamped_either(self):
        """The adoption is for a PACK's mount only: an unstamped remount over
        the pack's stamped entry is still refused."""
        mount = {"mcpServers": {"github": {"url": tools_api.GITHUB_MCP_URL}}}
        with patch.dict(whitelist.CONFIG, {"mcp_backends": [_backend("github")]}):
            with self.assertRaises(tools_api.McpRegisterError):
                tools_api.register_mcp_core(mount)

    def test_the_pat_placeholder_resolves_to_the_stored_value(self):
        with patch.object(vault, "read_internal",
                          lambda name: {"value": "ghp_x"} if name == "github_pat"
                          else (_ for _ in ()).throw(vault.VaultDenied(name))):
            self.assertEqual(
                proxy._resolve_secrets({"Authorization": "Bearer ${VAULT:github_pat.value}"}),
                {"Authorization": "Bearer ghp_x"})
            self.assertEqual(proxy._resolve_secrets("${VAULT:github_pat}"), "ghp_x")


# --------------------------------------------------------------------------
# 6. the connect routes and the vault types they keep
# --------------------------------------------------------------------------
class _MemVault:
    def __init__(self, **existing):
        self.store = dict(existing)

    def __enter__(self):
        self._p = [
            patch.object(vault, "deposit", self._deposit),
            patch.object(vault, "remove", lambda e: self.store.pop(e, None)),
            patch.object(vault, "credential_type",
                         lambda e: self.store[e][1] if e in self.store else None),
            patch.object(vault, "has_credential", lambda e: e in self.store),
        ]
        for p in self._p:
            p.start()
        return self

    def _deposit(self, entry, bundle, *, cred_type="opaque", grant_agents=None,
                 actions=None):
        self.store[entry] = (bundle, cred_type)

    def __exit__(self, *exc):
        for p in self._p:
            p.stop()


class ConnectTests(_ItIstanza, _Config):
    H = {"Authorization": "Bearer ckt1.finto"}

    def setUp(self):
        super().setUp()
        self.cfg_patch = patch.dict(whitelist.CONFIG, {
            "mcp_backends": [_backend("github"), _backend(IMG_BACKEND)],
            "agents": {"clodia": {"allowed_tools": []}}})
        self.cfg_patch.start()
        self.addCleanup(self.cfg_patch.stop)

    def _post(self, cid: str, body: dict, generic: bool = True):
        from starlette.applications import Starlette
        from starlette.testclient import TestClient

        from .. import connectors_api
        c = TestClient(Starlette(routes=connectors_api.routes + tools_api.routes))
        url = (f"/internal/tools/connectors/{cid}/connect" if generic
               else "/tools/github/connect")
        return c.post(url, json=body, headers=self.H)

    def test_pack_position_deposits_the_pat_only_and_drops_the_legacy_mount(self):
        whitelist.CONFIG["mcp_backends"][:] = [_legacy_core_github(),
                                               _backend(IMG_BACKEND)]
        with _MemVault() as v:
            r = tools_api_github_connect({"pat": "ghp_x"})
            self.assertEqual(r.status_code, 200, r.body)
            self.assertEqual(v.store["github_pat"], ({"value": "ghp_x"}, "mcp_secret"))
        # Nothing mounted; the native connector's leftover is gone.
        self.assertEqual([b["name"] for b in whitelist.CONFIG["mcp_backends"]],
                         [IMG_BACKEND])
        concessi = whitelist.CONFIG["agents"]["clodia"]["allowed_tools"]
        for verbo in GIT_VERBS + ("github.list_issues",):
            self.assertIn(verbo, concessi)
        self.assertNotIn("github.*", concessi)

    def test_pack_position_never_touches_the_packs_mount(self):
        whitelist.CONFIG["mcp_backends"][:] = [_backend("github"), _backend(IMG_BACKEND)]
        for body in ({"pat": "ghp_x"}, {"pat": ""}):
            with self.subTest(body=body), \
                    _MemVault(github_pat=({"value": "old"}, "mcp_secret")) as v:
                r = tools_api_github_connect(body)
                self.assertEqual(r.status_code, 200)
                self.assertEqual("github_pat" in v.store, bool(body["pat"]))
            self.assertEqual(whitelist.CONFIG["mcp_backends"],
                             [_backend("github"), _backend(IMG_BACKEND)])

    def test_native_position_still_mounts_the_core_backend(self):
        self.posizione("native", "native")
        whitelist.CONFIG["mcp_backends"][:] = []
        with _MemVault() as v:
            r = tools_api_github_connect({"pat": "ghp_x"})
            self.assertEqual(r.status_code, 200)
            self.assertEqual(v.store["github_pat"], ({"value": "ghp_x"}, "mcp_secret"))
        (b,) = whitelist.CONFIG["mcp_backends"]
        self.assertEqual((b["name"], b.get("pack"), b["url"]),
                         ("github", None, tools_api.GITHUB_MCP_URL))

    def test_the_generic_route_adopts_the_legacy_github_entry(self):
        """The declared field is `value`; the entry keeps type `mcp_secret`,
        which the generic deposit would have refused as «not this
        connector's»."""
        with _MemVault(github_pat=({"value": "old"}, "mcp_secret")) as v:
            r = self._post("github", {"value": "ghp_new"})
            self.assertEqual(r.status_code, 200, r.text)
            self.assertNotIn("ghp_new", r.text)
            self.assertEqual(r.json()["vault_entry"], "github_pat")
            self.assertEqual(v.store["github_pat"], ({"value": "ghp_new"}, "mcp_secret"))

    def test_the_generic_route_adopts_the_legacy_openai_entry(self):
        with _MemVault(openai_api_key=({"api_key": "old"}, "api_key")) as v:
            r = self._post("openai-images", {"api_key": "sk-new"})
            self.assertEqual(r.status_code, 200, r.text)
            self.assertEqual(v.store["openai_api_key"], ({"api_key": "sk-new"}, "api_key"))
            r = self._post("openai-images", {"api_key": ""})
            self.assertFalse(r.json()["connected"])
            self.assertNotIn("openai_api_key", v.store)

    def test_the_native_position_route_is_unchanged(self):
        self.posizione("native", "native")
        with _MemVault() as v:
            self.assertEqual(self._post("github", {"value": "ghp_x"}).status_code, 200)
            self.assertEqual(self._post("openai-images", {"api_key": "sk"}).status_code, 200)
            self.assertEqual(v.store["github_pat"], ({"value": "ghp_x"}, "mcp_secret"))
            self.assertEqual(v.store["openai_api_key"], ({"api_key": "sk"}, "api_key"))

    def test_a_pack_declaring_another_entry_is_refused(self):
        images = _images_connector()
        images["providers"][0]["credential"]["vault_entry"] = "openai_other"
        self.scrivi_pack(_it_pack(images=images))
        self.assertEqual(resolved.registry().by_id("openai-images").pack, PACK)
        with _MemVault() as v:
            r = self._post("openai-images", {"api_key": "sk"})
            self.assertEqual(r.status_code, 409)
            self.assertEqual(v.store, {})


def tools_api_github_connect(body: dict):
    """Call the handler directly (no client): returns the JSONResponse."""
    class Req:
        client = None

        async def json(self):
            return body
    return asyncio.run(tools_api.github_connect(Req()))


# --------------------------------------------------------------------------
# 7. the pinned suites, again in `pack` position
# --------------------------------------------------------------------------
class GatePerimeterInPack(_ItIstanza, GP.DestinationsAlreadyAllowedTests):
    pass


class PushDestinationInPack(_ItIstanza, PD.PushDestinationTests):
    pass


class DispatchOutsideAScopeInPack(_ItIstanza, GD.OutsideAScopeTests):
    pass


class DispatchOriginInPack(_ItIstanza, GD.TheRepositoryOfAPushComesFromTheOriginTests):
    pass


class DispatchCredentialInPack(_ItIstanza, GD.TheCredentialIsScopeLevelTests):
    pass


class DispatchShallowCloneInPack(_ItIstanza, GD.AShallowCloneCanBeAskedForTests):
    pass


class DispatchGateClassInPack(_ItIstanza, GD.GateClassTests):
    pass


class RepoApprovalInPack(_ItIstanza, RW.ApprovalTests):
    pass


class RepoHostEntryInPack(_ItIstanza, RW.HostEntryTests):
    pass


class RepoScopeInPack(_ItIstanza, RW.ScopeTests):
    pass


class PdpSpecsInPack(_ItIstanza, PDP.SpecTests):
    pass


class PdpDangerInPack(_ItIstanza, PDP.DangerTests):
    pass


class PdpGrantableInPack(_ItIstanza, PDP.GrantableTests):
    pass


class PdpTaintInPack(_ItIstanza, PDP.TaintTests):
    pass


class PdpSchemesInPack(_ItIstanza, PDP.SchemeListsTests):
    pass


class PinnedSuitesRunInPackTests(_Istanza):
    """The re-runs above are vacuous unless the switch really is on pack and
    it-pack's connector is the one answering."""

    def test_the_fixture_is_in_pack_position(self):
        self.assertEqual(instance_profile.connector_mode("github"), "pack")
        self.assertEqual(resolved.registry().by_id("github").pack, PACK)
        self.assertNotIn("gateway-github", B.manifests())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
