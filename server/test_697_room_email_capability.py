"""A room can authorise and revoke Email again (clodia-platform#697).

#683 removed the agents' `email.*` verbs, so the builtin `mail` connector left
`mcp_catalogue()`: no Email card in Strumenti, `enable_mcp("email")` refused,
and neither «Autorizza una casella» nor a sender added in «In ascolto»
authorised Email any more. #696 made the courier read `meta.tools.mcp.email`
again, but a room that did not already carry it could not get it.

Email is listed again as a room CAPABILITY: authorised and revoked like an MCP,
with no agent verb, no resource row and nothing compiled into the toolbox. It
only gates the courier's linked-mailbox rows (`room_tools.email_authorised`).

These tests run on the REAL connector registry (the builtin `mail.yaml`), not
on a stubbed catalogue.
"""
from __future__ import annotations

from unittest.mock import patch

from starlette.applications import Starlette
from starlette.testclient import TestClient

from . import authz_runtime, egress, main, room_listen, room_tools as RT, topics_api, whitelist
from .test_620_room_mcp import _Env
from .test_696_courier_email_auth import _rooms
from .test_519_generic_actions import come_agent_server

#: Captured at import, before `_Env` stubs it with a fake catalogue.
REAL_CATALOGUE = RT.mcp_catalogue
ROOM = ("SEAL-1", "blog")
SCOPE = "SEAL-1/blog"
#: The room's lists the courier reads: a sender and a linked mailbox.
LISTS = {SCOPE: ["mailfrom:*@brightnode.io", "inbox:studio@x.it"]}
COURIER_ROW = [("blog", "studio@x.it", "")]


class CatalogueTests(_Env):
    def setUp(self):
        super().setUp()
        p = patch.object(RT, "mcp_catalogue", REAL_CATALOGUE)
        p.start(); self.addCleanup(p.stop)

    def test_email_is_listed_as_a_capability_with_no_agent_verb(self):
        e = RT.mcp_catalogue().get("email")
        self.assertIsNotNone(e, "the builtin mail connector is a room capability again")
        self.assertEqual((e["label"], e["kind"], e["namespaces"]),
                         ("Email", "connector", ["email"]))
        self.assertFalse(e["agent_verbs"])
        self.assertEqual((e["verbs"], e["write"], e["schemes"]), ([], [], []))

    def test_every_other_mcp_gives_agent_verbs(self):
        for mid, e in RT.mcp_catalogue().items():
            if mid != "email":
                self.assertTrue(e["agent_verbs"], mid)

    def test_the_mail_namespace_belongs_to_it(self):
        # What the `mailbox-link` action and `on_room_list_added` look up.
        self.assertEqual(RT.mcp_for_namespace("email"), "email")

    def test_email_is_still_not_an_enablable_verb_namespace(self):
        self.assertNotIn("email", RT.enablable())
        with self.assertRaises(RT.ToolboxError):
            RT.check("email.*")


class AuthoriseRevokeTests(_Env):
    def setUp(self):
        super().setUp()
        p = patch.object(RT, "mcp_catalogue", REAL_CATALOGUE)
        p.start(); self.addCleanup(p.stop)

    def courier(self):
        return _rooms({ROOM: self.meta()}, LISTS)

    def test_authorise_then_revoke_drives_the_courier_rows(self):
        self.assertEqual(self.courier(), [])
        RT.enable_mcp(*ROOM, "email")
        self.assertIn("email", self.meta()["tools"]["mcp"])
        self.assertTrue(RT.email_authorised(self.meta()))
        self.assertEqual(self.courier(), COURIER_ROW)
        RT.enable_mcp(*ROOM, "email", on=False)
        self.assertFalse(RT.email_authorised(self.meta()))
        self.assertEqual(self.courier(), [])

    def test_no_email_verb_reaches_an_agent(self):
        RT.enable_mcp(*ROOM, "email")
        self.assertFalse([v for v in RT.toolbox(self.meta())["enabled"]
                          if v.startswith("email.")])
        got = RT.verbs_for("officer", SCOPE)
        self.assertFalse([v for v in got if v.startswith("email.")], got)
        self.assertEqual(got, {"topic.*"})

    def test_no_resource_row_can_be_written_on_it(self):
        RT.enable_mcp(*ROOM, "email")
        with self.assertRaises(RT.ToolboxError):
            RT.set_resource(*ROOM, "email", "mailto:a@b.it", "allow")

    def test_rows_stored_before_683_compile_to_no_tuple(self):
        meta = {"tools": {"enabled": [], "mcp": {"email": {"resources": [
            {"uri": "mailto:a@b.it", "effect": "allow"},
            {"uri": "mailfrom:c@d.it", "effect": "allow"}]}}}}
        self.assertEqual(authz_runtime._resource_tuples(meta), [])

    def test_the_route_authorises_and_revokes(self):
        client = TestClient(Starlette(routes=topics_api.routes))
        with patch.object(topics_api, "_svc", self.svc), \
                patch.object(topics_api, "_authorize", come_agent_server):
            r = client.get("/internal/topics/SEAL-1/blog/tools",
                           headers={"Authorization": "Bearer ckt1.finto"})
            self.assertEqual(r.status_code, 200, r.text)
            self.assertFalse(r.json()["mcp_catalogue"]["email"]["agent_verbs"])
            for action, present in (("enable_mcp", True), ("disable_mcp", False)):
                r = client.post("/internal/topics/SEAL-1/blog/tools",
                                headers={"Authorization": "Bearer ckt1.finto"},
                                json={"action": action, "mcp": "email"})
                self.assertEqual(r.status_code, 200, r.text)
                self.assertEqual("email" in RT._mcp_entries(self.meta()), present)


class ListsAuthoriseTests(_Env):
    """A sender, a linked mailbox or a recipient authorises Email, as before
    #683 (`LIST_TOOLS`, #662)."""

    def setUp(self):
        super().setUp()
        whitelist.CONFIG.update({"scope_source_allow": {}, "scope_egress_allow": {}})
        p = patch.object(RT, "mcp_catalogue", REAL_CATALOGUE)
        p.start(); self.addCleanup(p.stop)

    def test_a_sender_in_listen_authorises_email(self):
        out = room_listen.add(*ROOM, "mail", "sender", "*@brightnode.io")
        self.assertEqual(out["ingress"].get("mcp_authorised"), "email")
        self.assertTrue(RT.email_authorised(self.meta()))
        self.assertEqual(_rooms({ROOM: self.meta()}, LISTS), COURIER_ROW)

    def test_removing_the_sender_leaves_email_authorised(self):
        room_listen.add(*ROOM, "mail", "sender", "*@brightnode.io")
        room_listen.remove(*ROOM, "mail", "sender", "*@brightnode.io")
        self.assertTrue(RT.email_authorised(self.meta()))

    def test_a_recipient_authorises_email_with_no_row(self):
        out = egress.scope_allow("egress", SCOPE, "mailto:c@d.it")
        self.assertEqual(out.get("mcp_authorised"), "email")
        self.assertNotIn("resource_allowed", out)
        self.assertEqual(RT._mcp_entries(self.meta())["email"]["resources"], [])

    def test_the_mailbox_link_action_authorises_email(self):
        from .tools import mail_switch
        client = TestClient(Starlette(routes=topics_api.routes))
        with patch.object(topics_api, "_svc", self.svc), \
                patch.object(topics_api, "_authorize", come_agent_server), \
                patch.object(mail_switch, "system_mailboxes", return_value=[
                    {"account": "studio", "email": "studio@x.it", "send_only": False}]):
            r = client.post("/internal/topics/SEAL-1/blog/mailbox-link",
                            headers={"Authorization": "Bearer ckt1.finto"},
                            json={"action": "connect", "account": "studio"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIn("inbox:studio@x.it", whitelist.CONFIG["scope_source_allow"][SCOPE])
        self.assertTrue(RT.email_authorised(self.meta()))
        self.assertEqual(_rooms({ROOM: self.meta()}, LISTS), COURIER_ROW)


if __name__ == "__main__":
    import unittest
    unittest.main()
