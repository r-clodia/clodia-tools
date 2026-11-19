"""Connecting GitHub grants no verb (clodia-platform#703).

`github_connect` used to add `github.*` to clodia's `allowed_tools`, then
(17 Aug 2026) a named list of verbs: a wildcard on an external backend grants
whatever it adds tomorrow — `delete_repository`, `force_push`,
`delete_branch`. Since A·V·R·Q is the only authority on which verbs an agent
has (#656), `allowed_tools` is read by nothing and the append was dead. Now
the handler only deposits the PAT; who uses the backend's verbs is decided by
tuples (the role plan of `authz_roles` for sysadmin). The two properties the
old list protected — no wildcard, nothing irreversible — are asserted on that
plan instead.
"""
from __future__ import annotations

import ast
import inspect
import unittest

from . import authz_roles, tools_api


class ConnectGrantsNothingTests(unittest.TestCase):
    def test_the_handler_does_not_touch_allowed_tools(self):
        src = inspect.getsource(tools_api.github_connect)
        tree = ast.parse(src)
        strings = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant)
                   and isinstance(n.value, str)}
        self.assertNotIn("allowed_tools", strings)
        self.assertNotIn("_GH_CONCESSI", src)


class RoleGithubVerbsTests(unittest.TestCase):
    LISTED = ["github.get_me", "github.list_issues", "github.issue_write",
              "github.delete_repository", "github.force_push", "github.delete_branch",
              "github.delete_file", "github.merge_pull_request",
              "github.create_repository", "github.clone", "github.push",
              "github.pull_request", "github.mirror", "github.pull"]

    def test_no_wildcard_and_nothing_irreversible(self):
        keep, source = authz_roles.github_verbs(self.LISTED)
        self.assertEqual(source, "backend")
        self.assertNotIn("github.*", keep)
        for v in ("delete_repository", "force_push", "delete_branch",
                  "delete_file", "merge_pull_request", "create_repository"):
            self.assertNotIn(f"github.{v}", keep, f"{v} must not be granted: irreversible")

    def test_the_git_component_verbs_are_not_role_tools(self):
        keep, _ = authz_roles.github_verbs(self.LISTED)
        for v in ("clone", "pull", "push", "pull_request", "mirror"):
            self.assertNotIn(f"github.{v}", keep)
        self.assertEqual(keep, ["github.get_me", "github.issue_write", "github.list_issues"])

    def test_unlisted_backend_falls_back_to_the_known_names(self):
        keep, source = authz_roles.github_verbs(None)
        self.assertEqual(source, "known")
        self.assertIn("github.list_pull_requests", keep)
        self.assertFalse(set(keep) & authz_roles.GITHUB_GIT_VERBS)


if __name__ == "__main__":
    unittest.main()
