"""What the PDP's connector tables decide today — pinned before they move.

clodia-platform#518 replaces the hardcoded tables of `egress.py`, `main.py` and
`taint.py` with a registry built from connector manifests. The acceptance
criterion asks for the behaviour to be **fixed before** the change: this file is
that fixture, and it was written and run green against the tables, then run
again against the registry. Nothing here reads a private table on purpose —
every assertion goes through the function the rest of the gateway calls, so the
test survives the move and keeps meaning something afterwards.

Where a line below reads oddly, it is pinning an oddity that exists today
(`email.reply` resolving to no destination at all, `datastore:` being a source
URI nobody can grant): the point of a characterisation test is to carry those
across unchanged, or to make their change visible and deliberate.
"""
import unittest

from . import egress
from . import taint


class SchemeListsTests(unittest.TestCase):
    """Which schemes may be granted, in each direction."""

    def test_egress_schemes(self):
        self.assertEqual(
            set(egress.summary()["egress_schemes"]),
            {"mailto", "tg", "http", "https", "gdrive", "gsheets", "outbox",
             "gcal"})

    def test_source_schemes(self):
        self.assertEqual(
            set(egress.summary()["source_schemes"]),
            {"mailfrom", "tg", "http", "https", "gdrive", "gsheets", "mcp",
             "inbox", "topic"})


class SpecTests(unittest.TestCase):
    """verb → (destination type, destinations), one case per mapped verb."""

    CASES = [
        ("email.send", {"to": "A@B.it, c@d.it", "cc": "e@f.it"}, "email",
         ["mailto:a@b.it", "mailto:c@d.it", "mailto:e@f.it"]),
        ("email.send", {"to": "a@b.it;c@d.it"}, "email",
         ["mailto:a@b.it", "mailto:c@d.it"]),
        # No `to` in the arguments: the recipient comes from the message being
        # replied to. No destination readable ⇒ UNKNOWN ⇒ denied.
        ("email.reply", {"message_id": "42"}, "email", []),
        ("telegram.send", {"chat_id": -100123}, "telegram", ["tg:-100123"]),
        ("telegram.send_file", {"chat_id": "@dadabit"}, "telegram",
         ["tg:@dadabit"]),
        ("web.post", {"url": "https://Example.IT:443/a/b?q=1"}, "http",
         ["https://example.it/"]),
        ("web.post", {"url": "notaurl"}, "http", []),
        ("gdrive.upload", {"folder_id": "FID"}, "drive", ["gdrive:folder/FID"]),
        ("gdrive.share", {"email": "X@Y.it"}, "drive", ["mailto:x@y.it"]),
        ("gdrive.mkdir", {"parent_id": "PID"}, "drive", ["gdrive:folder/PID"]),
        ("gdrive.move", {"folder_id": "F", "parent_id": "P"}, "drive",
         ["gdrive:folder/F", "gdrive:folder/P"]),
        ("gdrive.update", {"folder_id": "F"}, "drive", ["gdrive:folder/F"]),
        ("gsheets.add_tab", {"spreadsheet_id": "S"}, "gsheets", ["gsheets:S"]),
        ("gsheets.append_rows", {"spreadsheet_id": "S"}, "gsheets",
         ["gsheets:S"]),
        ("gsheets.write_range", {"spreadsheet_id": "S"}, "gsheets",
         ["gsheets:S"]),
        # GitHub: the native verbs carry the repository as a URL, the proxied
        # write verbs as owner + repo.
        ("github.push", {"repo": "https://github.com/R-Clodia/Tools"}, "github",
         ["https://github.com/r-clodia/tools"]),
        ("github.pull_request", {"repo": "r-clodia/tools"}, "github",
         ["https://github.com/r-clodia/tools"]),
        ("github.create_issue", {"owner": "R-Clodia", "repo": "Tools"},
         "github", ["https://github.com/r-clodia/tools"]),
        ("github.update_issue", {"owner": "a", "repo": "b"}, "github",
         ["https://github.com/a/b"]),
        ("github.issue_write", {"owner": "a", "repo": "b"}, "github",
         ["https://github.com/a/b"]),
        ("github.request_copilot_review", {"owner": "a", "repo": "b"},
         "github", ["https://github.com/a/b"]),
    ]

    def test_specs(self):
        for verb, args, dtype, dests in self.CASES:
            with self.subTest(verb=verb, args=args):
                spec = egress.spec_for(verb)
                self.assertIsNotNone(spec, f"{verb} has no spec")
                self.assertEqual(spec[0], dtype)
                self.assertEqual(spec[1](args), dests)

    def test_reads_have_no_destination(self):
        """A read is not an exit: it must not resolve to a destination."""
        for verb in ("email.read", "gdrive.download", "gsheets.read",
                     "github.get_file_contents", "github.list_commits",
                     "topic.read_file"):
            with self.subTest(verb=verb):
                self.assertIsNone(egress.spec_for(verb))


class CanonicalTests(unittest.TestCase):
    CASES = [
        ("mailto:A@B.it", "mailto:a@b.it"),
        ("mailfrom:A@B.it", "mailfrom:a@b.it"),
        ("inbox:A@B.it", "inbox:a@b.it"),
        ("outbox:A@B.it", "outbox:a@b.it"),
        ("gdrive://ABC", "gdrive:folder/ABC"),
        ("gdrive://folder/ABC", "gdrive:folder/ABC"),
        ("gdrive:folder/ABC", "gdrive:folder/ABC"),
        ("gsheets://S1", "gsheets:S1"),
        ("https://drive.google.com/drive/folders/ABC", "gdrive:folder/ABC"),
        ("https://drive.google.com/drive/u/0/folders/ABC", "gdrive:folder/ABC"),
        ("https://docs.google.com/spreadsheets/d/S1/edit", "gsheets:S1"),
        ("https://docs.google.com/document/d/D1/edit", "gdrive:doc/D1"),
        ("https://drive.google.com/file/d/F1/view", "gdrive:file/F1"),
        ("https://Example.IT/Path", "https://example.it/Path"),
        ("TG:-100", "tg:-100"),
        ("*", "*"),
    ]

    def test_canonical(self):
        for raw, want in self.CASES:
            with self.subTest(uri=raw):
                self.assertEqual(egress.canonical(raw), want)

    def test_idempotent(self):
        for raw, _ in self.CASES:
            once = egress.canonical(raw)
            self.assertEqual(egress.canonical(once), once, raw)


class MatchTests(unittest.TestCase):
    """Prefix rules apply to hierarchical schemes only — today's `_HIERARCHICAL`."""

    def test_prefix_allowed(self):
        for rule, dest in [
            ("https://github.com/r-clodia/", "https://github.com/r-clodia/x"),
            ("http://a.it/x/", "http://a.it/x/y"),
            ("gdrive:folder/F", "gdrive:folder/F/sub"),
            ("mcp:normattiva.", "mcp:normattiva.search"),
        ]:
            with self.subTest(rule=rule):
                self.assertTrue(egress._matches(dest, rule))

    def test_prefix_refused(self):
        for rule, dest in [
            ("mailto:a@b.it", "mailto:a@b.it.evil"),
            ("tg:-100", "tg:-1001"),
            ("gsheets:S", "gsheets:S2"),
            ("mcp:normattiva.", "mcp:normattiva-mirror.search"),
        ]:
            with self.subTest(rule=rule):
                self.assertFalse(egress._matches(dest, rule))

    def test_wildcard_inside_one_scheme(self):
        self.assertTrue(egress._matches("mailto:x@tomato.blue",
                                        "mailto:*@tomato.blue"))
        self.assertFalse(egress._matches("tg:x@tomato.blue",
                                         "mailto:*@tomato.blue"))


class DangerTests(unittest.TestCase):
    def test_each_scheme_has_its_note(self):
        for uri, needle in [
            ("mailto:a@b.it", "indirizzo email"),
            ("tg:-100", "Telegram"),
            ("gsheets:S", "foglio Google"),
            ("gcal:a@b.it", "calendario Google"),
            ("https://github.com/a/b", "repository su github.com"),
            ("https://altro.it/", "sistema di terzi"),
            ("*", "QUALUNQUE destinazione"),
        ]:
            with self.subTest(uri=uri):
                self.assertIn(needle, egress.danger_note(uri))

    def test_no_note_is_an_empty_string(self):
        self.assertEqual(egress.danger_note(""), "")
        self.assertEqual(egress.danger_note("gdrive:folder/F"), "")


class GrantableTests(unittest.TestCase):
    OK = [
        ("egress", "mailto:a@b.it"),
        ("egress", "mailto:*@tomato.blue"),
        ("egress", "tg:-1001234567890"),
        ("egress", "tg:@dadabit"),
        ("egress", "https://github.com/r-clodia/"),
        ("egress", "gdrive:folder/ABC"),
        ("egress", "gsheets:S1"),
        ("egress", "outbox:studio@x.it"),
        ("egress", "gcal:*@tomato.blue"),
        ("ingress", "mailfrom:a@b.it"),
        ("ingress", "inbox:studio@x.it"),
        ("ingress", "mcp:normattiva."),
        ("ingress", "topic:SEAL-1/acme"),
        ("ingress", "tg:-100123"),
    ]
    KO = [
        # wrong direction
        ("egress", "mailfrom:a@b.it"),
        ("egress", "topic:SEAL-1/acme"),
        ("ingress", "mailto:a@b.it"),
        ("ingress", "outbox:studio@x.it"),
        ("ingress", "gcal:a@b.it"),
        # degenerate: constrains nothing inside its own scheme
        ("egress", "mailto:"),
        ("egress", "gdrive:folder/"),
        ("egress", "https://"),
        ("ingress", "mcp:"),
        ("ingress", "mcp:."),
        # whole-scheme wildcards
        ("egress", "*"),
        ("egress", "gcal:*"),
        # shapes that could never match anything
        ("egress", "tg:pippo"),
        ("ingress", "tg:*"),
        ("ingress", "topic:SEAL-1/"),
        ("ingress", "topic:*"),
        # unknown scheme
        ("egress", "ftp://a.it/"),
        ("ingress", "datastore:x"),
    ]

    def test_grantable(self):
        for direction, uri in self.OK:
            with self.subTest(direction=direction, uri=uri):
                self.assertTrue(egress.check_grantable(direction, uri))

    def test_not_grantable(self):
        for direction, uri in self.KO:
            with self.subTest(direction=direction, uri=uri):
                with self.assertRaises(ValueError):
                    egress.check_grantable(direction, uri)


class TaintTests(unittest.TestCase):
    TAINTS = [
        "email.read", "email.list", "email.search", "email.get_attachment",
        "telegram.inbox", "telegram.receive", "telegram.pull",
        "topic.read_file", "topic.read_document", "topic.fetch",
        "gdrive.download", "gdocs.read", "gsheets.read", "gsheets.list_tabs",
        "gcalendar.list_events", "datastore.read",
        "web.fetch", "web.download", "web.search", "web.render", "web.get",
        "github.get_file_contents", "github.list_commits",
        "github.search_code", "github.issue_read", "github.pull_request_read",
    ]
    CLEAN = [
        "email.send", "telegram.send", "gdrive.upload", "gsheets.write_range",
        "topic.post_message", "topic.put", "github.push",
    ]

    def test_tainting_verbs(self):
        for verb in self.TAINTS:
            with self.subTest(verb=verb):
                self.assertTrue(taint.taints(verb))

    def test_verbs_that_do_not_taint(self):
        for verb in self.CLEAN:
            with self.subTest(verb=verb):
                self.assertFalse(taint.taints(verb))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
