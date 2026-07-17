import unittest

from server.topics.sync_filter import (
    SyncFilter, _parse, INCLUDED, SKIP_INCLUDE, SKIP_IGNORE, SKIP_HARD_DENY,
)


def _f(include: str = "", ignore: str = "") -> SyncFilter:
    return SyncFilter(_parse(include), _parse(ignore))


class TestMatcher(unittest.TestCase):
    def test_no_config_includes_everything(self):
        f = _f()
        self.assertEqual(f.evaluate("lead-pipeline/latest/x.json"), INCLUDED)
        self.assertEqual(f.evaluate("qualsiasi/cosa.txt"), INCLUDED)

    def test_hard_deny_not_bypassable(self):
        # incluso esplicitamente ma hard-denied → resta escluso
        f = _f(include="**", ignore="")
        self.assertEqual(f.evaluate("secrets/token.json"), SKIP_HARD_DENY)
        self.assertEqual(f.evaluate("a/b/private.key"), SKIP_HARD_DENY)
        self.assertEqual(f.evaluate("config.pem"), SKIP_HARD_DENY)
        self.assertEqual(f.evaluate(".env"), SKIP_HARD_DENY)
        self.assertEqual(f.evaluate(".env.local"), SKIP_HARD_DENY)
        self.assertEqual(f.evaluate(".trash/old.pdf"), SKIP_HARD_DENY)
        # i file di config del protocollo sono control-plane
        self.assertEqual(f.evaluate(".remoteinclude"), SKIP_HARD_DENY)
        self.assertEqual(f.evaluate(".remoteignore"), SKIP_HARD_DENY)

    def test_include_allowlist(self):
        f = _f(include="lead-pipeline/latest/**\n*.md")
        self.assertEqual(f.evaluate("lead-pipeline/latest/manifest.json"), INCLUDED)
        self.assertEqual(f.evaluate("brief.md"), INCLUDED)
        self.assertEqual(f.evaluate("sub/nota.md"), INCLUDED)
        # fuori dall'allowlist
        self.assertEqual(f.evaluate("lead-pipeline/archive/2025/x.csv"), SKIP_INCLUDE)
        self.assertEqual(f.evaluate("random.txt"), SKIP_INCLUDE)

    def test_ignore(self):
        f = _f(ignore="*.pdf\n*.docx\n~$*\n.DS_Store")
        self.assertEqual(f.evaluate("preventivo.pdf"), SKIP_IGNORE)
        self.assertEqual(f.evaluate("sub/dir/report.docx"), SKIP_IGNORE)
        self.assertEqual(f.evaluate("~$bozza.docx"), SKIP_IGNORE)
        self.assertEqual(f.evaluate("a/b/.DS_Store"), SKIP_IGNORE)
        self.assertEqual(f.evaluate("dati.csv"), INCLUDED)

    def test_negation_reinclude(self):
        f = _f(ignore="*.csv\n!keep/**/*.csv")
        self.assertEqual(f.evaluate("archive/x.csv"), SKIP_IGNORE)
        self.assertEqual(f.evaluate("keep/2026/y.csv"), INCLUDED)

    def test_order_include_before_ignore(self):
        # include allowlist passa, poi ignore esclude comunque un sottoinsieme
        f = _f(include="data/**", ignore="data/**/*.tmp")
        self.assertEqual(f.evaluate("data/a.csv"), INCLUDED)
        self.assertEqual(f.evaluate("data/a.tmp"), SKIP_IGNORE)
        self.assertEqual(f.evaluate("altro/a.csv"), SKIP_INCLUDE)

    def test_spec_tomato_leadgen(self):
        include = (
            "# Output leggeri\n"
            "lead-pipeline/latest/**\n"
            "lead-pipeline/archive/**/*.csv\n"
            "lead-pipeline/archive/**/*.json\n"
            "lead-pipeline/archive/**/*.html\n"
            "*.md\n"
        )
        ignore = (
            "*.pdf\n*.docx\n*.xlsx\n*.zip\n"
            "*.tmp\n*.bak\n~$*\n.DS_Store\n"
            ".trash/**\nsecrets/**\n"
        )
        f = _f(include, ignore)
        # gli output attesi della lead pipeline → synced
        for p in [
            "lead-pipeline/latest/lead_pipeline_manifest.json",
            "lead-pipeline/latest/lead_pipeline_items.csv",
            "lead-pipeline/latest/lead_pipeline_analytics.html",
        ]:
            self.assertEqual(f.evaluate(p), INCLUDED, p)
        # i preventivi sorgente NON entrano
        self.assertEqual(f.evaluate("preventivi/quote_001.pdf"), SKIP_INCLUDE)
        # un csv in archive è incluso, ma uno zip no anche se sotto latest
        self.assertEqual(f.evaluate("lead-pipeline/archive/2026/run.csv"), INCLUDED)
        self.assertEqual(f.evaluate("lead-pipeline/latest/dump.zip"), SKIP_IGNORE)


if __name__ == "__main__":
    unittest.main()
