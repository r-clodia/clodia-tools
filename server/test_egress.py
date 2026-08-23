"""Tests for the destination whitelist (clodia-platform#104 §7, #128).

Two properties carry the whole thing and both are easy to break by refactor: the
DENY defaults, and the fact that a prefix rule must not open a hostile neighbour
of a legitimate destination.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import egress


def _cfg(*uris, sources=()):
    """Config del gateway con la whitelist GLOBALE (#128: non per-agente)."""
    return {"egress_allow": list(uris), "source_allow": list(sources), "agents": {}}


def _with(cfg):
    from . import whitelist as wl
    return patch.object(wl, "CONFIG", cfg)


class UriExtractionTests(unittest.TestCase):
    """Gli estrattori producono URI: lo SCHEMA è il tipo.

    Prima il tipo era un campo separato dal valore e viveva in una tabella
    verbo→tipo: due cose accoppiate che potevano divergere. Con l'URI la voce si
    spiega da sé nel log, nel dialog e nella config.
    """

    def _dests(self, verb, args):
        with _with(_cfg("*")):
            return egress.decide({}, verb, args)["destinations"]

    def test_email_fields_become_mailto(self):
        self.assertEqual(
            self._dests("email.send", {"to": "A@Tomato.blue, b@x.it", "cc": "c@y.it"}),
            ["mailto:a@tomato.blue", "mailto:b@x.it", "mailto:c@y.it"])

    def test_telegram_becomes_tg(self):
        self.assertEqual(self._dests("telegram.send", {"chat_id": "76632169"}),
                         ["tg:76632169"])

    def test_http_keeps_scheme_and_host_only(self):
        """Su TLS il path non è visibile a un proxy: una whitelist che promette
        una granularità che non ha è peggio di una che dichiara la propria."""
        self.assertEqual(self._dests("web.post", {"url": "https://Example.COM/a/b?c=1"}),
                         ["https://example.com/"])

    def test_a_github_write_becomes_a_repo_url(self):
        self.assertEqual(
            self._dests("github.create_pull_request",
                        {"owner": "r-clodia", "repo": "clodia-logic"}),
            ["https://github.com/r-clodia/clodia-logic"])

    def test_the_short_form_is_a_readable_destination(self):
        """`github.pull_request(repo="owner/repo")` è la forma che si scrive a
        mano, e `normalize_repo` la accetta. Se l'estrattore la scarta prima,
        `decide()` risponde UNKNOWN e il verbo viene negato «destinazione non
        leggibile» — cioè si manda a toccare `egress_allow` per una forma che lo
        schema del verbo dichiara valida. Il PDP gira prima del verbo: la nozione
        di «forma di un repository» deve essere UNA."""
        self.assertEqual(egress._repo_url({"repo": "acme/tool"}),
                         ["https://github.com/acme/tool"])
        self.assertEqual(egress._repo_url({"repo": "https://github.com/Acme/Tool.git"}),
                         ["https://github.com/acme/tool"])

    def test_what_is_not_a_repository_stays_unreadable(self):
        """La proprietà 3 del modulo: una destinazione che non si legge dalla
        chiamata non passa. Un path del filesystem non deve diventare una
        destinazione leggibile — e `file://` nemmeno quando il seam dei test lo
        apre a `normalize_repo`, perché è il filesystem del gateway, non
        un'uscita."""
        from .tools import github_repo as gh
        for brutto in ("", "acme", "../etc/passwd", "/datadir/vault",
                       "acme/tool/extra"):
            with self.subTest(brutto):
                self.assertEqual(egress._repo_url({"repo": brutto}), [])
        with patch.object(gh, "ALLOW_LOCAL_REPOS", True):
            self.assertEqual(egress._repo_url({"repo": "file:///datadir/vault"}), [])

    def test_drive_share_is_a_person_not_a_folder(self):
        """`gdrive.share` è uscita verso una PERSONA: con l'URI la differenza si
        vede, e non si confonde con una cartella."""
        self.assertEqual(self._dests("gdrive.share", {"email": "Tizio@X.it"}),
                         ["mailto:tizio@x.it"])
        self.assertEqual(self._dests("gdrive.upload", {"folder_id": "1AbC"}),
                         ["gdrive:folder/1AbC"])

    def test_a_read_verb_is_not_egress_at_all(self):
        with _with(_cfg()):
            self.assertFalse(egress.decide({}, "github.list_issues",
                                           {"owner": "a", "repo": "b"})["checked"])
            self.assertFalse(egress.decide({}, "topic.open", {})["checked"])


class MatchingTests(unittest.TestCase):
    def _allowed(self, rules, verb, args):
        with _with(_cfg(*rules)):
            return egress.decide({}, verb, args)["allowed"]

    def test_exact_uri_matches(self):
        self.assertTrue(self._allowed(["mailto:d.carboni@gmail.com"], "email.send",
                                      {"to": "D.Carboni@Gmail.com"}))

    def test_wildcard_covers_a_domain(self):
        self.assertTrue(self._allowed(["mailto:*@tomato.blue"], "email.send",
                                      {"to": "chi@tomato.blue"}))

    def test_a_wildcard_does_not_leak_to_a_lookalike_domain(self):
        self.assertFalse(self._allowed(["mailto:*@tomato.blue"], "email.send",
                                       {"to": "chi@tomato.blue.evil.it"}))

    def test_a_wildcard_stays_inside_its_scheme(self):
        """`mailto:*@x.it` non deve autorizzare una chat o un repo."""
        self.assertFalse(self._allowed(["mailto:*@x.it"], "telegram.send",
                                       {"chat_id": "*@x.it"}))

    def test_a_prefix_works_where_hierarchy_exists(self):
        self.assertTrue(self._allowed(["https://github.com/r-clodia/"],
                                      "github.push_files",
                                      {"owner": "r-clodia", "repo": "clodia-web"}))

    def test_a_prefix_does_NOT_apply_to_an_address(self):
        """Un indirizzo non è un percorso: trattarlo come prefisso aprirebbe
        `a@b.it.evil` a chi ha approvato `a@b.it`. È il caso in cui un prefisso
        ingenuo regala un dominio ostile."""
        self.assertFalse(self._allowed(["mailto:a@b.it"], "email.send",
                                       {"to": "a@b.it.evil.com"}))

    def test_a_prefix_does_not_apply_to_a_chat_id(self):
        self.assertFalse(self._allowed(["tg:766"], "telegram.send",
                                       {"chat_id": "76632169"}))

    def test_one_refused_recipient_refuses_the_whole_call(self):
        """Un invio parziale non esiste: il messaggio va a tutti i destinatari in
        una volta, quindi una destinazione fuori whitelist nega la chiamata."""
        with _with(_cfg("mailto:*@tomato.blue")):
            v = egress.decide({}, "email.send",
                              {"to": "ok@tomato.blue", "cc": "fuori@altrove.it"})
        self.assertFalse(v["allowed"])
        self.assertEqual(v["refused"], ["mailto:fuori@altrove.it"])


class DenyDefaultTests(unittest.TestCase):
    def test_an_empty_list_denies(self):
        """§7 proprietà 1: default vuoto = nessuna uscita. La lista è opt-in e
        tutto ciò che manca è gated."""
        with _with(_cfg()):
            v = egress.decide({}, "email.send", {"to": "x@y.it"})
        self.assertFalse(v["allowed"])
        self.assertIn("nessuna destinazione dichiarata", v["reason"])

    def test_an_unreadable_destination_is_denied(self):
        """`email.reply` non porta il destinatario negli argomenti: viene dal
        messaggio a cui risponde, cioè da contenuto non fidato. «L'attaccante
        scrive, l'agente risponde con i dati» è il percorso dell'injection."""
        with _with(_cfg("mailto:*@tomato.blue")):
            v = egress.decide({}, "email.reply", {"email_id": "42"})
        self.assertFalse(v["allowed"])
        self.assertEqual(v["destinations"], [egress.UNKNOWN])

    def test_an_explicit_star_opens_everything_including_the_unknown(self):
        with _with(_cfg("*")):
            self.assertTrue(
                egress.decide({}, "email.reply", {"email_id": "42"})["allowed"])


class SchemeGuardTests(unittest.TestCase):
    """Le due liste hanno schemi distinti, e mescolarle è un errore rifiutato.

    L'asimmetria: sbagliare una destinazione è rumoroso (un invio bloccato, lo
    vedi), sbagliare una fonte è SILENZIOSO — un taint che non si accende e nessun
    gate a valle che scatta. Liste separate rendono impossibile che un errore in
    una perda nell'altra.
    """

    def test_a_source_scheme_in_the_egress_list_is_ignored_loudly(self):
        cfg = _cfg("mailfrom:tizio@x.it", "mailto:ok@x.it")
        with _with(cfg), self.assertLogs("clodia-tools.egress", level="WARNING") as cm:
            rules = egress.allowed_uris()
        self.assertEqual(rules, ["mailto:ok@x.it"])
        self.assertIn("mailfrom:tizio@x.it", "".join(cm.output))

    def test_an_egress_scheme_in_the_source_list_is_ignored_loudly(self):
        cfg = _cfg(sources=["tg:123", "mailfrom:ok@x.it"])
        with _with(cfg), self.assertLogs("clodia-tools.egress", level="WARNING"):
            self.assertEqual(egress.source_uris(), ["mailfrom:ok@x.it"])

    def test_the_source_list_is_empty_by_default(self):
        with _with({"agents": {}}):
            self.assertEqual(egress.source_uris(), [])


class LegacyMigrationTests(unittest.TestCase):
    """Le vecchie voci per-agente (tipo + valore nudo) diventano URI globali.

    Un'istanza aggiornata non deve perdere le destinazioni che un umano aveva già
    approvato: erano una decisione presa, e farla ripetere svuoterebbe di senso
    l'approvazione.
    """

    def test_per_agent_entries_are_promoted_to_the_global_list(self):
        cfg = {"agents": {
            "sysadmin": {"egress_allow": {"github": ["r-clodia/clodia-platform"]}},
            "messaggero": {"egress_allow": {"email": ["@tomato.blue", "d@x.it"],
                                            "telegram": ["76632169"]}},
        }}
        with _with(cfg):
            rules = egress.allowed_uris()
        self.assertIn("https://github.com/r-clodia/clodia-platform", rules)
        self.assertIn("mailto:*@tomato.blue", rules)
        self.assertIn("mailto:d@x.it", rules)
        self.assertIn("tg:76632169", rules)

    def test_a_per_type_star_is_not_promoted_to_a_global_star(self):
        """Aprire un tipo per un agente non è aprire tutto per tutti: promuoverlo
        sarebbe l'allargamento silenzioso peggiore della migrazione."""
        cfg = {"agents": {"clodia": {"egress_allow": {"http": ["*"]}}}}
        with _with(cfg):
            self.assertEqual(egress.allowed_uris(), [])


class ModeTests(unittest.TestCase):
    def _check(self, mode, cfg, verb, args, unattended=False):
        with patch.dict("os.environ", {"CLODIA_EGRESS_ENFORCE": mode,
                                       "CLODIA_DANGEROUSLY_SKIP_GATES": "0"}), _with(cfg):
            return egress.check("messaggero", {}, verb, args, unattended=unattended)

    def test_gate_is_the_default(self):
        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(egress.mode(), "gate")

    def test_an_unlisted_destination_asks_and_is_remembered_as_a_uri(self):
        v = self._check("gate", _cfg(), "email.send", {"to": "terzo@esterno.it"})
        self.assertEqual(v["action"], "gate")
        self.assertEqual(v["remember"], ["mailto:terzo@esterno.it"])
        self.assertIn("mailto:terzo@esterno.it", v["gate_key"])

    def test_report_allows_and_marks(self):
        v = self._check("report", _cfg(), "email.send", {"to": "x@y.it"})
        self.assertEqual(v["action"], "allow")
        self.assertTrue(v["would_deny"])

    def test_on_denies_without_asking(self):
        v = self._check("on", _cfg("mailto:*@tomato.blue"), "email.send",
                        {"to": "fuori@altrove.it"})
        self.assertEqual(v["action"], "deny")
        self.assertIn("egress_allow", str(egress.denied_error("x", v)))

    def test_unattended_turns_gate_into_deny(self):
        """Nessun umano davanti al turno: un gate resterebbe appeso fino al
        timeout (#116)."""
        v = self._check("gate", _cfg(), "email.send", {"to": "x@y.it"}, unattended=True)
        self.assertEqual(v["action"], "deny")
        self.assertEqual(v["mode"], "gate")
        self.assertEqual(v["applied_mode"], "on")

    def test_off_skips_entirely(self):
        v = self._check("off", _cfg(), "email.send", {"to": "x@y.it"})
        self.assertFalse(v["checked"])

    def test_an_unknown_mode_falls_back_to_gate(self):
        with patch.dict("os.environ", {"CLODIA_EGRESS_ENFORCE": "enforce"}):
            self.assertEqual(egress.mode(), "gate")


class ShorthandGatesInsteadOfDenyingTests(unittest.TestCase):
    """La forma breve deve poter essere APPROVATA, non solo letta.

    Il difetto visibile non era il valore estratto: era che `UNKNOWN`, in modo
    `gate`, fa deny SECCO — nessuna card, quindi nessun modo per un umano di dire
    sì, e un messaggio che manda a dichiarare `egress_allow.github` per niente.
    Questi test attraversano `check()`, dove quella differenza si vede.
    """

    def _check(self, mode, cfg, repo):
        with patch.dict("os.environ", {"CLODIA_EGRESS_ENFORCE": mode,
                                       "CLODIA_DANGEROUSLY_SKIP_GATES": "0"}), _with(cfg):
            return egress.check("fullstack-dev", {}, "github.pull_request",
                                {"repo": repo, "head": "b", "title": "t"})

    def test_an_unlisted_short_form_asks_instead_of_denying(self):
        v = self._check("gate", _cfg("https://github.com/r-clodia/"), "acme/tool")
        self.assertEqual(v["action"], "gate")
        self.assertEqual(v["remember"], ["https://github.com/acme/tool"])

    def test_a_listed_short_form_passes_without_asking(self):
        v = self._check("gate", _cfg("https://github.com/r-clodia/"),
                        "r-clodia/clodia-tools")
        self.assertEqual(v["action"], "allow")

    def test_the_refusal_now_names_the_whitelist_not_the_illegibility(self):
        """In modo `on` il perimetro decide ancora: negato, ma per il motivo
        giusto — quello che dice cosa aggiungere."""
        v = self._check("on", _cfg("https://github.com/r-clodia/"), "acme/tool")
        self.assertEqual(v["action"], "deny")
        self.assertIn("non in whitelist", v["reason"])


class RememberTests(unittest.TestCase):
    def setUp(self):
        from . import whitelist as wl
        self.cfg = {"agents": {}, "egress_allow": []}
        self.saves = 0
        for pt in (patch.object(wl, "CONFIG", self.cfg),
                   patch.object(wl, "save_config", self._saved)):
            pt.start()
            self.addCleanup(pt.stop)

    def _saved(self):
        self.saves += 1

    def test_an_approved_destination_lands_in_the_global_list(self):
        """Approvata per uno = approvata per tutti (#128): è la destinazione che si
        giudica, non chi spedisce. E un secondo agente non deve ri-chiedere."""
        rules = egress.remember("messaggero", "email", ["mailto:terzo@esterno.it"])
        self.assertEqual(rules, ["mailto:terzo@esterno.it"])
        self.assertEqual(self.cfg["egress_allow"], ["mailto:terzo@esterno.it"])
        self.assertEqual(self.saves, 1)
        with patch.dict("os.environ", {"CLODIA_EGRESS_ENFORCE": "gate",
                                       "CLODIA_DANGEROUSLY_SKIP_GATES": "0"}):
            v = egress.check("clodia", {}, "email.send", {"to": "terzo@esterno.it"})
        self.assertEqual(v["action"], "allow")

    def test_remembering_twice_does_not_duplicate(self):
        egress.remember("m", "email", ["mailto:a@b.it"])
        self.assertEqual(egress.remember("m", "email", ["mailto:a@b.it"]),
                         ["mailto:a@b.it"])

    def test_the_unknown_sentinel_is_never_remembered(self):
        self.assertEqual(egress.remember("m", "email", [egress.UNKNOWN]), [])
        self.assertEqual(self.cfg["egress_allow"], [])


class ReplyRecipientTests(unittest.TestCase):
    def test_address_is_extracted_from_a_from_header(self):
        for header, want in (("Mario Rossi <mario@x.it>", "mario@x.it"),
                             ("  <A@B.IT> ", "a@b.it"),
                             ("plain@z.it", "plain@z.it"),
                             ('"Chi Sa" <chi@sa.it>', "chi@sa.it")):
            with self.subTest(header=header):
                self.assertEqual(egress.address_of(header), want)

    def test_a_header_without_an_address_yields_nothing(self):
        for header in ("", "Mario Rossi", "<>", None):
            self.assertEqual(egress.address_of(header), "")


if __name__ == "__main__":
    unittest.main()


class DangerNoteTests(unittest.TestCase):
    """L'avvertenza nel dialog di approvazione (#128, revisione del 4 ago 2026).

    Sostituisce il controllo «un repo pubblico non è mai aggiungibile», che era un
    cavillo: richiedeva l'API GitHub, poteva sbagliare o essere stale, e spostava
    la decisione dal giudizio dell'owner a un lookup. Se lo aggiunge lui è chiaro;
    il compito del dialog è dire COSA sta concedendo.
    """

    def test_github_warns_about_public_visibility(self):
        n = egress.danger_note("https://github.com/r-clodia/clodia-web")
        self.assertIn("pubblico", n)
        self.assertIn("storia del repo", n)

    def test_another_host_warns_about_a_third_party_system(self):
        self.assertIn("terzi", egress.danger_note("https://api.tizio.it/"))

    def test_each_scheme_has_its_own_note(self):
        for uri, needle in (("mailto:x@y.it", "non è più richiamabile"),
                            ("tg:123", "non tua"),
                            ("gsheets:1abc", "chi ha il link")):
            with self.subTest(uri=uri):
                self.assertIn(needle, egress.danger_note(uri))

    def test_the_owners_own_drive_folder_gets_no_warning(self):
        """Una cartella del Drive dell'owner non è un sistema di terzi: avvertire
        anche lì insegnerebbe a ignorare l'avvertenza."""
        self.assertEqual(egress.danger_note("gdrive:folder/1AbC"), "")

    def test_a_star_says_it_opens_everything(self):
        self.assertIn("QUALUNQUE", egress.danger_note("*"))

    def test_the_dialog_carries_the_warning_and_says_it_is_for_everyone(self):
        r = egress.gate_reason("clodia", "github.push_files", "github",
                               ["https://github.com/r-clodia/clodia-web"])
        self.assertIn("⚠️", r)
        self.assertIn("pubblico", r)
        # approvare vale per tutti: è la destinazione che si giudica (#128)
        self.assertIn("TUTTI gli agenti", r)

    def test_no_warning_means_no_empty_alert_line(self):
        r = egress.gate_reason("clodia", "gdrive.upload", "drive",
                               ["gdrive:folder/1AbC"])
        self.assertNotIn("⚠️", r)


class CanonicalUriTests(unittest.TestCase):
    """Le forme che un umano scrive naturalmente devono combaciare.

    Trovato rispondendo alla domanda «se metto la URL della cartella Drive in
    whitelist il segnale si spegne?»: NO, non si spegneva. Il punteggio interroga
    `gdrive:folder/<id>`, e ciò che si copia dal browser è
    `https://drive.google.com/drive/folders/<id>`. Una notazione che non accetta la
    forma che l'utente ha sotto le dita è un trabocchetto, non un aiuto: si
    incolla, non combacia, e nessuno capisce perché.
    """

    FOLDER = "1QBzBmKKdnOTWTPkGz9NErAb3_IuvtYkO"

    def test_a_browser_drive_url_matches_the_canonical_folder_uri(self):
        dest = f"gdrive:folder/{self.FOLDER}"
        for rule in (f"gdrive:folder/{self.FOLDER}",
                     f"https://drive.google.com/drive/folders/{self.FOLDER}",
                     f"https://drive.google.com/drive/u/0/folders/{self.FOLDER}"):
            with self.subTest(rule=rule):
                self.assertTrue(egress._matches(dest, rule))

    def test_the_authority_form_is_the_same_resource(self):
        """`gdrive://<id>` e `gdrive:folder/<id>` sono la stessa risorsa in due
        codifiche, come l'URL del browser. Accettarne una sola trasformerebbe una
        questione di stile in un errore di configurazione silenzioso."""
        dest = f"gdrive:folder/{self.FOLDER}"
        for rule in (f"gdrive://{self.FOLDER}", f"gdrive://folder/{self.FOLDER}",
                     f"gdrive://{self.FOLDER}/"):
            with self.subTest(rule=rule):
                self.assertTrue(egress._matches(dest, rule))
        self.assertTrue(egress._matches("gsheets:1tIf", "gsheets://1tIf"))

    def test_the_authority_form_without_an_id_is_still_degenerate(self):
        """Accettare la codifica non deve aprire una scorciatoia per la regola che
        apre tutto."""
        for rule in ("gdrive://", "gdrive://folder/"):
            with self.subTest(rule=rule):
                self.assertFalse(egress._matches(f"gdrive:folder/{self.FOLDER}", rule))

    def test_a_spreadsheet_url_becomes_the_gsheets_uri(self):
        self.assertEqual(
            egress.canonical("https://docs.google.com/spreadsheets/d/1tIf/edit#gid=0"),
            "gsheets:1tIf")

    def test_a_bare_id_does_not_match(self):
        """Un id nudo non dice di che cosa è l'id: potrebbe essere una cartella, un
        foglio o un documento, e indovinare aprirebbe la cosa sbagliata."""
        self.assertFalse(egress._matches(f"gdrive:folder/{self.FOLDER}", self.FOLDER))

    def test_the_host_is_lowercased_but_not_the_path(self):
        self.assertEqual(egress.canonical("HTTPS://API.Tizio.IT/Path/Case"),
                         "https://api.tizio.it/Path/Case")

    def test_canonical_is_idempotent(self):
        for u in (f"gdrive:folder/{self.FOLDER}", "mailto:a@b.it", "tg:1",
                  "https://github.com/a/b"):
            with self.subTest(u=u):
                self.assertEqual(egress.canonical(egress.canonical(u)),
                                 egress.canonical(u))


class DegenerateRuleTests(unittest.TestCase):
    """Una regola che non vincola nulla dentro il proprio schema va scartata.

    `gdrive:folder/` consentirebbe QUALUNQUE cartella. Chi vuole quello scrive
    `*`, che si vede leggendo la lista; una barra finale dimenticata no.
    """

    def test_they_are_dropped_from_the_list_loudly(self):
        cfg = _cfg("gdrive:folder/", "mailto:", "tg:", "https://", "mailto:ok@x.it")
        with _with(cfg), self.assertLogs("clodia-tools.egress", level="WARNING") as cm:
            rules = egress.allowed_uris()
        self.assertEqual(rules, ["mailto:ok@x.it"])
        self.assertIn("aprirebbe l'intero tipo", "".join(cm.output))

    def test_they_do_not_match_even_if_passed_directly(self):
        """La difesa non deve dipendere da quale porta si è usata per entrare."""
        self.assertFalse(egress._matches("gdrive:folder/1AbC", "gdrive:folder/"))
        self.assertFalse(egress._matches("mailto:a@b.it", "mailto:"))

    def test_a_host_only_http_rule_is_legitimate(self):
        """`https://host/` significa «qualunque path su quell'host», che è una
        regola sensata — su TLS il path non è comunque distinguibile."""
        self.assertTrue(egress._matches("https://api.tizio.it/", "https://api.tizio.it/"))
        with _with(_cfg("https://api.tizio.it/")):
            self.assertEqual(egress.allowed_uris(), ["https://api.tizio.it/"])


class AdminVerbTests(unittest.TestCase):
    """`egress.allow` / `ingress.allow` — i verbi che allargano le liste (#128).

    Gated di proposito: `allow` rende silenziosa una destinazione o una fonte da lì
    in avanti, quindi è più privilegiato di qualunque singola invocazione che
    consentirebbe. `revoke` e `list` no: togliere autorità e leggerla non
    richiedono un consenso, e chiederlo insegnerebbe che anche restringere è
    un'operazione da negoziare.
    """

    def setUp(self):
        from . import whitelist as wl
        self.cfg = {"agents": {}, "egress_allow": [], "source_allow": []}
        for pt in (patch.object(wl, "CONFIG", self.cfg),
                   patch.object(wl, "save_config", lambda: None)):
            pt.start()
            self.addCleanup(pt.stop)

    def test_allow_normalises_and_is_idempotent(self):
        r1 = egress.allow("egress", "https://drive.google.com/drive/folders/1AbC")
        self.assertEqual(r1["uri"], "gdrive:folder/1AbC")
        self.assertTrue(r1["added"])
        self.assertFalse(egress.allow("egress", "gdrive://1AbC")["added"])
        self.assertEqual(self.cfg["egress_allow"], ["gdrive:folder/1AbC"])

    def test_the_wrong_direction_is_refused(self):
        """Uno schema nella lista sbagliata è un errore di configurazione, e
        rifiutarlo qui lo mostra subito invece di farlo sparire in un warning."""
        with self.assertRaises(ValueError) as cm:
            egress.allow("egress", "mailfrom:x@y.it")
        self.assertIn("non ammesso", str(cm.exception))
        with self.assertRaises(ValueError):
            egress.allow("ingress", "tg:123")

    def test_a_degenerate_uri_is_refused(self):
        with self.assertRaises(ValueError):
            egress.allow("egress", "gdrive:folder/")

    def test_a_star_cannot_be_granted_by_a_verb(self):
        """Aprire tutto si scrive nella config, dove si vede rileggendola — non lo
        si ottiene approvando un popup."""
        with self.assertRaises(ValueError) as cm:
            egress.allow("egress", "*")
        self.assertIn("config del gateway", str(cm.exception))

    def test_revoke_removes_and_reports_when_absent(self):
        egress.allow("ingress", "mailfrom:a@b.it")
        self.assertTrue(egress.revoke("ingress", "mailfrom:a@b.it")["removed"])
        self.assertFalse(egress.revoke("ingress", "mailfrom:a@b.it")["removed"])

    def test_revoke_accepts_the_other_encoding_too(self):
        """Chi ha aggiunto con l'URL del browser deve poter rimuovere con l'URL."""
        egress.allow("egress", "gdrive://1AbC")
        self.assertTrue(egress.revoke(
            "egress", "https://drive.google.com/drive/folders/1AbC")["removed"])

    def test_an_unknown_direction_is_refused(self):
        with self.assertRaises(ValueError):
            egress.allow("sideways", "mailto:a@b.it")

    def test_the_ingress_note_says_what_it_costs_not_what_it_grants(self):
        """È l'unico punto del modello in cui un'injection che chiedesse «aggiungi
        questa fonte» avrebbe un guadagno durevole: il dialog non può impedirlo,
        può dirlo."""
        n = egress.admin_note("ingress", "https://blog.qualunque.it/")
        self.assertIn("NON contaminerà", n)
        self.assertIn("non lo saprai", n)

    def test_the_egress_note_describes_the_class_of_destination(self):
        self.assertIn("pubblico", egress.admin_note(
            "egress", "https://github.com/a/b"))
