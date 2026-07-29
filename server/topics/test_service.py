"""Self-test TopicService sopra local-fs (Topic System v2, modello tier).

    python3 -m server.topics.test_service
"""
from __future__ import annotations

import tempfile
import warnings


def main() -> int:
    warnings.filterwarnings("ignore")
    from .local_fs import LocalFsStorage
    from .service import TopicService, TopicError
    from .storage import VersionConflict

    svc = TopicService(LocalFsStorage(tempfile.mkdtemp(prefix="clodia-topics-svc-")))
    ok = 0
    fail = 0

    def check(name, cond):
        nonlocal ok, fail
        print(f"  {'✓' if cond else '✗'} {name}")
        ok += cond
        fail += (not cond)

    # new su tier esplicito + storage nel meta
    m = svc.new("P2", "cliente-x", {"title": "Cliente X", "type": "contratto"})
    check("new: tier legacy P2 → SEAL-2", m["tier"] == "SEAL-2")
    check("new: storage backend nel meta", m.get("storage") == "local-fs")
    check("new: niente più classification", "classification" not in m)
    check("new: schema v2", m["schema_version"] == 2 and m["deadline"] is None and m["status"] == "active")

    # default tier SEAL-0 quando non specificato
    m0 = svc.new(None, "idea-libera")
    check("new: default tier SEAL-0", m0["tier"] == "SEAL-0")
    check("new: hook automatico", m0["hook_enabled"] is True)

    # new idempotente
    again = svc.new("P2", "cliente-x")
    check("new idempotente", again["created_at"] == m["created_at"])

    # Lo slug è globale perché coincide con l'id dell'hook.
    try:
        svc.new("P1", "cliente-x")
        check("slug globale tra tier", False)
    except TopicError:
        check("slug globale tra tier", True)

    # open: tldr = title + tier_name
    o = svc.open("P2", "cliente-x")
    check("open: tldr = title", o["tldr"] == "Cliente X")
    check("open: tier_name", o["tier_name"] == "Confidential")
    check("open: summary_version presente", bool(o["summary_version"]))

    # save_summary optimistic
    r = svc.save_summary("P2", "cliente-x", "Stato aggiornato.\n\n## Prossimi passi\n- firma\n",
                         base_version=o["summary_version"])
    check("save_summary: nuovo tldr", r["tldr"] == "Stato aggiornato.")

    # conflitto su versione stale
    try:
        svc.save_summary("P2", "cliente-x", "CLOBBER\n", base_version=o["summary_version"])
        check("conflitto su summary stale", False)
    except VersionConflict:
        check("conflitto su summary stale", True)

    # minutes rimosso in schema v2
    try:
        svc.add_minute("P2", "cliente-x", "deciso storage astratto")
        check("minutes rimosso", False)
    except TopicError:
        check("minutes rimosso", True)

    # AGENTS.md opzionale leggibile/searchable
    svc.put_file("P2", "cliente-x", "AGENTS.md", b"Regole della casa: priorita contratti.\n")
    check("AGENTS.md letto da open", "priorita contratti" in (svc.open("P2", "cliente-x")["agents_md"] or ""))

    # recap history: ogni CAMBIO di TLDR appende un'entry (newest-first), no duplicati
    svc.new("P2", "recap-x", {"title": "Recap X"})
    rv = svc.open("P2", "recap-x")["summary_version"]
    rv = svc.save_summary("P2", "recap-x", "Primo recap.\n", base_version=rv)["summary_version"]
    # stesso TLDR (cambia solo il corpo) → NON deve duplicare
    rv = svc.save_summary("P2", "recap-x", "Primo recap.\n\n## note\n- x", base_version=rv)["summary_version"]
    rv = svc.save_summary("P2", "recap-x", "Secondo recap.\n", base_version=rv)["summary_version"]
    rh = svc.open("P2", "recap-x")["recap_history"]
    tldrs = [e["tldr"] for e in rh]
    check("recap_history newest-first", bool(tldrs) and tldrs[0] == "Secondo recap.")
    check("recap_history contiene il primo recap", "Primo recap." in tldrs)
    check("recap_history no duplicati TLDR", tldrs.count("Primo recap.") == 1)
    check("recap_history ogni entry ha ts", all(e.get("ts") for e in rh))

    # list (tutti i tier) + action_points + tier
    lst = svc.list()
    names = {x["name"] for x in lst}
    check("list contiene i topic dei vari tier", {"cliente-x", "idea-libera"} <= names)
    cx = next(x for x in lst if x["name"] == "cliente-x")
    check("list: tier + action_points", cx["tier"] == "SEAL-2" and cx["action_points"] == ["firma"])

    # filtro per tier
    check("list per tier", {x["name"] for x in svc.list("P0")} == {"idea-libera"})

    # status chiuso
    check("set_status on-hold", svc.set_status("P2", "cliente-x", "on-hold")["status"] == "on-hold")
    try:
        svc.set_status("P2", "cliente-x", "urgentissimo")
        check("status invalido rifiutato", False)
    except TopicError:
        check("status invalido rifiutato", True)
    check("set_deadline ISO", svc.set_deadline("P2", "cliente-x", "2026-08-15")["deadline"] == "2026-08-15")
    check("set_deadline null", svc.set_deadline("P2", "cliente-x", None)["deadline"] is None)
    try:
        svc.set_deadline("P2", "cliente-x", "15/08/2026")
        check("deadline invalida rifiutata", False)
    except TopicError:
        check("deadline invalida rifiutata", True)

    # archive
    svc.archive("P2", "cliente-x")
    check("archived nascosto", "cliente-x" not in {x["name"] for x in svc.list()})
    check("archived con flag", "cliente-x" in {x["name"] for x in svc.list(include_archived=True)})

    # search lessicale (AGENTS.md)
    check("search trova in AGENTS.md", "cliente-x" in {h["name"] for h in svc.search("priorita contratti")})

    # tier non valido
    try:
        svc.new("personal", "x")
        check("tier 'personal' rifiutato", False)
    except TopicError:
        check("tier 'personal' rifiutato", True)

    print(f"\n{ok} ok, {fail} fail")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
