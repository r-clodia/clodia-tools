"""Protocollo `remoteinclude` / `remoteignore` per il sync remoto dei topic.

Filtro esplicito, sintassi stile `.gitignore`, per non pullare/pushare file
pesanti, temporanei o sensibili (spec 18 lug 2026). Nomi dedicati (non `.git*`)
per evitare ambiguità con Git reale.

Nomi CANONICI senza punto (il topic storage rifiuta i dotfile in `files/`); i
dotfile `.remoteinclude`/`.remoteignore` restano riconosciuti come alias.

Ordine di valutazione, per ogni path relativo alla root `files/` del topic (SENZA
il prefisso `files/`):
    1. hard deny di sicurezza / control-plane  → NON bypassabile
    2. se `.remoteinclude` esiste, il path deve matchare almeno una regola include
    3. `.remoteignore` esclude
    4. altrimenti incluso

Stati ritornati da `evaluate()` (sottoinsieme del vocabolario della spec — gli
altri, `synced`/`conflict`/`error`, li assegna il pull/push):
    included · skipped_by_include · skipped_by_ignore · skipped_by_hard_deny
"""
from __future__ import annotations

import re
from pathlib import Path

# Nomi CANONICI senza punto: il topic storage rifiuta i dotfile in `files/`
# (put_file vieta i segmenti che iniziano con `.`, riservati al control-plane
# — .messages/.trash/.remote-drive.json). Senza punto i file sono anche
# visibili/editabili nella vista file della UI. I dotfile restano riconosciuti
# come ALIAS (per storage che li permettono e per la spec originale).
INCLUDE_FILE = "remoteinclude"
IGNORE_FILE = "remoteignore"
INCLUDE_ALIASES = ("remoteinclude", ".remoteinclude")
IGNORE_ALIASES = ("remoteignore", ".remoteignore")

# Stati loggabili (spec «Applicazione a pull e push»).
INCLUDED = "included"
SKIP_INCLUDE = "skipped_by_include"
SKIP_IGNORE = "skipped_by_ignore"
SKIP_HARD_DENY = "skipped_by_hard_deny"
SYNCED = "synced"
CONFLICT = "conflict"
ERROR = "error"

# Hard deny non bypassabile: segreti, chiavi, cestino + i file di config stessi
# e il control-plane del topic (la spec autorizza il runtime ad aggiungerne).
_HARD_DENY = [
    "secrets/**", "**/secrets/**",
    ".trash/**", "**/.trash/**",
    ".git/**", "**/.git/**",
    "*.key", "*.pem", "*.p12", "*.pfx",
    "*.env", ".env*",
    # i file di config del protocollo (entrambe le forme) = control-plane:
    # mai sincronizzati, in nessuna direzione.
    "remoteinclude", ".remoteinclude", "remoteignore", ".remoteignore",
    "**/remoteinclude", "**/.remoteinclude", "**/remoteignore", "**/.remoteignore",
    "**/.remote-drive.json",
]


def _compile(pattern: str) -> tuple[re.Pattern, bool]:
    """Compila un pattern gitignore-style in (regex, negato).

    Regole supportate: `#` commento, `!` negazione, `/` finale (directory),
    ancoraggio (pattern con `/` interno = relativo alla root; senza `/` = match
    sul basename in qualsiasi cartella), `**` (zero+ segmenti), `*`, `?`, `[...]`.
    Il pattern è tokenizzato sull'INTERA stringa — non splittato su `/` — così
    `**/` e `/**` producono lo slash giusto senza doppioni.
    """
    neg = False
    p = pattern
    if p.startswith("!"):
        neg = True
        p = p[1:]
    if p.startswith("/"):
        anchored = True
        p = p[1:]
    else:
        anchored = "/" in p.rstrip("/")   # `/` interno → relativo alla root
    p = p.rstrip("/")

    out: list[str] = []
    i, n = 0, len(p)
    while i < n:
        c = p[i]
        if c == "*":
            if p[i:i + 2] == "**":
                if p[i:i + 3] == "**/":
                    out.append("(?:.*/)?")   # **/  → zero o più cartelle
                    i += 3
                else:
                    out.append(".*")          # ** finale o non seguito da /
                    i += 2
            else:
                out.append("[^/]*")
                i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        elif c == "[":
            k = p.find("]", i)
            if k == -1:
                out.append(re.escape(c))
                i += 1
            else:
                out.append("[" + p[i + 1:k] + "]")
                i = k + 1
        else:
            out.append(re.escape(c))
            i += 1
    body = "".join(out)
    prefix = "^" if anchored else r"(?:^|.*/)"
    # Un pattern-file (`foo`, `*.pdf`) matcha anche tutto ciò che sta sotto una
    # cartella omonima (`(?:/.*)?`), coerente con gitignore.
    return re.compile(prefix + body + "(?:/.*)?$"), neg


def _matches(rules: list[tuple[re.Pattern, bool]], rel: str) -> bool:
    """Last-match-wins con negazione (semantica gitignore): l'ultima regola che
    matcha decide; `!` la ri-include."""
    hit = False
    for rx, neg in rules:
        if rx.match(rel):
            hit = not neg
    return hit


def _parse(text: str) -> list[tuple[re.Pattern, bool]]:
    rules = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        rules.append(_compile(line.strip()))
    return rules


class SyncFilter:
    """Filtro compilato da `.remoteinclude` / `.remoteignore`. Immutabile."""

    def __init__(self, include: list, ignore: list) -> None:
        self._hard = [_compile(p) for p in _HARD_DENY]
        self._include = include        # [] = nessun include → tutto candidabile
        self._ignore = ignore

    @staticmethod
    def _read_first(d: Path, names) -> str:
        """Testo del primo file di config esistente fra i nomi accettati
        (canonico senza punto prima, poi l'alias dotfile)."""
        for n in names:
            p = d / n
            if p.is_file():
                return p.read_text(encoding="utf-8")
        return ""

    @classmethod
    def from_files_dir(cls, files_dir) -> "SyncFilter":
        d = Path(files_dir)
        return cls(
            _parse(cls._read_first(d, INCLUDE_ALIASES)),
            _parse(cls._read_first(d, IGNORE_ALIASES)),
        )

    @property
    def has_include(self) -> bool:
        return bool(self._include)

    def evaluate(self, rel: str) -> str:
        """Stato di un path relativo alla root files/ (senza prefisso `files/`)."""
        rel = rel.lstrip("/")
        if _matches(self._hard, rel):
            return SKIP_HARD_DENY
        if self._include and not _matches(self._include, rel):
            return SKIP_INCLUDE
        if _matches(self._ignore, rel):
            return SKIP_IGNORE
        return INCLUDED

    def allows(self, rel: str) -> bool:
        return self.evaluate(rel) == INCLUDED
