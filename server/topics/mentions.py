"""Parser delle mention nei messaggi di canale (issue clodia-platform#83, D1).

Le mention (`@nome` / `$nome`) diventano un campo STRUTTURATO del messaggio
al momento della scrittura (`post_message`), così chi calcola i badge
azionabili interroga una lista di destinatari e non fa regex sul testo raw.

Regole (falsi positivi esclusi per costruzione):
- il testo dentro i fenced code block (```...```) e l'inline code (`...`)
  non produce mention;
- le righe citate (prefisso `>`) non producono mention;
- `$$nome` è l'escape letterale dell'expander macro: NON è una mention;
- il sigillo deve trovarsi a un confine di parola "vero": inizio riga,
  whitespace o punteggiatura di apertura — `/log/@nome`, `a@b.it` e simili
  (path, email, log incollati) non contano.
"""
from __future__ import annotations

import re

# Stessa forma dei principal/agent name della piattaforma. L'ordinale
# opzionale `#N` indirizza una ISTANZA di un seed multi-spawn (issue#94):
# `@fullstack-dev#2` → mention strutturata "fullstack-dev#2".
_NAME = r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}"
_ORDINAL = r"(?:#[1-9][0-9]{0,2})?"

# Sigillo valido solo dopo inizio stringa, whitespace o punteggiatura di
# apertura (non dopo lettere, cifre, `/`, `.`, `$` ecc.).
_MENTION_RE = re.compile(rf"(?:(?<=^)|(?<=[\s\(\[\{{<,;:'\"]))[@$]({_NAME}{_ORDINAL})")

_FENCE_RE = re.compile(r"```.*?```", re.DOTALL)
_INLINE_CODE_RE = re.compile(r"`[^`\n]*`")
_QUOTED_LINE_RE = re.compile(r"^[ \t]{0,3}>.*$", re.MULTILINE)
# `$$nome` (escape letterale) va consumato PRIMA del match delle mention.
_ESCAPED_RE = re.compile(rf"\$\${_NAME}{_ORDINAL}")


def extract_mentions(text: str) -> list[str]:
    """Destinatari menzionati nel testo, deduplicati, in minuscolo,
    nell'ordine di prima apparizione. Lista vuota se nessuna mention."""
    if not text:
        return []
    clean = _FENCE_RE.sub(" ", text)
    clean = _INLINE_CODE_RE.sub(" ", clean)
    clean = _QUOTED_LINE_RE.sub(" ", clean)
    clean = _ESCAPED_RE.sub(" ", clean)
    out: list[str] = []
    for m in _MENTION_RE.finditer(clean):
        name = m.group(1).lower()
        if name not in out:
            out.append(name)
    return out
