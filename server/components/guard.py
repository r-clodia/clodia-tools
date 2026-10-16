"""Static import guard for gateway components (clodia-platform#558).

A component gets the gateway through `host` and nothing else. Before its entry
module is imported, every `.py` file of the pinned tree is parsed and the load
is refused when one of them reaches for the reference monitor's own state:

    server            (bare: it would give attribute access to the rest)
    server.vault      credentials — use host.credentials(prefix)
    server.state_paths, server.whitelist, server.gate, server.egress
                      decisional state: allow-lists, consents, the PDP
    server.main       the dispatcher itself

whether as `import x`, `from x import y`, `from server import vault`, or a
dynamic `importlib.import_module(...)` / `__import__(...)` (a dynamic import
whose target is not a string literal is refused too: the guard cannot read it).

This is a guard against mistakes and an aid to review, not a sandbox: a
component runs in-process with the gateway's privileges, and what makes that
acceptable is that it is first-party, merged upstream and pinned (`trust.py`,
`store.py`). Relative imports (`from . import x`) are the way a component
imports its own modules: its directory is not on `sys.path`.
"""
from __future__ import annotations

import ast
from pathlib import Path

FORBIDDEN_MODULES = (
    "server.vault",
    "server.state_paths",
    "server.whitelist",
    "server.gate",
    "server.egress",
    "server.main",
)

_DYNAMIC = {"import_module", "__import__"}


def _forbidden(module: str) -> bool:
    if module == "server":
        return True
    return any(module == f or module.startswith(f + ".") for f in FORBIDDEN_MODULES)


def scan_source(source: str, filename: str = "<component>") -> list[str]:
    """The violations in one source file (empty list = clean)."""
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as e:
        return [f"{filename}: does not parse ({e.msg}, line {e.lineno})"]
    out: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _forbidden(alias.name):
                    out.append(f"{filename}:{node.lineno}: imports '{alias.name}'")
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                continue          # relative: inside the component's own package
            mod = node.module or ""
            if _forbidden(mod) and mod != "server":
                out.append(f"{filename}:{node.lineno}: imports from '{mod}'")
            elif mod == "server":
                names = [a.name for a in node.names]
                bad = [n for n in names if n == "*" or _forbidden(f"server.{n}")]
                if bad:
                    out.append(f"{filename}:{node.lineno}: imports {bad} from 'server'")
        elif isinstance(node, ast.Call):
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else (
                fn.id if isinstance(fn, ast.Name) else "")
            if name in _DYNAMIC and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if _forbidden(arg.value):
                        out.append(f"{filename}:{node.lineno}: dynamically imports "
                                   f"'{arg.value}'")
                else:
                    out.append(f"{filename}:{node.lineno}: dynamic import with a "
                               "non-literal target")
    return out


def scan_tree(directory: Path) -> list[str]:
    """The violations in every `.py` file under `directory`."""
    out: list[str] = []
    for path in sorted(Path(directory).rglob("*")):
        rel = path.relative_to(directory).as_posix()
        if path.name == "__pycache__" or path.suffix.lower() in (
                ".pyc", ".pyo", ".so", ".pyd", ".dylib", ".dll"):
            out.append(f"{rel}: compiled code is not allowed in a component")
    for path in sorted(Path(directory).rglob("*.py")):
        rel = path.relative_to(directory).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            out.append(f"{rel}: unreadable ({type(e).__name__})")
            continue
        out += scan_source(text, rel)
    return out
