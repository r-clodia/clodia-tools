"""Filesystem tools exposed via MCP."""
from ..whitelist import resolve_safe_path, tool_allowed


def list_dir(path: str) -> dict:
    """List the entries of a directory.

    Args:
        path: Path relative to workspace root, or absolute. Must be inside the
              calling agent's allowed_paths.

    Returns:
        Dict with `path`, `entries` (list of dicts with name/kind/size).
    """
    tool_allowed("fs.list_dir")
    p = resolve_safe_path(path)
    if not p.exists():
        raise FileNotFoundError(f"path does not exist: {path}")
    if not p.is_dir():
        raise NotADirectoryError(f"path is not a directory: {path}")
    entries = []
    for child in sorted(p.iterdir()):
        try:
            stat = child.stat()
            entries.append({
                "name": child.name,
                "kind": "dir" if child.is_dir() else "file",
                "size": stat.st_size if child.is_file() else None,
            })
        except OSError:
            continue
    return {"path": str(p), "entries": entries}
