"""Pack runtime provisioning tools.

Small, typed operations for pack setup. These deliberately avoid exposing a
general shell: Sysadmin can install declared pip/npm packages into persistent
runtime paths and verify binaries, but cannot run arbitrary commands.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

_DATA = Path(os.environ.get("CLODIA_DATA", "/datadir"))
_RUNTIME = _DATA / "runtime"
_VENV = Path(os.environ.get("CLODIA_RUNTIME_VENV", str(_RUNTIME / "venv")))
_NPM_PREFIX = Path(os.environ.get("CLODIA_RUNTIME_NPM_PREFIX", str(_RUNTIME / "npm")))
_NPM_CACHE = Path(os.environ.get("CLODIA_RUNTIME_NPM_CACHE", str(_RUNTIME / "cache" / "npm")))
_CMD_TIMEOUT = int(os.environ.get("CLODIA_PACK_INSTALL_TIMEOUT", "600"))

_PIP_SPEC = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*(\[[A-Za-z0-9_,.-]+\])?([<>=!~]=?[A-Za-z0-9.*+!_,:<>=~.-]+)?$"
)
_NPM_SPEC = re.compile(
    r"^(@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+(@[A-Za-z0-9._~^<>=*-]+)?$"
)
_COMMAND = re.compile(r"^[A-Za-z0-9._+-]+$")


def _tail(text: str, limit: int = 4000) -> str:
    return (text or "")[-limit:]


def _run(argv: list[str], *, env: dict[str, str] | None = None) -> dict:
    proc = subprocess.run(
        argv,
        text=True,
        capture_output=True,
        timeout=_CMD_TIMEOUT,
        check=False,
        env=env,
    )
    return {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "stdout_tail": _tail(proc.stdout),
        "stderr_tail": _tail(proc.stderr),
    }


def _ensure_venv() -> Path:
    pip = _VENV / "bin" / "pip"
    if not pip.exists():
        _VENV.parent.mkdir(parents=True, exist_ok=True)
        res = _run([os.environ.get("CLODIA_RUNTIME_PYTHON", sys.executable), "-m", "venv", str(_VENV)])
        if not res["ok"]:
            raise RuntimeError(f"creazione venv fallita: {res['stderr_tail'] or res['stdout_tail']}")
    return pip


def _validate_specs(specs: list[str], pattern: re.Pattern[str], kind: str) -> list[str]:
    clean = []
    for raw in specs:
        spec = str(raw or "").strip()
        if not spec or not pattern.match(spec):
            raise ValueError(f"{kind}: package spec non ammessa: {raw!r}")
        clean.append(spec)
    if not clean:
        raise ValueError(f"{kind}: nessun package indicato")
    return clean


def install_pip(packages: list[str]) -> dict:
    specs = _validate_specs(packages, _PIP_SPEC, "pip")
    pip = _ensure_venv()
    res = _run([str(pip), "install", *specs])
    return {
        **res,
        "packages": specs,
        "venv": str(_VENV),
        "bin_dir": str(_VENV / "bin"),
    }


def install_npm(packages: list[str]) -> dict:
    specs = _validate_specs(packages, _NPM_SPEC, "npm")
    npm = shutil.which("npm")
    if not npm:
        raise RuntimeError("npm non disponibile nel container gateway")
    _NPM_PREFIX.mkdir(parents=True, exist_ok=True)
    _NPM_CACHE.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["npm_config_cache"] = str(_NPM_CACHE)
    res = _run([npm, "install", "-g", "--prefix", str(_NPM_PREFIX), *specs], env=env)
    return {
        **res,
        "packages": specs,
        "prefix": str(_NPM_PREFIX),
        "bin_dir": str(_NPM_PREFIX / "bin"),
    }


def runtime_path() -> str:
    parts = [str(_VENV / "bin"), str(_NPM_PREFIX / "bin")]
    return os.pathsep.join(parts + [os.environ.get("PATH", "")])


def check_command(command: str) -> dict:
    cmd = str(command or "").strip()
    if not _COMMAND.match(cmd):
        raise ValueError(f"comando non ammesso: {command!r}")
    found = shutil.which(cmd, path=runtime_path())
    return {
        "command": cmd,
        "found": bool(found),
        "path": found or "",
        "runtime_path": runtime_path(),
    }
