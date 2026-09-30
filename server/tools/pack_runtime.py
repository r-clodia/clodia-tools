"""Pack runtime provisioning tools.

Small, typed operations for pack setup. These deliberately avoid exposing a
general shell: Sysadmin can install declared pip/npm packages into persistent
runtime paths and verify binaries, but cannot run arbitrary commands.
"""
from __future__ import annotations

import importlib.metadata as _md
import logging
import os
import re
import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path

LOG = logging.getLogger("clodia-tools.pack_runtime")

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
    """Il venv persistente su `$CLODIA_DATA/runtime`, creato se manca.

    Deliberatamente SENZA `--system-site-packages`: con quel flag pip vedrebbe
    i pacchetti dell'immagine del gateway come già soddisfatti e salterebbe
    l'installazione ("Requirement already satisfied"), quindi la dipendenza del
    pack non finirebbe mai sul volume — e al rebuild successivo sparirebbe di
    nuovo insieme all'immagine. È esattamente clodia-platform#451. Il venv resta
    isolato in INSTALLAZIONE; l'accesso ai moduli dell'immagine in ESECUZIONE lo
    dà `runtime_env()` via PYTHONPATH, che pip non usa (vedi `_install_env`).
    """
    pip = _VENV / "bin" / "pip"
    if not pip.exists():
        _VENV.parent.mkdir(parents=True, exist_ok=True)
        res = _run([os.environ.get("CLODIA_RUNTIME_PYTHON", sys.executable), "-m", "venv", str(_VENV)])
        if not res["ok"]:
            raise RuntimeError(f"creazione venv fallita: {res['stderr_tail'] or res['stdout_tail']}")
    return pip


def _install_env() -> dict[str, str]:
    """Ambiente per `pip install`: quello del gateway MENO `PYTHONPATH`.

    Se il PYTHONPATH di runtime (site-packages del venv + dell'immagine)
    arrivasse a pip, pip considererebbe soddisfatto ciò che sta nell'immagine e
    non lo installerebbe nel venv: stessa perdita al rebuild del flag
    `--system-site-packages`, per un'altra strada.
    """
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    return env


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
    res = _run([str(pip), "install", *specs], env=_install_env())
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


def runtime_path(base: str | None = None) -> str:
    parts = [str(_VENV / "bin"), str(_NPM_PREFIX / "bin")]
    if base is None:
        base = os.environ.get("PATH", "")
    return os.pathsep.join(parts + [base])


def site_packages() -> list[str]:
    """Le `site-packages` del venv persistente (lista vuota se il venv non c'è)."""
    return [str(p) for p in sorted(_VENV.glob("lib/python*/site-packages")) if p.is_dir()]


def runtime_env(base: dict[str, str] | None = None) -> dict[str, str]:
    """Ambiente con cui si avvia un processo che usa le dipendenze dei pack.

    Lo usa `proxy._session` per i backend MCP stdio: i server MCP dei pack sono
    l'unico consumatore di `requires.pip`/`requires.npm`, e finora venivano
    avviati con `os.environ` puro — cioè senza alcun riferimento al venv e al
    prefix npm in cui `packs.install_pip`/`install_npm` depositano le
    dipendenze. Installate sul volume ma invisibili a chi doveva usarle: il
    pack funzionava solo finché quelle stesse librerie erano anche
    nell'immagine (clodia-platform#451).

    - `PATH`: venv/bin + npm/bin davanti, per `requires.bin` e per i server
      dichiarati come console script.
    - `PYTHONPATH`: site-packages dell'immagine **poi** del venv (#458). Le prime
      servono perché con venv/bin in testa un `command: python3` (la forma che
      usano tutti i pack first-party) finisce sull'interprete del venv, che
      senza `--system-site-packages` non vedrebbe nemmeno `mcp` — il server non
      partirebbe affatto. Così i due interpreti sono equivalenti in esecuzione,
      senza rendere il venv permeabile in installazione (vedi `_ensure_venv`).
    """
    env = dict(os.environ if base is None else base)
    env["PATH"] = runtime_path(env.get("PATH", ""))
    image_site = [p for p in {sysconfig.get_path("purelib"), sysconfig.get_path("platlib")}
                  if p and Path(p).is_dir()]
    previous = [p for p in (env.get("PYTHONPATH", "") or "").split(os.pathsep) if p]
    parts: list[str] = []
    # The image's site-packages come FIRST (clodia-platform#458). The venv only
    # adds what the image lacks (e.g. PIL for image-captions); it must not be
    # able to replace what the gateway itself ships. Every pack declares
    # `mcp>=1.2` with no upper bound, so pip resolved mcp 2.x into the venv, and
    # with the venv first it shadowed the image's mcp 1.x under every pack's
    # server: all five stdio backends died on `mcp.server.fastmcp`. One pack's
    # install must not be able to break every other pack's server.
    for part in sorted(image_site) + site_packages() + previous:
        if part not in parts:
            parts.append(part)
    if parts:
        env["PYTHONPATH"] = os.pathsep.join(parts)
    return env


def _canonical(name: str) -> str:
    """Nome di distribuzione normalizzato (PEP 503): `Pillow` e `pillow` sono
    lo stesso pacchetto, e `requires.pip` è scritto a mano nei manifest."""
    return re.sub(r"[-_.]+", "-", name).strip().lower()


def _requirements_txt(path: Path) -> list[str]:
    """Le righe utili di un `requirements.txt` di pack (niente commenti, niente
    opzioni `-r`/`--index-url`)."""
    try:
        raw = path.read_text(encoding="utf-8")
    except Exception:  # noqa: BLE001
        return []
    out = []
    for line in raw.splitlines():
        spec = line.split("#", 1)[0].strip()
        if spec and not spec.startswith("-"):
            out.append(spec)
    return out


def _declared_pip() -> dict[str, dict]:
    """`{pack: {"pip": [spec...], "mcp_servers": [nome...]}}` dai pack installati
    in `$CLODIA_DATA/plugins/`.

    Due sorgenti, unite: `requires.pip` del manifest **e**
    `<pack>/mcp/requirements.txt`. Servono entrambe, non è ridondanza:
    `studio-legale` e `studio-commercialista` hanno il file e NON hanno
    `requires` nel manifest, mentre `business-pack` ha tutte e due. Guardare
    solo il manifest lascerebbe fuori proprio due dei pack citati in
    clodia-platform#451.
    """
    import yaml

    found: dict[str, dict] = {}
    for pack_dir in sorted(Path(_DATA).glob("plugins/*")):
        if not pack_dir.is_dir():
            continue
        meta: dict = {}
        manifest = pack_dir / "plugin.yaml"
        if manifest.is_file():
            try:
                loaded = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
                meta = loaded if isinstance(loaded, dict) else {}
            except Exception:  # noqa: BLE001 — un manifest illeggibile non è un blocco
                meta = {}
        requires = meta.get("requires")
        declared = (requires or {}).get("pip") or [] if isinstance(requires, dict) else []
        pip: list[str] = []
        for spec in list(declared) + _requirements_txt(pack_dir / "mcp" / "requirements.txt"):
            spec = str(spec or "").strip()
            if spec and spec not in pip:
                pip.append(spec)
        if not pip:
            continue
        servers = meta.get("mcp_servers") or {}
        found[pack_dir.name] = {
            "pip": pip,
            "mcp_servers": sorted(servers) if isinstance(servers, dict) else [],
        }
    return found


def _installed_distributions() -> set[str]:
    """Nomi canonici delle distribuzioni visibili con `runtime_env()`: quelle
    del venv persistente più quelle dell'immagine."""
    search = site_packages() + list(sys.path)
    names: set[str] = set()
    for dist in _md.distributions(path=search):
        name = (dist.metadata["Name"] if dist.metadata else None) or ""
        if name:
            names.add(_canonical(name))
    return names


def missing_requirements() -> list[dict]:
    """I `requires.pip` dichiarati dai pack installati che NESSUNO soddisfa.

    `[{pack, missing: [spec...], mcp_servers: [...]}]`, vuoto quando è tutto a
    posto. È il controllo che mancava in clodia-platform#451: le dipendenze pip
    finivano nelle site-packages del CONTAINER, e ogni rebuild del gateway le
    buttava via lasciando i server MCP dei pack rotti *in silenzio* — l'unico
    segno era un `ModuleNotFoundError` nel log alla prima chiamata dell'agente.

    SHORTCUT: confronta i NOMI, non i vincoli di versione. Regge per il caso
              che si vuole cogliere (il pacchetto non c'è affatto). Per un
              `Pillow>=10` soddisfatto da una 9 servirebbe `packaging`, che
              non è fra i requirements del gateway.
    """
    declared = _declared_pip()
    if not declared:
        return []
    try:
        installed = _installed_distributions()
    except Exception as e:  # noqa: BLE001 — diagnostica, mai un blocco
        LOG.warning("requisiti dei pack non verificabili: %s", e)
        return []
    out: list[dict] = []
    for pack in sorted(declared):
        info = declared[pack]
        missing = [spec for spec in info["pip"]
                   if _canonical(re.split(r"[<>=!~\[;]", spec, 1)[0]) not in installed]
        if missing:
            out.append({"pack": pack, "missing": missing,
                        "mcp_servers": info["mcp_servers"]})
    return out


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
