"""Reachability of a vulnerable dependency from the project's own code.

Evidence is positive only. A package the code does not import can still be reached through
another library (Log4Shell hit applications that log through SLF4J and never import
log4j-core), so nothing here ever claims a dependency is unreachable. Levels, weakest first:

    installed  the resolved version is affected (the advisory match itself)
    imported   the project's code imports the package
    called     the code calls a function the advisory names (canonical call ids, `functions`)

Attacker data reaching that call is the taint engine's job (`frame scan`), not this module's.
Imports and calls come from Frame's own frontends (`Program.imports`, `Call.canonical`), for
the source files under the directory of the manifest that declared the package.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from frame.sca.model import MAVEN, NPM, NUGET, PYPI, normalize_name

# ecosystem -> the source languages whose files can use its packages
LANGUAGES = {PYPI: ("python",), NPM: ("javascript", "typescript"), MAVEN: ("java",), NUGET: ("csharp",)}

# PyPI distributions whose import name is not their (normalised) project name. A project's own
# virtualenv, when present, is read first (`top_level.txt` / `RECORD`): it is the exact answer.
PYPI_MODULES: Dict[str, Tuple[str, ...]] = {
    "pyyaml": ("yaml",), "beautifulsoup4": ("bs4",), "pillow": ("PIL",), "pyjwt": ("jwt",),
    "python-dateutil": ("dateutil",), "scikit-learn": ("sklearn",), "opencv-python": ("cv2",),
    "opencv-python-headless": ("cv2",), "protobuf": ("google.protobuf",), "pycryptodome": ("Crypto",),
    "pycryptodomex": ("Cryptodome",), "python-jose": ("jose",), "pymongo": ("pymongo", "bson", "gridfs"),
    "msgpack-python": ("msgpack",), "djangorestframework": ("rest_framework",), "pyopenssl": ("OpenSSL",),
    "attrs": ("attr", "attrs"), "python-multipart": ("multipart",), "setuptools": ("setuptools", "pkg_resources"),
    "dnspython": ("dns",), "psycopg2-binary": ("psycopg2",), "mysqlclient": ("MySQLdb",),
    "python-ldap": ("ldap", "ldapurl", "ldif"), "pysaml2": ("saml2",), "pycrypto": ("Crypto",),
    "google-cloud-storage": ("google.cloud.storage",), "python-socketio": ("socketio",),
    "python-engineio": ("engineio",), "flask-cors": ("flask_cors",), "pyasn1": ("pyasn1",),
    "ruamel-yaml": ("ruamel.yaml",), "py-yaml": ("yaml",), "gitpython": ("git",), "pygithub": ("github",),
    "python-magic": ("magic",), "pyzmq": ("zmq",), "pywin32": ("win32api", "win32con", "pywintypes"),
}


@dataclass
class FileUsage:
    rel: str
    language: str
    imports: Set[str] = field(default_factory=set)                       # canonical modules / names
    wildcards: Set[str] = field(default_factory=set)                     # `using X;`, `import x.*`
    calls: List[Tuple[Optional[str], str, int]] = field(default_factory=list)   # (canonical, text, line)


def _venv_modules(home: Path) -> Dict[str, Set[str]]:
    """Normalised distribution name -> top-level modules, from a virtualenv in `home`."""
    out: Dict[str, Set[str]] = {}
    for venv in (home / ".venv", home / "venv", home / "env"):
        for info in venv.glob("lib/python*/site-packages/*.dist-info"):
            meta = info / "METADATA"
            try:
                name = next((ln.split(":", 1)[1].strip() for ln in meta.read_text(errors="replace").splitlines()
                             if ln.startswith("Name:")), None)
            except OSError:
                continue
            if not name:
                continue
            mods: Set[str] = set()
            top = info / "top_level.txt"
            if top.is_file():
                mods = {ln.strip().replace("/", ".") for ln in top.read_text(errors="replace").splitlines() if ln.strip()}
            elif (info / "RECORD").is_file():
                for ln in (info / "RECORD").read_text(errors="replace").splitlines():
                    first = ln.split(",", 1)[0].split("/", 1)[0]
                    if first and not first.endswith((".dist-info", ".data")) and first not in ("..", "__pycache__"):
                        mods.add(first[:-3] if first.endswith(".py") else first)
            if mods:
                out.setdefault(normalize_name(PYPI, name), set()).update(mods)
    return out


def module_names(ecosystem: str, name: str, venv: Optional[Dict[str, Set[str]]] = None) -> Set[str]:
    """What the package is imported as. Empty when that cannot be known (Maven: an artifact's
    Java packages are not derivable from its coordinates)."""
    if ecosystem == PYPI:
        n = normalize_name(PYPI, name)
        if venv and n in venv:
            return set(venv[n])
        if n in PYPI_MODULES:
            return set(PYPI_MODULES[n])
        return {n.replace("-", "_")}
    if ecosystem == NPM:
        return {name}
    if ecosystem == NUGET:
        return {name}
    return set()


def _imports_module(ecosystem: str, value: str, module: str) -> bool:
    if ecosystem == PYPI:
        return value == module or value.startswith(module + ".")
    if ecosystem == NPM:
        return value == module or value.startswith((module + "/", module + "."))
    return value == module or value.startswith(module + ".")


class Usage:
    """Source usage under a root, translated once per file."""

    def __init__(self, root: Path, excluded: Iterable):
        self.root = Path(root)
        self.excluded = frozenset(excluded)
        self._files: Optional[List[FileUsage]] = None
        self._venvs: Dict[Path, Dict[str, Set[str]]] = {}

    def files(self) -> List[FileUsage]:
        if self._files is None:
            self._files = self._collect()
        return self._files

    def venv(self, home: Path) -> Dict[str, Set[str]]:
        if home not in self._venvs:
            self._venvs[home] = _venv_modules(home)
        return self._venvs[home]

    def _collect(self) -> List[FileUsage]:
        from frame.sil.instructions import Call
        from frame.sil.scanner import FrameScanner, language_for_file
        scanner = FrameScanner(verify=False)
        wanted = {lang for langs in LANGUAGES.values() for lang in langs}
        out: List[FileUsage] = []
        for path in sorted(self.root.rglob("*")):
            if not path.is_file() or not path.suffix or \
                    FrameScanner._is_excluded_dir_member(path, self.root, self.excluded):
                continue
            lang = language_for_file(path)
            if lang not in wanted:
                continue
            try:
                text = path.read_text(encoding="utf-8-sig", errors="replace")
                frontend = scanner._get_frontend(lang)
                program = frontend.translate(text, str(path)) if frontend is not None else None
            except Exception:
                continue
            if program is None:
                continue
            fu = FileUsage(path.relative_to(self.root).as_posix(), lang)
            fu.imports = {str(v) for v in (getattr(program, "imports", {}) or {}).values()}
            fu.wildcards = {str(w).rstrip(".*") for w in (getattr(program, "import_wildcards", ()) or ())}
            imports = {str(k): str(v) for k, v in (getattr(program, "imports", {}) or {}).items()}
            for proc in program.procedures.values():
                for ins in proc.get_all_instrs():
                    if isinstance(ins, Call):
                        text_name = str(getattr(ins.func, "value", ins.func)).strip('"')
                        line = ins.loc.line if ins.loc else 0
                        fu.calls.append((ins.canonical, text_name, line))
                        for arg in ins.args:                  # calls nested in arguments: `f(g(x))`
                            for name in _nested_calls(arg[0] if isinstance(arg, tuple) else arg):
                                fu.calls.append((_qualify(name, imports), name, line))
            out.append(fu)
        return out


def _nested_calls(exp, depth: int = 0) -> List[str]:
    """Textual names of the calls inside an expression (they have no Call instruction)."""
    from frame.sil.types import ExpCall
    out: List[str] = []
    if depth > 20 or exp is None:
        return out
    if isinstance(exp, ExpCall):
        out.append(str(getattr(exp.func, "value", exp.func)))
    for child in vars(exp).values() if hasattr(exp, "__dict__") else ():
        items = child if isinstance(child, (list, tuple)) else [child]
        for it in items:
            if hasattr(it, "__dict__") and type(it).__module__ == "frame.sil.types":
                out.extend(_nested_calls(it, depth + 1))
    return out


def _qualify(name: str, imports: Dict[str, str]) -> Optional[str]:
    """`_.toNumber` -> `lodash.toNumber` through the file's imports (the rule canonical ids
    follow); None when the head is not an imported name."""
    head, _, rest = name.strip('"').partition(".")
    if head not in imports:
        return None
    return f"{imports[head]}.{rest}" if rest else imports[head]


def _home_of(manifest_rel: str) -> str:
    parts = Path(manifest_rel).parent.parts
    if parts and parts[-1] == "obj":
        parts = parts[:-1]
    return "/".join(parts)


def _under(rel: str, home: str) -> bool:
    return not home or rel == home or rel.startswith(home + "/")


def _function_matches(fu: FileUsage, ids: Set[str]) -> List[Tuple[str, int, str]]:
    """(function id, line, the call as written) for each call of a listed function."""
    hits = []
    for canonical, text, line in fu.calls:
        if canonical and canonical in ids:
            hits.append((canonical, line, text))
            continue
        if fu.language in ("csharp", "java") and fu.wildcards and "." in text:
            # `using Ns;` + `Type.Method(...)`: the advisory's own id decides, nothing is guessed
            for w in fu.wildcards:
                cand = f"{w}.{text}"
                if cand in ids:
                    hits.append((cand, line, text))
                    break
    return hits


def annotate(findings: List[dict], usage: Usage, root: Path) -> None:
    """Add `reachability` to each finding (in place)."""
    for f in findings:
        eco = f["ecosystem"]
        langs = LANGUAGES.get(eco, ())
        home = _home_of(f["path"])
        files = [fu for fu in usage.files() if fu.language in langs and _under(fu.rel, home)] if langs else []
        venv = usage.venv(root / home) if eco == PYPI else None
        modules = module_names(eco, f["package"], venv)
        fn_ids = {x["id"] for x in f.get("functions", [])}
        source_of = {x["id"]: x.get("source", "") for x in f.get("functions", [])}
        if fn_ids and not modules:
            # an advisory naming functions also names their packages (Java classes, C# types)
            modules = {re.sub(r"\.[^.]+\.[^.]+$", "", i) for i in fn_ids if i.count(".") >= 2}
        imported_in = sorted({fu.rel for fu in files for m in modules
                              if any(_imports_module(eco, v, m) for v in fu.imports | fu.wildcards)})
        calls = [{"function": fid, "location": f"{fu.rel}:{line}", "source": source_of.get(fid, ""), "call": text}
                 for fu in files for fid, line, text in _function_matches(fu, fn_ids)]
        level = "called" if calls else "imported" if imported_in else "installed"
        f["reachability"] = {"level": level, "imported_in": imported_in[:20], "calls": calls[:50],
                             "analysed": bool(files)}
