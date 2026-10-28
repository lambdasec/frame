"""Release metadata from package registries: every version of a package and the dependency
ranges each version declares. Used only by `frame deps --plan --registry` (opt-in: it goes to
the network), cached under `$FRAME_KB_CACHE/../registry/<ecosystem>/` so a re-plan is offline.

Interface: `versions(name)` -> {version: {"deprecated": bool}} (None: unknown package) and
`deps(name, version)` -> {name: range} (None: not known).

npm: the abbreviated metadata document (`application/vnd.npm.install-v1+json`), which lists
every version with its `dependencies` and `optionalDependencies` (peer ranges are not
installed by the package, so they are not edges).
PyPI: the JSON API: `/pypi/<name>/json` for every release (a release whose files are all
yanked counts as deprecated), and `/pypi/<name>/<version>/json` for that version's
`requires_dist`, fetched only for the versions the planner asks about. A requirement under an
`extra == ...` marker is not installed by default and is not an edge; other markers
(`python_version`) are kept, which can only make the plan stricter. PyPI reports a version
with no dependencies and one whose metadata omits them the same way (`requires_dist: null`).
crates.io: the sparse index (`index.crates.io`), one JSON line per version with its
dependencies (`req`, `kind`; a `package` field is the real crate name of a renamed one) and
`yanked`. Dev-dependencies are not built into dependents and are not edges. Optional ones are
kept: whether a feature enables one is not known here, and assuming it is off could claim a
vulnerable crate gone while it is still built.
Deprecated and pre-release versions are kept in the data and filtered by the planner.

Tests read recorded documents from a directory (`RecordedRegistry`), the same JSON the
registry returns.
"""

from __future__ import annotations

import gzip
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Dict, Optional

from frame.sca.model import CARGO, NPM, PYPI, normalize_name

TIMEOUT = 30


class RegistryError(RuntimeError):
    pass


def cache_dir() -> Path:
    from frame.kb.store import cache_root
    return Path(os.environ.get("FRAME_REGISTRY_CACHE") or cache_root().parent / "registry")


def _cache_name(name: str) -> str:
    return urllib.parse.quote(name, safe="") + ".json.gz"


def _versions_of(doc: dict) -> Dict[str, dict]:
    """{version: {"deps": {name: range}, "deprecated": bool}} from an npm metadata document."""
    out: Dict[str, dict] = {}
    for v, meta in (doc.get("versions") or {}).items():
        if not isinstance(meta, dict):
            continue
        deps = {}
        for key in ("dependencies", "optionalDependencies"):
            d = meta.get(key)
            if isinstance(d, dict):
                deps.update({str(k): str(r) for k, r in d.items()})
        out[v] = {"deps": deps, "deprecated": bool(meta.get("deprecated"))}
    return out


class NpmRegistry:
    """Fetches (once) and caches each package's abbreviated metadata."""

    def __init__(self, base: str = "https://registry.npmjs.org", offline: bool = False):
        self.base = base.rstrip("/")
        self.offline = offline
        self.fetched = 0
        self._mem: Dict[str, Optional[Dict[str, dict]]] = {}

    def versions(self, name: str) -> Optional[Dict[str, dict]]:
        if name in self._mem:
            return self._mem[name]
        path = cache_dir() / NPM / _cache_name(name)
        doc = None
        if path.is_file():
            try:
                doc = json.loads(gzip.decompress(path.read_bytes()))
            except (OSError, ValueError):
                doc = None
        if doc is None and not self.offline:
            doc = self._fetch(name)
            if doc is not None:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(gzip.compress(json.dumps(doc).encode()))
        out = _versions_of(doc) if doc is not None else None
        self._mem[name] = out
        return out

    def deps(self, name: str, version: str) -> Optional[Dict[str, str]]:
        meta = (self.versions(name) or {}).get(version)
        return meta["deps"] if meta is not None else None

    def _fetch(self, name: str) -> Optional[dict]:
        url = f"{self.base}/{urllib.parse.quote(name, safe='@')}"
        req = urllib.request.Request(url, headers={"Accept": "application/vnd.npm.install-v1+json",
                                                   "User-Agent": "frame-sca"})
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:          # nosec: fixed registry URL
                doc = json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            raise RegistryError(f"{url}: HTTP {e.code}") from e
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise RegistryError(f"{url}: {e}") from e
        self.fetched += 1
        # keep what the planner reads: version -> dependency ranges and deprecation
        return {"name": doc.get("name", name), "versions": {
            v: {k: m[k] for k in ("dependencies", "optionalDependencies", "deprecated") if k in m}
            for v, m in (doc.get("versions") or {}).items() if isinstance(m, dict)}}


class RecordedRegistry:
    """npm metadata documents recorded on disk (`<quoted name>.json` or `.json.gz`)."""

    def __init__(self, root: Path):
        self.root = Path(root)

    def versions(self, name: str) -> Optional[Dict[str, dict]]:
        stem = urllib.parse.quote(name, safe="")
        for p in (self.root / f"{stem}.json.gz", self.root / f"{stem}.json"):
            if p.is_file():
                data = p.read_bytes()
                return _versions_of(json.loads(gzip.decompress(data) if p.suffix == ".gz" else data))
        return None

    def deps(self, name: str, version: str) -> Optional[Dict[str, str]]:
        meta = (self.versions(name) or {}).get(version)
        return meta["deps"] if meta is not None else None


_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*\(?\s*([^;()]*?)\s*\)?\s*(?:;\s*(.*))?$")


def parse_requires_dist(reqs) -> Dict[str, str]:
    """PEP 508 strings -> {normalised name: specifier}; extras-only requirements dropped."""
    out: Dict[str, str] = {}
    for r in reqs or []:
        m = _REQ.match(str(r))
        if not m:
            continue
        marker = m.group(3) or ""
        if re.search(r"\bextra\s*==", marker):
            continue
        name, spec = normalize_name(PYPI, m.group(1)), m.group(2).strip()
        out[name] = ",".join(x for x in (out.get(name, ""), spec) if x) or ">=0"
    return out


class PypiRegistry:
    """PyPI's JSON API, cached per package and per version."""

    def __init__(self, base: str = "https://pypi.org/pypi", offline: bool = False):
        self.base = base.rstrip("/")
        self.offline = offline
        self.fetched = 0
        self._mem: Dict[str, object] = {}

    def _get(self, rel: str, cache_name: str) -> Optional[dict]:
        if cache_name in self._mem:
            return self._mem[cache_name]                       # type: ignore[return-value]
        path = cache_dir() / PYPI / cache_name
        doc = None
        if path.is_file():
            try:
                doc = json.loads(gzip.decompress(path.read_bytes()))
            except (OSError, ValueError):
                doc = None
        if doc is None and not self.offline:
            url = f"{self.base}/{rel}/json"
            req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "frame-sca"})
            try:
                with urllib.request.urlopen(req, timeout=TIMEOUT) as r:      # nosec: fixed registry URL
                    raw = json.loads(r.read())
            except urllib.error.HTTPError as e:
                if e.code != 404:
                    raise RegistryError(f"{url}: HTTP {e.code}") from e
                raw = None
            except (urllib.error.URLError, OSError, ValueError) as e:
                raise RegistryError(f"{url}: {e}") from e
            if raw is not None:
                self.fetched += 1
                doc = ({"releases": {v: {"yanked": bool(fs) and all(f.get("yanked") for f in fs)}
                                     for v, fs in (raw.get("releases") or {}).items() if fs}}
                       if "/" not in rel else {"requires_dist": (raw.get("info") or {}).get("requires_dist")})
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(gzip.compress(json.dumps(doc).encode()))
        self._mem[cache_name] = doc
        return doc

    def versions(self, name: str) -> Optional[Dict[str, dict]]:
        n = normalize_name(PYPI, name)
        doc = self._get(urllib.parse.quote(n), _cache_name(n))
        if doc is None:
            return None
        return {v: {"deprecated": m["yanked"], "deps": None} for v, m in doc["releases"].items()}

    def deps(self, name: str, version: str) -> Optional[Dict[str, str]]:
        n = normalize_name(PYPI, name)
        doc = self._get(f"{urllib.parse.quote(n)}/{urllib.parse.quote(version)}",
                        _cache_name(f"{n}@{version}"))
        return parse_requires_dist(doc.get("requires_dist")) if doc is not None else None


def crates_index_path(name: str) -> str:
    n = name.lower()
    if len(n) <= 2:
        return f"{len(n)}/{n}"
    if len(n) == 3:
        return f"3/{n[0]}/{n}"
    return f"{n[:2]}/{n[2:4]}/{n}"


class CratesRegistry:
    """crates.io's sparse index, cached per crate."""

    def __init__(self, base: str = "https://index.crates.io", offline: bool = False):
        self.base = base.rstrip("/")
        self.offline = offline
        self.fetched = 0
        self._mem: Dict[str, Optional[Dict[str, dict]]] = {}

    def _load(self, name: str) -> Optional[Dict[str, dict]]:
        if name in self._mem:
            return self._mem[name]
        path = cache_dir() / CARGO / _cache_name(name.lower())
        lines = None
        if path.is_file():
            try:
                lines = gzip.decompress(path.read_bytes()).decode()
            except OSError:
                lines = None
        if lines is None and not self.offline:
            url = f"{self.base}/{crates_index_path(name)}"
            req = urllib.request.Request(url, headers={"User-Agent": "frame-sca"})
            try:
                with urllib.request.urlopen(req, timeout=TIMEOUT) as r:          # nosec: fixed index URL
                    lines = r.read().decode()
            except urllib.error.HTTPError as e:
                if e.code not in (404, 410):
                    raise RegistryError(f"{url}: HTTP {e.code}") from e
            except (urllib.error.URLError, OSError) as e:
                raise RegistryError(f"{url}: {e}") from e
            if lines is not None:
                self.fetched += 1
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(gzip.compress(lines.encode()))
        out = None
        if lines is not None:
            out = {}
            for line in lines.splitlines():
                try:
                    v = json.loads(line)
                except ValueError:
                    continue
                deps = {}
                for d in v.get("deps") or []:
                    if d.get("kind") == "dev":
                        continue
                    crate = d.get("package") or d.get("name")
                    if crate:
                        deps[crate] = str(d.get("req") or "*")
                out[str(v.get("vers"))] = {"deprecated": bool(v.get("yanked")), "deps": deps}
        self._mem[name] = out
        return out

    def versions(self, name: str) -> Optional[Dict[str, dict]]:
        return self._load(name)

    def deps(self, name: str, version: str) -> Optional[Dict[str, str]]:
        meta = (self._load(name) or {}).get(version)
        return meta["deps"] if meta is not None else None


class Registries:
    """The registry for each ecosystem the planner supports."""

    def __init__(self, offline: bool = False):
        self._by = {NPM: NpmRegistry(offline=offline), PYPI: PypiRegistry(offline=offline),
                    CARGO: CratesRegistry(offline=offline)}

    def for_ecosystem(self, ecosystem: str):
        return self._by.get(ecosystem)

    @property
    def fetched(self) -> int:
        return sum(r.fetched for r in self._by.values())


def is_prerelease(version: str, ecosystem: str = NPM) -> bool:
    if ecosystem == PYPI:                                   # PEP 440, as the range code reads it
        from frame.sca.ranges import _is_prerelease_pep440
        return _is_prerelease_pep440(version)
    return bool(re.search(r"\d-[0-9A-Za-z]", version))
