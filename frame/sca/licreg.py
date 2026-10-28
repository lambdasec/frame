"""Licences from package registries, for the packages a lockfile and the installed metadata say
nothing about (`frame deps --licenses --registry`, `--sbom --registry`; opt-in: it goes to the
network, cached beside the planner's metadata).

Only a version's own declared licence counts, never a package-level or latest-version value:

    npm        the version document's `license` (or the deprecated `licenses` list: a choice)
    PyPI       the version's `license_expression`, else its `license` when that is itself a
               valid SPDX expression (free text and trove classifiers stay unknown)
    RubyGems   the version's `licenses` (several: a choice)
    crates.io  the version's `license` (an SPDX expression)
    NuGet      the version's catalog entry `licenseExpression` (a `licenseUrl` stays unknown)

    Maven      the version's POM `<licenses>` on Maven Central, else its parent POM's (as
               Maven inherits them); several are a choice. POMs name licences in free text, so
               each must map to exactly one SPDX id through SPDX's own licence list (fetched with
               the metadata, not shipped): its URL is one of that licence's `seeAlso` URLs, or its
               name is the licence's SPDX name or id. One that does not map leaves it unknown.

Not available per version, so not read: Hex (the package's latest metadata only), pub.dev
(pubspecs carry no licence), Go (no registry metadata).
"""

from __future__ import annotations

import gzip
import json
import urllib.error
import urllib.parse
import urllib.request
import re
from typing import Callable, Dict, List, Optional, Set, Tuple

from frame.sca.licenses import _npm_license, composer_license, is_spdx
from frame.sca.model import CARGO, MAVEN, NPM, NUGET, PYPI, RUBYGEMS, DependencyFile, normalize_name
from frame.sca.registry import TIMEOUT, RegistryError, cache_dir

SUPPORTED = (NPM, PYPI, RUBYGEMS, CARGO, NUGET, MAVEN)
SPDX_LIST = "https://raw.githubusercontent.com/spdx/license-list-data/main/json/licenses.json"


def _get_json(url: str) -> Optional[dict]:
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "frame-sca"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:                 # nosec: fixed registry URLs
            data = r.read()
            if r.headers.get("Content-Encoding") == "gzip":
                data = gzip.decompress(data)
            return json.loads(data)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise RegistryError(f"{url}: HTTP {e.code}") from e
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise RegistryError(f"{url}: {e}") from e


def _q(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def _npm(name: str, version: str) -> str:
    doc = _get_json(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}/{_q(version)}")
    return _npm_license(doc) if isinstance(doc, dict) else ""


def _pypi(name: str, version: str) -> str:
    doc = _get_json(f"https://pypi.org/pypi/{_q(normalize_name(PYPI, name))}/{_q(version)}/json")
    info = (doc or {}).get("info") or {}
    expr = (info.get("license_expression") or "").strip()
    if expr:
        return expr
    raw = (info.get("license") or "").strip()
    return raw if raw and "\n" not in raw and is_spdx(raw) else ""


def _rubygems(name: str, version: str) -> str:
    doc = _get_json(f"https://rubygems.org/api/v2/rubygems/{_q(name)}/versions/{_q(version)}.json")
    return composer_license((doc or {}).get("licenses") or [])


def _crates(name: str, version: str) -> str:
    doc = _get_json(f"https://crates.io/api/v1/crates/{_q(name)}/{_q(version)}")
    return str(((doc or {}).get("version") or {}).get("license") or "")


def _nuget(name: str, version: str) -> str:
    leaf = _get_json(f"https://api.nuget.org/v3/registration5-gz-semver2/{_q(name.lower())}/{_q(version.lower())}.json")
    entry = (leaf or {}).get("catalogEntry")
    if isinstance(entry, str):
        entry = _get_json(entry)
    return str((entry or {}).get("licenseExpression") or "") if isinstance(entry, dict) else ""


def _get_text(url: str) -> Optional[str]:
    req = urllib.request.Request(url, headers={"User-Agent": "frame-sca"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:                 # nosec: fixed registry URLs
            return r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise RegistryError(f"{url}: HTTP {e.code}") from e
    except (urllib.error.URLError, OSError) as e:
        raise RegistryError(f"{url}: {e}") from e


def _norm_url(u: str) -> str:
    u = u.strip().lower()
    u = re.sub(r"^https?://", "", u)
    u = re.sub(r"^www\.", "", u)
    u = re.sub(r"[#?].*$", "", u)
    u = re.sub(r"\.(txt|html?|php|md)$", "", u)
    return u.rstrip("/")


def _norm_name(n: str) -> str:
    return re.sub(r"\s+", " ", n.strip().lower())


_spdx_maps: Optional[Tuple[Dict[str, str], Dict[str, str]]] = None


def spdx_maps(doc: Optional[dict] = None) -> Tuple[Dict[str, str], Dict[str, str]]:
    """(normalised URL -> id, normalised name or id -> id) from SPDX's licence list; a URL or a
    name that two licences share is left out (it does not decide)."""
    global _spdx_maps
    if doc is None and _spdx_maps is not None:
        return _spdx_maps
    if doc is None:
        path = cache_dir() / "spdx-licenses.json"
        if path.is_file():
            doc = json.loads(path.read_text())
        else:
            doc = _get_json(SPDX_LIST) or {}
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"licenses": [{k: x.get(k) for k in ("licenseId", "name", "seeAlso")}
                                                     for x in doc.get("licenses", [])]}))
    urls: Dict[str, Set[str]] = {}
    names: Dict[str, Set[str]] = {}
    for x in doc.get("licenses", []):
        lid = x.get("licenseId")
        if not lid:
            continue
        for u in x.get("seeAlso") or []:
            urls.setdefault(_norm_url(u), set()).add(lid)
        for n in (x.get("name"), lid):
            if n:
                names.setdefault(_norm_name(n), set()).add(lid)
    maps = ({u: next(iter(ids)) for u, ids in urls.items() if len(ids) == 1},
            {n: next(iter(ids)) for n, ids in names.items() if len(ids) == 1})
    _spdx_maps = maps
    return maps


def pom_licences(text: str) -> Tuple[List[Tuple[str, str]], Optional[Tuple[str, str, str]]]:
    """([(name, url)] declared in this POM, its parent (group, artifact, version) or None)."""
    from frame.sca.lockfiles import LockfileError, _xml
    try:
        root = _xml("pom.xml", text)
    except LockfileError:
        return [], None
    lics = [((lic.findtext("name") or "").strip(), (lic.findtext("url") or "").strip())
            for lic in root.findall("licenses/license")]
    parent = root.find("parent")
    ref = None
    if parent is not None:
        g, a, v = (parent.findtext(k) for k in ("groupId", "artifactId", "version"))
        if g and a and v:
            ref = (g.strip(), a.strip(), v.strip())
    return [x for x in lics if x[0] or x[1]], ref


def to_spdx(declared: List[Tuple[str, str]], maps: Tuple[Dict[str, str], Dict[str, str]]) -> str:
    """Several licences are a choice; every one must map, or the result is unknown ("")."""
    by_url, by_name = maps
    ids = []
    for name, url in declared:
        lid = by_url.get(_norm_url(url)) if url else None
        lid = lid or (by_name.get(_norm_name(name)) if name else None)
        if lid is None:
            return ""
        if lid not in ids:
            ids.append(lid)
    return " OR ".join(ids)


def maven_declared(name: str, version: str, depth: int = 6) -> List[Tuple[str, str]]:
    """The licences Maven would see for g:a:v: its POM's, else its nearest ancestor's."""
    g, _, a = name.partition(":")
    for _ in range(depth):
        text = _get_text(f"https://repo1.maven.org/maven2/{g.replace('.', '/')}/{a}/{version}/{a}-{version}.pom")
        if text is None:
            return []
        lics, parent = pom_licences(text)
        if lics or parent is None:
            return lics
        g, a, version = parent
    return []


def _maven(name: str, version: str) -> str:
    return to_spdx(maven_declared(name, version), spdx_maps())


FETCHERS: Dict[str, Callable[[str, str], str]] = {
    NPM: _npm, PYPI: _pypi, RUBYGEMS: _rubygems, CARGO: _crates, NUGET: _nuget, MAVEN: _maven}


class RegistryLicences:
    """A version's declared licence from its registry, cached (also when it declares none)."""

    def __init__(self, offline: bool = False, fetchers: Optional[Dict[str, Callable[[str, str], str]]] = None):
        self.offline = offline
        self.fetchers = fetchers if fetchers is not None else FETCHERS
        self.fetched = 0

    def license(self, ecosystem: str, name: str, version: str) -> Optional[str]:
        """The licence ("" when the registry declares none); None when not known here."""
        fetch = self.fetchers.get(ecosystem)
        if fetch is None:
            return None
        path = cache_dir() / ecosystem / "licences" / (_q(f"{normalize_name(ecosystem, name)}@{version}") + ".json")
        if path.is_file():
            try:
                return json.loads(path.read_text())["license"]
            except (OSError, ValueError, KeyError):
                pass
        if self.offline:
            return None
        lic = fetch(name, version)
        self.fetched += 1
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"license": lic}))
        return lic


def enrich_from_registry(files: List[DependencyFile], licences: RegistryLicences) -> List[str]:
    """Fill the licences still unknown after the lockfile and installed metadata; returns warnings."""
    warnings: List[str] = []
    for df in files:
        if df.ecosystem not in SUPPORTED:
            continue
        for p in df.packages.values():
            if p.license or not p.version:
                continue
            try:
                lic = licences.license(df.ecosystem, p.name, p.version)
            except RegistryError as e:
                warnings.append(f"registry licences: {e}")
                return warnings                         # one failure: the registry is unreachable
            if lic:
                p.license, p.license_source = lic, "registry"
    return warnings


__all__: List[str] = ["RegistryLicences", "enrich_from_registry", "SUPPORTED"]
