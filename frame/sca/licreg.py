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

Not available per version, so not read: Hex (the package's latest metadata only), pub.dev
(pubspecs carry no licence), Go (no registry metadata). Maven POMs name licences in free
text, often through a parent POM: not read yet.
"""

from __future__ import annotations

import gzip
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable, Dict, List, Optional

from frame.sca.licenses import _npm_license, composer_license, is_spdx
from frame.sca.model import CARGO, NPM, NUGET, PYPI, RUBYGEMS, DependencyFile, normalize_name
from frame.sca.registry import TIMEOUT, RegistryError, cache_dir

SUPPORTED = (NPM, PYPI, RUBYGEMS, CARGO, NUGET)


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


FETCHERS: Dict[str, Callable[[str, str], str]] = {
    NPM: _npm, PYPI: _pypi, RUBYGEMS: _rubygems, CARGO: _crates, NUGET: _nuget}


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
