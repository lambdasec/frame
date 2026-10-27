"""The dependency graph: packages read from one manifest or lockfile, and the edges the file
records between them."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from urllib.parse import quote

# OSV ecosystem names
PYPI, NPM, MAVEN, NUGET = "PyPI", "npm", "Maven", "NuGet"
GO, CARGO, SWIFT = "Go", "crates.io", "SwiftURL"


def normalize_name(ecosystem: str, name: str) -> str:
    """The name a registry (and OSV) compares by: PEP 503 for PyPI, case-insensitive NuGet."""
    if ecosystem == PYPI:
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem == NUGET:
        return name.lower()
    return name


@dataclass
class Package:
    ecosystem: str
    name: str                            # as written in the file
    version: Optional[str]               # exact resolved version; None when the file only has a range
    direct: Optional[bool] = None        # None: the file does not say
    dev: bool = False                    # only needed for development / tests
    spec: str = ""                       # the requested range, when there is no exact version
    license: str = ""                    # as the lockfile declares it (npm); empty when it does not say

    @property
    def key(self) -> str:
        return f"{self.ecosystem}:{normalize_name(self.ecosystem, self.name)}@{self.version or ''}"

    @property
    def purl(self) -> Optional[str]:
        if not self.version:
            return None
        v = quote(self.version, safe="")
        if self.ecosystem == PYPI:
            return f"pkg:pypi/{normalize_name(PYPI, self.name)}@{v}"
        if self.ecosystem == NPM:
            return f"pkg:npm/{quote(self.name, safe='/')}@{v}"
        if self.ecosystem == MAVEN and ":" in self.name:
            group, artifact = self.name.split(":", 1)
            return f"pkg:maven/{quote(group, safe='')}/{quote(artifact, safe='')}@{v}"
        if self.ecosystem == NUGET:
            return f"pkg:nuget/{quote(self.name, safe='')}@{v}"
        if self.ecosystem == GO:
            return f"pkg:golang/{quote(self.name, safe='/')}@v{v}"      # OSV drops the v; Go keeps it
        if self.ecosystem == CARGO:
            return f"pkg:cargo/{quote(self.name, safe='')}@{v}"
        if self.ecosystem == SWIFT:
            return f"pkg:swift/{quote(self.name, safe='/')}@{v}"
        return None

    def to_dict(self) -> dict:
        d = {"name": self.name, "version": self.version, "ecosystem": self.ecosystem,
             "direct": self.direct, "dev": self.dev, "purl": self.purl}
        if self.spec:
            d["spec"] = self.spec
        if self.license:
            d["license"] = self.license
        return d


@dataclass
class DependencyFile:
    """What one manifest or lockfile says."""
    path: str                            # relative to the scanned root
    ecosystem: str
    kind: str                            # "lockfile" | "manifest"
    packages: Dict[str, Package] = field(default_factory=dict)      # key -> package
    edges: Dict[str, Set[str]] = field(default_factory=dict)        # key -> keys it depends on
    # declared requirements: requiring package key ("" for the project itself) -> normalised
    # dependency name -> the range it declares (what an upgrade must satisfy)
    requires: Dict[str, Dict[str, str]] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)

    def add(self, pkg: Package) -> Package:
        """Add `pkg`, merging with an entry of the same key (direct and non-dev win)."""
        cur = self.packages.get(pkg.key)
        if cur is None:
            self.packages[pkg.key] = pkg
            return pkg
        if pkg.direct:
            cur.direct = True
        elif cur.direct is None:
            cur.direct = pkg.direct
        cur.dev = cur.dev and pkg.dev
        return cur

    def edge(self, parent: str, child: str) -> None:
        if parent != child:
            self.edges.setdefault(parent, set()).add(child)

    def require(self, parent: str, name: str, spec) -> None:
        if isinstance(spec, dict):                      # poetry: {version = "...", markers = ...}
            spec = spec.get("version", "")
        if isinstance(spec, str) and spec.strip():
            self.requires.setdefault(parent, {})[normalize_name(self.ecosystem, name)] = spec.strip()

    def mark_direct(self, names: Dict[str, bool]) -> None:
        """Set `direct` (and `dev`, from the manifest's dev section) by normalised name."""
        for pkg in self.packages.values():
            n = normalize_name(self.ecosystem, pkg.name)
            if n in names:
                pkg.direct = True
                pkg.dev = names[n]
            elif names:
                pkg.direct = False

    def to_dict(self) -> dict:
        pkgs = sorted(self.packages.values(), key=lambda p: (normalize_name(p.ecosystem, p.name), p.version or ""))
        return {"path": self.path, "ecosystem": self.ecosystem, "kind": self.kind,
                "packages": [p.to_dict() for p in pkgs],
                "edges": {k: sorted(v) for k, v in sorted(self.edges.items())},
                "warnings": self.warnings}
