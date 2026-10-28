"""The dependency graph: packages read from one manifest or lockfile, and the edges the file
records between them."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import quote

# OSV ecosystem names
PYPI, NPM, MAVEN, NUGET = "PyPI", "npm", "Maven", "NuGet"
GO, CARGO, SWIFT = "Go", "crates.io", "SwiftURL"
# C / C++: no OSV package ecosystem; matched by upstream repository and release tag (OSV GIT)
CONAN, VCPKG, GIT = "ConanCenter", "vcpkg", "GIT"
RUBYGEMS, PACKAGIST, PUB, HEX = "RubyGems", "Packagist", "Pub", "Hex"


def normalize_name(ecosystem: str, name: str) -> str:
    """The name a registry (and OSV) compares by: PEP 503 for PyPI, case-insensitive NuGet."""
    if ecosystem == PYPI:
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem in (NUGET, PACKAGIST):
        return name.lower()                     # both registries compare names case-insensitively
    return name


@dataclass
class Package:
    ecosystem: str
    name: str                            # as written in the file
    version: Optional[str]               # exact resolved version; None when the file only has a range
    direct: Optional[bool] = None        # None: the file does not say
    dev: bool = False                    # only needed for development / tests
    spec: str = ""                       # the requested range, when there is no exact version
    license: str = ""                    # as the lockfile (npm, Composer) or installed metadata declares it
    license_source: str = ""             # "" (the file itself) | "installed"
    repo: str = ""                       # C/C++: the upstream repository, host/owner/name
    tags: List[str] = field(default_factory=list)   # C/C++: the release tag(s) this version is
    commit: str = ""                     # a git submodule: the full commit it is pinned to
    checkout: str = ""                   # ... and its checkout, whose history decides commit ranges

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
        if self.ecosystem == RUBYGEMS:
            return f"pkg:gem/{quote(self.name, safe='')}@{v}"
        if self.ecosystem == PACKAGIST and "/" in self.name:
            vendor, name = self.name.split("/", 1)
            return f"pkg:composer/{quote(vendor, safe='')}/{quote(name, safe='')}@{v}"
        if self.ecosystem == PUB:
            return f"pkg:pub/{quote(self.name, safe='')}@{v}"
        if self.ecosystem == HEX:
            return f"pkg:hex/{quote(self.name, safe='')}@{v}"
        if self.ecosystem == CONAN:
            return f"pkg:conan/{quote(self.name, safe='')}@{v}"
        if self.ecosystem in (VCPKG, GIT) and self.repo.startswith(("github.com/", "gitlab.com/", "bitbucket.org/")):
            host, owner, name = self.repo.split("/", 2)
            return f"pkg:{host.split('.')[0]}/{quote(owner, safe='')}/{quote(name, safe='')}@{v}"
        if self.ecosystem == VCPKG:
            return f"pkg:generic/{quote(self.name, safe='')}@{v}"
        family, _, release = self.ecosystem.partition(":")
        if family in ("Debian", "Ubuntu") and release:          # source packages (purl-spec deb type)
            distro = f"{family.lower()}-{release.split(':')[0]}"
            return f"pkg:deb/{family.lower()}/{quote(self.name, safe='')}@{v}?arch=source&distro={distro}"
        if family == "Alpine" and release:
            return f"pkg:apk/alpine/{quote(self.name, safe='')}@{v}?distro={release.lstrip('v')}"
        if family in ("AlmaLinux", "Rocky Linux") and release and self.version:
            # purl-spec rpm type: the epoch is a qualifier, not part of the version
            ns = family.lower().replace(" ", "-")
            epoch, _, evr = self.version.partition(":") if ":" in self.version else ("", "", self.version)
            return (f"pkg:rpm/{ns}/{quote(self.name, safe='')}@{quote(evr, safe='')}?distro={ns}-{release}"
                    + (f"&epoch={epoch}" if epoch and epoch != "0" else ""))
        return None

    def to_dict(self) -> dict:
        d = {"name": self.name, "version": self.version, "ecosystem": self.ecosystem,
             "direct": self.direct, "dev": self.dev, "purl": self.purl}
        if self.spec:
            d["spec"] = self.spec
        if self.license:
            d["license"] = self.license
            if self.license_source:
                d["license_source"] = self.license_source
        if self.repo:
            d["repo"] = self.repo
            d["tags"] = list(self.tags)
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
    # packages production code reaches through something that is not itself a package (a git
    # or path gem): roots for working out what is development only, besides the direct ones
    prod_roots: Set[str] = field(default_factory=set)
    # Go: the module's `go` directive (the language version it builds with), "" when not said
    go_version: str = ""
    # a Go binary: the functions it contains, as advisories name them (`frame.sca.binaries`)
    binary_functions: frozenset = frozenset()
    binary_platform: Tuple[str, str] = ("", "")   # its GOOS, GOARCH
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
