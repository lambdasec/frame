"""Language runtimes installed in an image or a root filesystem, each read from the version file
it ships with (never from a directory or file name):

| Runtime | File | Package |
|---|---|---|
| JDK / JRE | `<java home>/release` (`JAVA_VERSION`) | `OpenJDK` `openjdk` |
| Node.js | `<prefix>/include/node/node_version.h` | `Node.js` `node` |
| CPython | `<prefix>/include/python3.X/patchlevel.h` (`PY_VERSION`) | `github.com/python/cpython` at tag `v<version>` (OSV's GIT records, as C/C++ are matched) |
| .NET | `shared/Microsoft.*.App/<v>/Microsoft.*.App.deps.json`, a self-contained app's `*.deps.json` | the NuGet runtime pack it names (`Microsoft.NETCore.App.Runtime.linux-x64`) |
| Ruby | `lib/ruby/<api>/<arch>/rbconfig.rb` (`MAJOR`.`MINOR`.`TEENY`) | `Ruby` `ruby` |

Go's toolchain is read from Go binaries already (`Go:stdlib`, `frame.sca.binaries`).

A runtime an OS package installed is left to the distribution's advisories (distributions patch
without changing the upstream version), unless the image's distribution is one Frame has no
advisories for (Amazon Linux's Corretto rpm, say), where the runtime's own advisories are the only
ones there are. A JDK whose JVM is not HotSpot (IBM Semeru's OpenJ9) is reported in a warning,
not matched: OpenJDK's advisories describe HotSpot builds, and many of them are HotSpot flaws.
"""

from __future__ import annotations

import json
import re
from typing import Dict, List, Optional, Set, Tuple

from frame.sca.model import GIT, NODEJS, NUGET, OPENJDK, RUBY, DependencyFile, Package

CPYTHON_REPO = "github.com/python/cpython"

_JDK_RELEASE = re.compile(r"(?:^|/)release$")
_NODE_H = re.compile(r"(?:^|/)include/node/node_version\.h$")
_PY_H = re.compile(r"(?:^|/)include/python[23]\.\d+[a-z]*/patchlevel\.h$")
_DEPS_JSON = re.compile(r"\.deps\.json$")
_RBCONFIG = re.compile(r"(?:^|/)lib/ruby/[^/]+/[^/]+/rbconfig\.rb$")
# the NuGet runtime packs GitHub's advisories name (Microsoft.NETCore.App.Runtime.linux-x64, ...)
_RUNTIME_PACK = re.compile(r"(?:runtimepack\.)?(Microsoft\.(?:NETCore|AspNetCore|WindowsDesktop)\.App\.Runtime\.[A-Za-z0-9.-]+)/"
                           r"([0-9][0-9A-Za-z.+-]*)")


def runtime_file(path: str) -> bool:
    """A file this module reads (the image readers keep only the files some reader needs)."""
    return bool(_JDK_RELEASE.search(path) or _NODE_H.search(path) or _PY_H.search(path)
                or _DEPS_JSON.search(path) or _RBCONFIG.search(path))


def _assignments(text: str) -> Dict[str, str]:
    """KEY="value" lines of a JDK release file."""
    out = {}
    for line in text.splitlines():
        m = re.fullmatch(r'\s*([A-Z_][A-Z0-9_]*)\s*=\s*"?(.*?)"?\s*', line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def _defines(text: str) -> Dict[str, str]:
    return {m.group(1): m.group(2).strip().strip('"') for m in
            re.finditer(r"^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)[ \t]+([^\n]*?)\s*(?:/[*/].*)?$", text, re.M)}


def _jdk(text: str) -> Tuple[Optional[str], Optional[str]]:
    """(version, why not matched) of a JDK release file; (None, None) when it is not one."""
    a = _assignments(text)
    version = a.get("JAVA_VERSION")
    if not version or not ("IMPLEMENTOR" in a or "JAVA_RUNTIME_VERSION" in a or "JVM_VARIANT" in a):
        return None, None
    variant = a.get("JVM_VARIANT", "")
    if variant and variant.lower() != "hotspot":
        return version, f"its JVM is {variant} ({a.get('IMPLEMENTOR', 'unknown vendor')}), not HotSpot; " \
                        "OpenJDK's advisories describe HotSpot builds, so it is not matched (see the vendor's bulletins)"
    return version, None


def _node(text: str) -> Tuple[Optional[str], Optional[str]]:
    d = _defines(text)
    parts = [d.get(f"NODE_{k}_VERSION") for k in ("MAJOR", "MINOR", "PATCH")]
    if not all(p and p.isdigit() for p in parts):
        return None, None
    version = ".".join(parts)
    if d.get("NODE_VERSION_IS_RELEASE") != "1":
        return version, "a pre-release build (NODE_VERSION_IS_RELEASE is not 1); not matched"
    return version, None


def _python(text: str) -> Optional[str]:
    v = _defines(text).get("PY_VERSION")
    return v if v and re.fullmatch(r"\d+\.\d+\.\d+(?:(?:a|b|rc)\d+)?\+?", v) else None


def _ruby(text: str) -> Optional[str]:
    conf = dict(re.findall(r'^\s*CONFIG\["([A-Z_]+)"\]\s*=\s*"([^"]*)"', text, re.M))
    parts = [conf.get(k) for k in ("MAJOR", "MINOR", "TEENY")]
    if not all(p and p.isdigit() for p in parts):
        return None
    return ".".join(parts)


def _runtime_packs(text: str) -> List[Tuple[str, str]]:
    """The NuGet runtime packs a deps.json lists as libraries: a shared framework's own
    (`Microsoft.NETCore.App.Runtime.linux-x64/8.0.34`) or a self-contained app's
    (`runtimepack.Microsoft.NETCore.App.Runtime.linux-x64/8.0.34`)."""
    try:
        doc = json.loads(text)
    except ValueError:
        return []
    libs = doc.get("libraries") if isinstance(doc, dict) else None
    out = []
    for key in libs if isinstance(libs, dict) else {}:
        m = _RUNTIME_PACK.fullmatch(key)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def _home(path: str, marker: re.Pattern) -> str:
    """The directory a version file describes (`/opt/java/openjdk`, `/usr/local`)."""
    return path[:marker.search(path).start()].rstrip("/") or "/"


def read_runtimes(files: Dict[str, object], origin: str, owned: Set[str],
                  distro_supported: bool) -> Tuple[List[DependencyFile], List[str]]:
    """One DependencyFile per installed runtime (kind `image`), and warnings."""
    out: List[DependencyFile] = []
    warnings: List[str] = []
    left_to_distro = 0

    def is_owned(path: str) -> bool:
        return path in owned or path.rsplit("/", 1)[0] in owned

    def add(where: str, pkg: Package) -> None:
        df = DependencyFile(f"{origin}:/{where.lstrip('/')}", pkg.ecosystem, "image")
        df.add(pkg)
        out.append(df)

    for path in sorted(files):
        text = files[path]
        if not isinstance(text, str) or not runtime_file(path):
            continue
        if is_owned(path) and distro_supported:
            if not _DEPS_JSON.search(path) or _runtime_packs(text):
                left_to_distro += 1
            continue
        if _JDK_RELEASE.search(path):
            version, why = _jdk(text)
            if version and why:
                warnings.append(f"{origin}:/{path}: JDK {version}: {why}")
            elif version:
                add(_home(path, _JDK_RELEASE), Package(OPENJDK, "openjdk", version))
        elif _NODE_H.search(path):
            version, why = _node(text)
            if version and why:
                warnings.append(f"{origin}:/{path}: Node.js {version}: {why}")
            elif version:
                add(_home(path, _NODE_H), Package(NODEJS, "node", version))
        elif _PY_H.search(path):
            version = _python(text)
            if version:
                add(_home(path, _PY_H), Package(GIT, CPYTHON_REPO, version, repo=CPYTHON_REPO, tags=[f"v{version}"]))
        elif _RBCONFIG.search(path):
            version = _ruby(text)
            if version:
                add(_home(path, _RBCONFIG), Package(RUBY, "ruby", version))
        else:
            for name, version in _runtime_packs(text):
                add(path.rsplit("/", 1)[0], Package(NUGET, name, version))
    if left_to_distro:
        warnings.append(f"{origin}: {left_to_distro} runtime(s) installed by the OS package manager are covered "
                        "by the distribution's advisories")
    return out, warnings
