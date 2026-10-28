"""Readers for dependency manifests and lockfiles. Each takes the file's path and text and
returns a `DependencyFile`; none runs anything or touches the network.

A lockfile gives exact versions and, for most formats, the edges between packages. Which
packages are direct comes from the manifest beside it (`pyproject.toml`, `Pipfile`,
`package.json`) when the lockfile does not say; with neither, `direct` stays None rather
than being guessed.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]

from frame.sca import _yaml
from frame.sca.model import CARGO, GO, MAVEN, NPM, NUGET, PYPI, SWIFT, DependencyFile, Package, normalize_name


class LockfileError(ValueError):
    """A file that cannot be read as the format its name says."""


# ---------------------------------------------------------------------------------------------
# Python

_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")


def _pep508(text: str) -> Optional[Tuple[str, Optional[str], str]]:
    """`name[extras] (op version, ...) ; marker` -> (name, pinned version or None, spec)."""
    text = text.split(";", 1)[0].strip()
    if not text or "://" in text:
        return None                                        # a direct URL reference
    m = _REQ.match(text)
    if not m:
        return None
    name, spec = m.group(1), m.group(3).strip().strip("()").strip()
    if " @ " in text or spec.startswith("@"):
        return None                                        # a direct URL reference
    pin = re.fullmatch(r"===?\s*([A-Za-z0-9][A-Za-z0-9.+!_-]*)", spec)
    return name, (pin.group(1) if pin and "*" not in pin.group(1) else None), spec


def parse_requirements(path: str, text: str, read: Optional[Callable[[str], Optional[str]]] = None,
                       _seen: Optional[set] = None) -> DependencyFile:
    df = DependencyFile(path, PYPI, "manifest")
    seen = _seen if _seen is not None else {path}
    joined = re.sub(r"\\\r?\n", " ", text)
    for raw in joined.splitlines():
        line = re.sub(r"(^|\s)#.*$", "", raw).strip()
        if not line:
            continue
        include = re.match(r"^(?:-r|--requirement)(?:\s+|=)?(\S+)$", line)
        if include:
            target = str(Path(path).parent / include.group(1))
            if read is not None and target not in seen:
                seen.add(target)
                sub = read(target)
                if sub is not None:
                    for p in parse_requirements(target, sub, read, seen).packages.values():
                        df.add(p)
            continue
        if line.startswith("-"):
            continue                                       # -c, -e, --index-url, --hash ...
        line = re.split(r"\s--", line, maxsplit=1)[0]               # per-requirement options
        r = _pep508(line)
        if r is None:
            continue
        name, version, spec = r
        df.add(Package(PYPI, name, version, direct=True, spec="" if version else spec))
    return df


def _pyproject_direct(text: str) -> Dict[str, bool]:
    """Direct dependency names of a pyproject.toml -> is it a dev dependency."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return {}
    out: Dict[str, bool] = {}

    def add(name: str, dev: bool) -> None:
        n = normalize_name(PYPI, name)
        out[n] = out.get(n, True) and dev

    project = data.get("project", {})
    for s in project.get("dependencies", []) or []:
        r = _pep508(s) if isinstance(s, str) else None
        if r:
            add(r[0], False)
    for group in (project.get("optional-dependencies") or {}).values():
        for s in group or []:
            r = _pep508(s) if isinstance(s, str) else None
            if r:
                add(r[0], False)
    for group in (data.get("dependency-groups") or {}).values():            # PEP 735
        for s in group or []:
            r = _pep508(s) if isinstance(s, str) else None
            if r:
                add(r[0], True)
    poetry = data.get("tool", {}).get("poetry", {})
    for name in (poetry.get("dependencies") or {}):
        if name.lower() != "python":
            add(name, False)
    for name in (poetry.get("dev-dependencies") or {}):
        add(name, True)
    for group in (poetry.get("group") or {}).values():
        for name in (group.get("dependencies") or {}):
            add(name, True)
    uv = data.get("tool", {}).get("uv", {})
    for s in uv.get("dev-dependencies", []) or []:
        r = _pep508(s) if isinstance(s, str) else None
        if r:
            add(r[0], True)
    for s in (data.get("tool", {}).get("pdm", {}).get("dev-dependencies") or {}).values():
        for item in s or []:
            r = _pep508(item) if isinstance(item, str) else None
            if r:
                add(r[0], True)
    return out


def parse_pyproject(path: str, text: str) -> DependencyFile:
    df = DependencyFile(path, PYPI, "manifest")
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise LockfileError(f"{path}: {e}") from e
    direct = _pyproject_direct(text)
    specs: Dict[str, Tuple[str, Optional[str], str]] = {}
    for s in data.get("project", {}).get("dependencies", []) or []:
        r = _pep508(s) if isinstance(s, str) else None
        if r:
            specs[normalize_name(PYPI, r[0])] = r
    for n, dev in direct.items():
        name, version, spec = specs.get(n, (n, None, ""))
        df.add(Package(PYPI, name, version, direct=True, dev=dev, spec="" if version else spec))
    return df


def _toml(path: str, text: str) -> dict:
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise LockfileError(f"{path}: {e}") from e


def parse_poetry_lock(path: str, text: str) -> DependencyFile:
    df = DependencyFile(path, PYPI, "lockfile")
    data = _toml(path, text)
    by_name: Dict[str, str] = {}
    for p in data.get("package", []):
        pkg = df.add(Package(PYPI, p["name"], str(p["version"]), dev=p.get("category") == "dev"))
        by_name[normalize_name(PYPI, p["name"])] = pkg.key
    for p in data.get("package", []):
        parent = by_name[normalize_name(PYPI, p["name"])]
        for dep, spec in (p.get("dependencies") or {}).items():
            child = by_name.get(normalize_name(PYPI, dep))
            if child:
                df.edge(parent, child)
                df.require(parent, dep, spec)
    return df


def parse_uv_lock(path: str, text: str) -> DependencyFile:
    df = DependencyFile(path, PYPI, "lockfile")
    data = _toml(path, text)
    roots, by_name = [], {}
    for p in data.get("package", []):
        source = p.get("source") or {}
        if "editable" in source or "virtual" in source:
            roots.append(p)                               # the project itself (or a workspace member)
            continue
        if "version" not in p:
            continue
        pkg = df.add(Package(PYPI, p["name"], str(p["version"])))
        by_name[normalize_name(PYPI, p["name"])] = pkg.key
    direct: Dict[str, bool] = {}
    for r in roots:
        for d in r.get("dependencies", []) or []:
            direct[normalize_name(PYPI, d["name"])] = False
        for group in (r.get("optional-dependencies") or {}).values():
            for d in group:
                direct.setdefault(normalize_name(PYPI, d["name"]), False)
        for group in (r.get("dev-dependencies") or {}).values():
            for d in group:
                direct.setdefault(normalize_name(PYPI, d["name"]), True)
        # the project's own declared ranges: `[package.metadata] requires-dist` of the root
        for d in ((r.get("metadata") or {}).get("requires-dist") or []):
            if isinstance(d, dict) and d.get("name") and d.get("specifier"):
                df.require("", d["name"], str(d["specifier"]))
    for p in data.get("package", []):
        parent = by_name.get(normalize_name(PYPI, p["name"]))
        if parent is None:
            continue
        for d in p.get("dependencies", []) or []:
            child = by_name.get(normalize_name(PYPI, d["name"]))
            if child:
                df.edge(parent, child)
    if roots:
        df.mark_direct(direct)
    return df


def parse_pdm_lock(path: str, text: str) -> DependencyFile:
    df = DependencyFile(path, PYPI, "lockfile")
    data = _toml(path, text)
    by_name = {}
    for p in data.get("package", []):
        groups = p.get("groups") or []
        pkg = df.add(Package(PYPI, p["name"], str(p["version"]), dev=bool(groups) and "default" not in groups))
        by_name[normalize_name(PYPI, p["name"])] = pkg.key
    for p in data.get("package", []):
        for s in p.get("dependencies", []) or []:
            r = _pep508(s)
            child = by_name.get(normalize_name(PYPI, r[0])) if r else None
            if child:
                df.edge(by_name[normalize_name(PYPI, p["name"])], child)
                df.require(by_name[normalize_name(PYPI, p["name"])], r[0], r[2])
    return df


def parse_pipfile_lock(path: str, text: str) -> DependencyFile:
    df = DependencyFile(path, PYPI, "lockfile")
    data = _json(path, text)
    for section, dev in (("default", False), ("develop", True)):
        for name, meta in (data.get(section) or {}).items():
            v = str((meta or {}).get("version", ""))
            if v.startswith("=="):
                df.add(Package(PYPI, name, v[2:].lstrip("="), dev=dev))
    return df


def _pipfile_direct(text: str) -> Dict[str, bool]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return {}
    out = {normalize_name(PYPI, n): False for n in (data.get("packages") or {})}
    for n in (data.get("dev-packages") or {}):
        out.setdefault(normalize_name(PYPI, n), True)
    return out


# ---------------------------------------------------------------------------------------------
# JavaScript

def _json(path: str, text: str) -> dict:
    try:
        data = json.loads(text)
    except ValueError as e:
        raise LockfileError(f"{path}: {e}") from e
    if not isinstance(data, dict):
        raise LockfileError(f"{path}: expected a JSON object")
    return data


def _package_json_direct(text: str) -> Dict[str, bool]:
    try:
        data = json.loads(text)
    except ValueError:
        return {}
    out: Dict[str, bool] = {}
    for section, dev in (("dependencies", False), ("optionalDependencies", False),
                         ("peerDependencies", False), ("devDependencies", True)):
        for n in (data.get(section) or {}):
            out[n] = out.get(n, True) and dev
    return out


def parse_package_json(path: str, text: str) -> DependencyFile:
    df = DependencyFile(path, NPM, "manifest")
    data = _json(path, text)
    for section, dev in (("dependencies", False), ("optionalDependencies", False),
                         ("devDependencies", True)):
        for name, spec in (data.get(section) or {}).items():
            exact = spec if isinstance(spec, str) and re.fullmatch(r"\d+\.\d+\.\d+[\w.+-]*", spec) else None
            df.add(Package(NPM, name, exact, direct=True, dev=dev, spec="" if exact else str(spec)))
    return df


def _npm_name(key: str) -> str:
    return key.rsplit("node_modules/", 1)[-1]


def parse_package_lock(path: str, text: str) -> DependencyFile:
    df = DependencyFile(path, NPM, "lockfile")
    data = _json(path, text)
    packages = data.get("packages")
    if isinstance(packages, dict):                       # lockfileVersion 2 and 3
        keys: Dict[str, str] = {}
        workspaces = [k for k, v in packages.items() if "node_modules/" not in k and isinstance(v, dict)]
        for k, meta in packages.items():
            if "node_modules/" not in k or not isinstance(meta, dict) or meta.get("link"):
                continue
            if not meta.get("version"):
                continue
            lic = meta.get("license")
            pkg = df.add(Package(NPM, _npm_name(k), str(meta["version"]),
                                 dev=bool(meta.get("dev") or meta.get("devOptional")),
                                 license=lic if isinstance(lic, str) else ""))
            keys[k] = pkg.key

        def resolve(owner: str, name: str) -> Optional[str]:
            base = owner
            while True:
                cand = f"{base}/node_modules/{name}" if base else f"node_modules/{name}"
                if cand in keys:
                    return keys[cand]
                if not base:
                    return None
                cut = base.rfind("/node_modules/")
                base = base[:cut] if cut >= 0 else ""

        direct: Dict[str, bool] = {}
        for k, meta in packages.items():
            if not isinstance(meta, dict):
                continue
            deps = {**(meta.get("dependencies") or {}), **(meta.get("optionalDependencies") or {}),
                    **(meta.get("peerDependencies") or {})}
            if k in workspaces:
                for n in deps:
                    direct[n] = False
                for n in (meta.get("devDependencies") or {}):
                    direct.setdefault(n, True)
                if k == "":
                    for n, spec in {**(meta.get("devDependencies") or {}), **deps}.items():
                        df.require("", n, spec)
                continue
            parent = keys.get(k)
            if parent is None:
                continue
            for n, spec in deps.items():
                child = resolve(k, n)
                if child:
                    df.edge(parent, child)
                    df.require(parent, n, spec)
        if direct:
            for k, key in keys.items():                   # direct = installed at a workspace's top
                pkg = df.packages[key]
                top = k.count("node_modules/") == 1 and (k.startswith("node_modules/") or
                                                         k.split("/node_modules/")[0] in workspaces)
                if top and _npm_name(k) in direct:
                    pkg.direct = True
                    pkg.dev = direct[_npm_name(k)] and pkg.dev
                elif pkg.direct is None:
                    pkg.direct = False
        return df

    def walk(deps: dict, parent: Optional[str]) -> None:   # lockfileVersion 1: nested
        for name, meta in (deps or {}).items():
            if not isinstance(meta, dict) or not meta.get("version"):
                continue
            pkg = df.add(Package(NPM, name, str(meta["version"]), dev=bool(meta.get("dev"))))
            if parent:
                df.edge(parent, pkg.key)
            for n, spec in (meta.get("requires") or {}).items():
                df.require(pkg.key, n, spec)
            walk(meta.get("dependencies") or {}, pkg.key)
    walk(data.get("dependencies") or {}, None)
    return df


def _yarn_spec_name(spec: str) -> str:
    spec = spec.strip().strip('"')
    at = spec.find("@", 1)
    return spec[:at] if at > 0 else spec


def parse_yarn_lock(path: str, text: str) -> DependencyFile:
    df = DependencyFile(path, NPM, "lockfile")
    berry = "__metadata:" in text
    entries: Dict[str, dict] = {}
    if berry:
        try:
            data = _yaml.loads(text)
        except _yaml.YamlError as e:
            raise LockfileError(f"{path}: {e}") from e
        for header, meta in data.items():
            if header == "__metadata" or not isinstance(meta, dict):
                continue
            entries[header] = meta
    else:                                                 # yarn v1's own format
        cur: Optional[dict] = None
        sub: Optional[dict] = None
        for raw in text.splitlines():
            if not raw.strip() or raw.lstrip().startswith("#"):
                continue
            indent = len(raw) - len(raw.lstrip(" "))
            line = raw.strip()
            if indent == 0:
                cur, sub = {}, None
                entries[line.rstrip(":")] = cur
            elif cur is None:
                continue
            elif indent == 2:
                if line.endswith(":"):
                    sub = cur.setdefault(line[:-1], {})
                else:
                    k, _, v = line.partition(" ")
                    cur[k] = v.strip().strip('"')
                    sub = None
            elif indent >= 4 and sub is not None:
                parts = re.match(r'^("[^"]+"|\S+)\s+(.+)$', line)
                if parts:
                    sub[parts.group(1).strip('"')] = parts.group(2).strip().strip('"')
    by_spec: Dict[str, str] = {}
    for header, meta in entries.items():
        version = str(meta.get("version", ""))
        specs = [s.strip().strip('"') for s in header.split(",") if s.strip()]
        if not version or not specs:
            continue
        if meta.get("linkType") == "soft" or any("@workspace:" in s or "@link:" in s for s in specs):
            continue
        pkg = df.add(Package(NPM, _yarn_spec_name(specs[0]), version))
        for s in specs:
            by_spec[s] = pkg.key
    for header, meta in entries.items():
        specs = [s.strip().strip('"') for s in header.split(",") if s.strip()]
        parent = by_spec.get(specs[0]) if specs else None
        if parent is None:
            continue
        deps = {**(meta.get("dependencies") or {}), **(meta.get("optionalDependencies") or {})}
        for name, rng in deps.items():
            rng = str(rng)
            child = by_spec.get(f"{name}@{rng}") or by_spec.get(f"{name}@npm:{rng}")
            if child:
                df.edge(parent, child)
                df.require(parent, name, rng[4:] if rng.startswith("npm:") else rng)
    return df


def _pnpm_key(key: str) -> Optional[Tuple[str, str]]:
    """`/name@1.2.3(peer@x)`, `name@1.2.3`, `/name/1.2.3_peer@x` -> (name, version)."""
    k = key.lstrip("/")
    k = re.sub(r"\(.*$", "", k)
    at = k.find("@", 1)
    if at > 0:
        name, version = k[:at], k[at + 1:]
    else:                                                 # lockfile v5: /name/version
        if "/" not in k:
            return None
        name, version = k.rsplit("/", 1)
    version = version.split("_", 1)[0]
    return (name, version) if name and version and version[0].isdigit() else None


def parse_pnpm_lock(path: str, text: str) -> DependencyFile:
    df = DependencyFile(path, NPM, "lockfile")
    try:
        data = _yaml.loads(text)
    except _yaml.YamlError as e:
        raise LockfileError(f"{path}: {e}") from e
    keys: Dict[Tuple[str, str], str] = {}
    for section in ("packages", "snapshots"):
        for key, meta in (data.get(section) or {}).items():
            nv = _pnpm_key(str(key))
            if nv is None or nv in keys:
                continue
            dev = isinstance(meta, dict) and str(meta.get("dev", "")).lower() == "true"
            keys[nv] = df.add(Package(NPM, nv[0], nv[1], dev=dev)).key

    def version_of(v) -> Optional[str]:
        v = v.get("version") if isinstance(v, dict) else v
        if not isinstance(v, str) or v.startswith(("link:", "file:")):
            return None
        nv = _pnpm_key(v) if "@" in v.lstrip("/") or v.startswith("/") else None
        return nv[1] if nv else re.sub(r"[(_].*$", "", v)

    for section in ("snapshots", "packages"):
        for key, meta in (data.get(section) or {}).items():
            nv = _pnpm_key(str(key))
            if nv is None or not isinstance(meta, dict):
                continue
            for dname, dv in {**(meta.get("dependencies") or {}), **(meta.get("optionalDependencies") or {})}.items():
                ver = version_of(dv)
                child = keys.get((dname, ver)) if ver else None
                if child:
                    df.edge(keys[nv], child)
    direct: Dict[str, bool] = {}
    importers = data.get("importers") or {".": data}
    for imp in importers.values():
        if not isinstance(imp, dict):
            continue
        for section, dev in (("dependencies", False), ("optionalDependencies", False), ("devDependencies", True)):
            for n, v in (imp.get(section) or {}).items():
                ver = version_of(v)
                if ver and (n, ver) in keys:
                    direct[n] = direct.get(n, True) and dev
                if isinstance(v, dict) and v.get("specifier"):
                    df.require("", n, v["specifier"])
    if direct:
        df.mark_direct(direct)
    return df


# ---------------------------------------------------------------------------------------------
# Java

def _xml(path: str, text: str) -> ET.Element:
    if "<!ENTITY" in text or "<!DOCTYPE" in text:
        raise LockfileError(f"{path}: a document type declaration is not read")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        raise LockfileError(f"{path}: {e}") from e
    for el in root.iter():                                # drop namespaces
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    return root


def parse_pom(path: str, text: str) -> DependencyFile:
    df = DependencyFile(path, MAVEN, "manifest")
    root = _xml(path, text)
    props: Dict[str, str] = {}
    properties = root.find("properties")
    for el in (list(properties) if properties is not None else []):
        props[el.tag] = (el.text or "").strip()
    for k in ("version", "groupId"):
        v = root.findtext(k) or root.findtext(f"parent/{k}")
        if v:
            props[f"project.{k}"] = props[f"pom.{k}"] = v.strip()

    def resolve(v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        for _ in range(5):
            m = re.search(r"\$\{([^}]+)\}", v)
            if not m or m.group(1) not in props:
                break
            v = v.replace(m.group(0), props[m.group(1)])
        return None if "${" in v else v.strip()

    managed: Dict[str, str] = {}
    for d in root.findall("dependencyManagement/dependencies/dependency"):
        g, a, v = d.findtext("groupId"), d.findtext("artifactId"), resolve(d.findtext("version"))
        if g and a and v:
            managed[f"{resolve(g)}:{a.strip()}"] = v
    for d in root.findall("dependencies/dependency"):
        g, a = resolve(d.findtext("groupId")), d.findtext("artifactId")
        if not g or not a:
            continue
        name = f"{g}:{a.strip()}"
        raw = d.findtext("version")
        v = resolve(raw) if raw else managed.get(name)
        exact = v if v and re.fullmatch(r"[\w.+-]+", v) else None
        df.add(Package(MAVEN, name, exact, direct=True, dev=(d.findtext("scope") or "").strip() == "test",
                       spec="" if exact else (raw or "").strip()))
    return df


def parse_gradle_lockfile(path: str, text: str) -> DependencyFile:
    df = DependencyFile(path, MAVEN, "lockfile")
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("empty="):
            continue
        coords, _, confs = line.partition("=")
        parts = coords.split(":")
        if len(parts) != 3:
            continue
        configurations = [c for c in confs.split(",") if c]
        dev = bool(configurations) and all("test" in c.lower() for c in configurations)
        df.add(Package(MAVEN, f"{parts[0]}:{parts[1]}", parts[2], dev=dev))
    return df


# ---------------------------------------------------------------------------------------------
# C#

def parse_nuget_lock(path: str, text: str) -> DependencyFile:
    df = DependencyFile(path, NUGET, "lockfile")
    data = _json(path, text)
    for framework in (data.get("dependencies") or {}).values():
        if not isinstance(framework, dict):
            continue
        keys: Dict[str, str] = {}
        for name, meta in framework.items():
            if not isinstance(meta, dict) or meta.get("type") == "Project" or not meta.get("resolved"):
                continue
            keys[name.lower()] = df.add(Package(NUGET, name, str(meta["resolved"]),
                                                direct=meta.get("type") == "Direct")).key
            if meta.get("type") == "Direct" and meta.get("requested"):
                df.require("", name, meta["requested"])
        for name, meta in framework.items():
            parent = keys.get(name.lower())
            if parent is None:
                continue
            for dep, spec in (meta.get("dependencies") or {}).items():
                child = keys.get(dep.lower())
                if child:
                    df.edge(parent, child)
                    df.require(parent, dep, spec)
    return df


def parse_project_assets(path: str, text: str) -> DependencyFile:
    """`obj/project.assets.json`, which every `dotnet restore` writes: the resolved graph per
    target framework, and the project's own (direct) references."""
    df = DependencyFile(path, NUGET, "lockfile")
    data = _json(path, text)
    direct: Dict[str, bool] = {}
    for fw in ((data.get("project") or {}).get("frameworks") or {}).values():
        for name, meta in ((fw or {}).get("dependencies") or {}).items():
            if isinstance(meta, dict) and meta.get("target", "Package") != "Package":
                continue
            dev = isinstance(meta, dict) and str(meta.get("suppressParent", "")).lower() == "all"
            direct[name.lower()] = direct.get(name.lower(), True) and dev
    for target in (data.get("targets") or {}).values():
        if not isinstance(target, dict):
            continue
        keys: Dict[str, str] = {}
        for ident, meta in target.items():
            if not isinstance(meta, dict) or meta.get("type") != "package" or "/" not in ident:
                continue
            name, version = ident.rsplit("/", 1)
            keys[name.lower()] = df.add(Package(NUGET, name, version)).key
        for ident, meta in target.items():
            if not isinstance(meta, dict) or "/" not in ident:
                continue
            parent = keys.get(ident.rsplit("/", 1)[0].lower())
            for dep in (meta.get("dependencies") or {}):
                child = keys.get(dep.lower())
                if parent and child:
                    df.edge(parent, child)
    if direct:
        df.mark_direct(direct)
    return df


def central_package_versions(text: str) -> Dict[str, str]:
    """`Directory.Packages.props` (central package management): name (lowercase) -> version."""
    try:
        root = _xml("Directory.Packages.props", text)
    except LockfileError:
        return {}
    out: Dict[str, str] = {}
    for el in root.iter("PackageVersion"):
        name, version = el.get("Include"), el.get("Version") or el.findtext("Version")
        if name and version:
            out[name.lower()] = version.strip()
    return out


def parse_csproj(path: str, text: str, central: Optional[Dict[str, str]] = None) -> DependencyFile:
    df = DependencyFile(path, NUGET, "manifest")
    root = _xml(path, text)
    for ref in root.iter("PackageReference"):
        name = ref.get("Include") or ref.get("Update")
        if not name or ref.get("Update"):
            continue
        v = (ref.get("VersionOverride") or ref.get("Version") or ref.findtext("Version")
             or (central or {}).get(name.lower()))
        v = v.strip() if v else None
        exact = v if v and re.fullmatch(r"\d[\w.+-]*", v) else None
        dev = (ref.get("PrivateAssets") or ref.findtext("PrivateAssets") or "").strip().lower() == "all"
        df.add(Package(NUGET, name, exact, direct=True, dev=dev, spec="" if exact else (v or "")))
    return df


def parse_packages_config(path: str, text: str) -> DependencyFile:
    df = DependencyFile(path, NUGET, "manifest")
    root = _xml(path, text)
    for p in root.iter("package"):
        if p.get("id") and p.get("version"):
            df.add(Package(NUGET, p.get("id"), p.get("version"),
                           dev=(p.get("developmentDependency") or "").lower() == "true"))
    return df


# ---------------------------------------------------------------------------------------------
# Go, Rust, Swift (dependencies only: Frame does not scan these languages' source)

def parse_go_mod(path: str, text: str) -> DependencyFile:
    """go.mod lists every module the build needs (Go 1.17+), `// indirect` marking the
    transitive ones; a `replace` with a version substitutes that module version."""
    df = DependencyFile(path, GO, "lockfile")
    requires: Dict[str, Tuple[str, bool]] = {}
    replaces: Dict[str, Optional[Tuple[str, str]]] = {}
    block: Optional[str] = None
    for raw in text.splitlines():
        indirect = "// indirect" in raw
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if block is not None:
            if line == ")":
                block = None
                continue
            entry = line
        else:
            m = re.match(r"^(require|replace|exclude|retract|module|go|toolchain|godebug)\b\s*(.*)$", line)
            if not m:
                continue
            if m.group(2) == "(":
                block = m.group(1)
                continue
            block_kind, entry = m.group(1), m.group(2)
            _go_entry(block_kind, entry, indirect, requires, replaces)
            continue
        _go_entry(block, entry, indirect, requires, replaces)
    for mod, (version, ind) in requires.items():
        rep = replaces.get(mod, False)
        if rep is None:
            continue                                       # replaced by a local directory
        name, ver = (rep if rep else (mod, version))
        df.add(Package(GO, name, ver.lstrip("v") if ver else None, direct=not ind))
    return df


def _go_entry(kind: str, entry: str, indirect: bool, requires: dict, replaces: dict) -> None:
    parts = entry.split()
    if kind == "require" and len(parts) >= 2:
        requires[parts[0].strip('"')] = (parts[1], indirect)
    elif kind == "replace" and "=>" in parts:
        i = parts.index("=>")
        target = parts[i + 1:]
        old = parts[0].strip('"')
        if len(target) >= 2:
            replaces[old] = (target[0].strip('"'), target[1])
        elif target and target[0].startswith((".", "/")):
            replaces[old] = None


def parse_cargo_lock(path: str, text: str) -> DependencyFile:
    df = DependencyFile(path, CARGO, "lockfile")
    data = _toml(path, text)
    keys: Dict[Tuple[str, str], str] = {}
    by_name: Dict[str, List[str]] = {}
    roots = []
    for p in data.get("package", []):
        if "source" not in p:                              # a workspace member: the project itself
            roots.append(p)
            continue
        pkg = df.add(Package(CARGO, p["name"], str(p["version"])))
        keys[(p["name"], str(p["version"]))] = pkg.key
        by_name.setdefault(p["name"], []).append(pkg.key)

    def target(dep: str) -> Optional[str]:
        parts = dep.split()                                 # "name", "name version", "name version (source)"
        if len(parts) >= 2:
            return keys.get((parts[0], parts[1]))
        cands = by_name.get(parts[0], [])
        return cands[0] if len(cands) == 1 else None

    direct: Dict[str, bool] = {}
    for p in data.get("package", []):
        children = [t for t in (target(d) for d in p.get("dependencies", []) or []) if t]
        if "source" not in p:
            for c in children:
                direct[df.packages[c].name] = False
            continue
        parent = keys[(p["name"], str(p["version"]))]
        for c in children:
            df.edge(parent, c)
    if roots:
        df.mark_direct(direct)
    return df


def _cargo_toml_dev(text: str) -> Dict[str, bool]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return {}
    out: Dict[str, bool] = {}
    tables = [data] + list((data.get("target") or {}).values())
    for t in tables:
        for section, dev in (("dependencies", False), ("build-dependencies", False), ("dev-dependencies", True)):
            for name, spec in (t.get(section) or {}).items():
                real = spec.get("package", name) if isinstance(spec, dict) else name
                out[real] = out.get(real, True) and dev
    return out


def _swift_name(location: str) -> str:
    """The repository URL as OSV's SwiftURL ecosystem names a package: host/path, no scheme
    or `.git`."""
    loc = re.sub(r"^[a-z+]+://", "", location.strip()).rstrip("/")
    loc = re.sub(r"^git@([^:]+):", r"\1/", loc)
    return loc[:-4] if loc.endswith(".git") else loc


def parse_package_resolved(path: str, text: str) -> DependencyFile:
    df = DependencyFile(path, SWIFT, "lockfile")
    data = _json(path, text)
    pins = data.get("pins") or (data.get("object") or {}).get("pins") or []
    for pin in pins:
        if not isinstance(pin, dict):
            continue
        location = pin.get("location") or pin.get("repositoryURL")
        if not location or pin.get("kind") in ("localSourceControl", "fileSystem"):
            continue
        state = pin.get("state") or {}
        version = state.get("version")
        df.add(Package(SWIFT, _swift_name(location), version or None,
                       spec="" if version else (state.get("branch") or state.get("revision") or "")))
    return df


# ---------------------------------------------------------------------------------------------

def _propagate_dev(df: DependencyFile) -> None:
    """A package is a dev dependency only if every direct dependency that reaches it is."""
    if not any(p.direct for p in df.packages.values()):
        return
    prod = [k for k, p in df.packages.items() if p.direct and not p.dev] + sorted(df.prod_roots)
    reach = set(prod)
    stack = list(prod)
    while stack:
        for c in df.edges.get(stack.pop(), ()):
            if c not in reach:
                reach.add(c)
                stack.append(c)
    for k, p in df.packages.items():
        p.dev = k not in reach


# file name -> (parser, the manifest beside it that names the direct dependencies)
LOCKFILES: Dict[str, Tuple[Callable[[str, str], DependencyFile], Optional[Tuple[str, Callable]]]] = {
    "poetry.lock": (parse_poetry_lock, ("pyproject.toml", _pyproject_direct)),
    "uv.lock": (parse_uv_lock, None),
    "pdm.lock": (parse_pdm_lock, ("pyproject.toml", _pyproject_direct)),
    "Pipfile.lock": (parse_pipfile_lock, ("Pipfile", _pipfile_direct)),
    "package-lock.json": (parse_package_lock, ("package.json", _package_json_direct)),
    "npm-shrinkwrap.json": (parse_package_lock, ("package.json", _package_json_direct)),
    "yarn.lock": (parse_yarn_lock, ("package.json", _package_json_direct)),
    "pnpm-lock.yaml": (parse_pnpm_lock, None),
    "gradle.lockfile": (parse_gradle_lockfile, None),
    "packages.lock.json": (parse_nuget_lock, None),
    "project.assets.json": (parse_project_assets, None),
    "go.mod": (parse_go_mod, None),
    "Cargo.lock": (parse_cargo_lock, ("Cargo.toml", _cargo_toml_dev)),
    "Package.resolved": (parse_package_resolved, None),
    "conan.lock": (lambda path, text: __import__("frame.sca.cppdeps", fromlist=["x"]).parse_conan_lock(path, text), None),
    "vcpkg-status": (lambda path, text: __import__("frame.sca.cppdeps", fromlist=["x"]).parse_vcpkg_status(path, text), None),
    "Gemfile.lock": (lambda path, text: _more().parse_gemfile_lock(path, text),
                     ("Gemfile", lambda text: _more().gemfile_groups(text))),
    "composer.lock": (lambda path, text: _more().parse_composer_lock(path, text),
                      ("composer.json", lambda text: _more().composer_json_direct(text))),
    "pubspec.lock": (lambda path, text: _more().parse_pubspec_lock(path, text), None),
    "mix.lock": (lambda path, text: _more().parse_mix_lock(path, text),
                 ("mix.exs", lambda text: _more().mix_exs_direct(text))),
}


def _more():
    from frame.sca import morelocks
    return morelocks
# lockfiles that mark dev-only packages themselves; for the others it follows from the edges
# (go.mod and Package.resolved record no edges, and Go and SwiftPM have no dev-only dependencies)
DEV_FLAGGED = frozenset({"package-lock.json", "npm-shrinkwrap.json", "Pipfile.lock", "gradle.lockfile",
                         "packages.lock.json", "project.assets.json", "go.mod", "Package.resolved",
                         "conan.lock", "vcpkg-status", "composer.lock", "pubspec.lock"})
# manifests read only when no lockfile of the same ecosystem sits beside them
MANIFESTS: Dict[str, Callable[[str, str], DependencyFile]] = {
    "pyproject.toml": parse_pyproject,
    "package.json": parse_package_json,
    "pom.xml": parse_pom,
    "packages.config": parse_packages_config,
}
_REQUIREMENTS = re.compile(r"requirements[-_.\w]*\.txt$")


def lockfile_ecosystem(name: str) -> Optional[str]:
    if name in ("poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock"):
        return PYPI
    if name in ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"):
        return NPM
    if name == "gradle.lockfile":
        return MAVEN
    if name in ("packages.lock.json", "project.assets.json"):
        return NUGET
    return {"go.mod": GO, "Cargo.lock": CARGO, "Package.resolved": SWIFT, "conan.lock": "ConanCenter",
            "vcpkg-status": "vcpkg", "Gemfile.lock": "RubyGems", "composer.lock": "Packagist",
            "pubspec.lock": "Pub", "mix.lock": "Hex"}.get(name)


_MORE_MANIFESTS = {"Gemfile": "parse_gemfile", "composer.json": "parse_composer_json",
                   "pubspec.yaml": "parse_pubspec_yaml", "mix.exs": "parse_mix_exs"}
_CPP_MANIFESTS = {"conanfile.txt": "parse_conanfile_txt", "conanfile.py": "parse_conanfile_py",
                  "vcpkg.json": "parse_vcpkg_json", ".gitmodules": "parse_gitmodules",
                  "CMakeLists.txt": "parse_cmake"}


def manifest_parser(name: str) -> Optional[Callable[..., DependencyFile]]:
    if name in MANIFESTS:
        return MANIFESTS[name]
    if name in _CPP_MANIFESTS:
        from frame.sca import cppdeps
        return getattr(cppdeps, _CPP_MANIFESTS[name])
    if name in _MORE_MANIFESTS:
        return getattr(_more(), _MORE_MANIFESTS[name])
    if name in ("build.gradle", "build.gradle.kts"):
        from frame.sca.gradle import parse_gradle
        return parse_gradle
    if _REQUIREMENTS.fullmatch(name):
        return parse_requirements
    if name.endswith(".csproj"):
        return parse_csproj
    return None


def manifest_ecosystem(name: str) -> Optional[str]:
    if name in ("pyproject.toml",) or _REQUIREMENTS.fullmatch(name):
        return PYPI
    if name == "package.json":
        return NPM
    if name == "pom.xml":
        return MAVEN
    if name == "packages.config" or name.endswith(".csproj"):
        return NUGET
    return {"conanfile.txt": "ConanCenter", "conanfile.py": "ConanCenter", "vcpkg.json": "vcpkg",
            ".gitmodules": "GIT", "CMakeLists.txt": "GIT", "Gemfile": "RubyGems", "composer.json": "Packagist",
            "pubspec.yaml": "Pub", "mix.exs": "Hex", "build.gradle": MAVEN, "build.gradle.kts": MAVEN}.get(name)


__all__: List[str] = ["LockfileError", "LOCKFILES", "MANIFESTS", "lockfile_ecosystem",
                      "manifest_parser", "manifest_ecosystem"]
