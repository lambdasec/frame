"""Direct dependencies of a Gradle build without running Gradle: `build.gradle` (Groovy) and
`build.gradle.kts` (Kotlin), with the version catalog (`gradle/libs.versions.toml`).

These are the DECLARED versions. Gradle's conflict resolution may pick another (a subproject
asking for a higher one wins), and transitive dependencies are not here at all: a
`gradle dependencies` report or `frame deps --resolve` gives the resolved graph, and a build
that has one is read from it instead.

Read: `dependencies { }` blocks (also inside `subprojects` / `allprojects`), with string
coordinates (`'g:a:v'`, `"g:a:$v"`), map / named-argument notation (`group: 'g', name: 'a',
version: 'v'`), catalog references (`libs.spring.web`, `libs.bundles.x`) and `platform(...)` /
`enforcedPlatform(...)` BOMs; `$x` / `${x}` from simple assignments, `ext` blocks and
gradle.properties. `project(...)` and `files(...)` are not packages. Test, annotation-processor,
kapt and ksp configurations are development only, and so is `buildscript { classpath }`.
Anything else (a computed version, a plugin-provided dependency) is listed without a version.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]

from frame.sca.model import MAVEN, DependencyFile, Package

_DEV_CONFIG = re.compile(r"^(test|androidTest|testFixtures|integrationTest|functionalTest)|"
                         r"(annotationProcessor|kapt|ksp|lintChecks|detektPlugins)", re.I)
_NOT_DEPS = ("project", "files", "fileTree", "gradleApi", "localGroovy", "gradleTestKit")


def _strip_comments(text: str) -> str:
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c in "'\"":
            q = text[i:i + 3] if text[i:i + 3] in ('"""', "'''") else c
            j = text.find(q, i + len(q))
            while j > 0 and q == c and text[j - 1] == "\\":
                j = text.find(q, j + 1)
            j = n if j < 0 else j + len(q)
            out.append(text[i:j])
            i = j
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _block(text: str, start: int) -> Tuple[str, int]:
    """The body of the `{ ... }` opening at `start` (string-aware)."""
    depth, i, n = 0, start, len(text)
    while i < n:
        c = text[i]
        if c in "'\"":
            j = text.find(c, i + 1)
            while j > 0 and text[j - 1] == "\\":
                j = text.find(c, j + 1)
            i = n if j < 0 else j + 1
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[start + 1:i], i + 1
        i += 1
    return text[start + 1:], n


def _blocks(text: str, name: str) -> List[Tuple[str, int]]:
    """Every `name { ... }` block: (body, offset of the name)."""
    out = []
    for m in re.finditer(rf"(?<![\w.]){name}\s*\{{", text):
        body, _ = _block(text, m.end() - 1)
        out.append((body, m.start()))
    return out


def _statements(body: str) -> List[str]:
    """Top-level statements of a block body (a statement may span lines inside parentheses)."""
    out, cur, depth = [], [], 0
    for line in body.splitlines():
        if not line.strip() and depth == 0:
            continue
        cur.append(line.strip())
        depth += line.count("(") - line.count(")") + line.count("{") - line.count("}")
        if depth <= 0:
            out.append(" ".join(cur))
            cur, depth = [], 0
    if cur:
        out.append(" ".join(cur))
    return out


def variables(text: str, props: Dict[str, str]) -> Dict[str, str]:
    """Simple string assignments: `def x = '1'`, `val x = "1"`, `x = '1'` in `ext { }`,
    `ext.x = '1'`, `extra["x"] = "1"`, plus gradle.properties."""
    out = dict(props)
    for m in re.finditer(r"""(?m)(?:^|[{;])\s*(?:def|val|var|ext\.|extra\[\s*["'])?\s*([A-Za-z_][\w.]*)["']?\]?\s*=\s*["']([^"'$]+)["']""",
                         text):
        out[m.group(1).split(".")[-1]] = m.group(2)
    for m in re.finditer(r"""set\(\s*["'](\w+)["']\s*,\s*["']([^"'$]+)["']\s*\)""", text):
        out[m.group(1)] = m.group(2)
    return out


def _subst(s: str, vars_: Dict[str, str]) -> Optional[str]:
    """`$x` / `${x}` replaced; None if one cannot be."""
    def repl(m):
        key = (m.group(1) or m.group(2)).split(".")[-1]
        if key not in vars_:
            raise KeyError(key)
        return vars_[key]
    try:
        return re.sub(r"\$\{([^}]+)\}|\$([A-Za-z_]\w*)", repl, s)
    except KeyError:
        return None


# ---------------------------------------------------------------------------------------------
# the version catalog

def _accessor(alias: str) -> str:
    return re.sub(r"[-_.]", ".", alias).lower()


def read_catalog(text: str) -> Tuple[Dict[str, Tuple[str, Optional[str]]], Dict[str, List[str]]]:
    """libraries: accessor -> (group:artifact, version or None); bundles: accessor -> accessors."""
    data = tomllib.loads(text)
    versions = data.get("versions") or {}

    def version_of(v) -> Optional[str]:
        if isinstance(v, str):
            return v
        if isinstance(v, dict):
            if "ref" in v:
                return version_of(versions.get(v["ref"]))
            for k in ("strictly", "require", "prefer"):
                if isinstance(v.get(k), str):
                    return v[k]
        return None
    libs: Dict[str, Tuple[str, Optional[str]]] = {}
    for alias, spec in (data.get("libraries") or {}).items():
        if isinstance(spec, str):
            parts = spec.split(":")
            if len(parts) >= 2:
                libs[_accessor(alias)] = (f"{parts[0]}:{parts[1]}", parts[2] if len(parts) > 2 else None)
            continue
        if not isinstance(spec, dict):
            continue
        module = spec.get("module") or (f"{spec['group']}:{spec['name']}" if spec.get("group") and spec.get("name") else None)
        if not module:
            continue
        v = spec.get("version")
        if v is None and isinstance(spec.get("version.ref"), str):
            v = {"ref": spec["version.ref"]}
        libs[_accessor(alias)] = (module, version_of(v))
    bundles = {_accessor(b): [_accessor(x) for x in xs] for b, xs in (data.get("bundles") or {}).items()
               if isinstance(xs, list)}
    return libs, bundles


def find_catalog(build_dir: Path, root: Path) -> Optional[Path]:
    for d in [build_dir, *build_dir.parents]:
        cand = d / "gradle" / "libs.versions.toml"
        if cand.is_file():
            return cand
        if d == root or (d / "settings.gradle").is_file() or (d / "settings.gradle.kts").is_file():
            break
    return None


# ---------------------------------------------------------------------------------------------

_COORD = re.compile(r"""^["']([^"':@\s]+):([^"':@\s]+)(?::([^"':@\s]*))?(?::[^"'@\s]*)?(?:@\w+)?["']$""")
_MAP = re.compile(r"""\b(group|name|version)\s*[:=]\s*["']([^"']*)["']""")


def _declaration(stmt: str) -> Optional[Tuple[str, str]]:
    m = re.match(r"^([A-Za-z_]\w*)\s*(?:\(\s*(.*)\s*\)|\s+(.*))\s*(\{.*)?$", stmt)
    if not m:
        return None
    return m.group(1), (m.group(2) if m.group(2) is not None else m.group(3) or "").strip()


def parse_gradle(path: str, text: str, props: Optional[Dict[str, str]] = None,
                 catalog: Optional[str] = None) -> DependencyFile:
    df = DependencyFile(path, MAVEN, "manifest")
    clean = _strip_comments(text)
    vars_ = variables(clean, props or {})
    libs, bundles = read_catalog(catalog) if catalog else ({}, {})
    buildscript_spans = [(off, off + len(body) + 20) for body, off in _blocks(clean, "buildscript")]

    def add(name: str, version: Optional[str], dev: bool, spec: str = "") -> None:
        df.add(Package(MAVEN, name, version, direct=True, dev=dev, spec="" if version else spec))

    def coords(arg: str, dev: bool) -> None:
        arg = arg.strip()
        inner = re.match(r"^(?:platform|enforcedPlatform)\s*\(\s*(.*)\s*\)$", arg)
        if inner:
            arg = inner.group(1).strip()
        if re.match(rf"^({'|'.join(_NOT_DEPS)})\b", arg) or arg.startswith(("kotlin(", "gradlePlugin")):
            return
        ref = re.match(r"^libs\.([\w.]+?)(?:\.get\(\))?$", arg)
        if ref:
            acc = ref.group(1).lower()
            if acc.startswith("bundles."):
                for lib in bundles.get(acc[len("bundles."):], []):
                    if lib in libs:
                        add(libs[lib][0], libs[lib][1], dev, "catalog")
            elif acc in libs:
                add(libs[acc][0], libs[acc][1], dev, "catalog")
            return
        first = arg.split(",")[0].strip()
        c = _COORD.match(first)
        if c:
            name = _subst(f"{c.group(1)}:{c.group(2)}", vars_)
            version = _subst(c.group(3), vars_) if c.group(3) else None
            if name and "$" not in name:
                add(name, version if version and re.fullmatch(r"[\w.+-]+", version) else None, dev,
                    c.group(3) or "unversioned")
            return
        fields = dict(_MAP.findall(arg))
        if fields.get("group") and fields.get("name"):
            name = _subst(f"{fields['group']}:{fields['name']}", vars_)
            version = _subst(fields["version"], vars_) if fields.get("version") else None
            if name:
                add(name, version if version and re.fullmatch(r"[\w.+-]+", version) else None, dev,
                    fields.get("version", "unversioned"))

    for body, off in _blocks(clean, "dependencies"):
        in_buildscript = any(a <= off < b for a, b in buildscript_spans)
        for stmt in _statements(body):
            decl = _declaration(stmt)
            if not decl:
                continue
            config, arg = decl
            if config in ("dependencies", "constraints", "if", "else", "for", "def", "val", "var"):
                continue
            dev = in_buildscript or bool(_DEV_CONFIG.search(config))
            coords(arg, dev)
    return df


def gradle_properties(build_dir: Path, root: Path) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for d in reversed([build_dir, *build_dir.parents]):
        if root not in d.parents and d != root:
            continue
        p = d / "gradle.properties"
        if p.is_file():
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                m = re.match(r"^\s*([\w.]+)\s*[=:]\s*(.+?)\s*$", line)
                if m and not line.lstrip().startswith(("#", "!")):
                    out[m.group(1).split(".")[-1]] = m.group(2)
    return out
