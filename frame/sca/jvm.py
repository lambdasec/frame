"""Resolved JVM dependency graphs, read from the reports Maven and Gradle write themselves.

A `pom.xml` only names direct dependencies, and most Java vulnerabilities arrive
transitively; resolving them means Maven's own mediation (parent POMs, imported BOMs,
profiles, nearest-wins), so Frame reads the build tool's answer instead of re-deriving it:

    mvn dependency:tree -DoutputFile=maven_dep_tree.txt           # text (or -DoutputType=json)
    gradle dependencies > gradle-dependencies.txt

`frame deps --resolve` runs those commands itself (see `resolve.py`).
"""

from __future__ import annotations

import json
import re
from typing import Dict, List, Optional, Tuple

from frame.sca.model import MAVEN, DependencyFile, Package

# file names the reports are read from when they sit in a scanned directory
MAVEN_TREE_FILES = ("maven_dep_tree.txt", "dependency-tree.txt", "maven-dependency-tree.txt")
MAVEN_TREE_JSON_FILES = ("maven_dep_tree.json", "dependency-tree.json", "maven-dependency-tree.json")
GRADLE_REPORT_FILES = ("gradle-dependencies.txt", "gradle_dependencies.txt")

_LOG_PREFIX = re.compile(r"^\[(?:INFO|WARNING|DEBUG)\]\s?")
_MAVEN_BRANCH = re.compile(r"^((?:[| ]  )*)[+\\]- (.*)$")


def _maven_coords(text: str) -> Optional[Tuple[str, str, Optional[str], bool]]:
    """`g:a:type[:classifier]:version[:scope]` -> (name, version, scope, optional)."""
    optional = "(optional)" in text
    token = text.split()[0] if text.split() else ""
    parts = token.split(":")
    if len(parts) < 4:
        return None
    name = f"{parts[0]}:{parts[1]}"
    if len(parts) == 4:                     # root: g:a:type:version
        return name, parts[3], None, optional
    if len(parts) == 5:                     # g:a:type:version:scope
        return name, parts[3], parts[4], optional
    return name, parts[4], parts[5], optional   # g:a:type:classifier:version:scope


def parse_maven_tree(path: str, text: str) -> DependencyFile:
    """`mvn dependency:tree` text output; several modules (`-DappendOutput=true`) may follow
    each other, each starting at a root line. The modules themselves are not packages."""
    df = DependencyFile(path, MAVEN, "resolved")
    stack: List[Optional[str]] = []         # key per depth; None for the module root
    for raw in text.splitlines():
        line = _LOG_PREFIX.sub("", raw.rstrip())
        if not line.strip():
            continue
        m = _MAVEN_BRANCH.match(line)
        if m is None:
            if _maven_coords(line.strip()) and ":" in line and " " not in line.strip():
                stack = [None]              # a module root
            continue
        if not stack:
            continue
        depth = len(m.group(1)) // 3 + 1
        coords = _maven_coords(m.group(2))
        if coords is None:
            continue
        name, version, scope, _ = coords
        pkg = df.add(Package(MAVEN, name, version, direct=depth == 1, dev=scope == "test"))
        del stack[depth:]
        parent = stack[depth - 1] if depth - 1 < len(stack) else None
        if parent:
            df.edge(parent, pkg.key)
        stack.append(pkg.key)
    return df


def parse_maven_tree_json(path: str, text: str) -> DependencyFile:
    """`mvn dependency:tree -DoutputType=json` (maven-dependency-plugin 3.7+). A multi-module
    build with `-DappendOutput=true` writes one JSON document per module, back to back."""
    df = DependencyFile(path, MAVEN, "resolved")
    roots: list = []
    decoder, i = json.JSONDecoder(), 0
    while True:
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            break
        try:
            data, i = decoder.raw_decode(text, i)
        except ValueError as e:
            from frame.sca.lockfiles import LockfileError
            raise LockfileError(f"{path}: {e}") from e
        roots.extend(data if isinstance(data, list) else [data])

    def walk(node: dict, parent: Optional[str], depth: int) -> None:
        for child in node.get("children") or []:
            if not isinstance(child, dict) or not child.get("groupId") or not child.get("version"):
                continue
            pkg = df.add(Package(MAVEN, f"{child['groupId']}:{child['artifactId']}", str(child["version"]),
                                 direct=depth == 1, dev=child.get("scope") == "test"))
            if parent:
                df.edge(parent, pkg.key)
            walk(child, pkg.key, depth + 1)

    for root in roots:
        if isinstance(root, dict):
            walk(root, None, 1)
    return df


_GRADLE_CONFIG = re.compile(r"^([A-Za-z][\w-]*)(?: - .*)?$")
_GRADLE_BRANCH = re.compile(r"^((?:[| ]    )*)[+\\]--- (.*)$")


def _gradle_entry(text: str) -> Tuple[Optional[str], Optional[str], str]:
    """-> (name, resolved version, marker); name None for a project node."""
    marker = ""
    for m in (" (*)", " (c)", " (n)", " FAILED"):
        if text.endswith(m):
            marker, text = m.strip(" ()"), text[: -len(m)]
            break
    if text.startswith("project "):
        return None, None, "project"
    requested, _, resolved = text.partition(" -> ")
    parts = requested.split(":")
    if len(parts) < 2:
        return None, None, "unknown"
    name = f"{parts[0]}:{parts[1]}"
    version = resolved.strip() if resolved else (parts[2] if len(parts) >= 3 else None)
    if version:
        version = version.split()[0]
    if version and version.startswith("{"):       # `{strictly 1.0}` without a resolution
        version = None
    return name, version, marker


def parse_gradle_report(path: str, text: str) -> DependencyFile:
    """`gradle dependencies` output: one tree per configuration (and per project when several
    `:p:dependencies` tasks ran). A package is dev only if every configuration it appears in
    is a test configuration. Unresolved (`(n)`) and constraint (`(c)`) lines are skipped."""
    df = DependencyFile(path, MAVEN, "resolved")
    test_config = False
    prod: Dict[str, bool] = {}
    stack: List[Optional[str]] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        m = _GRADLE_BRANCH.match(line)
        if m is None:
            c = _GRADLE_CONFIG.match(line.strip())
            if c and not line.startswith((" ", "|")):
                test_config = "test" in c.group(1).lower()
                stack = []
            continue
        depth = len(m.group(1)) // 5 + 1
        name, version, marker = _gradle_entry(m.group(2).strip())
        del stack[depth - 1:]
        parent = next((k for k in reversed(stack) if k), None)
        if marker in ("n", "c", "FAILED", "unknown") or (name is not None and not version):
            stack.append(None)
            continue
        if name is None:                   # `project :lib`: its dependencies hang off the parent
            stack.append(parent)
            continue
        pkg = df.add(Package(MAVEN, name, version, direct=parent is None))
        if not test_config:
            prod[pkg.key] = True
        if parent:
            df.edge(parent, pkg.key)
        stack.append(pkg.key)
    for k, p in df.packages.items():
        p.dev = not prod.get(k, False)
    return df
