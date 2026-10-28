"""Readers for C and C++ dependency declarations. Each dependency carries its upstream
repository (`cpp.normalize_repo`) and the release tag its version is, when that is certain:

    conan.lock (v1, v2), conanfile.txt, conanfile.py   tag from the recipe's own source URL
    vcpkg.json (+ overrides), vcpkg_installed status   tag from the port's REF pattern
    .gitmodules                                         the pinned commit; its tag via git
    CMakeLists.txt  FetchContent_Declare / ExternalProject_Add / CPMAddPackage

A bare commit, a version range or a `${VARIABLE}` gives no tag, and is never guessed. A submodule
pinned to an untagged commit is matched by commit instead, against the advisories' GIT commit
ranges on the submodule's own history (`frame.sca.gitrange`). Nothing here runs a build; `git`
is only asked, read-only, which commit a submodule is pinned to, whether that commit carries a
tag, and which commits are ancestors of which.
"""

from __future__ import annotations

import configparser
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

from frame.sca.cmake import commands
from frame.sca.cpp import normalize_repo, repo_and_tags, tag_from_url
from frame.sca.model import CONAN, GIT, VCPKG, DependencyFile, Package

_CONAN_REF = re.compile(r"^([A-Za-z0-9_.+-]+)/([^@#\s]+)")


def _conan_package(ref: str, dev: bool = False, direct: Optional[bool] = None) -> Optional[Package]:
    m = _CONAN_REF.match(ref.strip())
    if not m:
        return None
    name, version = m.group(1), m.group(2)
    if version.startswith("["):                       # a version range
        repo, _ = repo_and_tags("conan", name, None)
        return Package(CONAN, name, None, direct=direct, dev=dev, spec=version, repo=repo or "")
    repo, tags = repo_and_tags("conan", name, version)
    return Package(CONAN, name, version, direct=direct, dev=dev, repo=repo or "", tags=tags)


def parse_conan_lock(path: str, text: str) -> DependencyFile:
    from frame.sca.lockfiles import LockfileError
    df = DependencyFile(path, CONAN, "lockfile")
    try:
        data = json.loads(text)
    except ValueError as e:
        raise LockfileError(f"{path}: {e}") from e
    if "graph_lock" in data:                            # Conan 1: a graph of nodes
        nodes = (data["graph_lock"] or {}).get("nodes") or {}
        keys = {}
        for nid, node in nodes.items():
            ref = node.get("ref") or node.get("pref", "").split(":", 1)[0]
            pkg = _conan_package(ref, dev=node.get("context") == "build") if ref else None
            if pkg is not None:
                keys[nid] = df.add(pkg).key
        root = nodes.get("0") or {}
        for nid, node in nodes.items():
            for child in (node.get("requires") or []) + (node.get("build_requires") or []):
                if nid in keys and str(child) in keys:
                    df.edge(keys[nid], keys[str(child)])
        direct = {str(c) for c in (root.get("requires") or []) + (root.get("build_requires") or [])}
        for nid, key in keys.items():
            df.packages[key].direct = nid in direct
        return df
    for section, dev in (("requires", False), ("build_requires", True), ("python_requires", True),
                         ("config_requires", True)):
        for ref in data.get(section) or []:
            pkg = _conan_package(str(ref), dev=dev)
            if pkg is not None:
                df.add(pkg)
    return df


def parse_conanfile_txt(path: str, text: str) -> DependencyFile:
    df = DependencyFile(path, CONAN, "manifest")
    section = ""
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            continue
        if line and section in ("requires", "tool_requires", "build_requires", "test_requires"):
            pkg = _conan_package(line, dev=section != "requires", direct=True)
            if pkg is not None:
                df.add(pkg)
    return df


def parse_conanfile_py(path: str, text: str) -> DependencyFile:
    """`requires = "zlib/1.3"` (or a tuple / list) and `self.requires("zlib/1.3")` calls, read
    from the syntax tree; nothing is executed."""
    from frame.sil.source_facts import _parse, _text, _walk
    df = DependencyFile(path, CONAN, "manifest")
    root = _parse(text, "python")
    if root is None:
        return df
    kinds = {"requires": False, "tool_requires": True, "build_requires": True, "test_requires": True}
    for n in _walk(root):
        refs: List[Tuple[str, bool]] = []
        if n.type == "assignment" and _text(n.child_by_field_name("left")) in kinds:
            right = n.child_by_field_name("right")
            dev = kinds[_text(n.child_by_field_name("left"))]
            items = [right] if right is not None and right.type == "string" else \
                (right.named_children if right is not None else [])
            refs = [(_text(s).strip("'\""), dev) for s in items if s.type == "string"]
        elif n.type == "call":
            fn = _text(n.child_by_field_name("function"))
            if fn.startswith("self.") and fn[5:] in kinds:
                args = n.child_by_field_name("arguments")
                first = args.named_children[0] if args is not None and args.named_children else None
                if first is not None and first.type == "string":
                    refs = [(_text(first).strip("'\""), kinds[fn[5:]])]
        for ref, dev in refs:
            pkg = _conan_package(ref, dev=dev, direct=True)
            if pkg is not None:
                df.add(pkg)
    return df


def parse_vcpkg_json(path: str, text: str) -> DependencyFile:
    from frame.sca.lockfiles import LockfileError
    df = DependencyFile(path, VCPKG, "manifest")
    try:
        data = json.loads(text)
    except ValueError as e:
        raise LockfileError(f"{path}: {e}") from e
    overrides = {o.get("name"): str(o.get("version") or o.get("version-string") or o.get("version-semver") or "")
                 for o in data.get("overrides") or [] if isinstance(o, dict)}
    baseline = data.get("builtin-baseline", "")
    for dep in data.get("dependencies") or []:
        name = dep if isinstance(dep, str) else (dep.get("name") if isinstance(dep, dict) else None)
        if not name:
            continue
        version = overrides.get(name) or None
        repo, tags = repo_and_tags("vcpkg", name, version)
        spec = "" if version else (f">={dep['version>=']}" if isinstance(dep, dict) and dep.get("version>=")
                                   else f"baseline {baseline[:12]}" if baseline else "")
        df.add(Package(VCPKG, name, version, direct=True, dev=isinstance(dep, dict) and bool(dep.get("host")),
                       spec=spec, repo=repo or "", tags=tags))
    return df


def parse_vcpkg_status(path: str, text: str) -> DependencyFile:
    """`vcpkg_installed/vcpkg/status`: what vcpkg installed, exact versions."""
    df = DependencyFile(path, VCPKG, "lockfile")
    for para in re.split(r"\n\s*\n", text):
        fields = dict(re.findall(r"^([A-Za-z-]+):\s*(.*)$", para, re.M))
        if not fields.get("Package") or not fields.get("Version") or "install ok installed" not in fields.get("Status", ""):
            continue
        if fields.get("Feature"):
            continue                                    # a feature of a package already listed
        name, version = fields["Package"], fields["Version"]
        repo, tags = repo_and_tags("vcpkg", name, version)
        df.add(Package(VCPKG, name, version, repo=repo or "", tags=tags))
    return df


def _git(root: Path, *args: str) -> Optional[str]:
    if shutil.which("git") is None:
        return None
    try:
        out = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return out.stdout.strip() if out.returncode == 0 else None


def parse_gitmodules(path: str, text: str, root: Optional[Path] = None) -> DependencyFile:
    df = DependencyFile(path, GIT, "manifest")
    cp = configparser.ConfigParser(interpolation=None)
    try:
        cp.read_string(text)
    except configparser.Error:
        return df
    base = (root / Path(path).parent) if root is not None else None
    for section in cp.sections():
        url, sub = cp.get(section, "url", fallback=""), cp.get(section, "path", fallback="")
        repo = normalize_repo(url)
        if not repo or not sub:
            continue
        commit = tag = None
        if base is not None:
            ls = _git(base, "ls-tree", "HEAD", sub)
            m = re.search(r"\bcommit\s+([0-9a-f]{40})", ls or "")
            commit = m.group(1) if m else None
            if commit and (base / sub / ".git").exists():
                tag = _git(base / sub, "describe", "--tags", "--exact-match", commit)
        checkout = base / sub if base is not None and commit and (base / sub / ".git").exists() else None
        df.add(Package(GIT, repo, tag or (commit[:12] if commit else None), direct=True,
                       spec="" if (tag or commit) else "submodule (commit unknown)", repo=repo,
                       tags=[tag] if tag else [], commit=commit or "",
                       checkout=str(checkout.resolve()) if checkout else ""))
    return df


def parse_cmake(path: str, text: str) -> DependencyFile:
    df = DependencyFile(path, GIT, "manifest")
    for cmd in commands(text):
        repo = tag = None
        if cmd.name in ("fetchcontent_declare", "externalproject_add"):
            git_repo, git_tag, url = cmd.keyword("GIT_REPOSITORY"), cmd.keyword("GIT_TAG"), cmd.keyword("URL")
            if git_repo:
                repo = normalize_repo(git_repo)
                tag = git_tag
            elif url:
                repo, tag = normalize_repo(url), tag_from_url(url)
        elif cmd.name == "cpmaddpackage":
            short = cmd.args[0] if len(cmd.args) == 1 else None
            if short and short.startswith(("gh:", "gl:")) and "@" in short:   # "gh:owner/repo@1.2.3" or "#tag"
                spec_, _, ver = short[3:].partition("@")
                ver, _, explicit = ver.partition("#")
                host = "github.com" if short.startswith("gh:") else "gitlab.com"
                repo = normalize_repo(f"https://{host}/{spec_}")
                tag = explicit or (f"v{ver}" if ver else None)                 # CPM's default tag is v${VERSION}
            else:
                gh, gl, git_repo = cmd.keyword("GITHUB_REPOSITORY"), cmd.keyword("GITLAB_REPOSITORY"), \
                    cmd.keyword("GIT_REPOSITORY")
                repo = normalize_repo(f"https://github.com/{gh}") if gh else \
                    normalize_repo(f"https://gitlab.com/{gl}") if gl else normalize_repo(git_repo or "")
                tag = cmd.keyword("GIT_TAG") or (f"v{cmd.keyword('VERSION')}" if cmd.keyword("VERSION") else None)
        if not repo:
            continue
        if tag and ("${" in tag or re.fullmatch(r"[0-9a-f]{7,40}", tag)):
            version, tags = (None if "${" in tag else tag), []                 # a variable or a commit: no tag
        else:
            version, tags = tag, ([tag] if tag else [])
        df.add(Package(GIT, repo, version, direct=True, spec="" if version else (tag or "unpinned"),
                       repo=repo, tags=tags))
    return df
