"""C and C++ libraries copied into a repository (vendored), identified by what they declare.

A vendored copy has no manifest; what it does have is the library's own header, which states
its version (`#define ZLIB_VERSION "1.2.11"`, expat's `XML_MAJOR_VERSION` / `MINOR` / `MICRO`).
Each library Frame knows is a curated entry in `data/vendored.json`:

    header       the file that declares the version (one name, or several a release may use)
    version      `macro` (one string macro) or `parts` (macros joined with `.`), read from the
                 header's syntax tree (tree-sitter), never from text matched loosely
    companions   the library's own sources, relative to the header: one must be there, so a lone
                 header copied in to build against a system library is not a vendored library
    repo, tags   the upstream repository and its release-tag forms (`v{V}`, `curl-{V_}` with `.`
                 as `_`, `VER-{V-}` with `.` as `-`); `tests/test_sca_vendored.py` checks every form
                 against the tags OSV's own records list for that repository
    reference    the header upstream, where the macro is

The version is matched against OSV's GIT records by tag, as other C/C++ dependencies are.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from frame.sca.model import GIT, DependencyFile, Package

_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", "build", "dist", "target"}


@dataclass(frozen=True)
class Library:
    name: str
    repo: str
    tags: Tuple[str, ...]
    headers: Tuple[str, ...]
    macro: str
    parts: Tuple[str, ...]
    companions: Tuple[str, ...]
    reference: str


@lru_cache(maxsize=1)
def libraries() -> Tuple[Library, ...]:
    data = json.loads((Path(__file__).parent / "data" / "vendored.json").read_text())
    out = []
    for e in data["libraries"]:
        headers = e["header"] if isinstance(e["header"], list) else [e["header"]]
        tags = e["tag"] if isinstance(e["tag"], list) else [e["tag"]]
        out.append(Library(e["name"], e["repo"], tuple(tags), tuple(headers), e["version"].get("macro", ""),
                           tuple(e["version"].get("parts", ())), tuple(e["companions"]), e["reference"]))
    return tuple(out)


def tags_for(lib: Library, version: str) -> List[str]:
    return [t.replace("{V_}", version.replace(".", "_")).replace("{V-}", version.replace(".", "-"))
            .replace("{V}", version) for t in lib.tags]


@lru_cache(maxsize=1)
def _c_parser():
    import tree_sitter
    import tree_sitter_c
    language = tree_sitter.Language(tree_sitter_c.language())
    try:
        return tree_sitter.Parser(language)
    except TypeError:                                  # older bindings
        p = tree_sitter.Parser()
        p.set_language(language)
        return p


def defines(source: bytes) -> Dict[str, str]:
    """`#define NAME value` of a header, from its syntax tree (the first definition wins)."""
    tree = _c_parser().parse(source)
    out: Dict[str, str] = {}
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type == "preproc_def":
            name, value = node.child_by_field_name("name"), node.child_by_field_name("value")
            if name is not None and value is not None:
                key = name.text.decode("utf-8", "replace")
                out.setdefault(key, value.text.decode("utf-8", "replace").strip())
        stack.extend(reversed(node.children))
    return out


def _literal(value: str) -> Optional[str]:
    v = value.strip()
    while v.startswith("(") and v.endswith(")"):
        v = v[1:-1].strip()
    if len(v) >= 2 and v[0] == v[-1] == '"':
        return v[1:-1]
    return v if v.isdigit() else None


def version_of(lib: Library, source: bytes) -> Optional[str]:
    d = defines(source)
    if lib.macro:
        return _literal(d.get(lib.macro, "")) or None
    parts = [_literal(d.get(m, "")) for m in lib.parts]
    return ".".join(p for p in parts) if parts and all(p is not None and p.isdigit() for p in parts) else None


def _header_index() -> Dict[str, List[Library]]:
    index: Dict[str, List[Library]] = {}
    for lib in libraries():
        for h in lib.headers:
            index.setdefault(h, []).append(lib)
    return index


def header_names() -> frozenset:
    return frozenset(_header_index())


def _in_checkout(header: Path, root: Path) -> bool:
    """Inside a git checkout of its own below the root (a submodule: matched by its commit)."""
    for d in header.parents:
        if d == root or root not in d.parents:
            return False
        if (d / ".git").exists():
            return True
    return False


def identify(headers: Iterable[Path], root: Path) -> Tuple[List[DependencyFile], List[str]]:
    """The vendored libraries among candidate headers (files named like a known library's
    version header): one DependencyFile per header, the package named by its upstream
    repository, versioned by what the header declares."""
    root = Path(root).resolve()
    index = _header_index()
    files: List[DependencyFile] = []
    warnings: List[str] = []
    for header in sorted(Path(h).resolve() for h in headers):
        if header.name not in index or _in_checkout(header, root):
            continue
        rel = header.relative_to(root).as_posix()
        for lib in index[header.name]:
            if not any((header.parent / c).is_file() for c in lib.companions):
                continue                                  # a lone header is not a copy of the library
            try:
                version = version_of(lib, header.read_bytes())
            except OSError:
                continue
            df = DependencyFile(rel, GIT, "vendored")
            if version is not None and not re.fullmatch(r"\d+(\.\d+)*", version):
                # `8.6.0-DEV`, `1.2.11.1-motley`: a snapshot between releases, which no tag names
                warnings.append(f"{rel}: a vendored {lib.name} {version} is a development snapshot, not a "
                                "release; not matched")
                df.add(Package(GIT, lib.repo, version, direct=True, spec="vendored snapshot", repo=lib.repo))
            elif version is None:
                warnings.append(f"{rel}: a vendored {lib.name} whose version is not declared as expected; "
                                "not matched")
                df.add(Package(GIT, lib.repo, None, direct=True, spec="vendored (version unknown)", repo=lib.repo))
            else:
                df.add(Package(GIT, lib.repo, version, direct=True, repo=lib.repo, tags=tags_for(lib, version)))
            files.append(df)
    return files, warnings


def find_vendored(root: Path, excluded: Iterable[str] = ()) -> Tuple[List[DependencyFile], List[str]]:
    """Walk `root` for vendored libraries (`identify` on every candidate header)."""
    root = Path(root)
    names = header_names()
    skip = _SKIP_DIRS | set(excluded)
    found: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in skip and not d.startswith("."))
        found += [Path(dirpath) / n for n in filenames if n in names]
    return identify(found, root)


__all__: Sequence[str] = ["Library", "libraries", "tags_for", "defines", "version_of", "header_names", "identify",
                          "find_vendored"]
