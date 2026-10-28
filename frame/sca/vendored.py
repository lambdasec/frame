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
    exclude_tags: Tuple[str, ...] = ()      # tags a form misreads (`LIBXML2_6_0` is 2.6.0, not 6.0)


@lru_cache(maxsize=1)
def libraries() -> Tuple[Library, ...]:
    data = json.loads((Path(__file__).parent / "data" / "vendored.json").read_text())
    out = []
    for e in data["libraries"]:
        headers = e["header"] if isinstance(e["header"], list) else [e["header"]]
        tags = e["tag"] if isinstance(e["tag"], list) else [e["tag"]]
        out.append(Library(e["name"], e["repo"], tuple(tags), tuple(headers), e["version"].get("macro", ""),
                           tuple(e["version"].get("parts", ())), tuple(e["companions"]), e["reference"],
                           tuple(e.get("exclude_tags", {}))))
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
    try:
        _c_parser()
    except ImportError:                               # `frame deps` without the scan extra
        candidates = [h for h in headers if Path(h).name in index]
        if candidates:
            warnings.append(f"{len(candidates)} possible vendored C/C++ header(s) not read: identifying them needs "
                            "the tree-sitter grammars (pip install \"frame-security[scan]\")")
        return files, warnings
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


# ---------------------------------------------------------------------------------------------
# copies without their version header: file fingerprints
#
# A source file copied unchanged has the git blob id upstream's tree gives it at every release
# that shipped it, so the release is read from upstream's own trees: no version is guessed.
# `data/vendored-fingerprints.json.gz` (generated by `build_fingerprints`) holds, per library,
# its release tags and, per source file name, which releases shipped each blob.

FINGERPRINTS = Path(__file__).parent / "data" / "vendored-fingerprints.json.gz"
BLOB_DIGITS = 16                       # of a blob id: 64 bits, against ~30,000 blobs in all


def _runs(indices: List[int]) -> str:
    """[3, 4, 5, 9] -> "3-5,9" (sorted indices)."""
    spans: List[List[int]] = []
    for i in indices:
        if spans and spans[-1][1] == i - 1:
            spans[-1][1] = i
        else:
            spans.append([i, i])
    return ",".join(str(x) if x == y else f"{x}-{y}" for x, y in spans)


def _indices(runs: str) -> set:
    out: set = set()
    for part in runs.split(","):
        a, _, b = part.partition("-")
        out.update(range(int(a), int(b or a) + 1))
    return out


def _tag_versions(lib: Library, tags: Iterable[str]) -> Dict[str, str]:
    """Release tag -> version, for the tags one of the library's forms names."""
    out: Dict[str, str] = {}
    for form in lib.tags:
        rx = re.compile("^" + re.escape(form).replace(re.escape("{V_}"), r"(?P<u>\d+(?:_\d+)+)")
                        .replace(re.escape("{V-}"), r"(?P<d>\d+(?:-\d+)+)")
                        .replace(re.escape("{V}"), r"(?P<v>\d+(?:\.\d+)+)") + "$")
        for t in tags:
            m = rx.match(t)
            if m and t not in out and t not in lib.exclude_tags:
                g = m.groupdict()
                out[t] = g.get("v") or (g.get("u") or "").replace("_", ".") or (g.get("d") or "").replace("-", ".")
    return out


def build_fingerprints(clones: Path, names: Optional[Iterable[str]] = None) -> dict:
    """Clone (blobless, bare) each library's repository under `clones` and record, for every
    release tag, the blob ids of the `.c` files in the directories holding its companions."""
    import subprocess
    from datetime import date
    out: dict = {"_source": {"generated": f"{date.today().isoformat()} by frame.sca.vendored.build_fingerprints",
                             "from": "each library's own repository: git ls-tree at its release tags"},
                 "libraries": {}}
    for lib in libraries():
        if names is not None and lib.name not in set(names):
            continue
        repo = Path(clones) / f"{lib.name}.git"
        if not repo.is_dir():
            subprocess.run(["git", "clone", "-q", "--bare", "--filter=blob:none", f"https://{lib.repo}", str(repo)],
                           check=True)
        tags = subprocess.run(["git", "-C", str(repo), "tag"], capture_output=True, text=True, check=True).stdout.split()
        versions = _tag_versions(lib, tags)
        companions = {Path(c).name for c in lib.companions}
        by_version: Dict[str, List[str]] = {}
        for tag, v in versions.items():
            by_version.setdefault(v, []).append(tag)    # Mbed TLS tags a release `v2.7.16` and `mbedtls-2.7.16`
        releases: List[str] = []
        files: Dict[str, Dict[str, set]] = {}
        for version in sorted(by_version, key=lambda v: [int(x) for x in v.split(".")]):
            shipped: Dict[str, set] = {}
            for tag in sorted(by_version[version]):
                tree = subprocess.run(["git", "-C", str(repo), "ls-tree", "-r", tag], capture_output=True, text=True,
                                      check=True).stdout.splitlines()
                entries = [(line.split("\t", 1)[1], line.split()[2]) for line in tree if "\t" in line]
                dirs = {os.path.dirname(p) for p, _ in entries if os.path.basename(p) in companions}
                for p, blob in entries:     # no companion: generated sources (sqlite's amalgamation)
                    if p.endswith(".c") and os.path.dirname(p) in dirs:
                        shipped.setdefault(os.path.basename(p), set()).add(blob[:BLOB_DIGITS])
            if not shipped:
                continue
            index = len(releases)
            releases.append(version)
            for name, blobs in shipped.items():
                for blob in blobs:
                    files.setdefault(name, {}).setdefault(blob, set()).add(index)
        if releases:
            out["libraries"][lib.name] = {"releases": releases,
                                          "files": {n: {b: _runs(sorted(ix)) for b, ix in sorted(bs.items())}
                                                    for n, bs in sorted(files.items())}}
    return out


@lru_cache(maxsize=1)
def fingerprints() -> Dict[str, dict]:
    import gzip
    if not FINGERPRINTS.is_file():
        return {}
    return json.loads(gzip.decompress(FINGERPRINTS.read_bytes()))["libraries"]


def blob_id(data: bytes) -> str:
    """git's blob id of a file's content (`git hash-object`)."""
    import hashlib
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def fingerprint_names() -> frozenset:
    return frozenset(n for lib in fingerprints().values() for n in lib["files"])


def identify_by_fingerprint(sources: Iterable[Path], root: Path,
                            identified: Iterable[DependencyFile] = ()) -> Tuple[List[DependencyFile], List[str]]:
    """Vendored libraries among `.c` files named like a known library's sources, by their blob
    ids. Files of one library in one directory are one copy: the releases that shipped every
    one of them. A copy whose version header was found (`identified`) is left to that."""
    root = Path(root).resolve()
    data = fingerprints()
    by_name = {lib.name: lib for lib in libraries()}
    groups: Dict[Tuple[str, Path], List[Tuple[str, set]]] = {}
    covered = set()
    for df in identified:
        if df.kind != "vendored":
            continue
        header = root / df.path
        for lib in libraries():
            if header.name in lib.headers:
                covered |= {((header.parent / c).parent.resolve(), lib.name) for c in lib.companions}
    for path in sorted(Path(p).resolve() for p in sources):
        if _in_checkout(path, root):
            continue
        try:
            content = path.read_bytes()
        except OSError:
            continue
        ids = {blob_id(content)[:BLOB_DIGITS]}
        if b"\r\n" in content:                                  # checked out with Windows line endings
            ids.add(blob_id(content.replace(b"\r\n", b"\n"))[:BLOB_DIGITS])
        for name, lib in data.items():
            blobs = lib["files"].get(path.name, {})
            hit = next((blobs[i] for i in ids if i in blobs), None)
            if hit is not None and (path.parent, name) not in covered:
                groups.setdefault((name, path.parent), []).append((path.name, _indices(hit)))
    files: List[DependencyFile] = []
    warnings: List[str] = []
    for (name, d), hits in sorted(groups.items()):
        lib = by_name[name]
        if not {Path(c).name for c in lib.companions} & {n for n, _ in hits}:
            continue                                     # none of the library's own core sources
        rel = d.relative_to(root).as_posix() if d != root else "."
        common = set.intersection(*(s for _, s in hits))
        if not common:
            warnings.append(f"{rel}: {len(hits)} file(s) of {name} from different releases (a mixed or partly "
                            "updated copy); not matched")
            continue
        versions = [data[name]["releases"][i] for i in sorted(common)]
        df = DependencyFile(rel, GIT, "vendored")
        spec = f"vendored, {len(hits)} file(s) equal to upstream's"
        if len(versions) == 1:
            df.add(Package(GIT, lib.repo, versions[0], direct=True, spec=spec, repo=lib.repo,
                           tags=tags_for(lib, versions[0])))
        else:
            shown = versions if len(versions) <= 4 else versions[:2] + ["..."] + versions[-1:]
            df.add(Package(GIT, lib.repo, " or ".join(shown), direct=True, spec=spec, repo=lib.repo,
                           alternatives=[tags_for(lib, v) for v in versions]))
        files.append(df)
    return files, warnings


__all__: Sequence[str] = ["Library", "libraries", "tags_for", "defines", "version_of", "header_names", "identify",
                          "find_vendored", "build_fingerprints", "fingerprints", "blob_id", "fingerprint_names",
                          "identify_by_fingerprint"]
