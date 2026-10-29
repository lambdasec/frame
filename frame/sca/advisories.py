"""Advisories: build the dataset from OSV exports, load it from the cache, and match a
dependency graph against it.

The dataset is a knowledge-base revision of its own (default `hf:lambdasec/frame-advisories`,
or `FRAME_ADVISORIES_SOURCE`), laid out like `frame-kb` (manifest.json with every file's
SHA-256) and fetched by the same client, but rebuilt daily: packs are pinned per project, while
advisories should be current. Each ecosystem is one gzip'd table (`osv.compact`), so a pull
fetches only the ecosystems a project uses. Matching never goes to the network.
"""

from __future__ import annotations

import gzip
import json
import os
import tempfile
import zipfile
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence

import hashlib

from frame.sca.model import (CARGO, CONAN, GIT, GO, HEX, MAVEN, NPM, NUGET, PACKAGIST, PUB, PYPI, RUBYGEMS, SWIFT, VCPKG,
                             DependencyFile, normalize_name)
from frame.sca.osv import (DISTRO_FAMILIES, SCHEMA, entries, fixed_versions, git_entries, hoist_summaries,
                           is_affected, restore_summaries, table)

DEFAULT_SOURCE = "hf:lambdasec/frame-advisories"
ECOSYSTEMS = (PYPI, NPM, MAVEN, NUGET, GO, CARGO, SWIFT, RUBYGEMS, PACKAGIST, PUB, HEX)
# C/C++ packages are matched against GIT advisories (by repository), sharded so a project
# pulls only the repositories it depends on
CPP_ECOSYSTEMS = (CONAN, VCPKG, GIT)
GIT_SHARDS = 256


def git_shard(repo: str) -> str:
    return f"advisories/GIT/{hashlib.sha256(repo.encode()).hexdigest()[:2]}.json.gz"


SOURCE_POINTER = "advisories-source"


def source() -> str:
    """FRAME_ADVISORIES_SOURCE, else the source the last `frame kb pull --advisories` used (so
    a pull from a mirror or a directory is what later reads use), else the public dataset."""
    env = os.environ.get("FRAME_ADVISORIES_SOURCE")
    if env:
        return env
    from frame.kb.store import cache_root
    try:
        last = (cache_root() / SOURCE_POINTER).read_text().strip()
    except OSError:
        last = ""
    return last or DEFAULT_SOURCE


def remember_source(src: str) -> None:
    from frame.kb.store import cache_root
    p = cache_root() / SOURCE_POINTER
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(src + "\n")


def pull_hint(missing: Iterable[str]) -> str:
    """The command that caches what is missing: an image's distribution release is not a
    project ecosystem, so it is named."""
    distro = sorted(e for e in missing if e.split(":", 1)[0] in DISTRO_FAMILIES)
    joined = ",".join(distro)
    if " " in joined:
        joined = f'"{joined}"'                         # `Rocky Linux:9` must stay one shell word
    return "frame kb pull --advisories" + (f" --ecosystems {joined}" if distro else "")


def table_path(ecosystem: str) -> str:
    # Debian:12 -> Debian_12, Rocky Linux:9 -> Rocky_Linux_9 (portable names)
    return f"advisories/{ecosystem.replace(':', '_').replace(' ', '_')}.json.gz"


def functions_path(ecosystem: str) -> str:
    return f"functions/{ecosystem}.json.gz"


def _gz_json(obj) -> bytes:
    raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return gzip.compress(raw, compresslevel=9, mtime=0)                 # reproducible bytes


# ---------------------------------------------------------------------------------------------
# building

def _records(inputs: Sequence[Path]) -> Iterator[dict]:
    """OSV records from `all.zip` exports, directories of `<id>.json` files, or single files."""
    for p in inputs:
        p = Path(p)
        if p.is_dir():
            for f in sorted(p.rglob("*.json")):
                yield from _load_json(f.read_bytes(), str(f))
        elif p.suffix == ".zip":
            with zipfile.ZipFile(p) as z:
                for name in sorted(z.namelist()):
                    if name.endswith(".json"):
                        yield from _load_json(z.read(name), f"{p}:{name}")
        else:
            yield from _load_json(p.read_bytes(), str(p))


class _Spill:
    """Entries kept on disk by key (an ecosystem, a GIT shard) while records are read: buffered,
    appended in batches as gzip members (no file stays open, so 350 keys need no 350 handles),
    read back one key at a time in the order they were added."""

    BATCH = 50_000

    def __init__(self, root: Path):
        self.root, self.paths = root, {}
        self.buffered: Dict[tuple, List[str]] = {}
        self.count = 0

    def keys(self) -> List[tuple]:
        return list(self.paths)

    def add(self, key: tuple, name: str, entry: dict) -> None:
        if key not in self.paths:
            self.paths[key] = self.root / f"{len(self.paths)}.jsonl.gz"
        self.buffered.setdefault(key, []).append(json.dumps([name, entry], separators=(",", ":")))
        self.count += 1
        if self.count >= self.BATCH:
            self.flush()

    def flush(self) -> None:
        for key, lines in self.buffered.items():
            with gzip.open(self.paths[key], "at", compresslevel=1, encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
        self.buffered, self.count = {}, 0

    def read(self, key: tuple) -> Dict[str, List[dict]]:
        """The key's entries by name, in the order added; a summary several entries share (one
        record naming many packages) is one string again. The file is removed."""
        out: Dict[str, List[dict]] = {}
        shared: Dict[str, str] = {}
        path = self.paths[key]
        with gzip.open(path, "rt", encoding="utf-8") as f:
            for line in f:
                name, entry = json.loads(line)
                if isinstance(entry.get("summary"), str):
                    entry["summary"] = shared.setdefault(entry["summary"], entry["summary"])
                out.setdefault(name, []).append(entry)
        path.unlink()
        return out


def _load_json(data: bytes, origin: str) -> Iterator[dict]:
    try:
        doc = json.loads(data)
    except ValueError:
        return
    if isinstance(doc, list):
        yield from (d for d in doc if isinstance(d, dict))
    elif isinstance(doc, dict):
        yield from (doc.get("vulns") if isinstance(doc.get("vulns"), list) else [doc])


# what `frame kb mine-functions --out DIR` writes besides its per-ecosystem tables
MINER_REPORTS = ("needs-curation.json", "progress.json")


def build_advisories(inputs: Sequence[Path], out: Path, revision: str,
                     ecosystems: Optional[Iterable[str]] = None, functions_dir: Optional[Path] = None,
                     mitigations_dir: Optional[Path] = None) -> Path:
    """Lay out an advisories revision: `advisories/<ecosystem>.json.gz` per ecosystem plus
    `manifest.json` (same format as `frame kb build`). With `functions_dir`, Frame's own
    vulnerable-function data (`<Ecosystem>.json`: advisory id -> [{"id", "source"}], curated or
    derived from fix commits) is shipped beside it as `functions/<ecosystem>.json.gz`. With
    `mitigations_dir`, curated configuration mitigations (`<Ecosystem>.json`, validated by
    `frame.sca.mitigations.check`) are shipped as `mitigations/<ecosystem>.json.gz`."""
    import re
    from frame.kb.store import KBError, MANIFEST, _sha256
    from frame.kb.store import SCHEMA as KB_SCHEMA
    if not re.fullmatch(r"[A-Za-z0-9._-]+", revision):
        raise KBError(f"invalid revision id {revision!r}")
    wanted = list(ecosystems) if ecosystems else list(ECOSYSTEMS) + [GIT]
    with_git = GIT in wanted
    wanted = [e for e in wanted if e != GIT]
    out = Path(out)
    files: Dict[str, dict] = {}
    # One pass over the records, each entry spilled to disk under its ecosystem (or its GIT
    # repository's shard), then one table at a time: memory is the largest table's, not every
    # ecosystem's at once (a daily build reads ~100 ecosystems and 256 shards). An ecosystem's
    # records may come from several inputs (a record naming PyPI and npm is in both exports), so a
    # table is built only after every input was read.
    with tempfile.TemporaryDirectory(prefix="frame-advisories-") as spill_dir:
        spill = _Spill(Path(spill_dir))
        for rec in _records(inputs):                          # raw records are not kept
            for eco, name, entry in entries(rec, wanted):
                spill.add(("eco", eco), name, entry)
            if with_git:
                for repo, entry in git_entries(rec):
                    spill.add(("git", git_shard(repo)), repo, entry)
        spill.flush()
        for key in sorted(k for k in spill.keys() if k[0] == "eco"):   # distribution releases as read
            eco = key[1]
            tbl = table(eco, spill.read(key))
            if not tbl["packages"]:
                continue
            tbl["revision"] = revision
            data = _gz_json(hoist_summaries(tbl))
            rel = table_path(eco)
            target = out / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            files[rel] = {"sha256": _sha256(data), "size": len(data), "language": eco.lower(),
                          "kind": "advisories", "name": eco,
                          "advisories": sum(len(v) for v in tbl["packages"].values())}
        for key in sorted(k for k in spill.keys() if k[0] == "git"):
            rel = key[1]
            by_repo = spill.read(key)
            repos = {repo: table(GIT, {repo: by_repo.pop(repo)})["packages"][repo] for repo in sorted(by_repo)}
            data = _gz_json({"schema": SCHEMA, "ecosystem": GIT, "revision": revision, "packages": repos})
            (out / rel).parent.mkdir(parents=True, exist_ok=True)
            (out / rel).write_bytes(data)
            files[rel] = {"sha256": _sha256(data), "size": len(data), "language": "git", "kind": "advisories",
                          "name": rel.rsplit("/", 1)[1].split(".")[0],
                          "advisories": sum(len(v) for v in repos.values())}
    for f in sorted(Path(functions_dir).glob("*.json")) if functions_dir is not None else []:
        eco = f.stem
        if f.name in MINER_REPORTS:
            continue                       # `frame kb mine-functions` writes these beside its tables
        if eco not in ECOSYSTEMS:
            raise KBError(f"{f}: not an ecosystem ({', '.join(ECOSYSTEMS)})")
        fns = _check_functions(json.loads(f.read_text(encoding="utf-8")), str(f))
        data = _gz_json({"schema": SCHEMA, "ecosystem": eco, "revision": revision, "functions": fns})
        rel = functions_path(eco)
        (out / rel).parent.mkdir(parents=True, exist_ok=True)
        (out / rel).write_bytes(data)
        files[rel] = {"sha256": _sha256(data), "size": len(data), "language": eco.lower(),
                      "kind": "functions", "name": eco, "advisories": len(fns)}
    for f in sorted(Path(mitigations_dir).glob("*.json")) if mitigations_dir is not None else []:
        from frame.sca.mitigations import MitigationError, check, mitigations_path
        eco = f.stem
        if eco not in ECOSYSTEMS:
            raise KBError(f"{f}: not an ecosystem ({', '.join(ECOSYSTEMS)})")
        try:
            mits = check(json.loads(f.read_text(encoding="utf-8")), str(f))
        except MitigationError as e:
            raise KBError(str(e)) from e
        data = _gz_json({"schema": SCHEMA, "ecosystem": eco, "revision": revision, "mitigations": mits})
        rel = mitigations_path(eco)
        (out / rel).parent.mkdir(parents=True, exist_ok=True)
        (out / rel).write_bytes(data)
        files[rel] = {"sha256": _sha256(data), "size": len(data), "language": eco.lower(),
                      "kind": "mitigations", "name": eco, "advisories": len(mits)}
    manifest = {"schema": KB_SCHEMA, "revision": revision, "files": files}
    out.mkdir(parents=True, exist_ok=True)
    (out / MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return out / MANIFEST


_SOURCES = ("osv", "fix-commit", "curated")


def _check_functions(data: dict, origin: str) -> Dict[str, List[dict]]:
    from frame.kb.store import KBError
    if not isinstance(data, dict):
        raise KBError(f"{origin}: expected {{advisory id: [{{id, source}}]}}")
    for adv, entries_ in data.items():
        if not isinstance(entries_, list) or not all(
                isinstance(e, dict) and isinstance(e.get("id"), str) and e.get("source") in _SOURCES
                for e in entries_):
            raise KBError(f"{origin}: {adv}: each function needs an id and a source in {_SOURCES}")
    return data


# ---------------------------------------------------------------------------------------------
# loading

def cached_revision_dir() -> Optional[Path]:
    if os.environ.get("FRAME_KB", "").lower() in ("off", "0", "false", "no"):
        return None
    from frame.kb.store import _revision_dir
    return _revision_dir(source(), None)


@dataclass
class AdvisoryDB:
    revision: Optional[str] = None
    tables: Dict[str, Dict[str, List[dict]]] = field(default_factory=dict)   # ecosystem -> name -> advisories
    missing: List[str] = field(default_factory=list)                          # ecosystems not cached
    notes: List[str] = field(default_factory=list)                            # what matching could not decide
    undecided: List[Optional[str]] = field(default_factory=list)            # ... their severities

    @classmethod
    def from_dir(cls, d: Optional[Path], ecosystems: Iterable[str]) -> "AdvisoryDB":
        db = cls(revision=d.name if d is not None else None)
        for eco in sorted(set(ecosystems)):
            f = d / table_path(eco) if d is not None else None
            if f is None or not f.is_file():
                db.missing.append(eco)
                continue
            table = json.loads(gzip.decompress(f.read_bytes()))
            if table.get("schema") != SCHEMA:
                db.missing.append(eco)
                continue
            db.tables[eco] = restore_summaries(table)
            fn_file = d / functions_path(eco) if d is not None else None
            if fn_file is not None and fn_file.is_file():
                extra = json.loads(gzip.decompress(fn_file.read_bytes())).get("functions", {})
                for advs in db.tables[eco].values():
                    for adv in advs:
                        have = {x["id"] for x in adv.get("functions", []) + adv.get("classes", [])}
                        for ident in [adv["id"], *adv.get("aliases", [])]:
                            for fn in extra.get(ident, []):
                                if fn["id"] not in have:
                                    have.add(fn["id"])
                                    # a class the fix changed is not a function: only reachability's
                                    # `imported` level reads it, never sinks or call matching
                                    key = "classes" if fn.get("kind") == "class" else "functions"
                                    adv.setdefault(key, []).append(fn)
        return db

    @classmethod
    def cached(cls, ecosystems: Iterable[str], repos: Iterable[str] = ()) -> "AdvisoryDB":
        db = cls.from_dir(cached_revision_dir(), [e for e in ecosystems if e not in CPP_ECOSYSTEMS])
        db.load_git(cached_revision_dir(), repos)
        return db

    def load_git(self, d: Optional[Path], repos: Iterable[str]) -> None:
        """The GIT advisories of these repositories (their shards)."""
        table_: Dict[str, List[dict]] = self.tables.setdefault(GIT, {})
        for rel in sorted({git_shard(r) for r in repos}):
            f = d / rel if d is not None else None
            if f is None or not f.is_file():
                if GIT not in self.missing:
                    self.missing.append(GIT)
                continue
            shard = json.loads(gzip.decompress(f.read_bytes()))
            table_.update({r: advs for r, advs in shard.get("packages", {}).items() if r in set(repos)})

    def advisories(self, ecosystem: str, name: str) -> List[dict]:
        return self.tables.get(ecosystem, {}).get(normalize_name(ecosystem, name), [])

    def repo_advisories(self, repo: str) -> List[dict]:
        return self.tables.get(GIT, {}).get(repo, [])


# ---------------------------------------------------------------------------------------------
# matching

def _paths_to_direct(df: DependencyFile, key: str) -> List[str]:
    """Shortest chain `direct -> ... -> key` through the file's edges (keys); [key] when the
    package is direct or the file records no edges into it."""
    parents: Dict[str, List[str]] = {}
    for a, bs in df.edges.items():
        for b in bs:
            parents.setdefault(b, []).append(a)
    seen, queue = {key: None}, deque([key])
    while queue:
        cur = queue.popleft()
        pkg = df.packages.get(cur)
        if pkg is not None and pkg.direct:
            chain = []
            while cur is not None:
                chain.append(cur)
                cur = seen[cur]
            return chain                                       # direct ... key
        for p in sorted(parents.get(cur, ())):
            if p not in seen:
                seen[p] = cur
                queue.append(p)
    return [key]


def match(files: Iterable[DependencyFile], db: AdvisoryDB) -> List[dict]:
    """One finding per (manifest, package version, advisory)."""
    out: List[dict] = []
    for df in files:
        for key, pkg in sorted(df.packages.items()):
            if not pkg.version and not pkg.tags and not pkg.alternatives:
                continue
            if pkg.repo and not pkg.tags and pkg.commit and pkg.checkout:
                # an untagged submodule commit: OSV's commit ranges, on the checkout's history
                from frame.sca.gitrange import commit_affected, git_ancestry
                ancestry = git_ancestry(Path(pkg.checkout))
                candidates, missing, no_ranges = [], [], []
                for adv in db.repo_advisories(pkg.repo):
                    if not adv.get("commits"):
                        no_ranges.append(adv["id"])          # tags only: an untagged commit is not decided
                        db.undecided.append(adv.get("severity"))
                        continue
                    verdict = commit_affected(pkg.commit, adv["commits"], ancestry)
                    if verdict is None:
                        missing.append(adv["id"])
                        db.undecided.append(adv.get("severity"))
                    candidates.append((adv, bool(verdict)))
                for ids, why in ((missing, "their commits are not in the checkout (a shallow clone?)"),
                                 (no_ranges, "they give tags but no commit ranges (pull newer advisories, "
                                             "or pin the submodule to a tag)")):
                    if ids:
                        db.notes.append(f"{pkg.repo}@{pkg.commit[:12]} ({df.path}): {len(ids)} advisory(ies) not "
                                        f"decided, {why}: {', '.join(ids[:5])}")
            elif pkg.repo and pkg.alternatives:           # one of several releases (a vendored copy's files)
                candidates, split = [], []
                for adv in db.repo_advisories(pkg.repo):
                    hits = [any(t in adv.get("versions", ()) for t in tags) for tags in pkg.alternatives]
                    if all(hits):
                        candidates.append((adv, True))
                    elif any(hits):
                        split.append(adv["id"])           # affects some of the releases it may be
                        db.undecided.append(adv.get("severity"))
                if split:
                    db.notes.append(f"{pkg.repo} {pkg.version} ({df.path}): {len(split)} advisory(ies) not decided, "
                                    f"they affect some of the {len(pkg.alternatives)} releases these files are in: "
                                    f"{', '.join(split[:5])}")
            elif pkg.repo:                                # C/C++: OSV's affected tags of the repository
                candidates = [(adv, any(t in adv.get("versions", ()) for t in pkg.tags))
                              for adv in db.repo_advisories(pkg.repo)]
            else:
                candidates = [(adv, is_affected(pkg.ecosystem, pkg.version, adv))
                              for adv in db.advisories(pkg.ecosystem, pkg.name)]
            for adv, affected in candidates:
                if not affected:
                    continue
                chain = _paths_to_direct(df, key)
                out.append({
                    "id": adv["id"], "aliases": adv.get("aliases", []), "summary": adv.get("summary", ""),
                    "severity": adv.get("severity"), "score": adv.get("score"), "cvss": adv.get("cvss"),
                    "ecosystem": pkg.ecosystem, "package": pkg.name, "version": pkg.version,
                    "purl": pkg.purl, "path": df.path, "direct": pkg.direct, "dev": pkg.dev,
                    "fixed": [] if pkg.repo else fixed_versions(pkg.ecosystem, pkg.version, adv),
                    **({"repo": pkg.repo, "tag": next(t for t in pkg.tags if t in adv.get("versions", ()))}
                       if pkg.repo and pkg.tags else
                       {"repo": pkg.repo, "tags": [next(t for t in tags if t in adv.get("versions", ()))
                                                   for tags in pkg.alternatives]}
                       if pkg.repo and pkg.alternatives else {"repo": pkg.repo, "commit": pkg.commit} if pkg.repo else {}),
                    "via": [f"{df.packages[k].name}@{df.packages[k].version}" for k in chain],
                    "functions": adv.get("functions", []),
                    "classes": adv.get("classes", []),
                    "category": "dependency", "evidence": "matched"})
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, None: 4}
    out.sort(key=lambda f: (rank.get(f["severity"], 4), f["path"], f["package"], f["id"]))
    return out


def ecosystems_of(files: Iterable[DependencyFile]) -> List[str]:
    return sorted({p.ecosystem for f in files for p in f.packages.values()})


def repos_of(files: Iterable[DependencyFile]) -> List[str]:
    """Upstream repositories of the C/C++ dependencies (their GIT advisory shards)."""
    return sorted({p.repo for f in files for p in f.packages.values() if p.repo})

