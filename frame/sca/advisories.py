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
import zipfile
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence

import hashlib

from frame.sca.model import (CARGO, CONAN, GIT, GO, HEX, MAVEN, NPM, NUGET, PACKAGIST, PUB, PYPI, RUBYGEMS, SWIFT, VCPKG,
                             DependencyFile, normalize_name)
from frame.sca.osv import SCHEMA, entries, fixed_versions, git_entries, is_affected, table

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


def table_path(ecosystem: str) -> str:
    return f"advisories/{ecosystem}.json.gz"


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


def _load_json(data: bytes, origin: str) -> Iterator[dict]:
    try:
        doc = json.loads(data)
    except ValueError:
        return
    if isinstance(doc, list):
        yield from (d for d in doc if isinstance(d, dict))
    elif isinstance(doc, dict):
        yield from (doc.get("vulns") if isinstance(doc.get("vulns"), list) else [doc])


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
    by_eco: Dict[str, Dict[str, List[dict]]] = {e: {} for e in wanted}
    by_repo: Dict[str, List[dict]] = {}
    for rec in _records(inputs):                              # one pass; raw records are not kept
        for eco, name, entry in entries(rec, wanted):
            by_eco[eco].setdefault(name, []).append(entry)
        if with_git:
            for repo, entry in git_entries(rec):
                by_repo.setdefault(repo, []).append(entry)
    out = Path(out)
    files: Dict[str, dict] = {}
    for eco in wanted:
        tbl = table(eco, by_eco.pop(eco))
        if not tbl["packages"]:
            continue
        tbl["revision"] = revision
        data = _gz_json(tbl)
        rel = table_path(eco)
        target = out / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        files[rel] = {"sha256": _sha256(data), "size": len(data), "language": eco.lower(),
                      "kind": "advisories", "name": eco,
                      "advisories": sum(len(v) for v in tbl["packages"].values())}
    for f in sorted(Path(functions_dir).glob("*.json")) if functions_dir is not None else []:
        eco = f.stem
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
    shards: Dict[str, Dict[str, List[dict]]] = {}
    for repo in sorted(by_repo):
        shards.setdefault(git_shard(repo), {})[repo] = table(GIT, {repo: by_repo.pop(repo)})["packages"][repo]
    for rel, repos in sorted(shards.items()):
        data = _gz_json({"schema": SCHEMA, "ecosystem": GIT, "revision": revision, "packages": repos})
        (out / rel).parent.mkdir(parents=True, exist_ok=True)
        (out / rel).write_bytes(data)
        files[rel] = {"sha256": _sha256(data), "size": len(data), "language": "git", "kind": "advisories",
                      "name": rel.rsplit("/", 1)[1].split(".")[0], "advisories": sum(len(v) for v in repos.values())}
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
            db.tables[eco] = table.get("packages", {})
            fn_file = d / functions_path(eco) if d is not None else None
            if fn_file is not None and fn_file.is_file():
                extra = json.loads(gzip.decompress(fn_file.read_bytes())).get("functions", {})
                for advs in db.tables[eco].values():
                    for adv in advs:
                        have = {x["id"] for x in adv.get("functions", [])}
                        for ident in [adv["id"], *adv.get("aliases", [])]:
                            for fn in extra.get(ident, []):
                                if fn["id"] not in have:
                                    have.add(fn["id"])
                                    adv.setdefault("functions", []).append(fn)
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
            if not pkg.version and not pkg.tags:
                continue
            if pkg.repo:                                  # C/C++: OSV's affected tags of the repository
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
                       if pkg.repo else {}),
                    "via": [f"{df.packages[k].name}@{df.packages[k].version}" for k in chain],
                    "functions": adv.get("functions", []),
                    "category": "dependency", "evidence": "matched"})
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, None: 4}
    out.sort(key=lambda f: (rank.get(f["severity"], 4), f["path"], f["package"], f["id"]))
    return out


def ecosystems_of(files: Iterable[DependencyFile]) -> List[str]:
    return sorted({p.ecosystem for f in files for p in f.packages.values()})


def repos_of(files: Iterable[DependencyFile]) -> List[str]:
    """Upstream repositories of the C/C++ dependencies (their GIT advisory shards)."""
    return sorted({p.repo for f in files for p in f.packages.values() if p.repo})

