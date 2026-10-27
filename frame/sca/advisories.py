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

from frame.sca.model import CARGO, GO, MAVEN, NPM, NUGET, PYPI, SWIFT, DependencyFile, normalize_name
from frame.sca.osv import SCHEMA, entries, fixed_versions, is_affected, table

DEFAULT_SOURCE = "hf:lambdasec/frame-advisories"
ECOSYSTEMS = (PYPI, NPM, MAVEN, NUGET, GO, CARGO, SWIFT)


def source() -> str:
    return os.environ.get("FRAME_ADVISORIES_SOURCE") or DEFAULT_SOURCE


def table_path(ecosystem: str) -> str:
    return f"advisories/{ecosystem}.json.gz"


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
                     ecosystems: Optional[Iterable[str]] = None) -> Path:
    """Lay out an advisories revision: `advisories/<ecosystem>.json.gz` per ecosystem plus
    `manifest.json` (same format as `frame kb build`)."""
    import re
    from frame.kb.store import KBError, MANIFEST, _sha256
    from frame.kb.store import SCHEMA as KB_SCHEMA
    if not re.fullmatch(r"[A-Za-z0-9._-]+", revision):
        raise KBError(f"invalid revision id {revision!r}")
    wanted = list(ecosystems) if ecosystems else list(ECOSYSTEMS)
    by_eco: Dict[str, Dict[str, List[dict]]] = {e: {} for e in wanted}
    for rec in _records(inputs):                              # one pass; raw records are not kept
        for eco, name, entry in entries(rec, wanted):
            by_eco[eco].setdefault(name, []).append(entry)
    out = Path(out)
    files: Dict[str, dict] = {}
    for eco in wanted:
        tbl = table(eco, by_eco.pop(eco))
        if not tbl["packages"]:
            continue
        tbl["revision"] = revision
        raw = json.dumps(tbl, separators=(",", ":"), sort_keys=True).encode("utf-8")
        data = gzip.compress(raw, compresslevel=9, mtime=0)       # reproducible bytes
        rel = table_path(eco)
        target = out / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        files[rel] = {"sha256": _sha256(data), "size": len(data), "language": eco.lower(),
                      "kind": "advisories", "name": eco,
                      "advisories": sum(len(v) for v in tbl["packages"].values())}
    manifest = {"schema": KB_SCHEMA, "revision": revision, "files": files}
    out.mkdir(parents=True, exist_ok=True)
    (out / MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return out / MANIFEST


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
        return db

    @classmethod
    def cached(cls, ecosystems: Iterable[str]) -> "AdvisoryDB":
        return cls.from_dir(cached_revision_dir(), ecosystems)

    def advisories(self, ecosystem: str, name: str) -> List[dict]:
        return self.tables.get(ecosystem, {}).get(normalize_name(ecosystem, name), [])


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
            if not pkg.version:
                continue
            for adv in db.advisories(pkg.ecosystem, pkg.name):
                if not is_affected(pkg.ecosystem, pkg.version, adv):
                    continue
                chain = _paths_to_direct(df, key)
                out.append({
                    "id": adv["id"], "aliases": adv.get("aliases", []), "summary": adv.get("summary", ""),
                    "severity": adv.get("severity"), "score": adv.get("score"), "cvss": adv.get("cvss"),
                    "ecosystem": pkg.ecosystem, "package": pkg.name, "version": pkg.version,
                    "purl": pkg.purl, "path": df.path, "direct": pkg.direct, "dev": pkg.dev,
                    "fixed": fixed_versions(pkg.ecosystem, pkg.version, adv),
                    "via": [f"{df.packages[k].name}@{df.packages[k].version}" for k in chain],
                    "functions": adv.get("functions", []),
                    "category": "dependency", "evidence": "matched"})
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, None: 4}
    out.sort(key=lambda f: (rank.get(f["severity"], 4), f["path"], f["package"], f["id"]))
    return out


def ecosystems_of(files: Iterable[DependencyFile]) -> List[str]:
    return sorted({p.ecosystem for f in files for p in f.packages.values()})

