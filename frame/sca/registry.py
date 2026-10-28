"""Release metadata from package registries: every version of a package and the dependency
ranges each version declares. Used only by `frame deps --plan --registry` (opt-in: it goes to
the network), cached under `$FRAME_KB_CACHE/../registry/<ecosystem>/` so a re-plan is offline.

npm: the abbreviated metadata document (`application/vnd.npm.install-v1+json`), which lists
every version with its `dependencies` and `optionalDependencies` (peer ranges are not
installed by the package, so they are not edges). Deprecated and pre-release versions are kept
in the data and filtered by the planner.

Tests read recorded documents from a directory (`RecordedRegistry`), the same JSON the
registry returns.
"""

from __future__ import annotations

import gzip
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Dict, Optional

from frame.sca.model import NPM

TIMEOUT = 30


class RegistryError(RuntimeError):
    pass


def cache_dir() -> Path:
    from frame.kb.store import cache_root
    return Path(os.environ.get("FRAME_REGISTRY_CACHE") or cache_root().parent / "registry")


def _cache_name(name: str) -> str:
    return urllib.parse.quote(name, safe="") + ".json.gz"


def _versions_of(doc: dict) -> Dict[str, dict]:
    """{version: {"deps": {name: range}, "deprecated": bool}} from an npm metadata document."""
    out: Dict[str, dict] = {}
    for v, meta in (doc.get("versions") or {}).items():
        if not isinstance(meta, dict):
            continue
        deps = {}
        for key in ("dependencies", "optionalDependencies"):
            d = meta.get(key)
            if isinstance(d, dict):
                deps.update({str(k): str(r) for k, r in d.items()})
        out[v] = {"deps": deps, "deprecated": bool(meta.get("deprecated"))}
    return out


class NpmRegistry:
    """Fetches (once) and caches each package's abbreviated metadata."""

    def __init__(self, base: str = "https://registry.npmjs.org", offline: bool = False):
        self.base = base.rstrip("/")
        self.offline = offline
        self.fetched = 0
        self._mem: Dict[str, Optional[Dict[str, dict]]] = {}

    def versions(self, name: str) -> Optional[Dict[str, dict]]:
        if name in self._mem:
            return self._mem[name]
        path = cache_dir() / NPM / _cache_name(name)
        doc = None
        if path.is_file():
            try:
                doc = json.loads(gzip.decompress(path.read_bytes()))
            except (OSError, ValueError):
                doc = None
        if doc is None and not self.offline:
            doc = self._fetch(name)
            if doc is not None:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(gzip.compress(json.dumps(doc).encode()))
        out = _versions_of(doc) if doc is not None else None
        self._mem[name] = out
        return out

    def _fetch(self, name: str) -> Optional[dict]:
        url = f"{self.base}/{urllib.parse.quote(name, safe='@')}"
        req = urllib.request.Request(url, headers={"Accept": "application/vnd.npm.install-v1+json",
                                                   "User-Agent": "frame-sca"})
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:          # nosec: fixed registry URL
                doc = json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            raise RegistryError(f"{url}: HTTP {e.code}") from e
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise RegistryError(f"{url}: {e}") from e
        self.fetched += 1
        # keep what the planner reads: version -> dependency ranges and deprecation
        return {"name": doc.get("name", name), "versions": {
            v: {k: m[k] for k in ("dependencies", "optionalDependencies", "deprecated") if k in m}
            for v, m in (doc.get("versions") or {}).items() if isinstance(m, dict)}}


class RecordedRegistry:
    """Metadata documents recorded on disk (`<quoted name>.json` or `.json.gz`)."""

    def __init__(self, root: Path):
        self.root = Path(root)

    def versions(self, name: str) -> Optional[Dict[str, dict]]:
        stem = urllib.parse.quote(name, safe="")
        for p in (self.root / f"{stem}.json.gz", self.root / f"{stem}.json"):
            if p.is_file():
                data = p.read_bytes()
                return _versions_of(json.loads(gzip.decompress(data) if p.suffix == ".gz" else data))
        return None


def is_prerelease(version: str) -> bool:
    return bool(re.search(r"\d-[0-9A-Za-z]", version))
