"""Fetching, verifying, caching and pinning knowledge-base revisions (see frame.kb)."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, List, Optional

DEFAULT_SOURCE = "hf:lambdasec/frame-kb"
MANIFEST = "manifest.json"
LOCKFILE = Path(".frame") / "kb.lock"
SCHEMA = 1
# What a knowledge base may contain: data under these directories, never code.
_ALLOWED_PREFIXES = ("packs/", "specs/", "advisories/")
_ALLOWED_SUFFIXES = (".toml", ".json", ".json.gz")
_TIMEOUT = 30


class KBError(Exception):
    """A knowledge base that cannot be fetched, read or trusted."""


@dataclass
class Pulled:
    source: str
    revision: str            # the manifest's revision id (or its content hash)
    manifest_sha256: str
    path: Path               # the cached revision directory
    files: List[str] = field(default_factory=list)
    fetched: int = 0         # files downloaded this time (the rest were cached)


def cache_root() -> Path:
    return Path(os.environ.get("FRAME_KB_CACHE") or Path.home() / ".cache" / "frame" / "kb")


def _source(source: Optional[str]) -> str:
    return source or os.environ.get("FRAME_KB_SOURCE") or DEFAULT_SOURCE


def _slug(source: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", source).strip("_") or "kb"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _url(source: str, revision: str, path: str) -> str:
    """Where `path` of `revision` lives: a Hugging Face dataset (`hf:org/name`), an HTTP(S)
    mirror (`https://host/base`, which may contain `{revision}`), or a local directory."""
    if source.startswith("hf:"):
        return f"https://huggingface.co/datasets/{source[3:]}/resolve/{revision}/{path}"
    if source.startswith(("http://", "https://")):
        base = source.replace("{revision}", revision)
        return f"{base.rstrip('/')}/{path}"
    return str(Path(source[len("file://"):] if source.startswith("file://") else source) / path)


def _fetch(source: str, revision: str, path: str) -> bytes:
    url = _url(source, revision, path)
    if not url.startswith(("http://", "https://")):
        try:
            return Path(url).read_bytes()
        except OSError as e:
            raise KBError(f"cannot read {url}: {e.strerror or e}") from e
    req = urllib.request.Request(url, headers={"User-Agent": "frame-kb"})
    token = os.environ.get("HF_TOKEN") if source.startswith("hf:") else None
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:     # nosec: fixed hosts / mirror
            return resp.read()
    except (urllib.error.URLError, OSError) as e:
        raise KBError(f"cannot fetch {url}: {getattr(e, 'reason', e)}") from e


def _check_path(path: str) -> str:
    p = PurePosixPath(path)
    if p.is_absolute() or ".." in p.parts or not path.startswith(_ALLOWED_PREFIXES) \
            or not path.endswith(_ALLOWED_SUFFIXES):
        raise KBError(f"manifest lists a file a knowledge base may not hold: {path!r}")
    return path


def _read_manifest(data: bytes) -> dict:
    try:
        manifest = json.loads(data)
    except ValueError as e:
        raise KBError(f"manifest is not JSON: {e}") from e
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA \
            or not isinstance(manifest.get("files"), dict):
        raise KBError(f"unsupported manifest (expected schema {SCHEMA} with a files table)")
    for path, meta in manifest["files"].items():
        _check_path(path)
        if not isinstance(meta, dict) or not re.fullmatch(r"[0-9a-f]{64}", str(meta.get("sha256", ""))):
            raise KBError(f"manifest entry for {path} has no sha256")
    return manifest


def pull(languages: Optional[Iterable[str]] = None, revision: str = "main",
         source: Optional[str] = None, expect_manifest_sha256: Optional[str] = None) -> Pulled:
    """Download `revision` of the knowledge base (only `languages`' files, plus files for every
    language), verify each file against the manifest, and cache it. With
    `expect_manifest_sha256` (a lockfile pin) a manifest that differs is refused."""
    src = _source(source)
    raw = _fetch(src, revision, MANIFEST)
    digest = _sha256(raw)
    if expect_manifest_sha256 and digest != expect_manifest_sha256:
        raise KBError(f"manifest of {src}@{revision} does not match the pinned sha256 "
                      f"({digest[:12]} != {expect_manifest_sha256[:12]})")
    manifest = _read_manifest(raw)
    rev_id = str(manifest.get("revision") or digest[:16])
    if not re.fullmatch(r"[A-Za-z0-9._-]+", rev_id):
        raise KBError(f"invalid revision id {rev_id!r}")
    dest = cache_root() / _slug(src) / rev_id
    wanted = {lang.lower() for lang in languages} if languages else None
    pulled = Pulled(source=src, revision=rev_id, manifest_sha256=digest, path=dest)
    for path, meta in sorted(manifest["files"].items()):
        lang = str(meta.get("language", "")).lower()
        if wanted is not None and lang and lang not in wanted:
            continue
        target = dest / path
        if target.is_file() and _sha256(target.read_bytes()) == meta["sha256"]:
            pulled.files.append(path)
            continue
        data = _fetch(src, revision, path)
        if _sha256(data) != meta["sha256"]:
            raise KBError(f"{path}: content does not match the manifest's sha256")
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(target.suffix + ".part")
        tmp.write_bytes(data)
        tmp.replace(target)
        pulled.files.append(path)
        pulled.fetched += 1
    dest.mkdir(parents=True, exist_ok=True)
    (dest / MANIFEST).write_bytes(raw)
    (cache_root() / _slug(src) / "current").write_text(rev_id + "\n")
    return pulled


def find_lock(start: Path) -> Optional[Path]:
    """The `.frame/kb.lock` of the project containing `start` (stops at a `.git` root)."""
    here = Path(start).resolve()
    if here.is_file():
        here = here.parent
    for d in [here, *here.parents]:
        cand = d / LOCKFILE
        if cand.is_file():
            return cand
        if (d / ".git").exists():
            break
    return None


def read_lock(start: Path) -> Optional[dict]:
    lock = find_lock(start)
    if lock is None:
        return None
    try:
        data = json.loads(lock.read_text())
    except (OSError, ValueError) as e:
        raise KBError(f"{lock}: unreadable lockfile: {e}") from e
    if not all(isinstance(data.get(k), str) for k in ("source", "revision", "manifest_sha256")):
        raise KBError(f"{lock}: expected source, revision and manifest_sha256")
    return data


def write_lock(project_root: Path, pulled: Pulled) -> Path:
    path = Path(project_root) / LOCKFILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"source": pulled.source, "revision": pulled.revision,
                                "manifest_sha256": pulled.manifest_sha256}, indent=2) + "\n")
    return path


def _revision_dir(source: str, revision: Optional[str]) -> Optional[Path]:
    base = cache_root() / _slug(source)
    if revision is None:
        try:
            revision = (base / "current").read_text().strip()
        except OSError:
            return None
    d = base / revision
    return d if (d / MANIFEST).is_file() else None


def kb_pack_dirs(project_start: Optional[Path] = None) -> List[Path]:
    """Pack directories a scan should load from the cache: the lockfile's revision when the
    project pins one (only if it is cached: a scan never downloads), else the last pulled
    revision. `FRAME_KB=off` disables the knowledge base."""
    if os.environ.get("FRAME_KB", "").lower() in ("off", "0", "false", "no"):
        return []
    lock = read_lock(project_start) if project_start is not None else None
    d = _revision_dir(lock["source"], lock["revision"]) if lock else _revision_dir(_source(None), None)
    if d is None:
        return []
    packs = d / "packs"
    return [packs] if packs.is_dir() else []


def kb_spec_file(table: str) -> Optional[Path]:
    """`specs/<table>.toml` of the last pulled revision, if it has one (spec tables load once
    per process, so they follow the cache's current revision, not a project's lockfile)."""
    if os.environ.get("FRAME_KB", "").lower() in ("off", "0", "false", "no"):
        return None
    d = _revision_dir(_source(None), None)
    f = d / "specs" / f"{table}.toml" if d is not None else None
    return f if f is not None and f.is_file() else None


def status(project_start: Optional[Path] = None) -> Dict[str, object]:
    lock = read_lock(project_start) if project_start is not None else None
    src = lock["source"] if lock else _source(None)
    d = _revision_dir(src, lock["revision"] if lock else None)
    files = 0
    if d is not None:
        files = sum(1 for p in (d / "packs").rglob("*.toml")) if (d / "packs").is_dir() else 0
    return {"source": src, "pinned": lock["revision"] if lock else None,
            "cached": d.name if d is not None else None, "path": str(d) if d else None,
            "packs": files, "cache": str(cache_root())}


def build(packs_dir: Path, out: Path, revision: str, specs_dir: Optional[Path] = None) -> Path:
    """Lay out a knowledge-base revision from a directory of packs (`<language>/<name>.toml`):
    `out/packs/...` plus `out/manifest.json`. The result can be published as is, served by a
    mirror, or copied to an air-gapped machine and pulled with `--source DIR`."""
    from frame.sil.packs.loader import load_pack_file
    if not re.fullmatch(r"[A-Za-z0-9._-]+", revision):
        raise KBError(f"invalid revision id {revision!r}")
    out = Path(out)
    files: Dict[str, dict] = {}
    for f in sorted(Path(packs_dir).rglob("*.toml")):
        pack = load_pack_file(f)                       # a broken pack never ships
        rel = f"packs/{pack.language}/{f.name}"
        data = f.read_bytes()
        target = out / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(f, target)
        files[rel] = {"sha256": _sha256(data), "size": len(data), "language": pack.language,
                      "kind": "pack", "name": pack.name}
    if specs_dir is not None:
        from frame.sil.specs.tables import TABLES, _load
        for f in sorted(Path(specs_dir).glob("*.toml")):
            if f.stem not in TABLES:
                raise KBError(f"{f}: not a spec table ({', '.join(TABLES)})")
            _load(str(f))                               # a broken table never ships
            rel = f"specs/{f.name}"
            data = f.read_bytes()
            target = out / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(f, target)
            files[rel] = {"sha256": _sha256(data), "size": len(data), "language": f.stem,
                          "kind": "specs", "name": f.stem}
    manifest = {"schema": SCHEMA, "revision": revision, "files": files}
    (out / MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return out / MANIFEST
