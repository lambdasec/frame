"""Record what an example needs to run offline: the advisories for its packages (from the
advisories dataset you have pulled, `frame kb pull --advisories`) as a small mirror in the
dataset's own layout, so anyone can `frame kb pull --advisories --source <example>/offline-advisories`.

    python examples/record_offline.py examples/sca-express

The mirror is a revision directory: manifest.json (each file's SHA-256) and
advisories/<Ecosystem>.json.gz, with the dataset revision it came from. Advisory data is OSV's
(CC-BY 4.0), via lambdasec/frame-advisories.
"""

from __future__ import annotations

import gzip
import json
import sys
from pathlib import Path

from frame.kb.store import MANIFEST, SCHEMA as KB_SCHEMA, _sha256
from frame.sca import read_dependencies
from frame.sca.advisories import SCHEMA, AdvisoryDB, cached_revision_dir, ecosystems_of, table_path
from frame.sca.model import normalize_name


def record(example: Path) -> Path:
    files = read_dependencies(example, exclude_dirs={"offline-advisories", "offline-registry", "node_modules"}).files
    # unpacked root filesystems (a subdirectory with an os-release): their OS packages too
    from frame.sca.container import OS_RELEASE, read_rootfs
    for d in sorted(p for p in example.iterdir() if any((p / r).is_file() for r in OS_RELEASE)):
        files += read_rootfs(d)[0]
    ecos = ecosystems_of(files)
    db = AdvisoryDB.cached(ecos)
    if db.missing:
        from frame.sca.advisories import pull_hint
        sys.exit(f"no advisories cached for {', '.join(db.missing)}: run `{pull_hint(db.missing)}` first")
    src = cached_revision_dir()
    revision = f"example-{src.name}" if src else "example"
    out = example / "offline-advisories"
    manifest = {"schema": KB_SCHEMA, "revision": revision, "files": {}}
    for eco in ecos:
        names = sorted({p.name for f in files if f.ecosystem == eco for p in f.packages.values()})
        packages = {}
        for n in names:
            advs = db.advisories(eco, n)
            if advs:
                packages[normalize_name(eco, n)] = advs          # tables are keyed by normalised names
        data = gzip.compress(json.dumps({"schema": SCHEMA, "ecosystem": eco, "revision": revision,
                                         "packages": packages}, sort_keys=True).encode(), mtime=0)
        rel = table_path(eco)
        (out / rel).parent.mkdir(parents=True, exist_ok=True)
        (out / rel).write_bytes(data)
        manifest["files"][rel] = {"sha256": _sha256(data), "size": len(data), "language": eco.lower(),
                                  "kind": "advisories", "name": eco,
                                  "advisories": sum(len(v) for v in packages.values())}
    (out / MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return out


if __name__ == "__main__":
    for arg in sys.argv[1:]:
        print(record(Path(arg)))
