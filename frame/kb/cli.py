"""`frame kb pull | status | path | build`."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from frame.kb.store import KBError, build, pull, read_lock, status, write_lock


def only_ids(value: str) -> set:
    """Advisory ids from a comma list, a file of ids (one per line), or a needs-curation.json."""
    p = Path(value)
    if p.is_file():
        text = p.read_text()
        try:
            data = json.loads(text)
        except ValueError:
            return {ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("#")}
        items = data if isinstance(data, list) else list(data)
        return {x["advisory"] if isinstance(x, dict) else str(x) for x in items}
    return {x.strip() for x in value.split(",") if x.strip()}


def add_kb_command(subparsers) -> None:
    p = subparsers.add_parser(
        "kb", help="Download, pin and inspect Frame's knowledge base (framework packs, vulnerability advisories)",
        description="The knowledge base delivers framework packs and vulnerability advisories as versioned "
                    "data. `pull` downloads the files a project needs (its languages' packs, or with "
                    "--advisories its ecosystems' advisories) and verifies each against the manifest; "
                    "scans use the cached copy and never go to the network.")
    sub = p.add_subparsers(dest="kb_command")
    pl = sub.add_parser("pull", help="Download (or update) the knowledge base into the cache")
    pl.add_argument("--project", default=".", metavar="DIR",
                    help="Project whose languages decide what to download, and whose .frame/kb.lock "
                         "pins the revision (default: .)")
    pl.add_argument("--languages", help="Comma-separated languages instead of the project's")
    pl.add_argument("--all", action="store_true", help="Every language")
    pl.add_argument("--ecosystems", metavar="LIST",
                    help="With --advisories: these ecosystems instead of the project's, e.g. Debian:12,Alpine:v3.18 "
                         "for a container image (frame deps --image prints the one it needs)")
    pl.add_argument("--revision", help="Revision to fetch (default: the lockfile's, else main)")
    pl.add_argument("--source", help="hf:org/name, an https mirror, or a local directory "
                                     "(default: $FRAME_KB_SOURCE, else hf:lambdasec/frame-kb)")
    pl.add_argument("--lock", action="store_true", help="Write the revision to <project>/.frame/kb.lock")
    pl.add_argument("--advisories", action="store_true",
                    help="Pull the vulnerability advisories (lambdasec/frame-advisories) instead of the packs, "
                         "for the ecosystems the project's dependencies use (all with --all)")
    st = sub.add_parser("status", help="Which revision a scan of the project would use")
    st.add_argument("--project", default=".", metavar="DIR")
    st.add_argument("-f", "--format", default="text", choices=["text", "json"])
    bd = sub.add_parser("build", help="Lay out a knowledge-base revision from a directory of packs")
    bd.add_argument("packs_dir", help="Directory of <language>/<name>.toml packs")
    bd.add_argument("out", help="Output directory (publish it, mirror it, or pull from it)")
    bd.add_argument("--revision", required=True, help="Revision id written to the manifest")
    bd.add_argument("--specs", metavar="DIR", help="Directory of library spec tables (<table>.toml) to include")
    ba = sub.add_parser("build-advisories", help="Lay out an advisories revision from OSV exports")
    ba.add_argument("inputs", nargs="+", help="OSV all.zip exports, directories of OSV JSON, or JSON files")
    ba.add_argument("out", help="Output directory")
    ba.add_argument("--revision", required=True, help="Revision id written to the manifest")
    ba.add_argument("--ecosystems", help="Comma-separated OSV ecosystems (default: every one Frame reads)")
    mf = sub.add_parser("mine-functions", help="Vulnerable functions from advisories' fix commits")
    mf.add_argument("inputs", nargs="+", help="OSV all.zip exports, directories of OSV JSON, or JSON files")
    mf.add_argument("--out", required=True, metavar="DIR", help="Where <Ecosystem>.json files are written")
    mf.add_argument("--existing", metavar="DIR", help="Curated <Ecosystem>.json files to keep (they win)")
    mf.add_argument("--ecosystems", default="PyPI,npm,Maven,NuGet", help="Comma-separated (default: %(default)s)")
    mf.add_argument("--limit", type=int, help="Mine at most this many advisories")
    mf.add_argument("--cache", metavar="DIR", help="Commit cache (default: ~/.cache/frame/mine)")
    mf.add_argument("--recorded", metavar="DIR", help="Read commits recorded on disk instead of GitHub")
    mf.add_argument("--only", metavar="IDS",
                    help="Mine only these advisories: a comma-separated list, a file with one id per line, or a "
                         "needs-curation.json (matched by id or alias); --since is not needed")
    mf.add_argument("--since", metavar="TIMESTAMP",
                    help="Only advisories modified after this (oldest first); use the last run's resume_after")
    ba.add_argument("--mitigations", metavar="DIR",
                    help="Directory of <Ecosystem>.json curated configuration mitigations (advisory id -> [mitigation])")
    ba.add_argument("--functions", metavar="DIR",
                    help="Directory of <Ecosystem>.json vulnerable-function files (advisory id -> [{id, source}])")


def _languages(args) -> list:
    if args.all:
        return []
    if args.languages:
        return [x.strip() for x in args.languages.split(",") if x.strip()]
    from frame.sil.inventory import build_inventory
    langs = set(build_inventory(Path(args.project), read_sources=False).languages)
    if "typescript" in langs:
        langs.add("javascript")                    # TS uses the JavaScript packs
    if "cpp" in langs:
        langs.add("c")
    return sorted(langs)


def cmd_kb(args) -> int:
    try:
        if args.kb_command == "pull" and args.advisories:
            from frame.sca.advisories import CPP_ECOSYSTEMS, ECOSYSTEMS, ecosystems_of, git_shard, repos_of, source
            shards: list = []
            if args.ecosystems:
                ecos = [e.strip() for e in args.ecosystems.split(",") if e.strip()]
            elif args.all:
                ecos = list(ECOSYSTEMS) + ["git"]
            else:
                from frame.sca import read_dependencies
                files = read_dependencies(Path(args.project)).files
                ecos = [e for e in ecosystems_of(files) if e not in CPP_ECOSYSTEMS]
                shards = sorted({git_shard(r) for r in repos_of(files)})
            if not ecos and not shards:
                print("no dependencies found; nothing to pull (use --all for every ecosystem)")
                return 0
            got = pull([e.lower() for e in ecos], revision=args.revision or "main", source=args.source or source(),
                       also=shards)
            from frame.sca.advisories import remember_source
            remember_source(args.source or source())
            print(f"{got.source}@{got.revision}: {len(got.files)} files ({got.fetched} downloaded) "
                  f"for {', '.join(ecos + ([f'{len(shards)} C/C++ repository shard(s)'] if shards else []))}")
            return 0
        if args.kb_command == "pull":
            lock = read_lock(Path(args.project))
            revision = args.revision or (lock["revision"] if lock and not args.source else "main")
            pinned = lock["manifest_sha256"] if lock and not args.revision and not args.source else None
            langs = _languages(args)
            got = pull(langs or None, revision=revision, source=args.source or (lock or {}).get("source"),
                       expect_manifest_sha256=pinned)
            print(f"{got.source}@{got.revision}: {len(got.files)} files "
                  f"({got.fetched} downloaded) for {', '.join(langs) or 'every language'}")
            if args.lock:
                print(f"pinned in {write_lock(Path(args.project), got)}")
            return 0
        if args.kb_command == "status":
            st = status(Path(args.project))
            if args.format == "json":
                print(json.dumps(st, indent=2))
            else:
                print(f"source:  {st['source']}\npinned:  {st['pinned'] or '-'}\n"
                      f"cached:  {st['cached'] or '- (scans use the built-in packs)'}\n"
                      f"packs:   {st['packs']}\ncache:   {st['cache']}")
            return 0
        if args.kb_command == "mine-functions":
            from frame.sca.advisories import _records
            from frame.sca.mine import GitHubSource, Progress, RecordedSource, mine
            ecos = [e.strip() for e in args.ecosystems.split(",") if e.strip()]
            existing = {}
            if args.existing:
                for e in ecos:
                    f = Path(args.existing) / f"{e}.json"
                    if f.is_file():
                        existing[e] = json.loads(f.read_text())
            source = RecordedSource(Path(args.recorded)) if args.recorded else GitHubSource(
                Path(args.cache) if args.cache else Path.home() / ".cache" / "frame" / "mine")
            progress = Progress()
            records = _records([Path(i) for i in args.inputs])
            if args.only:
                wanted = only_ids(args.only)
                records = (r for r in records if isinstance(r, dict)
                           and ({r.get("id"), *(r.get("aliases") or [])} & wanted))
            tables, report = mine(records, ecos, source, args.limit, existing,
                                  since=args.since, progress=progress)
            out = Path(args.out)
            out.mkdir(parents=True, exist_ok=True)
            for e, table in tables.items():
                if table:
                    (out / f"{e}.json").write_text(json.dumps(table, indent=1, sort_keys=True) + "\n")
            curate = [{"advisory": m.advisory, "internal_only": m.internal_only,
                       "outside_functions": m.outside_functions} for m in report if m.needs_curation]
            (out / "needs-curation.json").write_text(json.dumps(curate, indent=1) + "\n")
            (out / "progress.json").write_text(json.dumps({
                "processed": progress.processed, "rate_limited": progress.rate_limited,
                "resume_after": progress.resume_after or args.since or ""}, indent=1) + "\n")
            mined = sum(1 for m in report if m.entries)
            print(f"{len(report)} advisories with fix commits: {mined} mined, {len(curate)} need curation, "
                  f"{sum(1 for m in report if m.skipped and not m.entries)} unavailable"
                  + (f"; stopped: {progress.rate_limited} -- resume with --since {progress.resume_after or args.since}"
                     if progress.rate_limited else ""))
            return 0
        if args.kb_command == "build-advisories":
            from frame.sca.advisories import build_advisories
            ecos = [e.strip() for e in args.ecosystems.split(",")] if args.ecosystems else None
            manifest = build_advisories([Path(i) for i in args.inputs], Path(args.out), args.revision, ecos,
                                        Path(args.functions) if args.functions else None,
                                        Path(args.mitigations) if args.mitigations else None)
            files = json.loads(manifest.read_text())["files"]
            for rel, meta in sorted(files.items()):
                print(f"{rel}: {meta['advisories']} advisories, {meta['size']} bytes")
            return 0
        if args.kb_command == "build":
            manifest = build(Path(args.packs_dir), Path(args.out), args.revision,
                             Path(args.specs) if args.specs else None)
            n = len(json.loads(manifest.read_text())["files"])
            print(f"{manifest}: {n} files, revision {args.revision}")
            return 0
    except KBError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    print("usage: frame kb {pull,status,build,build-advisories,mine-functions}", file=sys.stderr)
    return 2
