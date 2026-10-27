"""`frame kb pull | status | path | build`."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from frame.kb.store import KBError, build, pull, read_lock, status, write_lock


def add_kb_command(subparsers) -> None:
    p = subparsers.add_parser(
        "kb", help="Download, pin and inspect Frame's knowledge base (framework packs)",
        description="The knowledge base delivers framework packs as versioned data. `pull` downloads "
                    "the files for the languages a project uses and verifies each against the "
                    "manifest; scans use the cached copy and never go to the network.")
    sub = p.add_subparsers(dest="kb_command")
    pl = sub.add_parser("pull", help="Download (or update) the knowledge base into the cache")
    pl.add_argument("--project", default=".", metavar="DIR",
                    help="Project whose languages decide what to download, and whose .frame/kb.lock "
                         "pins the revision (default: .)")
    pl.add_argument("--languages", help="Comma-separated languages instead of the project's")
    pl.add_argument("--all", action="store_true", help="Every language")
    pl.add_argument("--revision", help="Revision to fetch (default: the lockfile's, else main)")
    pl.add_argument("--source", help="hf:org/name, an https mirror, or a local directory "
                                     "(default: $FRAME_KB_SOURCE, else hf:lambdasec/frame-kb)")
    pl.add_argument("--lock", action="store_true", help="Write the revision to <project>/.frame/kb.lock")
    st = sub.add_parser("status", help="Which revision a scan of the project would use")
    st.add_argument("--project", default=".", metavar="DIR")
    st.add_argument("-f", "--format", default="text", choices=["text", "json"])
    bd = sub.add_parser("build", help="Lay out a knowledge-base revision from a directory of packs")
    bd.add_argument("packs_dir", help="Directory of <language>/<name>.toml packs")
    bd.add_argument("out", help="Output directory (publish it, mirror it, or pull from it)")
    bd.add_argument("--revision", required=True, help="Revision id written to the manifest")
    bd.add_argument("--specs", metavar="DIR", help="Directory of library spec tables (<table>.toml) to include")


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
        if args.kb_command == "build":
            manifest = build(Path(args.packs_dir), Path(args.out), args.revision,
                             Path(args.specs) if args.specs else None)
            n = len(json.loads(manifest.read_text())["files"])
            print(f"{manifest}: {n} files, revision {args.revision}")
            return 0
    except KBError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    print("usage: frame kb {pull,status,build}", file=sys.stderr)
    return 2
