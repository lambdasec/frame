"""`frame packs list` / `frame packs check`."""

from __future__ import annotations

import sys
from pathlib import Path

from .loader import PackSet, builtin_packs, discover_project_packs, load_pack_file, _pack_files
from .schema import PackError


def add_packs_command(subparsers) -> None:
    p = subparsers.add_parser(
        "packs", help="List or validate framework packs",
        description="Framework packs teach Frame a framework's sources, sinks, sanitizers and entry points.")
    sub = p.add_subparsers(dest="packs_command")
    lst = sub.add_parser("list", help="List the packs a scan would load")
    lst.add_argument("--language", help="Only packs for this language")
    lst.add_argument("--project", metavar="DIR", default=".",
                     help="Project directory whose .frame/packs to include (default: .)")
    chk = sub.add_parser("check", help="Validate pack files")
    chk.add_argument("paths", nargs="+", metavar="PATH", help="Pack .toml files or directories")


def cmd_packs(args) -> int:
    if args.packs_command == "check":
        bad = 0
        for raw in args.paths:
            try:
                files = _pack_files(Path(raw))
            except PackError as e:
                print(f"FAIL {e}", file=sys.stderr)
                bad += 1
                continue
            for f in files:
                try:
                    pack = load_pack_file(f)
                except PackError as e:
                    print(f"FAIL {e}", file=sys.stderr)
                    bad += 1
                    continue
                print(f"ok   {f}: {pack.language}/{pack.name} "
                      f"({len(pack.entrypoints)} entry points, {len(pack.rules)} rules)")
        return 1 if bad else 0
    if args.packs_command == "list":
        try:
            packs = PackSet.build(builtin=True, project_start=Path(args.project)).packs
        except PackError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 2
        shown = [p for p in packs if not args.language or p.applies_to_language(args.language)]
        for pack in sorted(shown, key=lambda p: (p.language, p.name)):
            where = "built-in" if pack.origin.startswith("builtin:") else pack.origin
            print(f"{pack.language:<11} {pack.name:<22} {len(pack.entrypoints):>2} entry  "
                  f"{len(pack.rules):>3} rules  {where}")
        print(f"{len(shown)} packs", file=sys.stderr)
        return 0
    print("usage: frame packs {list,check}", file=sys.stderr)
    return 2
