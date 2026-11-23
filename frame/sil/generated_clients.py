"""Client libraries generated into the project's own tree (`specs/data/generated-clients.toml`).

Prisma writes its client where the schema's `generator` block says (`output = "../src/prisma"`),
and the code imports it from there (`@/prisma/client`, `../generated/prisma`), not from
`@prisma/client`. Without this the client's calls carry a project path as their id and none of the
library's packs or value types meet them. `rewrite(programs, index)` (run in
`ProjectContext.build` before modules are linked) renames such imports, and the calls named
after them, to the library's module. A directory is the library's only when the configuration
names it; nothing is guessed from a path's name.
"""

from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Tuple

DATA = Path(__file__).parent / "specs" / "data" / "generated-clients.toml"
_SKIP = {"node_modules", ".git", "dist", "build", ".next", "coverage", "vendor"}
_MAX_FILES = 64


@lru_cache(maxsize=1)
def clients() -> Tuple[Dict[str, object], ...]:
    try:
        import tomllib
    except ImportError:                      # Python 3.10
        import tomli as tomllib              # type: ignore
    with open(DATA, "rb") as fh:
        data = tomllib.load(fh)
    return tuple(data.get("client", []))


def _blocks(text: str, kind: str) -> List[Dict[str, str]]:
    """The `key = "value"` entries of each `<kind> <name> { ... }` block of a schema file."""
    out = []
    text = re.sub(r"//[^\n]*", "", text)
    for m in re.finditer(rf"(?m)^\s*{re.escape(kind)}\s+\w+\s*\{{(.*?)^\s*\}}", text, re.DOTALL):
        out.append({k: v for k, v in re.findall(r'(?m)^\s*(\w+)\s*=\s*"([^"]*)"', m.group(1))})
    return out


def output_dirs(root: Path) -> List[Tuple[Path, str]]:
    """(generated directory, library module) for every generated client the project's
    configuration declares under `root`."""
    found: List[Tuple[Path, str]] = []
    specs = clients()
    patterns = {pat for c in specs for pat in c.get("files", [])}
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP and not d.startswith(".")]
        for name in filenames:
            if not any(Path(name).match(p) for p in patterns):
                continue
            seen += 1
            if seen > _MAX_FILES:
                return found
            path = Path(dirpath) / name
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for c in specs:
                if not any(Path(name).match(p) for p in c.get("files", [])):
                    continue
                for block in _blocks(text, str(c.get("block", ""))):
                    out = block.get(str(c.get("output", "")))
                    providers = c.get("providers") or []
                    if out and (not providers or block.get("provider") in providers):
                        found.append(((path.parent / out).resolve(), str(c["module"])))
    return found


def _module_of(index, mod, spec: str, dirs: List[Tuple[Path, str]]) -> Optional[str]:
    """The library module a specifier imports, when it names a generated directory (or a file
    in it)."""
    base = mod.path.parent
    candidates = [(base / spec).resolve()] if spec.startswith(".") else \
        [Path(c) for c in index._alias_candidates(base, spec)]
    for cand in candidates:
        for out, module in dirs:
            if cand == out or out in cand.parents:
                return module
    return None


def rewrite(programs: Dict[str, object], index) -> None:
    """Rename imports of generated clients, and the callee ids built on them, to the library's
    module; the programs whose ids moved are re-annotated and marked for the packs' rules."""
    dirs = output_dirs(index.root)
    if not dirs:
        return
    from frame.sil.instructions import Call
    from frame.sil.value_origins import annotate
    for key, program in programs.items():
        if (getattr(program, "language", "") or "") not in ("javascript", "typescript"):
            continue
        mod = index.modules.get(key)
        if mod is None:
            continue
        renames: Dict[str, str] = {}
        imports = getattr(program, "imports", None) or {}
        for local, value in list(imports.items()):
            value = str(value)
            # the module part first: `@/prisma/client.PrismaClient` is module `@/prisma/client`
            # and symbol `PrismaClient` (a relative path's leading dots are not a separator)
            cuts = [i for i in range(1, len(value)) if value[i] == "." and value[i - 1] not in "./"
                    and (i + 1 >= len(value) or value[i + 1] not in "./")] + [len(value)]
            for cut in cuts:
                spec = value[:cut]
                if spec in renames:
                    break
                module = _module_of(index, mod, spec, dirs)
                if module:
                    renames[spec] = module
                    break
        if not renames:
            continue
        for local, value in list(imports.items()):
            for old, new in renames.items():
                if str(value) == old or str(value).startswith(old + "."):
                    imports[local] = new + str(value)[len(old):]
        for proc in program.procedures.values():
            for node in proc.nodes.values():
                for ins in node.instrs:
                    if not isinstance(ins, Call) or not ins.canonical:
                        continue
                    for old, new in renames.items():
                        if ins.canonical == old or ins.canonical.startswith(old + "."):
                            ins.canonical = new + ins.canonical[len(old):]
                            ins.pack_spec = None
        annotate(program)
        program.origins_moved = True
