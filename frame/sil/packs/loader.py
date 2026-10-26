"""Finding and loading packs: built-in data, a project's `.frame/packs`, ad hoc paths."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]

from .schema import Pack, PackError, parse_pack

BUILTIN_DIR = Path(__file__).parent / "data"
PROJECT_PACK_DIR = Path(".frame") / "packs"


def load_pack_file(path: Path, origin: Optional[str] = None) -> Pack:
    path = Path(path)
    origin = origin or str(path)
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as e:
        raise PackError(f"{origin}: cannot read pack: {e}") from e
    except tomllib.TOMLDecodeError as e:
        raise PackError(f"{origin}: invalid TOML: {e}") from e
    return parse_pack(data, origin)


def _pack_files(path: Path) -> List[Path]:
    path = Path(path)
    if path.is_dir():
        return sorted(p for p in path.rglob("*.toml") if p.is_file())
    if path.is_file():
        return [path]
    raise PackError(f"{path}: no such pack file or directory")


@lru_cache(maxsize=1)
def builtin_packs() -> tuple:
    """Every shipped pack. A broken built-in pack is a bug: fail loudly, not silently."""
    packs = []
    for f in _pack_files(BUILTIN_DIR) if BUILTIN_DIR.is_dir() else []:
        packs.append(load_pack_file(f, origin=f"builtin:{f.relative_to(BUILTIN_DIR).as_posix()}"))
    names = [(p.language, p.name) for p in packs]
    dupes = {n for n in names if names.count(n) > 1}
    if dupes:
        raise PackError(f"duplicate built-in packs: {sorted(dupes)}")
    return tuple(packs)


def discover_project_packs(start: Path) -> List[Path]:
    """`.frame/packs` of the project containing `start`: the nearest ancestor that has
    one, stopping at the repository root (a `.git` directory)."""
    here = Path(start).resolve()
    if here.is_file():
        here = here.parent
    for d in [here, *here.parents]:
        cand = d / PROJECT_PACK_DIR
        if cand.is_dir():
            return [cand]
        if (d / ".git").exists():
            break
    return []


class PackSet:
    """The packs a scan uses. Immutable once built."""

    def __init__(self, packs: Iterable[Pack] = ()):
        self.packs: List[Pack] = list(packs)

    @classmethod
    def build(cls, extra: Sequence[str] = (), *, builtin: bool = True,
              project_start: Optional[Path] = None) -> "PackSet":
        packs: List[Pack] = list(builtin_packs()) if builtin else []
        paths: List[Path] = []
        if project_start is not None:
            paths += discover_project_packs(project_start)
        paths += [Path(p) for p in extra]
        for p in paths:
            for f in _pack_files(p):
                packs.append(load_pack_file(f))
        return cls(packs)

    def for_language(self, language: str) -> List[Pack]:
        return [p for p in self.packs if p.applies_to_language(language)]

    def names(self) -> List[str]:
        return [f"{p.language}/{p.name}" for p in self.packs]

    def __bool__(self) -> bool:
        return bool(self.packs)
