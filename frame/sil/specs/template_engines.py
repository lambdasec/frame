"""Server-side template engines as data (`data/template-engines.toml`): each engine's raw-output,
include and variable-binding syntax, the extensions and directories views live in, and the
switches that turn escaping off. Loaded strictly: every pattern must compile and carry the
named groups its role needs (`expr`, `file`, `alias` and `source`, `context`)."""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import FrozenSet, List, NamedTuple, Optional, Pattern, Tuple

try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]

PATH = Path(__file__).parent / "data" / "template-engines.toml"
IDENT = r"[A-Za-z_$][\w$]*"
_TOP = {"extensions", "view_dirs", "layouts", "keywords", "escape", "engine"}
_ESCAPE = {"template_off", "dynamic_include", "config_off"}
_ENGINE = {"name", "raw", "include", "alias", "block_open", "block_close", "block_raw_engines"}
_GROUPS = {"raw": {"expr"}, "include": {"file"}, "alias": {"alias", "source"}, "block_open": {"context"},
           "block_close": set()}


class Engine(NamedTuple):
    name: str
    raw: Tuple[Pattern, ...]
    include: Tuple[Pattern, ...]
    alias: Tuple[Pattern, ...]
    block_open: Optional[Pattern]
    block_close: Optional[Pattern]
    block_raw_engines: Tuple[str, ...]


class TemplateEngines(NamedTuple):
    extensions: Tuple[str, ...]
    view_dirs: Tuple[str, ...]
    layouts: Tuple[str, ...]
    keywords: FrozenSet[str]
    template_escape_off: Pattern
    dynamic_include: Pattern
    config_escape_off: Pattern
    engines: Tuple[Engine, ...]

    def patterns(self, role: str) -> List[Pattern]:
        return [p for e in self.engines for p in getattr(e, role)]

    def raw_of(self, names) -> List[Pattern]:
        return [p for e in self.engines if e.name in names for p in e.raw]


def _compile(name: str, where: str, pattern, role: str) -> Pattern:
    if not isinstance(pattern, str) or not pattern:
        raise ValueError(f"{name}: {where} must be a pattern")
    try:
        rx = re.compile(pattern.replace("{ident}", IDENT))
    except re.error as e:
        raise ValueError(f"{name}: {where} does not compile: {e}") from e
    missing = _GROUPS.get(role, set()) - set(rx.groupindex)
    if missing:
        raise ValueError(f"{name}: {where} needs the named group(s) {sorted(missing)}")
    return rx


def _strings(name: str, where: str, value) -> Tuple[str, ...]:
    if not isinstance(value, list) or not value or not all(isinstance(v, str) and v for v in value):
        raise ValueError(f"{name}: {where} must be a non-empty list of strings")
    return tuple(value)


@lru_cache(maxsize=None)
def load(path: Path = PATH) -> TemplateEngines:
    name = Path(path).name
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    if set(data) != _TOP:
        raise ValueError(f"{name}: needs exactly {sorted(_TOP)}")
    escape = data["escape"]
    if not isinstance(escape, dict) or set(escape) != _ESCAPE:
        raise ValueError(f"{name}: [escape] needs exactly {sorted(_ESCAPE)}")
    engines = []
    for i, e in enumerate(data["engine"]):
        where = f"engine {i + 1}"
        if not isinstance(e, dict) or "name" not in e or "raw" not in e or set(e) - _ENGINE:
            raise ValueError(f"{name}: {where} needs name and raw; allowed {sorted(_ENGINE)}")
        if ("block_open" in e) != ("block_close" in e) or ("block_open" in e) != ("block_raw_engines" in e):
            raise ValueError(f"{name}: {where}: block_open, block_close and block_raw_engines go together")

        def pats(role, e=e, where=where):
            return tuple(_compile(name, f"{where} {role}", p, role)
                         for p in _strings(name, f"{where} {role}", e[role])) if role in e else ()
        engines.append(Engine(
            name=e["name"], raw=pats("raw"), include=pats("include"), alias=pats("alias"),
            block_open=_compile(name, f"{where} block_open", e["block_open"], "block_open") if "block_open" in e else None,
            block_close=_compile(name, f"{where} block_close", e["block_close"], "block_close") if "block_close" in e else None,
            block_raw_engines=_strings(name, f"{where} block_raw_engines", e["block_raw_engines"])
            if "block_raw_engines" in e else ()))
    known = {e.name for e in engines}
    for e in engines:
        unknown = set(e.block_raw_engines) - known
        if unknown:
            raise ValueError(f"{name}: engine {e.name}: block_raw_engines names unknown {sorted(unknown)}")
    return TemplateEngines(
        extensions=_strings(name, "extensions", data["extensions"]),
        view_dirs=_strings(name, "view_dirs", data["view_dirs"]),
        layouts=_strings(name, "layouts", data["layouts"]),
        keywords=frozenset(_strings(name, "keywords", data["keywords"])),
        template_escape_off=_compile(name, "[escape] template_off", escape["template_off"], "escape"),
        dynamic_include=_compile(name, "[escape] dynamic_include", escape["dynamic_include"], "escape"),
        config_escape_off=_compile(name, "[escape] config_off", escape["config_off"], "escape"),
        engines=tuple(engines))


__all__ = ["Engine", "IDENT", "PATH", "TemplateEngines", "load"]
