"""Which variables a server-side template prints without escaping.

`res.render("order", {order, sort})` is an XSS sink only for the data the template
writes raw (`<%- x %>`, `{{{ x }}}`, `x | safe`, pug `!= x`); the rest is escaped
by the engine. The scanner asks this module which top-level data keys a view
prints raw, and drops the render sink for the others.

The answer is conservative: `None` means "cannot tell" (view not found, an
include that cannot be read, autoescape turned off), and the caller keeps every
render argument as a sink, exactly as if this module did not exist.

Supported flavours (the raw markers are distinct, so one pass reads them all), each an entry of
specs/data/template-engines.toml: EJS, Handlebars/Mustache, Nunjucks/Swig/Twig/Jinja-style, Pug/Jade.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

from frame.sil.specs.template_engines import IDENT as _IDENT, load as _engines

# Each engine's syntax (raw output, includes, bound variables), the view extensions and
# directories, and the escape switches are data: specs/data/template-engines.toml.
_MAX_DEPTH = 4
_MAX_ANCESTORS = 8


def _roots(expr: str) -> Set[str]:
    """Top-level identifiers an expression reads (`order.card.cvv` -> `order`)."""
    expr = re.sub(r"(['\"`])(?:\\.|(?!\1).)*\1", " ", expr)          # string literals
    out: Set[str] = set()
    for m in re.finditer(r"(?<![\w$.])(" + _IDENT + r")", expr):
        name = m.group(1)
        if name not in _engines().keywords:
            out.add(name)
    return out


def find_template(view: str, source_file: str) -> Optional[Path]:
    """The template file `view` names, looked up in the view directories of the
    source file's directory and its ancestors."""
    if not view or "\x00" in view or view.startswith(("http:", "https:")):
        return None
    start = Path(source_file).resolve().parent if source_file and source_file != "<unknown>" else None
    if start is None:
        return None
    engines = _engines()
    names = [view] if Path(view).suffix in engines.extensions else [view + ext for ext in engines.extensions]
    here = start
    for _ in range(_MAX_ANCESTORS):
        for d in engines.view_dirs:
            for name in names:
                cand = here / d / name
                try:
                    if cand.is_file() and cand.resolve().is_relative_to((here / d).resolve()):
                        return cand
                except OSError:
                    continue
        if here.parent == here:
            break
        here = here.parent
    return None


def _scan(path: Path, depth: int, seen: Set[Path]) -> Optional[Tuple[Set[str], Dict[str, Set[str]]]]:
    """(raw expression roots, alias -> source roots) for a template and what it
    includes; None when it cannot be read completely."""
    if depth > _MAX_DEPTH:
        return None
    path = path.resolve()
    if path in seen:
        return set(), {}
    seen.add(path)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    engines = _engines()
    if engines.template_escape_off.search(text) or engines.dynamic_include.search(text):
        return None
    raw: Set[str] = set()
    aliases: Dict[str, Set[str]] = {}
    for rx in engines.patterns("raw"):
        for m in rx.finditer(text):
            if re.match(r"\s*(?:include|partial|extends)\b", m.group("expr")):
                continue                             # an include's own output; its file is read below
            roots = _roots(m.group("expr"))
            if not roots:
                return None                          # raw output we cannot attribute to a name
            raw |= roots
    for engine in engines.engines:                   # handlebars: a block's context
        if engine.block_open is None:
            continue
        for m in engine.block_open.finditer(text):
            if _block_has_raw(engine, text, m.end()):
                raw |= _roots(m.group("context"))
    for rx in engines.patterns("alias"):
        for m in rx.finditer(text):
            aliases.setdefault(m.group("alias"), set()).update(_roots(m.group("source")))
    for rx in engines.patterns("include"):
        for m in rx.finditer(text):
            target = _resolve_include(path, m.group("file"))
            if target is None:
                return None
            sub = _scan(target, depth + 1, seen)
            if sub is None:
                return None
            raw |= sub[0]
            for k, v in sub[1].items():
                aliases.setdefault(k, set()).update(v)
    return raw, aliases


def _block_has_raw(engine, text: str, start: int) -> bool:
    """Whether a raw marker (of the engine's `block_raw_engines`) appears before the block closes."""
    end = engine.block_close.search(text[start:])
    chunk = text[start: start + end.start()] if end else text[start:]
    return any(rx.search(chunk) for rx in _engines().raw_of(engine.block_raw_engines))


def _resolve_include(from_file: Path, ref: str) -> Optional[Path]:
    extensions = _engines().extensions
    names = [ref] if Path(ref).suffix in extensions else [ref + e for e in extensions]
    for base in (from_file.parent, from_file.parent.parent):
        for name in names:
            for cand in (base / name, base / "partials" / name):
                try:
                    if cand.is_file():
                        return cand
                except OSError:
                    continue
    return None


@lru_cache(maxsize=512)
def _raw_keys(path_str: str, mtime: float) -> Optional[FrozenSet[str]]:
    path = Path(path_str)
    scanned = _scan(path, 0, set())
    if scanned is None:
        return None
    raw, aliases = scanned
    # a layout next to the view prints raw output with the same data
    for layout in _engines().layouts:
        for ext in _engines().extensions:
            cand = path.parent / (layout + ext)
            if cand.is_file() and cand != path:
                extra = _scan(cand, 1, {path.resolve()})
                if extra is None:
                    return None
                raw |= extra[0]
                for k, v in extra[1].items():
                    aliases.setdefault(k, set()).update(v)
    resolved: Set[str] = set()
    todo: List[str] = list(raw)
    while todo:
        name = todo.pop()
        if name in resolved:
            continue
        resolved.add(name)
        todo.extend(aliases.get(name, ()))
    return frozenset(resolved)


_MAX_CONFIG_FILES = 400


def _app_root(path: Path) -> Path:
    for parent in path.parents:
        if (parent / "package.json").is_file():
            return parent
    return path.parent


@lru_cache(maxsize=64)
def _engine_escaping_disabled(root: str) -> bool:
    """Whether the application turns the template engine's escaping off anywhere
    (`swig.setDefaults({ autoescape: false })`, `nunjucks.configure({ autoescape: false })`,
    Handlebars `noEscape: true`). Then `{{ x }}` is raw output and the template says nothing."""
    seen = 0
    for ext in ("*.js", "*.ts", "*.mjs", "*.cjs"):
        for f in Path(root).rglob(ext):
            if "node_modules" in f.parts or ".git" in f.parts:
                continue
            seen += 1
            if seen > _MAX_CONFIG_FILES:
                return False
            try:
                if _engines().config_escape_off.search(f.read_text(encoding="utf-8", errors="replace")):
                    return True
            except OSError:
                continue
    return False


def raw_data_keys(view: str, source_file: str) -> Optional[FrozenSet[str]]:
    """The names the view `view` (rendered from `source_file`) can print without
    escaping, or None when that cannot be determined."""
    path = find_template(view, source_file)
    if path is None:
        return None
    if _engine_escaping_disabled(str(_app_root(path))):
        return None
    try:
        return _raw_keys(str(path), path.stat().st_mtime)
    except OSError:
        return None


def keep_render_arguments(view: str, source_file: str, keys: Iterable[str]) -> Optional[Set[str]]:
    """Of the data keys passed to a render call, those that can reach raw output;
    None when the template is unknown (keep every argument)."""
    raw = raw_data_keys(view, source_file)
    if raw is None:
        return None
    return {k for k in keys if k in raw}
