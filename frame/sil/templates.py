"""Which variables a server-side template prints without escaping.

`res.render("order", {order, sort})` is an XSS sink only for the data the template
writes raw (`<%- x %>`, `{{{ x }}}`, `x | safe`, pug `!= x`); the rest is escaped
by the engine. The scanner asks this module which top-level data keys a view
prints raw, and drops the render sink for the others.

The answer is conservative: `None` means "cannot tell" (view not found, an
include that cannot be read, autoescape turned off), and the caller keeps every
render argument as a sink, exactly as if this module did not exist.

Supported flavours (the raw markers are distinct, so one pass reads them all):
EJS, Handlebars/Mustache, Nunjucks/Swig/Twig/Jinja-style, Pug/Jade.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

_EXTENSIONS = (".ejs", ".pug", ".jade", ".hbs", ".handlebars", ".njk", ".nunjucks",
               ".twig", ".swig", ".html")
_VIEW_DIRS = ("views", "templates", "app/views", "src/views", "app/templates", "src/templates")
_MAX_DEPTH = 4
_MAX_ANCESTORS = 8
_IDENT = r"[A-Za-z_$][\w$]*"
_KEYWORDS = frozenset(
    "true false null undefined this new typeof instanceof in of if else for while return var let const "
    "function and or not is none include extends block endblock".split())

# raw output, one regex per flavour; group 1 is the expression
_RAW = [
    re.compile(r"<%-(.*?)%>", re.S),                    # EJS
    re.compile(r"\{\{\{\{?(.*?)\}\}\}\}?", re.S),       # Handlebars {{{x}}}
    re.compile(r"\{\{\s*&(.*?)\}\}", re.S),             # Mustache {{& x}}
    re.compile(r"\{\{(.*?)\|\s*(?:safe|raw)\b.*?\}\}", re.S),   # Nunjucks / Swig / Twig
    re.compile(r"^\s*[\w.#-]*(?:\([^)]*\))?\s*!=(.*)$", re.M),  # Pug  p!= x
    re.compile(r"!\{(.*?)\}"),                          # Pug interpolation !{x}
]
_ALIAS = [
    (re.compile(r"for\s*\(\s*(?:const|let|var)?\s*(" + _IDENT + r")\s+(?:of|in)\s+([^)]+)\)"), 1, 2),
    (re.compile(r"for\s+(" + _IDENT + r")(?:\s*,\s*" + _IDENT + r")?\s+in\s+([^%}\n]+)"), 1, 2),
    (re.compile(r"each\s+(" + _IDENT + r")(?:\s*,\s*" + _IDENT + r")?\s+in\s+(.+)"), 1, 2),
    (re.compile(r"(?:const|let|var)\s+(" + _IDENT + r")\s*=\s*([^;%\n]+)"), 1, 2),
    (re.compile(r"set\s+(" + _IDENT + r")\s*=\s*([^%}\n]+)"), 1, 2),
]
_FOREACH = re.compile(r"([\w$.\[\]]+)\.(?:forEach|map|filter|some|every|reduce)\s*\(\s*"
                      r"(?:function\s*)?\(?\s*(" + _IDENT + r")")
_EACH_BLOCK = re.compile(r"\{\{\s*#(?:each|with)\s+([^}]+?)\s*\}\}")
_AUTOESCAPE_OFF = re.compile(r"autoescape\s+(?:false|off)", re.I)
_INCLUDE = [
    re.compile(r"<%[-_]?\s*include\s*\(?\s*['\"]([^'\"]+)['\"]"),     # EJS
    re.compile(r"\{%\s*(?:include|extends|import|from)\s+['\"]([^'\"]+)['\"]"),   # Nunjucks / Twig
    re.compile(r"\{\{>\s*([\w./-]+)"),                                 # Handlebars partial
    re.compile(r"^\s*(?:include|extends)\s+([\w./-]+)\s*$", re.M),    # Pug
]
_DYNAMIC_INCLUDE = re.compile(r"<%[-_]?\s*include\s*\(\s*[^'\"\s]|\{%\s*(?:include|extends)\s+[^'\"\s]")


def _roots(expr: str) -> Set[str]:
    """Top-level identifiers an expression reads (`order.card.cvv` -> `order`)."""
    expr = re.sub(r"(['\"`])(?:\\.|(?!\1).)*\1", " ", expr)          # string literals
    out: Set[str] = set()
    for m in re.finditer(r"(?<![\w$.])(" + _IDENT + r")", expr):
        name = m.group(1)
        if name not in _KEYWORDS:
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
    names = [view] if Path(view).suffix in _EXTENSIONS else [view + ext for ext in _EXTENSIONS]
    here = start
    for _ in range(_MAX_ANCESTORS):
        for d in _VIEW_DIRS:
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
    if _AUTOESCAPE_OFF.search(text) or _DYNAMIC_INCLUDE.search(text):
        return None
    raw: Set[str] = set()
    aliases: Dict[str, Set[str]] = {}
    for rx in _RAW:
        for m in rx.finditer(text):
            if re.match(r"\s*(?:include|partial|extends)\b", m.group(1)):
                continue                             # an include's own output; its file is read below
            roots = _roots(m.group(1))
            if not roots:
                return None                          # raw output we cannot attribute to a name
            raw |= roots
    for m in _EACH_BLOCK.finditer(text):             # handlebars: the block's context
        raw_in_block = _block_has_raw(text, m.end())
        if raw_in_block:
            raw |= _roots(m.group(1))
    for rx, a, s in _ALIAS:
        for m in rx.finditer(text):
            aliases.setdefault(m.group(a), set()).update(_roots(m.group(s)))
    for m in _FOREACH.finditer(text):
        aliases.setdefault(m.group(2), set()).update(_roots(m.group(1)))
    for rx in _INCLUDE:
        for m in rx.finditer(text):
            target = _resolve_include(path, m.group(1))
            if target is None:
                return None
            sub = _scan(target, depth + 1, seen)
            if sub is None:
                return None
            raw |= sub[0]
            for k, v in sub[1].items():
                aliases.setdefault(k, set()).update(v)
    return raw, aliases


def _block_has_raw(text: str, start: int) -> bool:
    """Whether a raw marker appears before the next closing `{{/each}}`/`{{/with}}`."""
    end = re.search(r"\{\{\s*/(?:each|with)\s*\}\}", text[start:])
    chunk = text[start: start + end.start()] if end else text[start:]
    return any(rx.search(chunk) for rx in _RAW[:3])


def _resolve_include(from_file: Path, ref: str) -> Optional[Path]:
    names = [ref] if Path(ref).suffix in _EXTENSIONS else [ref + e for e in _EXTENSIONS]
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
    for layout in ("layout", "_layout", "base"):
        for ext in _EXTENSIONS:
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


def raw_data_keys(view: str, source_file: str) -> Optional[FrozenSet[str]]:
    """The names the view `view` (rendered from `source_file`) can print without
    escaping, or None when that cannot be determined."""
    path = find_template(view, source_file)
    if path is None:
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
