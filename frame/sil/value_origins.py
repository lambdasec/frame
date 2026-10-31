"""Value origins: the call a variable's value comes from, so a later call on it has a callee id.

`const c = mysql.createConnection(o); c.query(q)` makes `c.query` the call
`mysql.createConnection.query`, as Python's frontend already names `conn.execute` after
`conn = sqlite3.connect(...)`. A name counts only when it is bound exactly once in its procedure
(never a parameter), or once at module level and never in the procedure that reads it; a copy
`d = c` carries the origin. Nothing is guessed: a name bound twice, or to anything but a call
with an id, has no origin, and its calls keep `canonical = None`.

What those calls return is data (`specs/data/value-types.toml`, `typed_names`): `sqlite3.connect`
returns a `sqlite3.Connection`, whose `cursor()` returns a `sqlite3.Cursor`, so
`sqlite3.connect.cursor.execute` is looked up as `sqlite3.Cursor.execute` and under the spec
table's receiver names for that type (`cursor.execute`)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]

from .instructions import Assign, Call
from .types import ExpCall, ExpConst, ExpVar

MODULE = "<module>"
PATH = Path(__file__).parent / "specs" / "data" / "value-types.toml"


def _call_text(call: Call) -> Optional[str]:
    f = call.func
    if isinstance(f, ExpConst) and isinstance(f.value, str):
        return f.value
    if isinstance(f, ExpVar):
        return str(f.var)
    return None


def _ret_name(call: Call) -> Optional[str]:
    ret = call.ret
    if not ret:
        return None
    ident = ret[0] if isinstance(ret, tuple) else ret
    return str(ident)                                  # `$app_1`: a temporary, not the variable app


def _instrs(proc):
    for node in proc.nodes.values():
        yield from node.instrs


def _definitions(proc) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for p, _ in proc.params:
        counts[str(p)] = 2        # a parameter is never single-bound
    for i in _instrs(proc):
        name = _ret_name(i) if isinstance(i, Call) else str(i.id) \
            if isinstance(i, Assign) else None
        if name:
            counts[name] = counts.get(name, 0) + 1
    return counts


def _expression_call_origin(exp, imports: Dict[str, str]) -> Optional[str]:
    """`new Pool(o)` / `mysql.createPool(o)` written as an expression (no Call instruction): the
    class or the call id, through the file's imports."""
    if not isinstance(exp, ExpCall):
        return None
    text = _call_text(exp)
    if not text:
        return None
    new = text.startswith("new ")
    name = text[4:] if new else text
    head, _, rest = name.partition(".")
    qualified = imports.get(head)
    if qualified is None or not head.isidentifier():
        return None
    return f"{qualified}.{rest}" if rest else qualified


def _origins(proc, outer: Dict[str, str], fill: bool, imports: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Origins of the names bound once in `proc`; with `fill`, also give unresolved calls on
    them their callee id."""
    imports = imports or {}
    defs = _definitions(proc)
    origin: Dict[str, str] = {}

    def of(name: str) -> Optional[str]:
        if name in origin:
            return origin[name]
        return outer.get(name) if name not in defs else None

    for _ in range(8):                                  # chains `a = f(); b = a.g(); b.h()`
        changed = False
        for i in _instrs(proc):
            if isinstance(i, Call):
                text = _call_text(i)
                if i.canonical is None and fill and text and "." in text and not text.startswith(("this.", "self.")):
                    head, rest = text.split(".", 1)
                    o = of(head)
                    if o is not None and head.isidentifier():
                        i.canonical = f"{o}.{rest}"
                        changed = True
                r = _ret_name(i)
                if r and defs.get(r) == 1 and i.canonical and origin.get(r) != i.canonical:
                    origin[r] = i.canonical
                    changed = True
            elif isinstance(i, Assign) and isinstance(i.exp, (ExpVar, ExpCall)):
                x = str(i.id)
                o = of(str(i.exp.var)) if isinstance(i.exp, ExpVar) else _expression_call_origin(i.exp, imports)
                if o is not None and defs.get(x) == 1 and origin.get(x) != o:
                    origin[x] = o
                    changed = True
        if not changed:
            break
    return origin


def annotate(program) -> None:
    """Fill `Call.canonical` from value origins (calls whose callee id the frontend left unset)."""
    imports = {k: str(v) for k, v in (getattr(program, "imports", None) or {}).items()}
    module = program.procedures.get(MODULE)
    outer = _origins(module, {}, fill=True, imports=imports) if module is not None else {}
    program.export_origin = outer.get("module.exports")
    for name, proc in program.procedures.items():
        if name != MODULE:
            _origins(proc, outer, fill=True, imports=imports)


def link_modules(programs: Dict[str, object], resolve) -> None:
    """In a project: a call on a module another file of the project is (`../db.query`, the JS
    frontend's name for `db.query` after `const db = require("../db")`) takes the origin of the
    value that file exports (`module.exports = mysql.createPool(...)`). `resolve(key, specifier)`
    gives the file a specifier names, or None."""
    for key, program in programs.items():
        for proc in program.procedures.values():
            for i in _instrs(proc):
                if not isinstance(i, Call) or i.canonical is not None:
                    continue
                text = _call_text(i)
                if not text or not text.startswith("."):
                    continue
                cut = len(text)
                while True:
                    cut = text.rfind(".", 0, cut)
                    if cut <= 0:
                        break
                    target = resolve(key, text[:cut])
                    if target is not None:
                        origin = getattr(programs.get(target), "export_origin", None)
                        if origin:
                            i.canonical = f"{origin}.{text[cut + 1:]}"
                        break


# -- what library calls return ------------------------------------------------------------------

@lru_cache(maxsize=None)
def load(path: Path = PATH) -> Dict[str, Tuple[Dict[str, str], Dict[str, Tuple[str, ...]]]]:
    """language -> (call id -> returned type, type or class -> spec receiver names)."""
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    out = {}
    for lang, table in data.items():
        if not isinstance(table, dict) or set(table) - {"returns", "receivers"}:
            raise ValueError(f"{Path(path).name}: [{lang}] holds only returns and receivers")
        returns, receivers = table.get("returns", {}), table.get("receivers", {})
        if not all(isinstance(k, str) and isinstance(v, str) and v for k, v in returns.items()):
            raise ValueError(f"{Path(path).name}: [{lang}.returns] maps call ids to a type name")
        if not all(isinstance(v, list) and v and all(isinstance(n, str) and n for n in v)
                   for v in receivers.values()):
            raise ValueError(f"{Path(path).name}: [{lang}.receivers] maps a type to spec receiver names")
        out[lang] = (dict(returns), {k: tuple(v) for k, v in receivers.items()})
    return out


def _without_arguments(text: str) -> str:
    """`sqlite3.connect("x").execute` -> `sqlite3.connect.execute`: a chained call's id is
    written with the argument text of the calls in it."""
    out, depth, quote = [], 0, ""
    for ch in text:
        if quote:
            if ch == quote:
                quote = ""
            continue
        if depth and ch in "\"'`":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif not depth:
            out.append(ch)
    return "".join(out)


def typed_names(canonical: str, language: str) -> List[str]:
    """Spec keys for a call id whose receiver is a typed library value (most specific first);
    empty when no part of the id is a call whose return type is known."""
    lang = "javascript" if (language or "").lower() == "typescript" else (language or "").lower()
    returns, receivers = load().get(lang, ({}, {}))
    parts = _without_arguments(canonical).split(".")
    typ: Optional[str] = None
    i = 0
    while i < len(parts) - 1:                           # the last part is the method called
        for j in range(len(parts) - 1, i, -1):          # longest call id first
            key = ".".join(([typ] if typ else []) + parts[i:j]) if typ else ".".join(parts[i:j])
            if key in returns:
                typ, i = returns[key], j
                break
        else:
            if typ is None:                             # an instance of a class (`new pg.Pool()`)
                cls = next((".".join(parts[:j]) for j in range(len(parts) - 1, 0, -1)
                            if ".".join(parts[:j]) in receivers), None)
                if cls is None:
                    return []
                typ, i = cls, len(cls.split("."))
                continue
            break
    if typ is None or i != len(parts) - 1:
        return []
    method = parts[-1]
    return [f"{typ}.{method}"] + [f"{r}.{method}" for r in receivers.get(typ, ())]


__all__ = ["annotate", "load", "typed_names"]
