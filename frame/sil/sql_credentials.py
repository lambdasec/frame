"""Which parameters of a SQL statement written in the program store a credential.

A statement text a call passes as its first argument (`db.execute("INSERT INTO users (name,
password) VALUES (?, ?)", (name, pw))`) is read for the columns its INSERT or UPDATE writes,
and for the placeholder each column takes its value from: positional (`?`, `%s`), numbered
(`$1`) or named (`:name`, `@name`, `$name`, `%(name)s`). A column whose name denotes a credential
(`secret_names.is_credential_name`: `password`, `session_token`, `api_key`) makes its placeholder a
credential-storage sink, which the frontends emit for the matching element of the parameters
argument. Anything this does not parse binds nothing: a statement it cannot read is never
guessed at.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Union

from .secret_names import is_credential_name

Key = Union[int, str]

_INSERT = re.compile(r"\s*(?:INSERT|REPLACE)(?:\s+OR\s+\w+)?\s+INTO\s+[\w.\"`\[\]]+\s*\(([^()]*)\)\s*VALUES\s*\(",
                     re.IGNORECASE | re.DOTALL)
_UPDATE = re.compile(r"\s*UPDATE\s+(?:OR\s+\w+\s+)?[\w.\"`\[\]]+\s+SET\s+", re.IGNORECASE | re.DOTALL)
_WHERE = re.compile(r"\s(?:WHERE|RETURNING|FROM)\s", re.IGNORECASE)
_PLACEHOLDER = re.compile(r"%\((\w+)\)s|%s|\?(\d*)|\$(\d+)|[:@$]([A-Za-z_]\w*)")


def _split_top(text: str) -> Optional[List[str]]:
    """`text` split at commas outside parentheses and quotes; None when unbalanced."""
    parts: List[str] = []
    depth, start, quote = 0, 0, ""
    for i, c in enumerate(text):
        if quote:
            if c == quote:
                quote = ""
            continue
        if c in "'\"":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth < 0:
                return None
        elif c == "," and depth == 0:
            parts.append(text[start:i])
            start = i + 1
    if depth or quote:
        return None
    parts.append(text[start:])
    return parts


def _values_list(sql: str, start: int) -> Optional[str]:
    """The text inside the parentheses opened just before `start`."""
    depth, quote = 1, ""
    for i in range(start, len(sql)):
        c = sql[i]
        if quote:
            if c == quote:
                quote = ""
            continue
        if c in "'\"":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return sql[start:i]
    return None


def _column(name: str) -> str:
    """`users."password"` -> `password`."""
    return name.strip().split(".")[-1].strip("\"`[] \t\n")


def credential_parameters(sql: str) -> Dict[Key, str]:
    """{placeholder: credential column} for the values an INSERT or UPDATE writes into credential
    columns. A placeholder is its 0-based position among the statement's positional ones, or its
    name. A value that is not a single placeholder (a literal, an expression) binds nothing."""
    if not isinstance(sql, str):
        return {}
    pairs: List[tuple] = []          # (column, value text, offset of the value in sql)
    m = _INSERT.match(sql)
    if m:
        columns = _split_top(m.group(1))
        values = _values_list(sql, m.end())
        split = _split_top(values) if values is not None else None
        if columns is None or split is None or len(columns) != len(split):
            return {}
        offset = m.end()
        for col, val in zip(columns, split):
            pairs.append((_column(col), val, offset))
            offset += len(val) + 1
        before = sql[:m.end()]
    else:
        m = _UPDATE.match(sql)
        if not m:
            return {}
        rest = sql[m.end():]
        w = _WHERE.search(rest)
        assigns = _split_top(rest[:w.start()] if w else rest)
        if assigns is None:
            return {}
        offset = m.end()
        for a in assigns:
            col, eq, val = a.partition("=")
            if not eq:
                return {}
            pairs.append((_column(col), val, offset + len(col) + 1))
            offset += len(a) + 1
        before = sql[:m.end()]
    ordinal = len([p for p in _PLACEHOLDER.finditer(before) if _positional(p)])
    out: Dict[Key, str] = {}
    for col, val, _ in pairs:
        found = list(_PLACEHOLDER.finditer(val))
        positional = [p for p in found if _positional(p)]
        whole = len(found) == 1 and val.strip() == found[0].group(0)
        if whole and is_credential_name(col):
            p = found[0]
            if p.group(3):
                out[int(p.group(3)) - 1] = col
            elif p.group(2):
                out[int(p.group(2)) - 1] = col
            elif positional:
                out[ordinal] = col
            else:
                out[p.group(1) or p.group(4)] = col
        ordinal += len(positional)
    return out


def _positional(p: "re.Match") -> bool:
    return p.group(0) in ("?", "%s")


__all__ = ["credential_parameters"]
