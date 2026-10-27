"""A reader for the YAML that package managers write (`pnpm-lock.yaml`, yarn berry's
`yarn.lock`): block mappings and block sequences of plain or quoted scalars.

Lockfiles are machine-written and use only that subset, so Frame reads them without a YAML
dependency. Flow collections (`{a: b}`, `[x, y]`) are kept as their text: no lockfile field
Frame reads is written that way. Block scalars (`|`, `>`) are skipped. Anything else is not
guessed at: a line that is not a mapping entry or a sequence item raises `YamlError`.
"""

from __future__ import annotations

from typing import Any, List, Optional, Tuple


class YamlError(ValueError):
    pass


def _unquote(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "'\"":
        body = s[1:-1]
        return body.replace("''", "'") if s[0] == "'" else body.replace('\\"', '"').replace("\\\\", "\\")
    return s


def _strip_comment(s: str) -> str:
    """Drop a trailing ` # comment` outside quotes."""
    quote = None
    for i, c in enumerate(s):
        if quote:
            if c == quote:
                quote = None
        elif c in "'\"":
            quote = c
        elif c == "#" and (i == 0 or s[i - 1] in " \t"):
            return s[:i].rstrip()
    return s


def _split_key(s: str) -> Optional[Tuple[str, str]]:
    """`key: value` / `key:` -> (key, value text); None when `s` is not a mapping entry."""
    if s[:1] in "'\"":
        q, i = s[0], 1
        while i < len(s):
            if s[i] == q:
                if q == "'" and s[i + 1:i + 2] == "'":
                    i += 2
                    continue
                if q == '"' and s[i - 1] == "\\":
                    i += 1
                    continue
                break
            i += 1
        rest = s[i + 1:]
        if not rest.startswith(":"):
            return None
        return _unquote(s[:i + 1]), rest[1:].strip()
    i = s.find(": ")
    if i < 0:
        return (s[:-1].strip(), "") if s.endswith(":") else None
    return s[:i].strip(), s[i + 2:].strip()


def _scalar(v: str) -> Any:
    if v[:1] in "'\"":
        return _unquote(v)
    return v


def loads(text: str) -> Any:
    root: dict = {}
    # each frame: (indent of its entries, container, key in the parent awaiting a value)
    stack: List[Tuple[int, Any]] = [(-1, root)]
    pending: Optional[Tuple[int, Any, str]] = None      # a `key:` with no value yet
    skip_above: Optional[int] = None                    # inside a block scalar
    for lineno, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#") or raw.strip() == "---":
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if skip_above is not None:
            if indent > skip_above:
                continue
            skip_above = None
        line = _strip_comment(raw.strip())
        if pending is not None:
            p_indent, p_parent, p_key = pending
            pending = None
            if indent > p_indent or (indent == p_indent and line.startswith("- ")):
                child: Any = [] if line.startswith("-") else {}
                p_parent[p_key] = child
                stack.append((indent, child))
            else:
                p_parent[p_key] = None
        while len(stack) > 1 and (indent < stack[-1][0] or (
                indent == stack[-1][0] and isinstance(stack[-1][1], list) and not line.startswith("-"))):
            stack.pop()                 # (a sequence may sit at its key's indent; a key there ends it)
        level, container = stack[-1]
        if indent != level and level >= 0:
            raise YamlError(f"line {lineno}: unexpected indentation")
        if line == "-" or line.startswith("- "):
            if not isinstance(container, list):
                raise YamlError(f"line {lineno}: a sequence item inside a mapping")
            item = line[1:].strip()
            entry = _split_key(item) if item else None
            if entry is not None and not item.startswith(("{", "[")):
                d: dict = {}
                container.append(d)
                stack.append((indent + 2, d))
                k, v = entry
                if v:
                    d[k] = _scalar(v)
                else:
                    pending = (indent + 2, d, k)
            else:
                container.append(_scalar(item) if item else None)
            continue
        if not isinstance(container, dict):
            raise YamlError(f"line {lineno}: a mapping entry inside a sequence")
        if stack[-1][0] < 0:
            stack[-1] = (indent, container)
        entry = _split_key(line)
        if entry is None:
            raise YamlError(f"line {lineno}: not a mapping entry: {line[:60]!r}")
        k, v = entry
        if v in ("|", ">", "|-", ">-", "|+", ">+"):
            container[k] = ""
            skip_above = indent
        elif v:
            container[k] = _scalar(v)
        else:
            pending = (indent, container, k)
    if pending is not None:
        pending[1][pending[2]] = None
    return root
