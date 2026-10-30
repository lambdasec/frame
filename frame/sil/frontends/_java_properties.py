"""Reading a Java `.properties` resource the way `java.util.Properties.load(InputStream)` reads
it, so `props.getProperty("key", "default")` after `props.load(...getResourceAsStream("x.properties"))`
has the value the project ships.

Format (the `Properties.load(Reader)` javadoc): a natural line ending in an odd number of
backslashes continues on the next line (leading whitespace of the continuation dropped);
blank lines and lines whose first non-blank character is `#` or `!` are comments; the key
ends at the first unescaped `=`, `:` or whitespace, then whitespace and one `=` or `:`
are skipped; `\\uXXXX` and `\\t \\n \\r \\f` are escapes, any other `\\x` is `x`. `load(InputStream)`
reads ISO 8859-1.

A resource is found on the classpath as the Maven and Gradle layouts put it there: in a
directory of the source file or one of its parents, directly, under `resources/` or under
`src/main/resources/`; the nearest wins. Not found (or unreadable) means unknown.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Dict, Optional

_ESCAPES = {"t": "\t", "n": "\n", "r": "\r", "f": "\f"}


def _logical_lines(text: str):
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].lstrip(" \t\f")
        i += 1
        if not line or line[0] in "#!":
            continue
        while True:
            trailing = len(line) - len(line.rstrip("\\"))
            if trailing % 2 == 0 or i >= len(lines):
                if trailing % 2:
                    line = line[:-1]
                break
            line = line[:-1] + lines[i].lstrip(" \t\f")
            i += 1
        yield line


def _unescape(s: str) -> str:
    out, i = [], 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            e = s[i + 1]
            if e == "u" and i + 6 <= len(s):
                try:
                    out.append(chr(int(s[i + 2:i + 6], 16)))
                    i += 6
                    continue
                except ValueError:
                    pass
            out.append(_ESCAPES.get(e, e))
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def parse(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for line in _logical_lines(text):
        i, n = 0, len(line)
        while i < n:
            c = line[i]
            if c == "\\":
                i += 2
                continue
            if c in "=: \t\f":
                break
            i += 1
        key = line[:i]
        while i < n and line[i] in " \t\f":
            i += 1
        if i < n and line[i] in "=:":
            i += 1
        while i < n and line[i] in " \t\f":
            i += 1
        out[_unescape(key)] = _unescape(line[i:])
    return out


@lru_cache(maxsize=256)
def _load(path: str) -> Optional[Dict[str, str]]:
    try:
        return parse(Path(path).read_bytes().decode("latin-1"))
    except OSError:
        return None


def resource(source_file: Optional[str], name: str) -> Optional[Dict[str, str]]:
    """The properties of classpath resource `name` for a source file, or None."""
    if not source_file or not name or ".." in name.split("/"):
        return None
    name = name.lstrip("/")
    here = Path(source_file).resolve().parent
    for d in [here, *here.parents]:
        for cand in (d / name, d / "resources" / name, d / "src" / "main" / "resources" / name):
            if cand.is_file():
                return _load(str(cand))
        if (d / ".git").exists():
            break
    return None


__all__ = ["parse", "resource"]
