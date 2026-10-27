"""A reader for CMake command invocations (`name(arg arg "quoted arg" [[bracket arg]])`), as
the CMake language defines them: whitespace-separated arguments, quoted and bracket arguments,
`#` and `#[[ ]]` comments, nested parentheses inside arguments. Enough to read
FetchContent / ExternalProject / CPM declarations and vcpkg port files without evaluating
CMake; variables (`${X}`) are kept as written.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class Command:
    name: str               # lower-cased
    args: List[str]
    line: int

    def keyword(self, key: str) -> Optional[str]:
        """The argument after `key` (`GIT_TAG v1.2`), case-sensitive like CMake keywords."""
        for i, a in enumerate(self.args[:-1]):
            if a == key:
                return self.args[i + 1]
        return None


_BRACKET_OPEN = re.compile(r"\[(=*)\[")


def commands(text: str) -> List[Command]:
    out: List[Command] = []
    i, n, line = 0, len(text), 1
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        if c == "#":
            m = _BRACKET_OPEN.match(text, i + 1)
            if m:                                           # #[[ block comment ]]
                end = text.find("]" + m.group(1) + "]", m.end())
                end = n if end < 0 else end + len(m.group(1)) + 2
            else:
                end = text.find("\n", i)
                end = n if end < 0 else end
            line += text.count("\n", i, end)
            i = end
            continue
        m = re.match(r"[A-Za-z_][A-Za-z0-9_]*", text[i:])
        if not m:
            i += 1
            continue
        name, j = m.group(0), i + len(m.group(0))
        while j < n and text[j] in " \t":
            j += 1
        if j >= n or text[j] != "(":
            i = j
            continue
        start_line = line
        args, j, line = _arguments(text, j + 1, line)
        out.append(Command(name.lower(), args, start_line))
        i = j
    return out


def _arguments(text: str, i: int, line: int):
    args: List[str] = []
    depth, cur, n = 0, None, len(text)

    def flush():
        nonlocal cur
        if cur is not None:
            args.append(cur)
        cur = None
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
        if c == '"':                                       # quoted argument
            flush()
            j, buf = i + 1, []
            while j < n and text[j] != '"':
                if text[j] == "\\" and j + 1 < n:
                    buf.append(text[j + 1])
                    j += 2
                    continue
                if text[j] == "\n":
                    line += 1
                buf.append(text[j])
                j += 1
            args.append("".join(buf))
            i = j + 1
            continue
        m = _BRACKET_OPEN.match(text, i) if c == "[" else None
        if m and cur is None:                               # [[bracket argument]]
            end = text.find("]" + m.group(1) + "]", m.end())
            end = n if end < 0 else end
            args.append(text[m.end():end])
            line += text.count("\n", i, end)
            i = end + len(m.group(1)) + 2
            continue
        if c == "#":
            flush()
            end = text.find("\n", i)
            i = n if end < 0 else end
            continue
        if c == "(":
            depth += 1
            cur = (cur or "") + c
        elif c == ")":
            if depth == 0:
                flush()
                return args, i + 1, line
            depth -= 1
            cur = (cur or "") + c
        elif c in " \t\r\n":
            flush()
        else:
            cur = (cur or "") + c
        i += 1
    flush()
    return args, i, line
