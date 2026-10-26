"""Facts read straight from source text that the SIL does not keep.

Today: module- or class-level compiled-regex constants (`HOST = re.compile(r"[a-z.]+")`,
`static final Pattern HOST = Pattern.compile("[a-z.]+")`, `const HOST = /^[a-z.]+$/`,
`static readonly Regex Host = new Regex("^[a-z.]+$")`). A guard such as
`if not HOST.fullmatch(x)` can only be judged by the pattern's text, which lives in
the constant's initialiser, not in the branch condition.
"""

from __future__ import annotations

import re
from typing import Dict

_PY = re.compile(r"""^[ \t]*([A-Za-z_]\w*)\s*=\s*(?:re\.)?compile\(\s*[rRuU]?(\"\"\"|'''|"|')(.*?)\2""",
                 re.M | re.S)
_JAVA = re.compile(r'''\bPattern\s+(\w+)\s*=\s*Pattern\.compile\(\s*"((?:\\.|[^"\\\n])*)"''')
_JS = re.compile(r"""(?:const|let|var)\s+(\w+)\s*=\s*/((?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/\\\n\[])+)/([a-z]*)\s*[;\n]""")
_CS = re.compile(r'''\bRegex\s+(\w+)\s*=\s*new\s+Regex\(\s*@?"((?:""|\\.|[^"\\\n])*)"''')


def constant_regexes(source: str, language: str) -> Dict[str, str]:
    """{constant name: regex text}; a name bound to two different patterns is dropped."""
    found: Dict[str, str] = {}
    conflicts = set()

    def add(name: str, pattern: str) -> None:
        if name in found and found[name] != pattern:
            conflicts.add(name)
        found[name] = pattern

    if language == "python":
        for m in _PY.finditer(source):
            add(m.group(1), m.group(3))
    elif language == "java":
        for m in _JAVA.finditer(source):
            add(m.group(1), m.group(2).replace("\\\\", "\\"))
    elif language in ("javascript", "typescript"):
        for m in _JS.finditer(source):
            if "m" not in m.group(3):               # the m flag moves ^ and $ to every line
                add(m.group(1), m.group(2))
    elif language == "csharp":
        for m in _CS.finditer(source):
            add(m.group(1), m.group(2).replace('""', '"'))
    for c in conflicts:
        found.pop(c, None)
    return found
