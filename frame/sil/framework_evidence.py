"""Does JS/TS code show that `req` / `request` really is a web request?

The JS source model matches `req.query`, `req.body`, ... by name. That is right in
an Express/Koa/Fastify/Nest app and a guess anywhere else. A finding whose source is
such a name gets `source_evidence = "naming-convention"` unless the file (or, in a
project, any file) imports a web framework, so consumers can rank or filter them.
"""

from __future__ import annotations

import re

from frame.sil.specs.request_objects import load as _request_objects

_IMPORT = re.compile(
    r"""(?:require\s*\(\s*|from\s+|import\s+|import\s*\(\s*)['"]((?:node:)?[@\w./-]+)['"]""")
SOURCE_ROOTS = _request_objects().js_request_names


def _patterns():
    r = _request_objects()                                   # specs/data/request-objects.toml
    words = "|".join(re.escape(d) for d in r.js_handler_decorators)
    types = "|".join(re.escape(t) for t in r.js_request_types)
    return (re.compile(rf"@(?:{words})\s*\("),
            re.compile(rf"\b\w+\s*:\s*(?:express\.|Express\.)?(?:{types})\b"))


def has_framework_evidence(source: str) -> bool:
    frameworks = _request_objects().js_framework_modules
    for m in _IMPORT.finditer(source):
        name = m.group(1).removeprefix("node:")
        if name in frameworks or name.split("/")[0] in frameworks:
            return True
    decorator, typed = _patterns()
    return bool(decorator.search(source) or typed.search(source))


def source_is_named_request(source_var: str) -> bool:
    """Whether a finding's source is a `req.*` / `request.*` name (the guessed ones)."""
    root = re.split(r"[.\[]", source_var or "", maxsplit=1)[0]
    return root in SOURCE_ROOTS
