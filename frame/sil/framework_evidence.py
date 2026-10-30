"""Does JS/TS code show that `req` / `request` really is a web request?

The JS source model matches `req.query`, `req.body`, ... by name. That is right in
an Express/Koa/Fastify/Nest app and a guess anywhere else. A finding whose source is
such a name gets `source_evidence = "naming-convention"` unless the file (or, in a
project, any file) imports a web framework, so consumers can rank or filter them.
"""

from __future__ import annotations

import re

from frame.sil.specs.request_objects import load as _request_objects

_FRAMEWORKS = (
    "express", "koa", "koa-router", "@koa/router", "fastify", "hapi", "@hapi/hapi", "restify",
    "@nestjs/common", "@nestjs/core", "next", "next/server", "sails", "loopback", "connect", "polka",
    "micro", "h3", "hono", "@adonisjs/core", "@feathersjs/feathers", "serverless-http", "http", "https",
)
_IMPORT = re.compile(
    r"""(?:require\s*\(\s*|from\s+|import\s+|import\s*\(\s*)['"]((?:node:)?[@\w./-]+)['"]""")
_NEST_DECORATOR = re.compile(r"@(?:Controller|Get|Post|Put|Delete|Patch|Req|Request)\s*\(")
_TYPED_REQUEST = re.compile(r"\b\w+\s*:\s*(?:express\.|Express\.)?(?:Request|NextRequest|FastifyRequest)\b")
SOURCE_ROOTS = _request_objects().js_request_names


def has_framework_evidence(source: str) -> bool:
    for m in _IMPORT.finditer(source):
        name = m.group(1).removeprefix("node:")
        if name in _FRAMEWORKS or name.split("/")[0] in _FRAMEWORKS:
            return True
    return bool(_NEST_DECORATOR.search(source) or _TYPED_REQUEST.search(source))


def source_is_named_request(source_var: str) -> bool:
    """Whether a finding's source is a `req.*` / `request.*` name (the guessed ones)."""
    root = re.split(r"[.\[]", source_var or "", maxsplit=1)[0]
    return root in SOURCE_ROOTS
