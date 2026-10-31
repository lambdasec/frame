"""OpenAPI documents in a project (the OpenAPI Specification, and Swagger 2.0): each operation's
`operationId` and its specification extensions, for frameworks that dispatch an operation to the
code an `operationId` names (connexion: a dotted Python path, optionally prefixed by the
`x-openapi-router-controller` module). Read from YAML or JSON; nothing is executed.

https://spec.openapis.org/oas/v3.1.0#operation-object, https://swagger.io/specification/v2/"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional

# The HTTP methods a Path Item Object can hold an Operation Object under.
_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox", "dist", "build"}
_MAX_BYTES = 2_000_000


@dataclass
class Operation:
    document: Path
    path: str                                   # the templated path (`/users/{username}`)
    method: str
    operation_id: str
    extensions: Dict[str, str] = field(default_factory=dict)   # `x-...` string values, operation over path item


def _load(path: Path) -> Optional[dict]:
    try:
        if path.stat().st_size > _MAX_BYTES:
            return None
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    try:
        if path.suffix == ".json":
            data = json.loads(text)
        else:
            import yaml
            data = yaml.safe_load(text)
    except Exception:
        return None
    if not isinstance(data, dict) or not isinstance(data.get("paths"), dict):
        return None
    if not (isinstance(data.get("openapi"), str) or str(data.get("swagger", "")).startswith("2")):
        return None
    return data


def _extensions(*objs: dict) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for obj in objs:                            # later (more specific) objects win
        for k, v in obj.items():
            if isinstance(k, str) and k.startswith("x-") and isinstance(v, str):
                out[k] = v
    return out


def operations(document: Path) -> List[Operation]:
    data = _load(document)
    if data is None:
        return []
    out: List[Operation] = []
    for route, item in data["paths"].items():
        if not isinstance(item, dict):
            continue
        for method in _METHODS:
            op = item.get(method)
            if isinstance(op, dict) and isinstance(op.get("operationId"), str) and op["operationId"]:
                out.append(Operation(document, str(route), method, op["operationId"], _extensions(item, op)))
    return out


def documents(root: Path) -> Iterator[Path]:
    """The YAML / JSON files under `root` that are OpenAPI or Swagger 2.0 documents."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            if name.endswith((".yaml", ".yml", ".json")):
                p = Path(dirpath) / name
                if _load(p) is not None:
                    yield p


__all__ = ["Operation", "documents", "operations"]
