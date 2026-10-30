"""YAML documents with the line of every value, for pointing a finding at its cause.

PyYAML's composer gives each node its position; values are built with the safe constructor
(YAML 1.1 scalars as PyYAML reads them, which is how the Kubernetes tooling written in Python
reads them; the API server's Go decoder agrees on the documents Kubernetes accepts). Tags the
safe loader does not know (CloudFormation's `!Ref`, `!Sub`, ...) are handed to `tags`, a map
from tag to a function of the node's plain value; any other unknown tag makes the document
unreadable, which is reported, never guessed around.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

import yaml

from .engine import DocPath

Lines = Dict[DocPath, int]


class YamlError(ValueError):
    pass


def _build(node, constructor, path: DocPath, lines: Lines, tags) -> Any:
    lines[path] = node.start_mark.line + 1
    tag = node.tag
    if isinstance(node, yaml.MappingNode):
        constructor.flatten_mapping(node)
        out: Dict[Any, Any] = {}
        for k, v in node.value:
            key = _build(k, constructor, path + ("<key>",), {}, tags)
            if isinstance(key, (list, dict)):
                raise YamlError(f"line {k.start_mark.line + 1}: a mapping key that is not a scalar")
            out[key] = _build(v, constructor, path + (key,), lines, tags)
            lines.setdefault(path + (key, "<key>"), k.start_mark.line + 1)
        value: Any = out
    elif isinstance(node, yaml.SequenceNode):
        value = [_build(v, constructor, path + (i,), lines, tags) for i, v in enumerate(node.value)]
    else:
        value = None
    if tag.startswith("!") and not tag.startswith("!!"):
        fn = tags.get(tag) if tags else None
        if fn is None:
            raise YamlError(f"line {node.start_mark.line + 1}: unknown tag {tag}")
        if isinstance(node, yaml.ScalarNode):
            value = node.value
        return fn(value)
    if isinstance(node, yaml.ScalarNode):
        try:
            return constructor.construct_object(node, deep=True)
        except yaml.YAMLError as e:
            raise YamlError(f"line {node.start_mark.line + 1}: {e}") from None
    return value


def load_all(text: str, tags: Optional[Dict[str, Callable[[Any], Any]]] = None
             ) -> Iterator[Tuple[Any, Lines, int]]:
    """Each document of a YAML stream as (value, lines, first line). Raises YamlError."""
    loader = yaml.SafeLoader(text)
    try:
        while loader.check_node():
            node = loader.get_node()
            if node is None:
                continue
            lines: Lines = {}
            value = _build(node, loader, (), lines, tags or {})
            yield value, lines, node.start_mark.line + 1
    except yaml.YAMLError as e:
        raise YamlError(str(e).replace("\n", " ")) from None
    finally:
        loader.dispose()


def line_of(lines: Lines, path: DocPath, default: int) -> int:
    """The line of `path`, else of its nearest ancestor that has one."""
    p: List = list(path)
    while True:
        if tuple(p) in lines:
            return lines[tuple(p)]
        if not p:
            return default
        p.pop()


__all__ = ["Lines", "YamlError", "line_of", "load_all"]
