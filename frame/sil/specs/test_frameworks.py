"""What says a file is test code (`data/test-frameworks.toml`): test-framework imports per
language, Java annotation packages, C# test attributes, JS runner globals and pytest's discovery
prefix. Loaded strictly: a missing or unknown key is an error."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Dict, FrozenSet, NamedTuple, Tuple

try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]

PATH = Path(__file__).parent / "data" / "test-frameworks.toml"
_SHAPE = {"imports": {"python", "java", "javascript", "c"}, "java": {"annotation_packages"},
          "csharp": {"attributes"}, "javascript": {"runner_globals"}, "python": {"test_function_prefix"}}


class TestFrameworks(NamedTuple):
    imports: Dict[str, Tuple[str, ...]]     # language family -> module names / prefixes
    java_annotation_packages: Tuple[str, ...]
    csharp_attributes: FrozenSet[str]
    js_runner_globals: FrozenSet[str]
    python_test_prefix: str


def _names(name: str, where: str, value) -> Tuple[str, ...]:
    if not isinstance(value, list) or not value or not all(isinstance(v, str) and v for v in value):
        raise ValueError(f"{name}: {where} must be a non-empty list of names")
    return tuple(value)


@lru_cache(maxsize=None)
def load(path: Path = PATH) -> TestFrameworks:
    name = Path(path).name
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    if set(data) != set(_SHAPE):
        raise ValueError(f"{name}: needs exactly {sorted(_SHAPE)}")
    for table, keys in _SHAPE.items():
        if not isinstance(data[table], dict) or set(data[table]) != keys:
            raise ValueError(f"{name}: [{table}] needs exactly {sorted(keys)}")
    prefix = data["python"]["test_function_prefix"]
    if not isinstance(prefix, str) or not prefix:
        raise ValueError(f"{name}: [python] test_function_prefix must be a name")
    return TestFrameworks(
        imports={lang: _names(name, f"[imports] {lang}", v) for lang, v in data["imports"].items()},
        java_annotation_packages=_names(name, "[java] annotation_packages", data["java"]["annotation_packages"]),
        csharp_attributes=frozenset(_names(name, "[csharp] attributes", data["csharp"]["attributes"])),
        js_runner_globals=frozenset(_names(name, "[javascript] runner_globals", data["javascript"]["runner_globals"])),
        python_test_prefix=prefix)


__all__ = ["PATH", "TestFrameworks", "load"]
