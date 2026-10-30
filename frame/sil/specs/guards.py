"""Library API facts for branch guards (`data/guards.toml`): string character tests, prefix and
membership methods, URL parsers and their host fields, path normalisers and separators, and the
regex match calls with how much of the subject each must cover. Loaded strictly."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Dict, FrozenSet, NamedTuple, Tuple

try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]

PATH = Path(__file__).parent / "data" / "guards.toml"
HOW = ("full", "prefix", "search")
_LISTS = ("charset_methods", "prefix_methods", "membership_methods", "collection_views",
          "literal_collection_types", "literal_collection_factories", "url_parsers", "host_fields",
          "path_normalizers", "path_separators")
_REGEX = {"compiled_methods", "literal_methods", "subject_methods", "matcher", "matcher_methods", "function"}
_FUNCTION = {"names", "pattern_arg", "subject_arg", "how"}


class RegexFunction(NamedTuple):
    names: FrozenSet[str]
    pattern_arg: int
    subject_arg: int
    how: str


class Guards(NamedTuple):
    charset_methods: FrozenSet[str]
    prefix_methods: FrozenSet[str]
    membership_methods: FrozenSet[str]
    collection_views: FrozenSet[str]
    literal_collection_types: Tuple[str, ...]
    literal_collection_factories: Tuple[str, ...]
    url_parsers: FrozenSet[str]
    host_fields: FrozenSet[str]
    path_normalizers: FrozenSet[str]
    path_separators: FrozenSet[str]
    compiled_methods: Dict[str, str]
    literal_methods: Dict[str, str]
    subject_methods: Dict[str, str]
    matcher: str
    matcher_methods: Dict[str, str]
    regex_functions: Tuple[RegexFunction, ...]

    def regex_function(self, name: str):
        return next((f for f in self.regex_functions if name in f.names), None)


def _hows(name: str, where: str, value) -> Dict[str, str]:
    if not isinstance(value, dict) or not value or not all(isinstance(k, str) and v in HOW for k, v in value.items()):
        raise ValueError(f"{name}: {where} maps method names to one of {list(HOW)}")
    return dict(value)


@lru_cache(maxsize=None)
def load(path: Path = PATH) -> Guards:
    name = Path(path).name
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    if set(data) != set(_LISTS) | {"regex"}:
        raise ValueError(f"{name}: needs exactly {sorted(set(_LISTS) | {'regex'})}")
    for k in _LISTS:
        if not isinstance(data[k], list) or not data[k] or not all(isinstance(v, str) and v for v in data[k]):
            raise ValueError(f"{name}: {k} must be a non-empty list of names")
    rx = data["regex"]
    if not isinstance(rx, dict) or set(rx) != _REGEX:
        raise ValueError(f"{name}: [regex] needs exactly {sorted(_REGEX)}")
    if not isinstance(rx["matcher"], str) or not rx["matcher"].isidentifier():
        raise ValueError(f"{name}: [regex] matcher must be a method name")
    functions = []
    for i, f in enumerate(rx["function"]):
        where = f"[[regex.function]] #{i + 1}"
        if not isinstance(f, dict) or set(f) != _FUNCTION or f["how"] not in HOW \
                or not all(isinstance(f[k], int) and not isinstance(f[k], bool) and f[k] >= 0
                           for k in ("pattern_arg", "subject_arg")) \
                or f["pattern_arg"] == f["subject_arg"] \
                or not isinstance(f["names"], list) or not f["names"]:
            raise ValueError(f"{name}: {where} needs names, distinct pattern_arg and subject_arg, how in {list(HOW)}")
        functions.append(RegexFunction(frozenset(f["names"]), f["pattern_arg"], f["subject_arg"], f["how"]))
    for k in ("literal_collection_types", "literal_collection_factories", "matcher_methods"):
        names = data.get(k) or rx.get(k)
        if not all(str(n).isidentifier() for n in names):
            raise ValueError(f"{name}: {k} must be plain identifiers")
    return Guards(
        **{k: frozenset(data[k]) for k in _LISTS if k not in ("literal_collection_types",
                                                              "literal_collection_factories")},
        literal_collection_types=tuple(data["literal_collection_types"]),
        literal_collection_factories=tuple(data["literal_collection_factories"]),
        compiled_methods=_hows(name, "[regex] compiled_methods", rx["compiled_methods"]),
        literal_methods=_hows(name, "[regex] literal_methods", rx["literal_methods"]),
        subject_methods=_hows(name, "[regex] subject_methods", rx["subject_methods"]),
        matcher=rx["matcher"],
        matcher_methods=_hows(name, "[regex] matcher_methods", rx["matcher_methods"]),
        regex_functions=tuple(functions))


__all__ = ["Guards", "HOW", "PATH", "RegexFunction", "load"]
