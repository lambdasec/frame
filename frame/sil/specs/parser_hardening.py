"""Parser and deserializer configuration (`data/parser-hardening.toml`): what hardens an XML
parser against XXE (JAXP features and attributes, lxml's parser keyword), which Java
deserializers have no safe mode, and how XStream, Jackson and SnakeYAML are configured safely or
unsafely. Loaded strictly: every key must be present, and nothing else may be."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Dict, FrozenSet, NamedTuple, Tuple

try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]

PATH = Path(__file__).parent / "data" / "parser-hardening.toml"

_SHAPE = {
    "xxe": {"features": dict, "access_attributes": list, "parser_products": list},
    "lxml": {"parse_functions": list, "parser": str, "parser_arg": int, "parser_keyword": str, "safe_keyword": str,
             "safe_factories": list},
    "dotnet": {"parser_types": list, "reader_factory": str, "resolver_property": str, "dtd_property": str,
               "dtd_parse": list, "dtd_safe": list, "prohibit_dtd_property": str},
    "deserialization": {"unsafe_types": list, "xstream": dict, "jackson": dict, "snakeyaml": dict},
    "deserialization.xstream": {"type": str, "hardening": list, "methods": list},
    "deserialization.jackson": {"type": str, "polymorphic": list, "methods": list},
    "deserialization.snakeyaml": {"type": str, "safe_constructors": list, "methods": list},
}


class ParserHardening(NamedTuple):
    xxe_features: Dict[str, str]
    xxe_access_attributes: Tuple[str, ...]
    xml_parser_products: FrozenSet[str]
    lxml_parse_functions: FrozenSet[str]
    lxml_parser: str
    lxml_safe_keyword: str
    lxml_parser_arg: int
    lxml_parser_keyword: str
    safe_parser_factories: FrozenSet[str]
    unsafe_deserializers: FrozenSet[str]
    xstream_type: str
    xstream_hardening: FrozenSet[str]
    jackson_type: str
    jackson_polymorphic: FrozenSet[str]
    yaml_type: str
    yaml_safe_constructors: FrozenSet[str]
    xstream_methods: FrozenSet[str] = frozenset()
    jackson_methods: FrozenSet[str] = frozenset()
    yaml_methods: FrozenSet[str] = frozenset()
    dotnet: Dict[str, object] = {}


def _check(name: str, where: str, table, shape) -> None:
    if not isinstance(table, dict) or set(table) != set(shape):
        raise ValueError(f"{name}: [{where}] needs exactly {sorted(shape)}")
    for key, typ in shape.items():
        value = table[key]
        ok = isinstance(value, typ) and not isinstance(value, bool) and (typ is int or bool(value))
        if typ is list:
            ok = ok and all(isinstance(v, str) and v for v in value)
        if typ is dict and where == "xxe":
            ok = ok and all(isinstance(v, str) and v for v in value.values())
        if not ok:
            raise ValueError(f"{name}: [{where}].{key} must be a non-empty {typ.__name__} of strings")


@lru_cache(maxsize=None)
def load(path: Path = PATH) -> ParserHardening:
    name = Path(path).name
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    if set(data) != {"xxe", "lxml", "dotnet", "deserialization"}:
        raise ValueError(f"{name}: needs exactly [xxe], [lxml], [dotnet] and [deserialization]")
    for where, shape in _SHAPE.items():
        table = data
        for part in where.split("."):
            table = table.get(part) if isinstance(table, dict) else None
        _check(name, where, table, shape)
    xxe, lxml, de = data["xxe"], data["lxml"], data["deserialization"]
    return ParserHardening(
        xxe_features={k: v.lower() for k, v in xxe["features"].items()},
        xxe_access_attributes=tuple(xxe["access_attributes"]),
        xml_parser_products=frozenset(xxe["parser_products"]),
        lxml_parse_functions=frozenset(lxml["parse_functions"]),
        lxml_parser=lxml["parser"],
        lxml_safe_keyword=lxml["safe_keyword"],
        lxml_parser_arg=lxml["parser_arg"],
        lxml_parser_keyword=lxml["parser_keyword"],
        safe_parser_factories=frozenset(lxml["safe_factories"]),
        unsafe_deserializers=frozenset(de["unsafe_types"]),
        xstream_type=de["xstream"]["type"],
        xstream_hardening=frozenset(de["xstream"]["hardening"]),
        jackson_type=de["jackson"]["type"],
        jackson_polymorphic=frozenset(de["jackson"]["polymorphic"]),
        yaml_type=de["snakeyaml"]["type"],
        yaml_safe_constructors=frozenset(de["snakeyaml"]["safe_constructors"]),
        xstream_methods=frozenset(de["xstream"]["methods"]), jackson_methods=frozenset(de["jackson"]["methods"]),
        yaml_methods=frozenset(de["snakeyaml"]["methods"]),
        dotnet=dict(data["dotnet"]))


__all__ = ["PATH", "ParserHardening", "load"]
