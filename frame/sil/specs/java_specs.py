"""
Library specifications for Java (Spring, Servlet, JDBC/JPA, the JDK, ...), and the
type tables the Java frontend uses to match them.

The table itself is data: `data/java.toml` (one `[[spec]]` per call name, in lookup
order), loaded by `frame/sil/specs/tables.py`. Edit the TOML, then run the benchmark sweep.
"""

from pathlib import Path
from typing import Dict

try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]

from frame.sil.procedure import ProcSpec
from frame.sil.specs.tables import load_table

JAVA_SPECS: Dict[str, ProcSpec] = load_table("java")


# The Java type model (receiver aliases, factory and chain return types, String method result
# types, permissive verifiers, the javax -> jakarta moves) is data: data/java-types.toml.
_TYPES_PATH = Path(__file__).parent / "data" / "java-types.toml"
_TYPE_TABLES = {"type_receivers": list, "factory_return_types": str, "return_types": str,
                "string_method_types": str}


def _load_types(path: Path = _TYPES_PATH) -> dict:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    expected = set(_TYPE_TABLES) | {"verifiers", "jakarta", "java_lang", "name_only", "project_packages"}
    if set(data) != expected:
        raise ValueError(f"{path.name}: needs exactly {sorted(expected)}")
    for table, kind in _TYPE_TABLES.items():
        if not isinstance(data[table], dict) or not data[table] or not all(
                isinstance(v, kind) and v and (kind is str or all(isinstance(x, str) and x for x in v))
                for v in data[table].values()):
            raise ValueError(f"{path.name}: [{table}] values must be non-empty {kind.__name__}s")
    receivers = data["name_only"].get("receivers") if isinstance(data["name_only"], dict) else None
    if set(data["name_only"]) != {"receivers", "not_receivers"} or not isinstance(receivers, dict) or not all(
            isinstance(v, list) and v and all(isinstance(g, str) and g for g in v) for v in receivers.values()):
        raise ValueError(f"{path.name}: [name_only] needs receivers (method = [type globs]) and not_receivers")
    for table, key in (("verifiers", "permissive"), ("jakarta", "migrated"), ("java_lang", "types"),
                       ("project_packages", "umbrella_roots")):
        if set(data[table]) != {key} or not isinstance(data[table][key], list) or not data[table][key]:
            raise ValueError(f"{path.name}: [{table}] needs exactly {key}, a non-empty list")
    return data


_TYPES = _load_types()
JAVA_TYPE_RECEIVERS: Dict[str, tuple] = {k: tuple(v) for k, v in _TYPES["type_receivers"].items()}
JAVA_FACTORY_RETURN_TYPES: Dict[str, str] = dict(_TYPES["factory_return_types"])
JAVA_RETURN_TYPES: Dict[str, str] = dict(_TYPES["return_types"])
JAVA_STRING_METHOD_TYPES: Dict[str, str] = dict(_TYPES["string_method_types"])
PERMISSIVE_VERIFIERS = frozenset(_TYPES["verifiers"]["permissive"])
JAKARTA_MIGRATED = tuple(_TYPES["jakarta"]["migrated"])
JAVA_LANG_TYPES = frozenset(_TYPES["java_lang"]["types"])
NAME_ONLY_RECEIVERS: Dict[str, tuple] = {k: tuple(v) for k, v in _TYPES["name_only"]["receivers"].items()}
NAME_ONLY_NOT_RECEIVERS = frozenset(_TYPES["name_only"]["not_receivers"])
UMBRELLA_PACKAGE_ROOTS = frozenset(_TYPES["project_packages"]["umbrella_roots"])


# Which route-registration lambdas receive which request objects is framework knowledge: the
# `[[lambda_handler]]` entries of the Java packs (sparkjava, javalin, vertx-web, spring, jooby, ratpack).


def type_spec_receivers(type_name: str) -> tuple:
    """Spec receiver names under which a call on a `type_name` value is looked
    up: the type itself, its decapitalised form (DocumentBuilder ->
    documentBuilder, SAXParser -> saxParser, URL -> url) and any alias."""
    upper = len(type_name) - len(type_name.lstrip("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
    if upper == len(type_name):
        decap = type_name.lower()
    elif upper > 1:
        decap = type_name[:upper - 1].lower() + type_name[upper - 1:]
    else:
        decap = type_name[:1].lower() + type_name[1:]
    return (type_name, decap) + JAVA_TYPE_RECEIVERS.get(type_name, ())
