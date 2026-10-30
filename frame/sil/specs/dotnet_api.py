""".NET library facts for the C# frontend (`data/dotnet-api.toml`). Loaded strictly."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Dict, FrozenSet, NamedTuple, Optional, Tuple

try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]

PATH = Path(__file__).parent / "data" / "dotnet-api.toml"
_KEYS = {"dangerous_values", "certificate_callbacks", "key_size", "assignment_sinks", "typed_property_sink",
         "request_types"}


class TypedPropertySink(NamedTuple):
    type: str
    property: str
    kind: str
    when: Optional[Tuple[str, str]]         # (property, substring of its literal value)


class DotnetApi(NamedTuple):
    dangerous_values: FrozenSet[str]
    certificate_callback_members: FrozenSet[str]
    accept_all_validators: Tuple[str, ...]
    key_size_types: FrozenSet[str]
    key_size_minimum: int
    assignment_sinks: Dict[str, str]
    typed_property_sinks: Tuple[TypedPropertySink, ...]
    request_types: FrozenSet[str]

    def typed_sink(self, type_name: str, prop: str) -> Optional[TypedPropertySink]:
        simple = type_name.split(".")[-1]
        return next((t for t in self.typed_property_sinks if t.type == simple and t.property == prop), None)


def _strings(name, key, value):
    if not isinstance(value, list) or not value or not all(isinstance(v, str) and v for v in value):
        raise ValueError(f"{name}: {key} must be a non-empty list of strings")
    return tuple(value)


@lru_cache(maxsize=None)
def load(path: Path = PATH) -> DotnetApi:
    name = Path(path).name
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    if set(data) != _KEYS:
        raise ValueError(f"{name}: needs exactly {sorted(_KEYS)}")
    cert, key = data["certificate_callbacks"], data["key_size"]
    if set(cert) != {"members", "accept_all"} or set(key) != {"types", "minimum"} \
            or not isinstance(key["minimum"], int):
        raise ValueError(f"{name}: [certificate_callbacks] needs members, accept_all; [key_size] types, minimum")
    sinks = data["assignment_sinks"]
    if not isinstance(sinks, dict) or not all(isinstance(v, str) and v for v in sinks.values()):
        raise ValueError(f"{name}: [assignment_sinks] maps property names to sink kinds")
    typed = []
    for i, t in enumerate(data["typed_property_sink"]):
        if not isinstance(t, dict) or set(t) - {"type", "property", "kind", "when"} \
                or not all(isinstance(t.get(k), str) and t[k] for k in ("type", "property", "kind")):
            raise ValueError(f"{name}: typed_property_sink #{i + 1} needs type, property, kind (and optional when)")
        when = t.get("when")
        if when is not None and (not isinstance(when, dict) or set(when) != {"property", "contains"}):
            raise ValueError(f"{name}: typed_property_sink #{i + 1}: when needs property and contains")
        typed.append(TypedPropertySink(t["type"], t["property"], t["kind"],
                                       (when["property"], when["contains"]) if when else None))
    return DotnetApi(
        dangerous_values=frozenset(_strings(name, "dangerous_values", data["dangerous_values"])),
        certificate_callback_members=frozenset(_strings(name, "certificate_callbacks.members", cert["members"])),
        accept_all_validators=_strings(name, "certificate_callbacks.accept_all", cert["accept_all"]),
        key_size_types=frozenset(_strings(name, "key_size.types", key["types"])),
        key_size_minimum=key["minimum"],
        assignment_sinks=dict(sinks),
        typed_property_sinks=tuple(typed),
        request_types=frozenset(_strings(name, "request_types", data["request_types"])))


__all__ = ["DotnetApi", "PATH", "TypedPropertySink", "load"]
