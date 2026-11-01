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
_KEYS = {"dangerous_values", "certificate_callbacks", "key_size", "typed_property_sink",
         "request_types", "supertypes", "extension_methods"}


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
    typed_property_sinks: Tuple[TypedPropertySink, ...]
    request_types: FrozenSet[str]
    supertypes: Dict[str, Tuple[str, ...]]
    extension_methods: Dict[str, Dict[str, str]]      # namespace -> method -> declaring static class

    def lineage(self, type_name: str) -> Tuple[str, ...]:
        """The type (simple name, without type arguments) and its documented supertypes, nearest first."""
        out, todo = [], [type_name.split("<", 1)[0].split(".")[-1]]
        while todo:
            t = todo.pop(0)
            if t and t not in out:
                out.append(t)
                todo.extend(self.supertypes.get(t, ()))
        return tuple(out)

    def typed_sink(self, type_name: str, prop: str) -> Optional[TypedPropertySink]:
        for simple in self.lineage(type_name):
            hit = next((t for t in self.typed_property_sinks if t.type == simple and t.property == prop), None)
            if hit is not None:
                return hit
        return None


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
    supers = data["supertypes"]
    if not isinstance(supers, dict) or not all(isinstance(v, list) and v and all(isinstance(x, str) and x for x in v)
                                               for v in supers.values()):
        raise ValueError(f"{name}: [supertypes] maps a type to its supertypes")
    ext = data["extension_methods"]
    if not isinstance(ext, dict) or not all(isinstance(m, dict) and m and all(isinstance(c, str) and c for c in m.values())
                                            for m in ext.values()):
        raise ValueError(f"{name}: [extension_methods] maps a namespace to method -> static class")
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
        typed_property_sinks=tuple(typed),
        request_types=frozenset(_strings(name, "request_types", data["request_types"])),
        supertypes={k: tuple(v) for k, v in supers.items()},
        extension_methods={ns: dict(m) for ns, m in ext.items()})


__all__ = ["DotnetApi", "PATH", "TypedPropertySink", "load"]
