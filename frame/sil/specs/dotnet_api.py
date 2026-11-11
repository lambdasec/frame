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
         "request_types", "supertypes", "extension_methods", "stores_arguments", "out_from_receiver",
         "read_only_collection_methods", "stream_overloads"}


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
    stores_arguments: Dict[str, Dict[str, Tuple[int, ...]]]   # type -> method -> argument positions stored
    out_from_receiver: FrozenSet[str]
    read_only_collection_methods: FrozenSet[str]
    stream_overloads: Dict[str, Tuple[int, Tuple[str, ...]]]  # constructor -> (argument, stream types)

    def stored_arguments(self, type_name: str, method: str) -> Tuple[int, ...]:
        """The argument positions `method` stores in a receiver of `type_name` (or a supertype)."""
        for simple in self.lineage(type_name):
            hit = self.stores_arguments.get(simple, {}).get(method)
            if hit is not None:
                return hit
        return ()

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
    stores = data["stores_arguments"]
    if not isinstance(stores, dict) or not all(
            isinstance(m, dict) and m and all(isinstance(v, list) and v and all(isinstance(i, int) and i >= 0 for i in v)
                                             for v in m.values()) for m in stores.values()):
        raise ValueError(f"{name}: [stores_arguments] maps a type to method -> argument positions")
    streams = data["stream_overloads"]
    if not isinstance(streams, dict) or not all(
            isinstance(v, dict) and set(v) == {"arg", "types"} and isinstance(v["arg"], int) and v["arg"] >= 0
            for v in streams.values()):
        raise ValueError(f"{name}: [stream_overloads] maps a constructor to {{arg, types}}")
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
        extension_methods={ns: dict(m) for ns, m in ext.items()},
        stores_arguments={t: {m: tuple(v) for m, v in ms.items()} for t, ms in stores.items()},
        out_from_receiver=frozenset(_strings(name, "out_from_receiver", data["out_from_receiver"])),
        read_only_collection_methods=frozenset(_strings(name, "read_only_collection_methods",
                                                        data["read_only_collection_methods"])),
        stream_overloads={c: (v["arg"], _strings(name, f"stream_overloads.{c}.types", v["types"]))
                          for c, v in streams.items()})


__all__ = ["DotnetApi", "PATH", "TypedPropertySink", "load"]
