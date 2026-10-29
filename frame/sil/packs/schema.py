"""Framework pack schema: what a pack file may say, and strict validation.

A pack is a TOML file describing one framework or library for one language:

    [pack]
    name = "fastapi"
    language = "python"                 # python javascript typescript java csharp c cpp
    description = "FastAPI / Starlette handlers"
    detect = { imports = ["fastapi", "starlette"] }

    [[entrypoint]]                       # who receives attacker data
    decorator = ["*.get", "*.post"]
    params = "all"
    exclude_param_type = ["fastapi.Request"]

    [[source]]   call = [...]  kind = "user_input"
    [[sink]]     call = [...]  args = [0]  kind = "sql"
    [[sanitizer]] call = [...] kinds = ["xss"]
    [[propagator]] call = [...] from = [0] to = "return"

`call` patterns are canonical callee ids (`flask.request.args.get`; `*` matches
within a dotted name). `name` patterns are textual call names (`res.send`, matched
as a whole name or a dotted suffix) and are the fallback for receivers whose type
the frontend cannot know; they apply only when the pack's `detect` evidence holds.

A pack REFINES the built-in specs: the fields it sets override the built-in spec
of the same call, everything else is kept.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ..instructions import SinkKind, TaintKind, _SINK_KIND_ALIASES

LANGUAGES = ("python", "javascript", "typescript", "java", "csharp", "c", "cpp")

_SOURCE_KINDS = {k.value for k in TaintKind} | {"user_input", "network_input", "file_input"}
_SINK_KINDS = {k.value for k in SinkKind} | set(_SINK_KIND_ALIASES)

_PACK_KEYS = {"name", "language", "description", "detect", "version", "references"}
_DETECT_KEYS = {"imports", "annotations", "extends", "files", "module_names"}
_ENTRY_KEYS = {"id", "decorator", "annotation", "class_decorator", "class_annotation", "extends",
               "method", "registered_via", "params", "param_annotation", "param_type", "exclude_param",
               "exclude_param_type", "tainted_param_type", "fields", "kind", "description"}
_SOURCE_KEYS = {"call", "name", "kind", "out_args", "description"}
_SINK_KEYS = {"call", "name", "args", "arg_names", "kind", "when_kwarg", "description"}
_SANITIZER_KEYS = {"call", "name", "kinds", "description"}
_PROPAGATOR_KEYS = {"call", "name", "from", "to", "receiver", "description"}
_SETTING_KEYS = {"id", "kind", "keys", "value", "at", "call", "receiver", "description"}
_FUNCTION_KEYS = {"name", "allocates", "frees", "allocates_via", "noreturn", "dereferences", "description"}
_TOP_KEYS = {"pack", "entrypoint", "source", "sink", "sanitizer", "propagator", "setting", "function"}
# What a [[setting]] reports, and where the setting can be written.
SETTING_KINDS = ("debug", "cookie_secure", "cookie_httponly")
SETTING_PLACES = ("kwarg", "assignment", "attribute", "subscript", "property")


class PackError(ValueError):
    """A pack file that cannot be used; the message names the file and the field."""


@dataclass
class Entrypoint:
    id: str = ""
    decorator: List[str] = field(default_factory=list)          # decorators / annotations / attributes
    class_decorator: List[str] = field(default_factory=list)
    extends: List[str] = field(default_factory=list)
    method: List[str] = field(default_factory=list)
    registered_via: List[str] = field(default_factory=list)      # callee a handler is passed to
    params: Any = "none"                 # "all" | "annotated" | "typed" | "none" | [names]
    param_annotation: List[str] = field(default_factory=list)
    param_type: List[str] = field(default_factory=list)
    exclude_param: List[str] = field(default_factory=list)
    exclude_param_type: List[str] = field(default_factory=list)
    tainted_param_type: List[str] = field(default_factory=list)  # request objects: taint the whole param
    fields: bool = False
    kind: str = "user_input"
    description: str = ""


@dataclass
class Rule:
    """One call-level rule; `role` is source | sink | sanitizer | propagator."""
    role: str
    call: List[str] = field(default_factory=list)
    name: List[str] = field(default_factory=list)
    kind: str = ""
    args: List[int] = field(default_factory=lambda: [0])
    arg_names: List[str] = field(default_factory=list)
    kinds: List[str] = field(default_factory=list)
    out_args: List[int] = field(default_factory=list)
    when_kwarg: Optional[Tuple[str, str]] = None
    propagate_from: List[int] = field(default_factory=list)
    propagate_to: str = "return"
    receiver: bool = False
    description: str = ""
    # a sink only where nothing else already makes the call one (generated rules, frame/sca):
    # never replaces a built-in or pack sink kind
    only_if_not_sink: bool = False


@dataclass
class Setting:
    """A configuration value that switches a protection off (`category = "hardening"`):
    `keys` set to the literal `value` at one place. Only an explicit off switch is a finding;
    a missing option never is (defaults differ per library)."""
    id: str
    kind: str                            # one of SETTING_KINDS
    keys: List[str]
    value: bool
    at: str                              # one of SETTING_PLACES
    call: List[str] = field(default_factory=list)       # kwarg / property: the call it is passed to
    receiver: List[str] = field(default_factory=list)   # subscript / attribute: the object written
    description: str = ""


@dataclass
class FunctionFact:
    """What a C or C++ function does with memory and control (`[[function]]`), as the c/cpp spec
    tables say it for the C library: a project's own allocator, `die()` or logging wrapper."""
    name: str
    allocates: str = ""                  # specs.tables.ALLOCATION_KINDS
    frees: str = ""                      # specs.tables.RELEASE_KINDS
    allocates_via: Optional[int] = None
    noreturn: bool = False
    dereferences: List[int] = field(default_factory=list)   # -1: every argument
    description: str = ""


@dataclass
class Pack:
    name: str
    language: str
    description: str = ""
    detect_imports: List[str] = field(default_factory=list)
    detect_annotations: List[str] = field(default_factory=list)
    detect_extends: List[str] = field(default_factory=list)
    detect_files: List[str] = field(default_factory=list)          # file name globs
    detect_module_names: List[str] = field(default_factory=list)   # names assigned at module level
    entrypoints: List[Entrypoint] = field(default_factory=list)
    rules: List[Rule] = field(default_factory=list)
    settings: List[Setting] = field(default_factory=list)
    functions: List[FunctionFact] = field(default_factory=list)
    origin: str = "builtin"              # builtin | path of the pack file

    @property
    def has_detect(self) -> bool:
        return bool(self.detect_imports or self.detect_annotations or self.detect_extends
                    or self.detect_files or self.detect_module_names)

    def applies_to_language(self, language: str) -> bool:
        if self.language == language:
            return True
        # a "javascript" pack also covers TypeScript; "c" also covers C++
        return (self.language == "javascript" and language == "typescript") or \
               (self.language == "c" and language == "cpp")


def _fail(origin: str, where: str, message: str) -> "PackError":
    return PackError(f"{origin}: {where}: {message}")


def _strings(origin: str, where: str, value: Any, *, allow_empty: bool = True) -> List[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise _fail(origin, where, "expected a string or a list of strings")
    if not value and not allow_empty:
        raise _fail(origin, where, "must not be empty")
    return list(value)


def _ints(origin: str, where: str, value: Any) -> List[int]:
    if isinstance(value, int) and not isinstance(value, bool):
        value = [value]
    if not isinstance(value, list) or not all(isinstance(v, int) and not isinstance(v, bool) and v >= 0
                                              for v in value):
        raise _fail(origin, where, "expected a non-negative integer or a list of them")
    return list(value)


def _check_keys(origin: str, where: str, table: Dict[str, Any], allowed: set) -> None:
    unknown = sorted(set(table) - allowed)
    if unknown:
        raise _fail(origin, where, f"unknown key(s) {unknown}; allowed: {sorted(allowed)}")


def _sink_kind(origin: str, where: str, value: Any) -> str:
    if not isinstance(value, str) or value not in _SINK_KINDS:
        raise _fail(origin, where, f"unknown sink kind {value!r}; known: {sorted(_SINK_KINDS)}")
    return value


def _source_kind(origin: str, where: str, value: Any) -> str:
    if not isinstance(value, str) or value not in _SOURCE_KINDS:
        raise _fail(origin, where, f"unknown source kind {value!r}; known: {sorted(_SOURCE_KINDS)}")
    return value


def _patterns(origin: str, where: str, table: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    call = _strings(origin, f"{where}.call", table["call"]) if "call" in table else []
    name = _strings(origin, f"{where}.name", table["name"]) if "name" in table else []
    if not call and not name:
        raise _fail(origin, where, "needs `call` (canonical id) and/or `name` (textual call name)")
    for p in call + name:
        if not p or p.strip() != p or " " in p:
            raise _fail(origin, where, f"bad pattern {p!r}")
    return call, name


def parse_pack(data: Dict[str, Any], origin: str = "builtin") -> Pack:
    """Validate a parsed TOML document and build a Pack. Raises PackError."""
    _check_keys(origin, "top level", data, _TOP_KEYS)
    head = data.get("pack")
    if not isinstance(head, dict):
        raise _fail(origin, "[pack]", "missing the [pack] table")
    _check_keys(origin, "[pack]", head, _PACK_KEYS)
    name, language = head.get("name"), head.get("language")
    if not isinstance(name, str) or not name:
        raise _fail(origin, "[pack].name", "required")
    if language not in LANGUAGES:
        raise _fail(origin, "[pack].language", f"must be one of {list(LANGUAGES)}")
    pack = Pack(name=name, language=language, description=str(head.get("description", "")), origin=origin)
    detect = head.get("detect", {})
    if not isinstance(detect, dict):
        raise _fail(origin, "[pack].detect", "expected a table")
    _check_keys(origin, "[pack].detect", detect, _DETECT_KEYS)
    pack.detect_imports = _strings(origin, "detect.imports", detect.get("imports", []))
    pack.detect_annotations = _strings(origin, "detect.annotations", detect.get("annotations", []))
    pack.detect_extends = _strings(origin, "detect.extends", detect.get("extends", []))
    pack.detect_files = _strings(origin, "detect.files", detect.get("files", []))
    pack.detect_module_names = _strings(origin, "detect.module_names", detect.get("module_names", []))

    for i, t in enumerate(data.get("entrypoint", [])):
        where = f"[[entrypoint]] #{i + 1}"
        _check_keys(origin, where, t, _ENTRY_KEYS)
        e = Entrypoint(id=str(t.get("id", f"{name}-entry-{i + 1}")), description=str(t.get("description", "")))
        for key in ("decorator", "class_decorator", "extends", "method", "registered_via", "param_annotation", "param_type",
                    "exclude_param", "exclude_param_type", "tainted_param_type"):
            if key in t:
                setattr(e, key, _strings(origin, f"{where}.{key}", t[key]))
        if "annotation" in t:                                   # alias of decorator
            e.decorator += _strings(origin, f"{where}.annotation", t["annotation"])
        if "class_annotation" in t:
            e.class_decorator += _strings(origin, f"{where}.class_annotation", t["class_annotation"])
        params = t.get("params", "none")
        if isinstance(params, str):
            if params not in ("all", "annotated", "typed", "none"):
                raise _fail(origin, f"{where}.params", "must be all | annotated | typed | none | [names]")
        else:
            params = _strings(origin, f"{where}.params", params)
        e.params = params
        if params == "annotated" and not e.param_annotation:
            raise _fail(origin, where, "params = \"annotated\" needs param_annotation")
        if params == "typed" and not e.param_type:
            raise _fail(origin, where, "params = \"typed\" needs param_type")
        e.fields = bool(t.get("fields", False))
        e.kind = _source_kind(origin, f"{where}.kind", t.get("kind", "user_input"))
        if not (e.decorator or e.class_decorator or e.extends or e.method or e.registered_via):
            raise _fail(origin, where, "needs at least one of decorator/annotation, class_decorator, "
                                       "extends, method, registered_via")
        if params == "none" and not e.fields and not e.tainted_param_type:
            raise _fail(origin, where, "taints nothing: set params, fields or tainted_param_type")
        pack.entrypoints.append(e)

    def rules(table_name: str, keys: set) -> None:
        for i, t in enumerate(data.get(table_name, [])):
            where = f"[[{table_name}]] #{i + 1}"
            _check_keys(origin, where, t, keys)
            call, names = _patterns(origin, where, t)
            r = Rule(role=table_name, call=call, name=names, description=str(t.get("description", "")))
            if table_name == "source":
                r.kind = _source_kind(origin, f"{where}.kind", t.get("kind", "user_input"))
                r.out_args = _ints(origin, f"{where}.out_args", t["out_args"]) if "out_args" in t else []
            elif table_name == "sink":
                r.kind = _sink_kind(origin, f"{where}.kind", t.get("kind"))
                r.args = _ints(origin, f"{where}.args", t["args"]) if "args" in t else [0]
                r.arg_names = _strings(origin, f"{where}.arg_names", t.get("arg_names", []))
                wk = t.get("when_kwarg")
                if wk is not None:
                    if not (isinstance(wk, dict) and set(wk) == {"name", "value"}
                            and all(isinstance(v, str) for v in wk.values())):
                        raise _fail(origin, f"{where}.when_kwarg", 'expected { name = "...", value = "..." }')
                    r.when_kwarg = (wk["name"], wk["value"])
            elif table_name == "sanitizer":
                r.kinds = [_sink_kind(origin, f"{where}.kinds", k)
                           for k in _strings(origin, f"{where}.kinds", t.get("kinds", []), allow_empty=False)]
            else:
                r.propagate_from = _ints(origin, f"{where}.from", t["from"]) if "from" in t else []
                r.receiver = bool(t.get("receiver", False))
                r.propagate_to = t.get("to", "return")
                if r.propagate_to != "return" and not (isinstance(r.propagate_to, str)
                                                       and r.propagate_to.startswith("arg")
                                                       and r.propagate_to[3:].isdigit()):
                    raise _fail(origin, f"{where}.to", 'must be "return" or "arg<N>"')
                if not r.propagate_from and not r.receiver:
                    raise _fail(origin, where, "needs `from` and/or `receiver = true`")
            pack.rules.append(r)

    rules("source", _SOURCE_KEYS)
    rules("sink", _SINK_KEYS)
    rules("sanitizer", _SANITIZER_KEYS)
    rules("propagator", _PROPAGATOR_KEYS)

    for i, t in enumerate(data.get("setting", [])):
        where = f"[[setting]] #{i + 1}"
        _check_keys(origin, where, t, _SETTING_KEYS)
        if t.get("kind") not in SETTING_KINDS:
            raise _fail(origin, f"{where}.kind", f"must be one of {list(SETTING_KINDS)}")
        if t.get("at") not in SETTING_PLACES:
            raise _fail(origin, f"{where}.at", f"must be one of {list(SETTING_PLACES)}")
        if not isinstance(t.get("value"), bool):
            raise _fail(origin, f"{where}.value", "must be true or false (the value that switches it off)")
        st = Setting(id=str(t.get("id", f"{name}-setting-{i + 1}")), kind=t["kind"], at=t["at"],
                     keys=_strings(origin, f"{where}.keys", t.get("keys", []), allow_empty=False),
                     value=t["value"], description=str(t.get("description", "")),
                     call=_strings(origin, f"{where}.call", t.get("call", [])),
                     receiver=_strings(origin, f"{where}.receiver", t.get("receiver", [])))
        if st.at in ("kwarg", "property") and not st.call:
            raise _fail(origin, where, f'at = "{st.at}" needs call')
        if st.at == "subscript" and not st.receiver:
            raise _fail(origin, where, 'at = "subscript" needs receiver')
        pack.settings.append(st)

    from frame.sil.specs.tables import ALLOCATION_KINDS, RELEASE_KINDS
    for i, t in enumerate(data.get("function", [])):
        where = f"[[function]] #{i + 1}"
        _check_keys(origin, where, t, _FUNCTION_KEYS)
        if language not in ("c", "cpp"):
            raise _fail(origin, where, "library facts are for C and C++ packs")
        if not isinstance(t.get("name"), str) or not t["name"]:
            raise _fail(origin, f"{where}.name", "needs the function's name")
        for key, kinds in (("allocates", ALLOCATION_KINDS), ("frees", RELEASE_KINDS)):
            if key in t and t[key] not in kinds:
                raise _fail(origin, f"{where}.{key}", f"must be one of {sorted(kinds)}")
        via = t.get("allocates_via")
        if via is not None and (not isinstance(via, int) or isinstance(via, bool) or via < 0):
            raise _fail(origin, f"{where}.allocates_via", "must be an argument position")
        derefs = t.get("dereferences", [])
        if not isinstance(derefs, list) or not all(isinstance(d, int) and not isinstance(d, bool) and d >= -1
                                                    for d in derefs):
            raise _fail(origin, f"{where}.dereferences", "must be argument positions (-1: every one)")
        if not isinstance(t.get("noreturn", False), bool):
            raise _fail(origin, f"{where}.noreturn", "must be true or false")
        fact = FunctionFact(name=t["name"], allocates=t.get("allocates", ""), frees=t.get("frees", ""),
                            allocates_via=via, noreturn=t.get("noreturn", False), dereferences=list(derefs),
                            description=str(t.get("description", "")))
        if not (fact.allocates or fact.frees or fact.noreturn or fact.dereferences):
            raise _fail(origin, where, "states nothing: set allocates, frees, noreturn or dereferences")
        pack.functions.append(fact)
    return pack
