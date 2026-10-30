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

import re

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ..instructions import SinkKind, TaintKind, _SINK_KIND_ALIASES

CODE_LANGUAGES = ("python", "javascript", "typescript", "java", "csharp", "c", "cpp")
# Infrastructure formats: their packs hold only [[policy]] entries (frame/iac).
IAC_LANGUAGES = ("kubernetes", "terraform", "cloudformation", "dockerfile")
LANGUAGES = CODE_LANGUAGES + IAC_LANGUAGES

_SOURCE_KINDS = {k.value for k in TaintKind} | {"user_input", "network_input", "file_input"}
_SINK_KINDS = {k.value for k in SinkKind} | set(_SINK_KIND_ALIASES)

_PACK_KEYS = {"name", "language", "description", "detect", "version", "references", "dict_queries"}
_DETECT_KEYS = {"imports", "annotations", "extends", "files", "module_names"}
_ENTRY_KEYS = {"id", "decorator", "annotation", "class_decorator", "class_annotation", "extends",
               "method", "registered_via", "class_name", "modifiers", "exclude_modifiers", "exclude_decorator", "exclude_method", "param_positions", "params_from", "first_param", "params", "param_annotation", "param_type", "exclude_param",
               "exclude_param_type", "tainted_param_type", "fields", "field_annotation", "kind", "description"}
_SOURCE_KEYS = {"call", "name", "kind", "out_args", "description"}
_SINK_KEYS = {"call", "name", "args", "arg_names", "kind", "when_kwarg", "json_for_literals", "description"}
_SANITIZER_KEYS = {"call", "name", "kinds", "description"}
_PROPAGATOR_KEYS = {"call", "name", "from", "to", "receiver", "description"}
_SETTING_KEYS = {"id", "kind", "keys", "value", "at", "call", "receiver", "description"}
_FUNCTION_KEYS = {"name", "allocates", "frees", "allocates_via", "noreturn", "dereferences", "description"}
_LAMBDA_KEYS = {"id", "methods", "qualified", "imports", "param_types", "description"}
_POLICY_KEYS = {"id", "title", "severity", "cwe", "when", "resources", "overrides", "tags", "references",
                "description"}
_DEFINE_KEYS = {"name", "params", "body", "description"}
_JAVA_KIND_KEYS = {
    "annotated_query": {"id", "annotations", "substitution", "kind", "param_name_annotation", "lone_parameter",
                        "description"},
    "required_flag": {"id", "types", "escape", "setter", "value", "kind", "description"},
    "disabled_protection": {"id", "configurer", "disable", "kind", "description"},
    "handler_return": {"id", "kind", "prefix", "class_decorator", "exclude_decorator", "return_type", "description"},
    "injected_field": {"id", "annotations", "description"},
}
_DEFERRED_KEYS = {"id", "methods", "description"}
_REGISTRATION_KEYS = {"id", "keys", "containers", "registered_as", "description"}
_FLUENT_KEYS = {"id", "methods", "roots", "name", "content_type", "content_type_header", "description"}
_TOP_KEYS = {"pack", "entrypoint", "source", "sink", "sanitizer", "propagator", "setting", "function",
             "lambda_handler", "fluent", "registration", "deferred_call", "annotated_query",
             "required_flag", "disabled_protection", "handler_return", "injected_field", "policy", "define"}
POLICY_SEVERITIES = ("critical", "high", "medium", "low", "info")
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
    class_name: List[str] = field(default_factory=list)          # globs on the class's own name (a convention)
    modifiers: List[str] = field(default_factory=list)           # all of these, as written (public)
    exclude_modifiers: List[str] = field(default_factory=list)   # none of these (static)
    exclude_decorator: List[str] = field(default_factory=list)   # none of these annotations ([NonAction])
    exclude_method: List[str] = field(default_factory=list)      # method-name globs that are not entries
    param_positions: List[int] = field(default_factory=list)     # only these parameters (0-based), if given
    params_from: int = 0                 # only parameters from this position on (0-based)
    first_param: List[str] = field(default_factory=list)         # globs on the first parameter (after self / cls)
    params: Any = "none"                 # "all" | "annotated" | "typed" | "none" | [names]
    param_annotation: List[str] = field(default_factory=list)
    param_type: List[str] = field(default_factory=list)
    exclude_param: List[str] = field(default_factory=list)
    exclude_param_type: List[str] = field(default_factory=list)
    tainted_param_type: List[str] = field(default_factory=list)  # request objects: taint the whole param
    fields: str = ""                     # "" | "all" | "annotated" | "settable" (true means "all")
    field_annotation: List[str] = field(default_factory=list)
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
    json_for_literals: bool = False      # sink: an object / array literal is sent as JSON, not as HTML
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
class LambdaHandler:
    """Java: a lambda handed to one of the framework's registration methods (`get("/x", (req, res)
    -> ...)`) receives the framework's request objects, written without parameter types; these are
    its parameters' types, in order (`[[lambda_handler]]`)."""
    id: str
    methods: List[str]                   # the registration call's method (last part of its name)
    param_types: List[str]               # qualified types of the lambda's parameters, in order
    qualified: bool = False              # only `x.method(...)`, never a bare `method(...)`
    imports: List[str] = field(default_factory=list)   # the file must also import one of these
    description: str = ""


@dataclass
class Registration:
    """JavaScript: functions an application hands to a framework by putting them in an object
    under one of `keys` (`Query: { user(parent, args) {...} }`), or one level deeper in an object
    bound to a name matching `containers` (`const resolvers = { Query: {...} }`), are registered
    as `registered_as`, for an `[[entrypoint]] registered_via` to select (`[[registration]]`)."""
    id: str
    keys: List[str]
    registered_as: str
    containers: List[str] = field(default_factory=list)
    description: str = ""


@dataclass
class AnnotatedQuery:
    """Java: an interface method whose annotation IS its implementation, a query text in which
    `substitution` (a pattern with a `name` group) splices a parameter into the statement
    (`[[annotated_query]]`; MyBatis `@Select("... ${name} ...")`). A parameter is named by its own
    name or by `param_name_annotation`'s value; with `lone_parameter`, a method with one parameter
    matches any substitution."""
    id: str
    annotations: List[str]
    substitution: Any                    # compiled pattern
    kind: str
    param_name_annotation: str = ""
    lone_parameter: bool = False
    description: str = ""


@dataclass
class RequiredFlag:
    """Java: an object handed to one of `escape` (`response.addCookie(c)`) without `setter(value)`
    having been called on it in the method is a finding of sink `kind` (`[[required_flag]]`): the
    flag's default is off. An object created inline at the escape call never had it set."""
    id: str
    types: List[str]
    escape: List[str]
    setter: str
    value: str
    kind: str
    description: str = ""


@dataclass
class DisabledProtection:
    """Java: a protection switched off through its configurer (`[[disabled_protection]]`): a
    `disable` method called on the result of a `configurer` call (`http.csrf().disable()`), or a
    `configurer` call given a customizer that only disables it (`csrf(c -> c.disable())`,
    `csrf(AbstractHttpConfigurer::disable)`)."""
    id: str
    configurer: List[str]
    disable: List[str]
    kind: str
    description: str = ""


@dataclass
class HandlerReturn:
    """Java: the value a web handler returns is a sink of `kind` (`[[handler_return]]`): one built
    from a literal starting with `prefix` (Spring's `"redirect:" + url`), or, with
    `class_decorator`, a String returned by a handler of such a class not marked with
    `exclude_decorator` (a Spring MVC view name)."""
    id: str
    kind: str
    prefix: str = ""
    class_decorator: List[str] = field(default_factory=list)
    exclude_decorator: List[str] = field(default_factory=list)
    return_type: List[str] = field(default_factory=list)
    description: str = ""


@dataclass
class DeferredCall:
    """Python: a method that runs the function it is called on, later, with the same arguments
    (`[[deferred_call]]`): Celery's `task.delay(a, b)` is the call `task(a, b)` for taint."""
    id: str
    methods: List[str]
    description: str = ""


@dataclass
class Fluent:
    """JavaScript: methods that configure the object they are called on and return it
    (`[[fluent]]`), so `res.status(200).send(x)` is the call `res.send(x)`. With `roots`, a call
    of a root (`$("#x")`) is such an object too, and a method called on the chain is named
    `<name>.<method>` (`$("#x").find("li").html(v)` is `$.html`). `content_type` /
    `content_type_header` are the methods that set a response's content type (`type(v)`,
    `set("Content-Type", v)`): a literal type that is neither HTML nor XML makes the response
    not an HTML sink."""
    id: str
    methods: List[str]
    roots: List[str] = field(default_factory=list)
    name: str = ""
    content_type: List[str] = field(default_factory=list)
    content_type_header: List[str] = field(default_factory=list)
    description: str = ""


@dataclass
class Policy:
    """An infrastructure misconfiguration (`[[policy]]`, IaC packs only): `when` is a formula in
    the policy language (frame/iac/policy.py) over a resource's views; a resource of one of
    `resources` (type globs; empty: every resource that has the views the formula names) that
    the configuration makes satisfy it is a finding. `overrides`: policies this one replaces on a
    resource where both hold (a stricter version of the same rule)."""
    id: str
    title: str
    severity: str
    cwe: str
    when: str
    expr: Any = None                     # the parsed formula
    resources: List[str] = field(default_factory=list)
    overrides: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
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
    lambda_handlers: List[LambdaHandler] = field(default_factory=list)
    fluents: List[Fluent] = field(default_factory=list)
    registrations: List[Registration] = field(default_factory=list)
    deferred_calls: List[DeferredCall] = field(default_factory=list)
    annotated_queries: List[AnnotatedQuery] = field(default_factory=list)
    required_flags: List[RequiredFlag] = field(default_factory=list)
    disabled_protections: List[DisabledProtection] = field(default_factory=list)
    handler_returns: List[HandlerReturn] = field(default_factory=list)
    injected_field_annotations: List[str] = field(default_factory=list)
    dict_queries: bool = False           # Python: in files this pack applies to, a dict literal is a query
    policies: List[Policy] = field(default_factory=list)
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
    if "dict_queries" in head:
        if not isinstance(head["dict_queries"], bool) or language != "python":
            raise _fail(origin, "[pack].dict_queries", "is true or false, in a Python pack")
        pack.dict_queries = head["dict_queries"]
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
                    "exclude_param", "exclude_param_type", "tainted_param_type", "field_annotation", "class_name",
                    "modifiers", "exclude_modifiers", "exclude_decorator", "exclude_method", "first_param"):
            if key in t:
                setattr(e, key, _strings(origin, f"{where}.{key}", t[key]))
        if "annotation" in t:                                   # alias of decorator
            e.decorator += _strings(origin, f"{where}.annotation", t["annotation"])
        if "class_annotation" in t:
            e.class_decorator += _strings(origin, f"{where}.class_annotation", t["class_annotation"])
        positions = t.get("param_positions", [])
        if not isinstance(positions, list) or not all(isinstance(i, int) and not isinstance(i, bool) and i >= 0
                                                      for i in positions):
            raise _fail(origin, f"{where}.param_positions", "must be a list of parameter positions (0-based)")
        e.param_positions = list(positions)
        start = t.get("params_from", 0)
        if not isinstance(start, int) or isinstance(start, bool) or start < 0:
            raise _fail(origin, f"{where}.params_from", "must be a parameter position (0-based)")
        e.params_from = start
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
        fields = t.get("fields", False)
        if fields is True:
            fields = "all"
        if fields is False:
            fields = ""
        if fields not in ("", "all", "annotated", "settable"):
            raise _fail(origin, f"{where}.fields", "must be true | false | all | annotated | settable")
        if (fields == "annotated") != bool(e.field_annotation):
            raise _fail(origin, where, "fields = \"annotated\" and field_annotation go together")
        e.fields = fields
        e.kind = _source_kind(origin, f"{where}.kind", t.get("kind", "user_input"))
        if not (e.decorator or e.class_decorator or e.extends or e.method or e.registered_via or e.class_name
                or e.first_param):
            raise _fail(origin, where, "needs at least one of decorator/annotation, class_decorator, "
                                       "extends, class_name, method, registered_via, first_param")
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
                if not isinstance(t.get("json_for_literals", False), bool):
                    raise _fail(origin, f"{where}.json_for_literals", "must be true or false")
                r.json_for_literals = t.get("json_for_literals", False)
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

    for i, t in enumerate(data.get("lambda_handler", [])):
        where = f"[[lambda_handler]] #{i + 1}"
        _check_keys(origin, where, t, _LAMBDA_KEYS)
        if language != "java":
            raise _fail(origin, where, "lambda handlers are for Java packs")
        for key in ("methods", "param_types"):
            if key not in t:
                raise _fail(origin, where, f"needs {key}")
        if not isinstance(t.get("qualified", False), bool):
            raise _fail(origin, f"{where}.qualified", "must be true or false")
        handler = LambdaHandler(
            id=str(t.get("id", f"{name}-lambda-{i + 1}")),
            methods=_strings(origin, f"{where}.methods", t["methods"]),
            param_types=_strings(origin, f"{where}.param_types", t["param_types"]),
            qualified=t.get("qualified", False),
            imports=_strings(origin, f"{where}.imports", t["imports"]) if "imports" in t else [],
            description=str(t.get("description", "")))
        if not handler.methods or not handler.param_types:
            raise _fail(origin, where, "methods and param_types must not be empty")
        if not (handler.imports or pack.detect_imports):
            raise _fail(origin, where, "needs imports, or the pack's detect.imports, to say when it applies")
        pack.lambda_handlers.append(handler)

    for table, keys in _JAVA_KIND_KEYS.items():
        for i, t in enumerate(data.get(table, [])):
            where = f"[[{table}]] #{i + 1}"
            _check_keys(origin, where, t, keys)
            if language != "java":
                raise _fail(origin, where, f"{table} entries are for Java packs")
            eid = str(t.get("id", f"{name}-{table}-{i + 1}"))
            desc = str(t.get("description", ""))

            def need(*ks, t=t, where=where):
                for k in ks:
                    if not t.get(k):
                        raise _fail(origin, where, f"needs {k}")
            if table == "injected_field":
                need("annotations")
                pack.injected_field_annotations += _strings(origin, f"{where}.annotations", t["annotations"])
                continue
            need("kind")
            kind = _sink_kind(origin, f"{where}.kind", t["kind"])
            if table == "annotated_query":
                need("annotations", "substitution")
                try:
                    rx = re.compile(t["substitution"])
                except (re.error, TypeError) as err:
                    raise _fail(origin, f"{where}.substitution", f"does not compile: {err}")
                if "name" not in rx.groupindex:
                    raise _fail(origin, f"{where}.substitution", "needs a (?P<name>...) group")
                if not isinstance(t.get("lone_parameter", False), bool):
                    raise _fail(origin, f"{where}.lone_parameter", "must be true or false")
                pack.annotated_queries.append(AnnotatedQuery(
                    id=eid, annotations=_strings(origin, f"{where}.annotations", t["annotations"]), substitution=rx,
                    kind=kind, param_name_annotation=str(t.get("param_name_annotation", "")),
                    lone_parameter=t.get("lone_parameter", False), description=desc))
            elif table == "required_flag":
                need("types", "escape", "setter", "value")
                pack.required_flags.append(RequiredFlag(
                    id=eid, types=_strings(origin, f"{where}.types", t["types"]),
                    escape=_strings(origin, f"{where}.escape", t["escape"]), setter=str(t["setter"]),
                    value=str(t["value"]), kind=kind, description=desc))
            elif table == "disabled_protection":
                need("configurer", "disable")
                pack.disabled_protections.append(DisabledProtection(
                    id=eid, configurer=_strings(origin, f"{where}.configurer", t["configurer"]),
                    disable=_strings(origin, f"{where}.disable", t["disable"]), kind=kind, description=desc))
            else:
                if not (t.get("prefix") or t.get("class_decorator")):
                    raise _fail(origin, where, "needs prefix or class_decorator")
                pack.handler_returns.append(HandlerReturn(
                    id=eid, kind=kind, prefix=str(t.get("prefix", "")),
                    class_decorator=_strings(origin, f"{where}.class_decorator", t.get("class_decorator", [])),
                    exclude_decorator=_strings(origin, f"{where}.exclude_decorator", t.get("exclude_decorator", [])),
                    return_type=_strings(origin, f"{where}.return_type", t.get("return_type", [])),
                    description=desc))

    for i, t in enumerate(data.get("deferred_call", [])):
        where = f"[[deferred_call]] #{i + 1}"
        _check_keys(origin, where, t, _DEFERRED_KEYS)
        if language != "python":
            raise _fail(origin, where, "deferred calls are for Python packs")
        if pack.has_detect:
            raise _fail(origin, where, "deferred calls apply to every file (the caller imports only the task "
                                       "module): use a pack without detect")
        if not t.get("methods"):
            raise _fail(origin, where, "needs methods")
        pack.deferred_calls.append(DeferredCall(id=str(t.get("id", f"{name}-deferred-{i + 1}")),
                                                methods=_strings(origin, f"{where}.methods", t["methods"]),
                                                description=str(t.get("description", ""))))

    for i, t in enumerate(data.get("registration", [])):
        where = f"[[registration]] #{i + 1}"
        _check_keys(origin, where, t, _REGISTRATION_KEYS)
        if language != "javascript":
            raise _fail(origin, where, "registrations are for JavaScript packs")
        for key in ("keys", "registered_as"):
            if key not in t:
                raise _fail(origin, where, f"needs {key}")
        reg = Registration(id=str(t.get("id", f"{name}-registration-{i + 1}")),
                           keys=_strings(origin, f"{where}.keys", t["keys"]),
                           registered_as=str(t["registered_as"]),
                           containers=_strings(origin, f"{where}.containers", t.get("containers", [])),
                           description=str(t.get("description", "")))
        if not reg.keys or not reg.registered_as:
            raise _fail(origin, where, "keys and registered_as must not be empty")
        pack.registrations.append(reg)

    for i, t in enumerate(data.get("fluent", [])):
        where = f"[[fluent]] #{i + 1}"
        _check_keys(origin, where, t, _FLUENT_KEYS)
        if language != "javascript":
            raise _fail(origin, where, "fluent entries are for JavaScript packs")
        if pack.has_detect:
            raise _fail(origin, where, "fluent entries apply to every file (the object is often a parameter "
                                       "of a file that imports nothing): use a pack without detect")
        if "methods" not in t:
            raise _fail(origin, where, "needs methods")
        fl = Fluent(id=str(t.get("id", f"{name}-fluent-{i + 1}")),
                    methods=_strings(origin, f"{where}.methods", t["methods"]),
                    roots=_strings(origin, f"{where}.roots", t.get("roots", [])),
                    name=str(t.get("name", "")),
                    content_type=_strings(origin, f"{where}.content_type", t.get("content_type", [])),
                    content_type_header=_strings(origin, f"{where}.content_type_header",
                                                 t.get("content_type_header", [])),
                    description=str(t.get("description", "")))
        if not fl.methods:
            raise _fail(origin, where, "methods must not be empty")
        if bool(fl.roots) != bool(fl.name):
            raise _fail(origin, where, "roots and name go together")
        pack.fluents.append(fl)

    code_tables = [t for t in _TOP_KEYS - {"pack", "policy", "define"} if data.get(t)]
    if language in IAC_LANGUAGES and code_tables:
        raise _fail(origin, f"[[{sorted(code_tables)[0]}]]", f"a {language} pack holds only [[policy]] entries")
    if language not in IAC_LANGUAGES and data.get("policy"):
        raise _fail(origin, "[[policy]]", f"policies are for infrastructure packs ({list(IAC_LANGUAGES)})")
    from frame.iac.policy import PolicyError, inline, parse as parse_policy
    if language not in IAC_LANGUAGES and data.get("define"):
        raise _fail(origin, "[[define]]", f"defines are for infrastructure packs ({list(IAC_LANGUAGES)})")
    defines: Dict[str, Any] = {}
    for i, t in enumerate(data.get("define", [])):
        where = f"[[define]] #{i + 1}"
        _check_keys(origin, where, t, _DEFINE_KEYS)
        name, params, body = t.get("name"), t.get("params", []), t.get("body")
        if not isinstance(name, str) or not name.isidentifier() or name in defines:
            raise _fail(origin, f"{where}.name", "a new identifier is required")
        params = _strings(origin, f"{where}.params", params)
        if not isinstance(body, str):
            raise _fail(origin, f"{where}.body", "required (a policy expression)")
        try:
            defines[name] = (params, parse_policy(body))
        except PolicyError as e:
            raise _fail(origin, f"{where}.body ({name})", str(e)) from None
    seen = set()
    for i, t in enumerate(data.get("policy", [])):
        where = f"[[policy]] #{i + 1}"
        _check_keys(origin, where, t, _POLICY_KEYS)
        for key in ("id", "title", "severity", "cwe", "when"):
            if not isinstance(t.get(key), str) or not t[key].strip():
                raise _fail(origin, f"{where}.{key}", "required (a string)")
        if t["id"] in seen:
            raise _fail(origin, f"{where}.id", f"{t['id']!r} listed twice")
        seen.add(t["id"])
        if t["severity"] not in POLICY_SEVERITIES:
            raise _fail(origin, f"{where}.severity", f"must be one of {list(POLICY_SEVERITIES)}")
        cwe = t["cwe"]
        if not (cwe.startswith("CWE-") and cwe[4:].isdigit()):
            raise _fail(origin, f"{where}.cwe", "must be CWE-<number>")
        try:
            expr = inline(parse_policy(t["when"]), defines)
        except PolicyError as e:
            raise _fail(origin, f"{where}.when ({t['id']})", str(e)) from None
        from frame.iac.formats import view_names
        from frame.iac.policy import roots
        unknown = roots(expr) - view_names(language)
        if unknown:
            raise _fail(origin, f"{where}.when ({t['id']})",
                        f"unknown name(s) {sorted(unknown)}; a {language} resource has {sorted(view_names(language))}")
        pack.policies.append(Policy(
            id=t["id"], title=t["title"], severity=t["severity"], cwe=cwe, when=t["when"], expr=expr,
            resources=_strings(origin, f"{where}.resources", t.get("resources", [])),
            overrides=_strings(origin, f"{where}.overrides", t.get("overrides", [])),
            tags=_strings(origin, f"{where}.tags", t.get("tags", [])),
            references=_strings(origin, f"{where}.references", t.get("references", [])),
            description=str(t.get("description", ""))))
    return pack
