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
_DETECT_KEYS = {"imports", "annotations", "extends", "files", "module_names", "dependencies"}
_ENTRY_KEYS = {"id", "decorator", "annotation", "class_decorator", "class_annotation", "extends",
               "method", "registered_via", "class_name", "modifiers", "exclude_modifiers", "exclude_decorator", "exclude_method", "param_positions", "params_from", "first_param", "params", "param_annotation", "param_type", "exclude_param",
               "exclude_param_type", "tainted_param_type", "fields", "field_annotation", "kind", "description",
               "request_type", "arity", "exclude_arity", "module_path", "exports", "directives", "body_directives", "origin",
               "receiver", "unbound", "route_syntax", "route_args"}
_REQUEST_TYPE_KEYS = {"id", "fields", "methods", "server_state", "kinds", "objects", "headers", "sessions",
                      "identities", "proxies", "origin", "description", "references"}
_SOURCE_KEYS = {"call", "name", "kind", "out_args", "description"}
_SINK_KEYS = {"call", "name", "args", "arg_names", "kind", "when_kwarg", "json_for_literals", "renders_view",
              "property", "description"}
_SANITIZER_KEYS = {"call", "name", "kinds", "description"}
_PROPAGATOR_KEYS = {"call", "name", "from", "to", "receiver", "description"}
_SETTING_KEYS = {"id", "kind", "keys", "value", "values", "at", "call", "receiver", "description"}
_FUNCTION_KEYS = {"name", "allocates", "frees", "allocates_via", "noreturn", "dereferences", "writes_headers",
                  "description"}
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
_TOOL_KEYS = {
    "python": {"id", "entrypoint", "decorator", "call", "name_kwarg", "text_kwargs", "when_kwargs", "docstring",
               "signature", "description"},
    "javascript": {"id", "entrypoint", "method", "name_arg", "description_arg", "config_arg", "name_field",
                   "text_fields", "handler_arg", "handler_field", "description"},
}
_TOP_KEYS = {"pack", "wrapper", "identity", "entrypoint", "source", "sink", "sanitizer", "propagator", "setting", "function",
             "lambda_handler", "fluent", "registration", "deferred_call", "annotated_query",
             "required_flag", "disabled_protection", "handler_return", "injected_field", "same_origin_check",
             "request_attribute", "middleware", "option_call", "content_type_call", "tool_registration", "request_type", "callback_param",
             "policy", "define"}
POLICY_SEVERITIES = ("critical", "high", "medium", "low", "info")
# Route rule syntaxes whose variables an entry point can read (`route_syntax`): Werkzeug's
# `<converter(args):name>` (Flask, Quart): a rule must start with "/".
ROUTE_SYNTAXES = {"werkzeug": r"<(?:[A-Za-z_][A-Za-z0-9_]*(?:\([^)]*\))?:)?([A-Za-z_][A-Za-z0-9_]*)>"}
# What a [[setting]] reports, and where the setting can be written.
SETTING_KINDS = ("debug", "cookie_secure", "cookie_httponly")
SETTING_PLACES = ("kwarg", "assignment", "attribute", "subscript", "property", "member")


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
    request_type: str = ""               # the selected parameters are request objects of this [[request_type]]
    receiver: bool = False               # Python: select the method's bound receiver (`self`), not parameters
    unbound: bool = False                # Python: the framework calls methods unbound (positions count `self`)
    route_syntax: str = ""               # "werkzeug": only the parameters the route rule's `<converter:name>` names
    route_args: List[str] = field(default_factory=list)   # the decorator arguments holding the rule ("0", "rule")
    origin: str = ""                     # the selected parameters hold a value of this origin (`express.Response`)
    module_path: List[str] = field(default_factory=list)    # globs on the file's path (`**/pages/api/**`)
    exports: List[str] = field(default_factory=list)        # what the module exports it as (`default`, `*`)
    directives: List[str] = field(default_factory=list)     # a directive its module starts with (`use server`)
    body_directives: List[str] = field(default_factory=list)  # a directive its own body starts with
    arity: List[int] = field(default_factory=list)          # only functions with this many parameters
    exclude_arity: List[int] = field(default_factory=list)  # not functions with this many
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
    renders_view: bool = False           # sink: (view, data) renders a template; only raw-printed data is a sink
    property: bool = False               # sink: assigning the property `call` names is the sink (`ctx.body = x`)
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
    receiver: List[str] = field(default_factory=list)   # subscript / attribute / member: the object written
    values: List[str] = field(default_factory=list)     # member: other literal values that switch it off
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
    writes_headers: bool = False         # writes an HTTP header from its literal argument (C)
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
class SameOriginCheck:
    """A call that is true exactly when its argument is a local URL, a path on this site (`/x`, not
    `//host` or `/\\host`): ASP.NET's `Url.IsLocalUrl(x)` (`[[same_origin_check]]`). Read as
    `x.startsWith("/") && !x.startsWith("//")`, which the redirect guard already understands."""
    id: str
    name: List[str]
    description: str = ""


@dataclass
class RequestAttribute:
    """Java: a request attribute a filter stores (`request.setAttribute("tenant", v)` in a class
    implementing one of `writer_bases`) is what every `getAttribute("tenant")` on a request in the
    project reads (`[[request_attribute]]`; servlet filters run before the servlet)."""
    id: str
    writer_bases: List[str]
    request_types: List[str]
    set: str
    get: str
    description: str = ""


@dataclass
class OptionCall:
    """C/C++: a function whose meaning is the constant at `option_arg` (`curl_easy_setopt(h,
    CURLOPT_URL, x)`): its canonical id carries the constants written there
    (`curl_easy_setopt:CURLOPT_URL`) and `:off` when `value_arg` is 0/false/NULL, so a rule can match
    one meaning (`[[option_call]]`)."""
    id: str
    name: str
    option_arg: int
    value_arg: Optional[int] = None
    description: str = ""


@dataclass
class ContentTypeCall:
    """C++: a response writer whose content type is the argument at `arg` (`res.set_content(body,
    "text/html")`); with an HTML literal there the call is named `<name>:html`, which a sink rule
    targets (`[[content_type_call]]`)."""
    id: str
    method: str
    arg: int
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
class ToolRegistration:
    """How a server library registers a tool the model may call (`[[tool_registration]]`), so
    `mcp_metadata.py` can read the text the model is shown (name, description, schema strings)
    and find the handler. Python: a decorator (`decorator` globs over the callee as written; the
    decorator's arguments count, plus the handler's `signature` and `docstring` when set) or a
    constructor call (`call`: the callee's last name part; only with one of `when_kwargs`), the
    tool's name in `name_kwarg`, its description-like keywords in `text_kwargs`. JavaScript: a
    method call (`method`) whose name is at `name_arg`, a description at `description_arg` when
    that argument is string-shaped, a config object at `config_arg` (fields `name_field`,
    `text_fields`, `handler_field`), else the handler at `handler_arg` (-1 is the last). Every
    string in the call's arguments counts, never one inside a function. `entrypoint` is the id
    of this pack's entry point whose procedures are the tools (`frame inventory`)."""
    id: str
    entrypoint: str = ""
    decorator: List[str] = field(default_factory=list)
    call: List[str] = field(default_factory=list)
    name_kwarg: str = ""
    text_kwargs: List[str] = field(default_factory=list)
    when_kwargs: List[str] = field(default_factory=list)
    docstring: bool = False
    signature: bool = False
    method: List[str] = field(default_factory=list)
    name_arg: Optional[int] = None
    description_arg: Optional[int] = None
    config_arg: Optional[int] = None
    name_field: str = ""
    text_fields: List[str] = field(default_factory=list)
    handler_arg: Optional[int] = None
    handler_field: str = ""
    description: str = ""


@dataclass
class CallbackParam:
    """A framework calls the functions registered through `registered_via` with a value of the
    origin `origin` at `position` (`[[callback_param]]`): Socket.IO's `io.on("connection",
    socket => ...)` hands in a socket, `fastify.register(plugin)` the instance. Calls on that
    parameter are then named after it (`socket.io.Socket.on`), so packs match them. `event`:
    only when the registration's first argument is one of these literals."""
    id: str
    registered_via: List[str]
    position: int
    origin: str
    event: List[str] = field(default_factory=list)
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
    detect_dependencies: List[str] = field(default_factory=list)   # npm packages the nearest package.json declares
    entrypoints: List[Entrypoint] = field(default_factory=list)
    rules: List[Rule] = field(default_factory=list)
    settings: List[Setting] = field(default_factory=list)
    functions: List[FunctionFact] = field(default_factory=list)
    lambda_handlers: List[LambdaHandler] = field(default_factory=list)
    fluents: List[Fluent] = field(default_factory=list)
    tool_registrations: List[ToolRegistration] = field(default_factory=list)
    request_types: Dict[str, Any] = field(default_factory=dict)    # id -> instructions.RequestType
    request_proxies: Dict[str, str] = field(default_factory=dict)  # Python: `flask.request` -> request type id
    callback_params: List[CallbackParam] = field(default_factory=list)
    registrations: List[Registration] = field(default_factory=list)
    deferred_calls: List[DeferredCall] = field(default_factory=list)
    wrappers: List[str] = field(default_factory=list)              # Python: calls returning a view wrapped
    identity_proxies: List[str] = field(default_factory=list)      # Python: module-level authenticated callers
    same_origin_checks: List[SameOriginCheck] = field(default_factory=list)
    request_attributes: List[RequestAttribute] = field(default_factory=list)
    middleware_methods: List[str] = field(default_factory=list)    # JS [[middleware]]
    option_calls: List[OptionCall] = field(default_factory=list)
    content_type_calls: List[ContentTypeCall] = field(default_factory=list)
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
                    or self.detect_files or self.detect_module_names or self.detect_dependencies)

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


def _request_types(origin: str, language: str, pack_name: str, pack, tables) -> None:
    """`[[request_type]]` entries: what a framework's request object holds. `objects` names the
    paths that hold another request object of the pack (resolved after all are read), `proxies`
    the module-level objects that are one inside a request (Python: `flask.request`)."""
    from frame.sil.instructions import RequestType
    raw: Dict[str, dict] = {}
    for i, t in enumerate(tables):
        where = f"[[request_type]] #{i + 1}"
        _check_keys(origin, where, t, _REQUEST_TYPE_KEYS)
        rid = t.get("id")
        if not isinstance(rid, str) or not rid or rid in raw:
            raise _fail(origin, f"{where}.id", "a new id is required")
        fields = _strings(origin, f"{where}.fields", t.get("fields", []))
        methods = _strings(origin, f"{where}.methods", t.get("methods", []))
        server = _strings(origin, f"{where}.server_state", t.get("server_state", []))
        objects = t.get("objects", {})
        if not isinstance(objects, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in objects.items()):
            raise _fail(origin, f"{where}.objects", "maps property paths to request type ids of this pack")
        if not fields and not methods and not objects:
            raise _fail(origin, where, "holds nothing: set fields, methods or objects")
        if fields == ["*"]:
            if methods:
                raise _fail(origin, where, 'with fields = ["*"] every method is client data too: no methods')
        elif "*" in fields or server:
            raise _fail(origin, where, 'server_state goes with fields = ["*"] (every property but those)')
        headers = _strings(origin, f"{where}.headers", t.get("headers", []))
        sessions = _strings(origin, f"{where}.sessions", t.get("sessions", []))
        identities = _strings(origin, f"{where}.identities", t.get("identities", []))
        proxies = _strings(origin, f"{where}.proxies", t.get("proxies", []))
        value_origin = t.get("origin", "")
        if not isinstance(value_origin, str) or (value_origin and not all(
                seg.isidentifier() for seg in value_origin.split("."))):
            raise _fail(origin, f"{where}.origin", "names the request object's value origin (`pyramid.request.Request`)")
        if proxies and language != "python":
            raise _fail(origin, f"{where}.proxies", "is for Python packs (module-level request proxies)")
        for path in fields + methods + server + headers + sessions + identities + list(objects) + proxies:
            if path != "*" and not all(seg.isidentifier() or seg.startswith("$") for seg in path.split(".")):
                raise _fail(origin, where, f"{path!r} is not a property path")

        def client(path: str) -> bool:
            head = path.split(".")
            if fields == ["*"]:
                return head[0] not in server
            return any(head[:len(f.split("."))] == f.split(".") for f in fields)
        kinds = t.get("kinds", {})
        if not isinstance(kinds, dict) or not all(isinstance(k, str) for k in kinds):
            raise _fail(origin, f"{where}.kinds", "maps property paths to source kinds")
        for path in kinds:
            if not client(path):
                raise _fail(origin, f"{where}.kinds", f"{path!r} is not one of its client fields")
        for path in headers:
            if not client(path):
                raise _fail(origin, f"{where}.headers", f"{path!r} is not one of its client fields")
        for path in sessions:
            if client(path):
                raise _fail(origin, f"{where}.sessions", f"{path!r} is client data, not the server's session")
        for path in identities:
            if client(path) or "." in path:
                raise _fail(origin, f"{where}.identities", f"{path!r} is not a server-state name (the authenticated caller)")
        raw[rid] = dict(t, fields=fields, methods=methods, server_state=server, objects=objects,
                        headers=headers, sessions=sessions, identities=identities, proxies=proxies, kinds=kinds,
                        where=where,
                        value_origin=value_origin)
    built: Dict[str, Any] = {}

    def build(rid: str, stack: Tuple[str, ...]) -> Any:
        if rid in built:
            return built[rid]
        t = raw[rid]
        if rid in stack:
            raise _fail(origin, f"{t['where']}.objects", f"request types hold each other ({' -> '.join(stack + (rid,))})")
        objs = []
        for path, other in t["objects"].items():
            if other not in raw:
                raise _fail(origin, f"{t['where']}.objects", f"names no [[request_type]] of this pack ({other})")
            objs.append((tuple(path.split(".")), build(other, stack + (rid,))))
        fields = t["fields"]
        built[rid] = RequestType(
            name=f"{language}/{pack_name}:{rid}",
            fields=() if fields == ["*"] else tuple(tuple(f.split(".")) for f in fields),
            methods=tuple(tuple(m.split(".")) for m in t["methods"]),
            all_fields=fields == ["*"], server_state=tuple(t["server_state"]),
            kinds=tuple((tuple(path.split(".")), _taint_kind_value(_source_kind(origin, f"{t['where']}.kinds", k)))
                        for path, k in t["kinds"].items()),
            objects=tuple(objs), headers=tuple(tuple(h.split(".")) for h in t["headers"]),
            sessions=tuple(tuple(h.split(".")) for h in t["sessions"]), identities=tuple(t["identities"]),
            origin=t["value_origin"])
        return built[rid]
    for rid in raw:
        pack.request_types[rid] = build(rid, ())
        for proxy in raw[rid]["proxies"]:
            if proxy in pack.request_proxies:
                raise _fail(origin, f"{raw[rid]['where']}.proxies", f"{proxy} is already a proxy of this pack")
            pack.request_proxies[proxy] = rid


def _check_keys(origin: str, where: str, table: Dict[str, Any], allowed: set) -> None:
    unknown = sorted(set(table) - allowed)
    if unknown:
        raise _fail(origin, where, f"unknown key(s) {unknown}; allowed: {sorted(allowed)}")


def _taint_kind_value(kind: str) -> str:
    """A pack's source kind as the TaintKind value (`file_input` is `file`)."""
    return {"user_input": "user", "network_input": "network", "file_input": "file"}.get(kind, kind)


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
    pack.detect_dependencies = _strings(origin, "detect.dependencies", detect.get("dependencies", []))
    if pack.detect_dependencies and language not in ("javascript", "typescript"):
        raise _fail(origin, "detect.dependencies", "reads package.json: for JavaScript packs")

    _request_types(origin, language, name, pack, data.get("request_type", []))

    for i, t in enumerate(data.get("entrypoint", [])):
        where = f"[[entrypoint]] #{i + 1}"
        _check_keys(origin, where, t, _ENTRY_KEYS)
        e = Entrypoint(id=str(t.get("id", f"{name}-entry-{i + 1}")), description=str(t.get("description", "")))
        for key in ("decorator", "class_decorator", "extends", "method", "registered_via", "param_annotation", "param_type",
                    "exclude_param", "exclude_param_type", "tainted_param_type", "field_annotation", "class_name",
                    "modifiers", "exclude_modifiers", "exclude_decorator", "exclude_method", "first_param",
                    "module_path", "exports", "directives", "body_directives"):
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
        params = t.get("params", "all" if (e.param_positions or e.params_from) else "none")  # positions select
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
        if "origin" in t:
            if not isinstance(t["origin"], str) or not t["origin"]:
                raise _fail(origin, f"{where}.origin", "needs the value's id (`express.Response`)")
            if "request_type" in t or "kind" in t:
                raise _fail(origin, where, "an origin entry point names what a parameter is: no request_type or kind")
            e.origin = t["origin"]
        for key in ("receiver", "unbound"):
            if key in t:
                if not isinstance(t[key], bool):
                    raise _fail(origin, f"{where}.{key}", "must be true or false")
                if language != "python":
                    raise _fail(origin, f"{where}.{key}", "is for Python packs (a method's explicit receiver)")
                setattr(e, key, t[key])
        if "route_syntax" in t:
            if t["route_syntax"] not in ROUTE_SYNTAXES:
                raise _fail(origin, f"{where}.route_syntax", f"must be one of {sorted(ROUTE_SYNTAXES)}")
            if not e.decorator:
                raise _fail(origin, where, "route_syntax reads the rule from the matched decorator: needs decorator")
            e.route_syntax = t["route_syntax"]
            e.route_args = _strings(origin, f"{where}.route_args", t.get("route_args", ["0"]), allow_empty=False)
        elif "route_args" in t:
            raise _fail(origin, f"{where}.route_args", "goes with route_syntax")
        if e.receiver and (e.unbound or e.param_positions or e.params_from or isinstance(params, list)):
            raise _fail(origin, where, "receiver = true selects the bound receiver: no positions, names or unbound")
        if "request_type" in t:
            if t["request_type"] not in pack.request_types:
                raise _fail(origin, f"{where}.request_type", f"names no [[request_type]] of this pack ({t['request_type']})")
            if "kind" in t:
                raise _fail(origin, where, "a request_type entry point makes request objects: no kind")
            e.request_type = t["request_type"]
        for key in ("arity", "exclude_arity"):
            if key in t:
                v = t[key]
                if not isinstance(v, list) or not v or not all(isinstance(n, int) and not isinstance(n, bool) and n >= 0
                                                               for n in v):
                    raise _fail(origin, f"{where}.{key}", "must be a list of parameter counts")
                setattr(e, key, list(v))
        if not (e.decorator or e.class_decorator or e.extends or e.method or e.registered_via or e.class_name
                or e.first_param or e.exports or e.directives or e.body_directives):
            raise _fail(origin, where, "needs at least one of decorator/annotation, class_decorator, "
                                       "extends, class_name, method, registered_via, first_param, exports")
        if e.module_path and not e.exports:
            raise _fail(origin, where, "module_path goes with exports (what a file-system convention dispatches to)")
        if params == "none" and not e.fields and not e.tainted_param_type and not e.origin and not e.receiver:
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
                if not isinstance(t.get("renders_view", False), bool):
                    raise _fail(origin, f"{where}.renders_view", "must be true or false")
                r.renders_view = t.get("renders_view", False)
                if not isinstance(t.get("property", False), bool):
                    raise _fail(origin, f"{where}.property", "must be true or false")
                r.property = t.get("property", False)
                if r.property and (not r.call or r.name or "args" in t):
                    raise _fail(origin, where, "a property sink names the property by `call` id only, with no args")
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
        if "values" in t and t.get("at") != "member":
            raise _fail(origin, f"{where}.values", 'only at = "member" (C# enum values such as CookieSecurePolicy.None)')
        st = Setting(id=str(t.get("id", f"{name}-setting-{i + 1}")), kind=t["kind"], at=t["at"],
                     keys=_strings(origin, f"{where}.keys", t.get("keys", []), allow_empty=False),
                     value=t["value"], description=str(t.get("description", "")),
                     call=_strings(origin, f"{where}.call", t.get("call", [])),
                     receiver=_strings(origin, f"{where}.receiver", t.get("receiver", [])),
                     values=_strings(origin, f"{where}.values", t.get("values", [])))
        if st.at in ("kwarg", "property") and not st.call:
            raise _fail(origin, where, f'at = "{st.at}" needs call')
        if st.at in ("subscript", "member") and not st.receiver:
            raise _fail(origin, where, f'at = "{st.at}" needs receiver')
        if st.at == "member" and language != "csharp":
            raise _fail(origin, where, 'at = "member" is for C# packs (a property assignment or initializer member)')
        pack.settings.append(st)

    from frame.sil.specs.tables import ALLOCATION_KINDS, RELEASE_KINDS
    for i, t in enumerate(data.get("function", [])):
        where = f"[[function]] #{i + 1}"
        _check_keys(origin, where, t, _FUNCTION_KEYS)
        if language not in ("c", "cpp") and set(t) - {"name", "noreturn", "description"}:
            raise _fail(origin, where, "outside C and C++ a [[function]] states only noreturn")
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
        if not isinstance(t.get("writes_headers", False), bool):
            raise _fail(origin, f"{where}.writes_headers", "must be true or false")
        fact = FunctionFact(name=t["name"], allocates=t.get("allocates", ""), frees=t.get("frees", ""),
                            allocates_via=via, noreturn=t.get("noreturn", False), dereferences=list(derefs),
                            writes_headers=t.get("writes_headers", False),
                            description=str(t.get("description", "")))
        if not (fact.allocates or fact.frees or fact.noreturn or fact.dereferences or fact.writes_headers):
            raise _fail(origin, where, "states nothing: set allocates, frees, noreturn, dereferences or writes_headers")
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

    def _position(where, value):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise _fail(origin, where, "must be an argument position (0-based)")
        return value

    for i, t in enumerate(data.get("option_call", [])):
        where = f"[[option_call]] #{i + 1}"
        _check_keys(origin, where, t, {"id", "name", "option_arg", "value_arg", "description"})
        if language not in ("c", "cpp"):
            raise _fail(origin, where, "option calls are for C and C++ packs")
        if not isinstance(t.get("name"), str) or not t["name"]:
            raise _fail(origin, f"{where}.name", "needs the function's name")
        pack.option_calls.append(OptionCall(
            id=str(t.get("id", f"{name}-option-{i + 1}")), name=t["name"],
            option_arg=_position(f"{where}.option_arg", t.get("option_arg")),
            value_arg=_position(f"{where}.value_arg", t["value_arg"]) if "value_arg" in t else None,
            description=str(t.get("description", ""))))

    for i, t in enumerate(data.get("content_type_call", [])):
        where = f"[[content_type_call]] #{i + 1}"
        _check_keys(origin, where, t, {"id", "method", "arg", "description"})
        if language != "cpp":
            raise _fail(origin, where, "content-type calls are for C++ packs")
        if not isinstance(t.get("method"), str) or not t["method"]:
            raise _fail(origin, f"{where}.method", "needs the method's name")
        pack.content_type_calls.append(ContentTypeCall(
            id=str(t.get("id", f"{name}-content-type-{i + 1}")), method=t["method"],
            arg=_position(f"{where}.arg", t.get("arg")), description=str(t.get("description", ""))))

    for i, t in enumerate(data.get("request_attribute", [])):
        where = f"[[request_attribute]] #{i + 1}"
        _check_keys(origin, where, t, {"id", "writer_bases", "request_types", "set", "get", "description"})
        if language != "java":
            raise _fail(origin, where, "request attributes are for Java packs")
        for k in ("writer_bases", "request_types", "set", "get"):
            if not t.get(k):
                raise _fail(origin, where, f"needs {k}")
        pack.request_attributes.append(RequestAttribute(
            id=str(t.get("id", f"{name}-request-attribute-{i + 1}")),
            writer_bases=_strings(origin, f"{where}.writer_bases", t["writer_bases"]),
            request_types=_strings(origin, f"{where}.request_types", t["request_types"]),
            set=str(t["set"]), get=str(t["get"]), description=str(t.get("description", ""))))

    for i, t in enumerate(data.get("middleware", [])):
        where = f"[[middleware]] #{i + 1}"
        _check_keys(origin, where, t, {"id", "methods", "description"})
        if language != "javascript":
            raise _fail(origin, where, "middleware registration is for JavaScript packs")
        if not t.get("methods"):
            raise _fail(origin, where, "needs methods")
        pack.middleware_methods += _strings(origin, f"{where}.methods", t["methods"])

    for i, t in enumerate(data.get("same_origin_check", [])):
        where = f"[[same_origin_check]] #{i + 1}"
        _check_keys(origin, where, t, {"id", "name", "description"})
        if language != "csharp":
            raise _fail(origin, where, "same-origin checks are for C# packs")
        if not t.get("name"):
            raise _fail(origin, where, "needs name (the method's name)")
        pack.same_origin_checks.append(SameOriginCheck(id=str(t.get("id", f"{name}-same-origin-{i + 1}")),
                                                       name=_strings(origin, f"{where}.name", t["name"]),
                                                       description=str(t.get("description", ""))))

    for i, t in enumerate(data.get("identity", [])):
        where = f"[[identity]] #{i + 1}"
        _check_keys(origin, where, t, {"proxies", "description", "references"})
        if language != "python":
            raise _fail(origin, where, "identity proxies are for Python packs (module-level objects)")
        pack.identity_proxies += _strings(origin, f"{where}.proxies", t.get("proxies", []), allow_empty=False)

    for i, t in enumerate(data.get("wrapper", [])):
        where = f"[[wrapper]] #{i + 1}"
        _check_keys(origin, where, t, {"call", "description", "references"})
        if language != "python":
            raise _fail(origin, where, "wrappers are for Python packs (a handler wrapped by a decorator call)")
        pack.wrappers += _strings(origin, f"{where}.call", t.get("call", []), allow_empty=False)

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

    for i, t in enumerate(data.get("tool_registration", [])):
        where = f"[[tool_registration]] #{i + 1}"
        if language not in _TOOL_KEYS:
            raise _fail(origin, where, f"tool registrations are for {sorted(_TOOL_KEYS)} packs")
        _check_keys(origin, where, t, _TOOL_KEYS[language])

        def _opt_position(key, t=t, where=where, low=0):
            if key not in t:
                return None
            v = t[key]
            if not isinstance(v, int) or isinstance(v, bool) or v < low:
                raise _fail(origin, f"{where}.{key}", "must be an argument position (0-based"
                                                      + (", -1 for the last)" if low < 0 else ")"))
            return v

        def _flag(key, t=t, where=where):
            if not isinstance(t.get(key, False), bool):
                raise _fail(origin, f"{where}.{key}", "is true or false")
            return t.get(key, False)
        reg = ToolRegistration(
            id=str(t.get("id", f"{name}-tool-{i + 1}")), entrypoint=str(t.get("entrypoint", "")),
            decorator=_strings(origin, f"{where}.decorator", t.get("decorator", [])),
            call=_strings(origin, f"{where}.call", t.get("call", [])),
            name_kwarg=str(t.get("name_kwarg", "")),
            text_kwargs=_strings(origin, f"{where}.text_kwargs", t.get("text_kwargs", [])),
            when_kwargs=_strings(origin, f"{where}.when_kwargs", t.get("when_kwargs", [])),
            docstring=_flag("docstring"), signature=_flag("signature"),
            method=_strings(origin, f"{where}.method", t.get("method", [])),
            name_arg=_opt_position("name_arg"), description_arg=_opt_position("description_arg"),
            config_arg=_opt_position("config_arg"), name_field=str(t.get("name_field", "")),
            text_fields=_strings(origin, f"{where}.text_fields", t.get("text_fields", [])),
            handler_arg=_opt_position("handler_arg", low=-1), handler_field=str(t.get("handler_field", "")),
            description=str(t.get("description", "")))
        if language == "python" and bool(reg.decorator) == bool(reg.call):
            raise _fail(origin, where, "needs exactly one of decorator or call")
        if language == "python" and reg.call and not reg.when_kwargs:
            raise _fail(origin, where, "a call form needs when_kwargs (the keywords that make it a tool)")
        if language == "python" and reg.call and (reg.docstring or reg.signature):
            raise _fail(origin, where, "docstring and signature are for the decorator form")
        if language == "javascript":
            if not reg.method:
                raise _fail(origin, where, "needs method")
            if reg.name_arg is None and not reg.name_field:
                raise _fail(origin, where, "needs name_arg or name_field")
            if reg.name_field and reg.config_arg is None:
                raise _fail(origin, where, "name_field needs config_arg")
            if reg.handler_arg is None and not reg.handler_field:
                raise _fail(origin, where, "needs handler_arg or handler_field")
            if reg.handler_field and reg.config_arg is None:
                raise _fail(origin, where, "handler_field needs config_arg")
            if reg.text_fields and reg.config_arg is None:
                raise _fail(origin, where, "text_fields needs config_arg")
        if reg.entrypoint and reg.entrypoint not in {e.id for e in pack.entrypoints}:
            raise _fail(origin, f"{where}.entrypoint", f"names no entry point of this pack ({reg.entrypoint})")
        pack.tool_registrations.append(reg)

    for i, t in enumerate(data.get("callback_param", [])):
        where = f"[[callback_param]] #{i + 1}"
        _check_keys(origin, where, t, {"id", "registered_via", "position", "origin", "event", "description"})
        if language not in ("javascript", "typescript"):
            raise _fail(origin, where, "callback parameters are for JavaScript packs")
        pos = t.get("position")
        if not isinstance(pos, int) or isinstance(pos, bool) or pos < 0:
            raise _fail(origin, f"{where}.position", "must be a parameter position (0-based)")
        if not isinstance(t.get("origin"), str) or not t["origin"]:
            raise _fail(origin, f"{where}.origin", "needs the value's id (`socket.io.Socket`)")
        cb = CallbackParam(id=str(t.get("id", f"{name}-callback-{i + 1}")),
                           registered_via=_strings(origin, f"{where}.registered_via", t.get("registered_via", []),
                                                   allow_empty=False),
                           position=pos, origin=t["origin"],
                           event=_strings(origin, f"{where}.event", t.get("event", [])),
                           description=str(t.get("description", "")))
        pack.callback_params.append(cb)

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
