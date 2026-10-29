"""Language-neutral facts the frontends record next to the instructions.

Framework knowledge ("a method annotated `@RequestMapping` is an endpoint",
"`flask.request.args.get` returns request data") needs three things the SIL
did not carry uniformly:

* a **canonical callee id** -- the fully qualified name of the called function,
  resolved through the file's imports (`cp.exec` -> `child_process.exec`,
  `request.args.get` -> `flask.request.args.get`, a `Statement`-typed receiver's
  `executeQuery` -> `java.sql.Statement.executeQuery`). It is best-effort and
  never guessed: `None` means "not resolved", and a consumer then falls back to
  the textual call name that has always been on `Call.func`.
* **annotations / decorators** on procedures, parameters and classes, with their
  arguments (`@app.route("/x", methods=["POST"])`, `@RequestMapping(value="/x")`,
  `[HttpPost("x")]`).
* **base classes and interfaces** of each class, as written and as resolved.

Keyword-argument names are recorded on `Call.kwarg_names`.

All of this is additive: nothing in the analysis reads it until a framework
pack asks, so recording it must not change a single finding.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Iterable, List, Optional


@dataclass
class Annotation:
    """One annotation / decorator / attribute."""
    name: str                                   # as written, no `@` or brackets: `app.route`
    canonical: Optional[str] = None             # resolved through imports, else None
    args: Dict[str, str] = field(default_factory=dict)   # named args; positional ones as "0", "1", ...
    text: str = ""                              # the source text, for diagnostics

    def arg(self, key: str) -> Optional[str]:
        return self.args.get(key)


@dataclass
class ClassInfo:
    """A class-like declaration: what it extends / implements and how it is marked."""
    name: str
    kind: str = "class"                         # class | interface | enum | struct
    bases: List[str] = field(default_factory=list)            # as written
    canonical_bases: List[str] = field(default_factory=list)  # resolved where possible, else as written
    annotations: List[Annotation] = field(default_factory=list)
    package: Optional[str] = None               # Java package / C# namespace
    fields: List[str] = field(default_factory=list)   # declared instance fields / properties
    field_annotations: Dict[str, List[Annotation]] = field(default_factory=dict)  # per field, where recorded
    settable_fields: List[str] = field(default_factory=list)  # public members code outside can assign (C#)


class ImportTable:
    """Local name -> qualified name for one file.

    `bind("r", "flask.request")` makes `r.args.get` resolve to
    `flask.request.args.get`. A local name bound to two different targets is
    dropped (it cannot be resolved by name, the same rule the JS frontend uses).
    """

    def __init__(self) -> None:
        self.names: Dict[str, str] = {}
        self.wildcards: List[str] = []          # on-demand imports: `java.util.*`, `using X;`, `from m import *`
        self._conflicts: set = set()

    def bind(self, local: str, qualified: str) -> None:
        if not local or not qualified:
            return
        if local in self.names and self.names[local] != qualified:
            self._conflicts.add(local)
        self.names[local] = qualified

    def finish(self) -> "ImportTable":
        for c in self._conflicts:
            self.names.pop(c, None)
        self._conflicts = set()
        return self

    def resolve(self, dotted: str) -> Optional[str]:
        """`dotted` with its head replaced by what the head was imported as."""
        if not dotted:
            return None
        head, sep, rest = dotted.partition(".")
        target = self.names.get(head)
        if target is None:
            return None
        return target + sep + rest if sep else target

    def as_dict(self) -> Dict[str, str]:
        return dict(self.names)


# --------------------------------------------------------------------------
# Annotation text
# --------------------------------------------------------------------------

def _split_top_level(text: str) -> List[str]:
    """Split on commas that are not inside quotes or brackets."""
    parts: List[str] = []
    depth, quote, cur = 0, "", []
    i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            cur.append(ch)
            if ch == "\\" and i + 1 < len(text):
                cur.append(text[i + 1])
                i += 1
            elif ch == quote:
                quote = ""
        elif ch in "\"'`":
            quote = ch
            cur.append(ch)
        elif ch in "([{<" and not (ch == "<" and depth == 0):
            depth += 1
            cur.append(ch)
        elif ch in ")]}>" and not (ch == ">" and depth == 0):
            depth = max(0, depth - 1)
            cur.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        i += 1
    tail = "".join(cur).strip()
    if tail:
        parts.append(tail)
    return parts


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'`":
        return value[1:-1]
    return value


def parse_annotation(text: str, table: Optional[ImportTable] = None,
                     value_alias: bool = False) -> Annotation:
    """Parse `@name(args)` / `[Name(args)]` / `name(args)` into an Annotation.

    Named arguments are `key=value` (Java, C#, Python decorator keywords);
    positional ones are stored as "0", "1", ... and, with `value_alias`, the
    first positional argument of a single-argument annotation is also "value"
    (Java's `@GetMapping("/x")` means `value="/x"`). String quotes are removed.
    """
    raw = text.strip()
    body = raw.lstrip("@").strip()
    if body.startswith("[") and body.endswith("]"):
        body = body[1:-1].strip()
    if body.startswith("assembly:") or body.startswith("return:"):
        body = body.split(":", 1)[1].strip()
    name, args_text = body, ""
    paren = body.find("(")
    if paren != -1 and body.endswith(")"):
        name, args_text = body[:paren].strip(), body[paren + 1:-1]
    args: Dict[str, str] = {}
    positional = 0
    for part in _split_top_level(args_text):
        key, sep, value = part.partition("=")
        if sep and key.strip().isidentifier() and not value.startswith("="):
            args[key.strip()] = _unquote(value)
        else:
            args[str(positional)] = _unquote(part)
            positional += 1
    if value_alias and positional == 1 and "value" not in args:
        args["value"] = args["0"]
    canonical = table.resolve(name) if table is not None else None
    return Annotation(name=name, canonical=canonical, args=args, text=raw)


# --------------------------------------------------------------------------
# Canonical callee ids
# --------------------------------------------------------------------------

_PY_BUILTINS = frozenset(
    "eval exec compile open input print getattr setattr delattr hasattr __import__ "
    "len str int float bool bytes bytearray list dict set tuple type isinstance "
    "map filter zip range sorted sum min max any all vars globals locals".split())

_JS_GLOBALS = frozenset(
    "eval Function setTimeout setInterval fetch document window JSON Math Object Array "
    "Buffer process console global globalThis localStorage sessionStorage navigator "
    "location XMLHttpRequest WebSocket URL RegExp Promise Reflect Proxy String Number".split())

# java.lang is imported implicitly; these are the types a call is often qualified by.
_JAVA_LANG = frozenset(
    "Object String StringBuilder StringBuffer Runtime Process ProcessBuilder System Class "
    "ClassLoader Thread Math Integer Long Double Float Boolean Byte Short Character Number "
    "Throwable Exception Error Runnable Iterable Comparable".split())

# Types a wildcard import (`import java.sql.*;`) commonly brings in. A curated list,
# not the JDK: a type is resolved through a wildcard only when its package is
# imported on demand AND the type is listed here; anything else stays unresolved.
_JAVA_WILDCARD_TYPES = {
    "java.sql": "Statement PreparedStatement CallableStatement Connection ResultSet DriverManager "
                "DatabaseMetaData Driver SQLException".split(),
    "java.io": "File FileInputStream FileOutputStream FileReader FileWriter BufferedReader "
               "BufferedWriter InputStream OutputStream ObjectInputStream ObjectOutputStream "
               "InputStreamReader PrintWriter RandomAccessFile Reader Writer".split(),
    "java.net": "URL URLConnection HttpURLConnection Socket ServerSocket URI InetAddress".split(),
    "java.util": "Random Scanner Properties ArrayList HashMap List Map Set".split(),
    "java.nio.file": "Files Paths Path".split(),
    "javax.servlet.http": "HttpServletRequest HttpServletResponse HttpSession Cookie".split(),
    "javax.xml.parsers": "DocumentBuilder DocumentBuilderFactory SAXParser SAXParserFactory".split(),
    "java.security": "MessageDigest SecureRandom KeyStore".split(),
    "javax.crypto": "Cipher Mac KeyGenerator".split(),
}

_CSHARP_NAMESPACE_TYPES = {
    "System": "Console Convert Math Environment Activator Type Random Uri String".split(),
    "System.IO": "File Directory Path FileStream StreamReader StreamWriter BinaryReader "
                 "BinaryWriter MemoryStream FileInfo DirectoryInfo".split(),
    "System.Data.SqlClient": "SqlCommand SqlConnection SqlDataAdapter SqlDataReader SqlParameter".split(),
    "Microsoft.Data.SqlClient": "SqlCommand SqlConnection SqlDataAdapter SqlDataReader".split(),
    "System.Data": "DataSet DataTable IDbCommand IDbConnection".split(),
    "System.Data.OleDb": "OleDbCommand OleDbConnection".split(),
    "System.Data.Odbc": "OdbcCommand OdbcConnection".split(),
    "System.Diagnostics": "Process ProcessStartInfo".split(),
    "System.Net": "WebClient HttpWebRequest WebRequest".split(),
    "System.Net.Http": "HttpClient".split(),
    "System.Web": "HttpRequest HttpResponse HttpContext HttpServerUtility".split(),
    "System.Xml": "XmlDocument XmlReader XmlTextReader XmlReaderSettings".split(),
    "System.Security.Cryptography": "MD5 SHA1 SHA256 DES TripleDES AES Aes RSA RNGCryptoServiceProvider "
                                    "MD5CryptoServiceProvider SHA1CryptoServiceProvider".split(),
    "System.Runtime.Serialization.Formatters.Binary": "BinaryFormatter".split(),
    "System.Reflection": "Assembly MethodInfo".split(),
}

_WILDCARD_TYPES = {"java": _JAVA_WILDCARD_TYPES, "csharp": _CSHARP_NAMESPACE_TYPES}

_CSHARP_SYSTEM = frozenset("Console Convert Math Environment Activator GC Buffer String Object".split())


def canonical_call(language: str, func: str, table: ImportTable, *,
                   receiver_type: Optional[str] = None,
                   callee_class: Optional[str] = None,
                   local_names: Iterable[str] = (),
                   local_types: Optional[Dict[str, str]] = None) -> Optional[str]:
    """The canonical id of a call, or None when it cannot be resolved.

    `func` is the textual callee as the frontend names it. `local_names` are
    functions the file itself defines (a call to one is the project's own code,
    not a library API, so it has no canonical id). `local_types` maps types the
    file declares to their qualified name (Java package + class).
    """
    if not func or func.startswith("<"):
        return None
    local = frozenset(local_names)
    if language == "python":
        return _canonical_dotted(func, table, local, _PY_BUILTINS, "builtins.")
    if language in ("javascript", "typescript"):
        return _canonical_js(func, table, local)
    if language in ("java", "csharp"):
        return _canonical_typed(language, func, table, receiver_type, callee_class,
                                local_types or {})
    if language in ("c", "cpp"):
        return _canonical_c(func, local)
    return None


def _strip_marker(func: str) -> str:
    """Drop frontend-internal suffixes such as the non-HTML response marker."""
    return func.split("#", 1)[0].split("@", 1)[0]


def _canonical_dotted(func: str, table: ImportTable, local: FrozenSet[str],
                      builtins: FrozenSet[str], builtin_prefix: str) -> Optional[str]:
    func = _strip_marker(func)
    head = func.split(".", 1)[0]
    if head in ("self", "cls", "this") or head in local:
        return None
    resolved = table.resolve(func)
    if resolved is not None:
        return resolved
    if head in builtins and head not in table.names:
        return builtin_prefix + func
    return None


def _canonical_js(func: str, table: ImportTable, local: FrozenSet[str]) -> Optional[str]:
    # The JS frontend has already rewritten a call on a required / imported module
    # to `<specifier>.<member>` (`cp.exec` -> `child_process.exec`); the specifier
    # is a canonical module id unless it is a relative path.
    func = _strip_marker(func)
    for module in table.names.values():
        spec = module.split("::", 1)[0]
        if not spec.startswith(".") and (func == spec or func.startswith(spec + ".")):
            return func
    head = func.split(".", 1)[0]
    if head in local or head in ("this", "self"):
        return None
    resolved = table.resolve(func)
    if resolved is not None and not resolved.startswith("."):
        return resolved
    if head in _JS_GLOBALS and head not in table.names:
        return func
    return None


def _canonical_typed(language: str, func: str, table: ImportTable, receiver_type: Optional[str],
                     callee_class: Optional[str], local_types: Dict[str, str]) -> Optional[str]:
    """Java / C#: the method on the declared type of its receiver."""
    if func.startswith("new "):
        type_name, method = func[4:].strip(), "<init>"
    else:
        type_name = receiver_type or callee_class or ""
        method = func.rsplit(".", 1)[-1]
        if not type_name and language == "java" and "()." in func:
            # `Runtime.getRuntime().exec(..)`: the receiver is a factory call whose
            # return type the Java specs know.
            from .specs.java_specs import JAVA_FACTORY_RETURN_TYPES
            inner = func.rsplit(").", 1)[0].rsplit("(", 1)[0].rsplit(".", 1)[-1]
            type_name = JAVA_FACTORY_RETURN_TYPES.get(inner, "")
    if not type_name or not method:
        return None
    qualified = qualify_type(language, type_name, table, local_types)
    if qualified is None:
        return None
    return f"{qualified}.{method}"


def qualify_type(language: str, type_name: str, table: ImportTable,
                 local_types: Optional[Dict[str, str]] = None) -> Optional[str]:
    """The fully qualified name of a type as written in this file, or None.

    Resolved, in order, through the file's own declarations, its explicit imports,
    an already-qualified name, the curated wildcard tables and the implicit
    `java.lang` / `System` set. Never guessed.
    """
    type_name = type_name.split("<", 1)[0].rstrip("?").strip()
    if not type_name:
        return None
    local_types = local_types or {}
    if type_name in local_types:
        return local_types[type_name]
    qualified = table.resolve(type_name)
    if qualified is None and "." in type_name:
        head = type_name.split(".", 1)[0]
        if head[:1].islower() or (language == "csharp" and head in ("System", "Microsoft")):
            qualified = type_name
    if qualified is None:
        wild = _WILDCARD_TYPES.get(language, {})
        owners = [w for w in table.wildcards if type_name in wild.get(w, ())]
        if len(owners) == 1:
            qualified = f"{owners[0]}.{type_name}"
    if qualified is None:
        if language == "java" and type_name in _JAVA_LANG:
            qualified = "java.lang." + type_name
        elif language == "csharp" and type_name in _CSHARP_SYSTEM:
            qualified = "System." + type_name
    return qualified


def _canonical_c(func: str, local: FrozenSet[str]) -> Optional[str]:
    # C has no module system: the symbol name is the identity. A function the
    # translation unit defines is the project's own and has no library id.
    func = _strip_marker(func)
    if func in local or func.rsplit("::", 1)[-1] in local:
        return None
    if "." in func or "->" in func:
        return None                       # a member call: the receiver's type is unknown
    return func


def merge_tables(*tables: ImportTable) -> ImportTable:
    out = ImportTable()
    for t in tables:
        for k, v in t.names.items():
            out.bind(k, v)
        out.wildcards.extend(t.wildcards)
    return out.finish()


def annotate_program_calls(program, table: ImportTable,
                           local_types: Optional[Dict[str, str]] = None) -> None:
    """Fill `Call.canonical` for every call in `program` from `table`.

    Run once by each frontend after translation; reads only what the frontend
    already recorded (`func`, `receiver_type`, `callee_class`).
    """
    # imported lazily: instructions imports nothing from here
    from .instructions import Call
    local_names = {n.split("#", 1)[0] for n in program.procedures}
    local_names |= {n.rsplit(".", 1)[-1].split("#", 1)[0] for n in program.procedures}
    for proc in program.procedures.values():
        for node in proc.nodes.values():
            for instr in node.instrs:
                if not isinstance(instr, Call) or instr.canonical is not None:
                    continue
                func = str(getattr(instr.func, "value", instr.func))
                instr.canonical = canonical_call(
                    program.language, func, table,
                    receiver_type=instr.receiver_type, callee_class=instr.callee_class,
                    local_names=local_names, local_types=local_types)
