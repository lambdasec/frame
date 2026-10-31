"""The module index behind cross-file taint: which file a call lands in.

A call to `db.run_query(q)` or `runQuery(q)` is a flow into another file only if
we know which file `db` / `runQuery` came from and which of that file's
procedures it names. `ProjectIndex` answers that for Python and JS/TS projects
from the files' own import and export statements, read with the frontends'
tree-sitter parsers; no code runs and no package manager is consulted.

What resolves (and what deliberately does not):

- Python: `import a.b`, `import a.b as m`, `from a import f [as g]`, `from . import
  sib`, `from ..pkg import f`; a name a package's `__init__` re-exports; a
  submodule imported as `from pkg import mod`. An absolute module is found by
  matching the tail of file paths (`app/db.py` answers `app.db` and `db`) and
  must sit under a root the importer can see: one of its own ancestor
  directories, or `src`/`lib`/`python` directly under the project root. Two
  equally good matches resolve to nothing. `from m import *` binds nothing.
- JS/TS: `require('./m')`, destructured `require`, `import d`, `import {a as b}`,
  `import * as ns`, and the exports `module.exports = {...}`, `module.exports =
  f`, `module.exports.x` / `exports.x`, `export function`, `export const`,
  `export {a as b}`, `export {a} from './m'`, `export * from './m'`, `export
  default f`. Only relative specifiers resolve (`./m`, `../m`, with the usual
  extensions and `index` files); packages and path aliases are external.
- Functions (Python module level, JS exported) and class methods are callees.
  A method call resolves three ways: `Class.method(...)` on a static or class
  method; `recv.method(...)` where `recv` has an inferred class (`recv = C(...)`,
  `recv = new C(...)`, `self.recv = C(...)`, `recv: C` annotations, TS
  constructor parameter properties and typed fields); and `C(...).method(...)`.
  Methods are looked up on the class and its in-project base classes. A
  receiver whose evidence does not all resolve to ONE class -- two assignments
  of different classes, a factory call, a type that is not a project class --
  is not guessed. Anything unresolved keeps the default argument-to-result
  propagation it always had.

Files are named by their path relative to the project root, POSIX style; that
key is what the translator keys summaries on. `closure` computes which files a
change can affect.
"""

import json
import re
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

PY_EXTENSIONS = (".py",)
JS_EXTENSIONS = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")
JAVA_EXTENSIONS = (".java",)
CSHARP_EXTENSIONS = (".cs",)      # indexed with the Java family: both resolve types nominally
# Extensions tried, in order, when a JS import omits one.
_JS_TRY = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts")
# A TS import may name the emitted `.js` of a `.ts` source.
_JS_TO_TS = {".js": (".ts", ".tsx"), ".jsx": (".tsx",), ".mjs": (".mts",), ".cjs": (".cts",)}
_PY_SOURCE_DIRS = ("src", "lib", "python")
DEFAULT = "default"           # the export name of a module's default export
_MAX_REEXPORT_DEPTH = 6
# `Service(...).method` -- a method called on a freshly constructed object.
_INLINE_CONSTRUCTION = re.compile(r"^([A-Za-z_][\w.]*)\(.*\)\.(\w+)$", re.S)

ProcRef = Tuple[str, str]     # (file key, procedure name)


_FACTORY_MARK = "()"      # evidence text for `x = f()` in JS: the class `f` builds, if it is a factory


def language_family(path: Path) -> Optional[str]:
    """`python` or `javascript` (JS and TS share one module system), else None."""
    suffix = path.suffix.lower()
    if suffix in PY_EXTENSIONS:
        return "python"
    if suffix in JS_EXTENSIONS:
        return "javascript"
    if suffix in JAVA_EXTENSIONS or suffix in CSHARP_EXTENSIONS:
        return "java"
    return None


@dataclass(frozen=True)
class Binding:
    """What a local name stands for: a module (`symbol` None) or one name it
    exports. `alt` is a submodule to fall back on when `file` turns out not to
    export `symbol` (`from pkg import mod`)."""
    file: str
    symbol: Optional[str] = None
    alt: Optional[str] = None


@dataclass
class FileModule:
    key: str
    path: Path
    family: str
    bindings: Dict[str, Binding] = field(default_factory=dict)
    # JS: the specifier text of each import -> target file. The frontend names a
    # call on an imported module `<specifier>.<member>` (`./db.runQuery`).
    specs: Dict[str, str] = field(default_factory=dict)
    exports: Dict[str, str] = field(default_factory=dict)         # JS: export -> local name
    reexports: Dict[str, Tuple[str, str]] = field(default_factory=dict)  # export -> (file, name)
    star_reexports: List[str] = field(default_factory=list)       # files
    imports: Set[str] = field(default_factory=set)                # graph edges
    procs: Set[str] = field(default_factory=set)                  # callable procedures
    # Classes: class -> method -> procedure name (from the translated program),
    # and which procedures are static/class methods.
    classes: Dict[str, Dict[str, str]] = field(default_factory=dict)
    static_procs: Set[str] = field(default_factory=set)
    bases: Dict[str, List[str]] = field(default_factory=dict)     # class -> base class texts
    # What type a receiver has: (enclosing class or None, receiver text) -> the
    # class texts it is constructed from or annotated as.
    receiver_types: Dict[Tuple[Optional[str], str], Set[str]] = field(default_factory=dict)
    # JS constructor functions: (constructor, method, line of the function
    # assigned to `this.method`), tied to procedures by position.
    ctor_methods: List[Tuple[str, str, int]] = field(default_factory=list)
    factory_calls: Dict[str, str] = field(default_factory=dict)   # function -> class text its returns build
    star_imports: List[str] = field(default_factory=list)         # Python `from m import *` (target keys)
    defined: Set[str] = field(default_factory=set)                # Python top-level names
    all_names: Optional[List[str]] = None                         # Python `__all__`
    # Java: the package, single-type imports (simple name -> qualified name), on-demand
    # imports (packages), each declared type's kind, and every type name the file mentions.
    package: str = ""
    java_imports: Dict[str, str] = field(default_factory=dict)
    java_wildcards: List[str] = field(default_factory=list)
    java_kinds: Dict[str, str] = field(default_factory=dict)      # type -> class | interface | enum | record
    java_abstract: Set[str] = field(default_factory=set)
    java_mentions: Set[str] = field(default_factory=set)
    java_methods: Dict[str, Dict[str, List[str]]] = field(default_factory=dict)   # type -> method -> procedures
    cs_extensions: Dict[str, List[str]] = field(default_factory=dict)   # C# extension method name -> procedures
    # Python `run = functools.partial(shell, "echo")`: name -> (function text, positional args bound)
    partials: Dict[str, Tuple[str, int]] = field(default_factory=dict)


@dataclass
class Closure:
    files: List[str]            # nearest first
    truncated: bool = False
    seeds: List[str] = field(default_factory=list)


def _text(node: Any) -> str:
    return node.text.decode("utf-8", "replace") if node is not None else ""


class ProjectIndex:
    """Imports and exports of a set of files, and the call resolution built on them."""

    def __init__(self, root: Path, files: Iterable[Path],
                 parser_for: Callable[[str], Any]):
        self.root = Path(root).resolve()
        self.modules: Dict[str, FileModule] = {}
        self._by_path: Dict[Path, str] = {}
        for f in files:
            p = Path(f).resolve()
            family = language_family(p)
            if family is None or p in self._by_path:
                continue
            key = self._key(p)
            self._by_path[p] = key
            self.modules[key] = FileModule(key=key, path=p, family=family)
        self._importers: Dict[str, Set[str]] = {}
        self._py_suffixes: Dict[Tuple[str, ...], List[str]] = {}
        self._index_python_paths()
        for mod in self.modules.values():
            try:
                src = mod.path.read_bytes()
                tree = parser_for(self._parser_language(mod.path)).parse(src)
            except Exception:
                continue
            if mod.family == "python":
                self._read_python(mod, tree.root_node)
                self._read_python_types(mod, tree.root_node)
            elif mod.family == "java":
                (self._read_csharp if mod.path.suffix.lower() == ".cs" else self._read_java)(mod, tree.root_node)
            else:
                self._read_javascript(mod, tree.root_node)
                self._read_javascript_types(mod, tree.root_node)
        self._apply_star_imports()
        self._link_java()
        for mod in self.modules.values():
            mod.imports.discard(mod.key)
            for target in mod.imports:
                self._importers.setdefault(target, set()).add(mod.key)

    def _apply_star_imports(self) -> None:
        """Bind the public names a `from m import *` brings in. A name defined
        in the importing file wins; a name two star imports both bring is
        ambiguous and stays unbound (never guessed)."""
        for _ in range(3):                                  # star imports of star imports
            changed = False
            for mod in self.modules.values():
                if not mod.star_imports:
                    continue
                offered: Dict[str, Set[Tuple[str, Optional[str]]]] = {}
                for target in mod.star_imports:
                    t = self.modules.get(target)
                    if t is None:
                        continue
                    names = (set(t.all_names) if t.all_names is not None
                             else {n for n in t.defined | set(t.bindings) if not n.startswith("_")})
                    for n in names:
                        if n in t.defined:
                            offered.setdefault(n, set()).add((target, n))
                        elif n in t.bindings and t.bindings[n].symbol is not None:
                            b = t.bindings[n]
                            offered.setdefault(n, set()).add((b.file, b.symbol))
                for n, sources in offered.items():
                    if len(sources) != 1 or n in mod.defined or n in mod.bindings:
                        continue
                    file, symbol = next(iter(sources))
                    mod.bindings[n] = Binding(file, symbol)
                    changed = True
            if not changed:
                break

    # ---- Java ---------------------------------------------------------------

    _JAVA_TYPE_NODES = ("class_declaration", "interface_declaration", "enum_declaration",
                        "record_declaration", "annotation_type_declaration")

    def _read_java(self, mod: FileModule, root: Any) -> None:
        """Package, imports, declared types with their supertypes, and every type name used."""
        for st in root.children:
            if st.type == "package_declaration":
                mod.package = next((_text(c) for c in st.named_children
                                    if c.type in ("scoped_identifier", "identifier")), "")
            elif st.type == "import_declaration":
                text = _text(st).strip().removeprefix("import").strip().rstrip(";").strip()
                if text.startswith("static "):
                    continue                                   # static imports: members, not types
                if text.endswith(".*"):
                    mod.java_wildcards.append(text[:-2].strip())
                else:
                    mod.java_imports[text.rsplit(".", 1)[-1]] = text
        stack = list(root.children)
        while stack:
            n = stack.pop()
            if n.type in self._JAVA_TYPE_NODES:
                name = _text(n.child_by_field_name("name"))
                if name:
                    kind = n.type.split("_")[0]
                    mod.java_kinds[name] = kind
                    mod.classes.setdefault(name, {})
                    supers = []
                    for field_name in ("superclass", "interfaces", "extends_interfaces"):
                        sn = n.child_by_field_name(field_name)
                        if sn is None:
                            sn = next((c for c in n.children if c.type == field_name), None)
                        if sn is not None:
                            supers += [_text(t).split("<")[0].rsplit(".", 1)[-1]
                                       for t in self._java_types_in(sn)]
                    for c in n.children:                        # `interface A extends B, C`
                        if c.type == "extends_interfaces":
                            supers += [_text(t).split("<")[0].rsplit(".", 1)[-1] for t in self._java_types_in(c)]
                    mod.bases[name] = [x for x in dict.fromkeys(supers) if x]
                    if any(c.type == "modifiers" and "abstract" in _text(c) for c in n.children):
                        mod.java_abstract.add(name)
            elif n.type == "type_identifier":
                mod.java_mentions.add(_text(n))
            elif n.type == "scoped_type_identifier":
                mod.java_mentions.add(_text(n).rsplit(".", 1)[-1])
            stack.extend(n.children)

    _CSHARP_TYPE_NODES = ("class_declaration", "interface_declaration", "struct_declaration",
                          "record_declaration", "record_struct_declaration", "enum_declaration")
    _CS = "cs:"      # namespace prefix: keeps C# types apart from Java packages in the shared maps

    def _read_csharp(self, mod: FileModule, root: Any) -> None:
        """Namespace, `using`s, declared types with their base types, every identifier used.
        Mapped onto the Java fields: the namespace is the package, `using X;` an on-demand import,
        `using A = X.Y;` an explicit one; the enclosing namespaces are visible without a using."""
        ns = ""
        stack = [root]
        while stack:
            n = stack.pop()
            if n.type in ("namespace_declaration", "file_scoped_namespace_declaration") and not ns:
                nm = n.child_by_field_name("name")
                ns = _text(nm) if nm is not None else ""
            stack.extend(reversed(n.children))
        mod.package = self._CS + ns
        parts = ns.split(".") if ns else []
        mod.java_wildcards.extend(self._CS + ".".join(parts[:i]) for i in range(len(parts) - 1, -1, -1))
        stack = [root]
        while stack:
            n = stack.pop()
            if n.type == "using_directive":
                names = [c for c in n.named_children if c.type in ("identifier", "qualified_name")]
                if any(c.type == "static" or _text(c) == "static" for c in n.children):
                    continue
                if any(c.type == "=" for c in n.children) and len(names) >= 2:
                    mod.java_imports[_text(names[0])] = self._CS + _text(names[-1])
                elif names:
                    mod.java_wildcards.append(self._CS + _text(names[-1]))
            elif n.type in self._CSHARP_TYPE_NODES:
                name = _text(n.child_by_field_name("name"))
                if name:
                    mod.java_kinds[name] = n.type.split("_")[0]
                    mod.classes.setdefault(name, {})
                    supers = []
                    for c in n.children:
                        if c.type == "base_list":
                            supers += [_text(t).split("<")[0].rsplit(".", 1)[-1] for t in c.named_children
                                       if t.type in ("identifier", "qualified_name", "generic_name")]
                    mod.bases[name] = [x for x in dict.fromkeys(supers) if x]
                    if any(c.type == "modifier" and _text(c) == "abstract" for c in n.children):
                        mod.java_abstract.add(name)
            elif n.type == "identifier":
                mod.java_mentions.add(_text(n))
            stack.extend(n.children)

    @staticmethod
    def _java_types_in(node: Any) -> List[Any]:
        out, stack = [], [node]
        while stack:
            n = stack.pop()
            if n.type == "type_identifier" or n.type == "scoped_type_identifier":
                out.append(n)
                continue
            if n.type == "type_arguments":
                continue
            stack.extend(reversed(n.children))
        return out

    def _link_java(self) -> None:
        """Index Java types by qualified name and package; draw an edge from each file to the
        files of the project types it mentions; record the implementers of each type."""
        self.java_types: Dict[str, Tuple[str, str]] = {}
        self.java_by_package: Dict[str, Dict[str, Tuple[str, str]]] = {}
        # A C# type declared in several files is one `partial` class: (first file, name)
        # -> every part, so a method declared in any part is found.
        self.java_partials: Dict[Tuple[str, str], List[Tuple[str, str]]] = {}
        parts: Dict[Tuple[str, str], List[Tuple[str, str]]] = {}
        for mod in sorted(self.modules.values(), key=lambda m: m.key):
            if mod.family != "java":
                continue
            for name in mod.java_kinds:
                parts.setdefault((mod.package, name), []).append((mod.key, name))
        for (package, name), decls in parts.items():
            fqn = f"{package}.{name}" if package else name
            pkg = self.java_by_package.setdefault(package, {})
            if len(decls) > 1 and not (package or "").startswith(self._CS):
                self.java_types[fqn] = decls[-1]             # two Java files declare it:
                continue                                     # unresolvable by name
            self.java_types[fqn] = pkg[name] = decls[0]
            if len(decls) > 1:
                for d in decls:
                    self.java_partials[d] = decls
        self.java_implementers: Dict[Tuple[str, str], List[Tuple[str, str]]] = {}
        for mod in self.modules.values():
            if mod.family != "java":
                continue
            for cls, supers in mod.bases.items():
                for sup in supers:
                    target = self.resolve_java_type(mod.key, sup)
                    if target is not None:
                        self.java_implementers.setdefault(target, []).append((mod.key, cls))
            for name in mod.java_mentions:
                target = self.resolve_java_type(mod.key, name)
                if target is not None:
                    mod.imports.add(target[0])

    def resolve_java_type(self, key: str, name: str) -> Optional[Tuple[str, str]]:
        """(file, type) a type name written in file `key` means: its own file's, an explicit
        import, the same package, an on-demand import. A name imported from outside the
        project is not a project type."""
        mod = self.modules.get(key)
        if mod is None or mod.family != "java" or not name:
            return None
        if "." in name:
            hit = self.java_types.get(name) or self.java_types.get(self._CS + name)
            if hit is not None:
                return hit
            name = name.rsplit(".", 1)[-1]
        if name in mod.java_kinds:
            return key, name
        if name in mod.java_imports:
            return self.java_types.get(mod.java_imports[name])
        same = self.java_by_package.get(mod.package, {}).get(name)
        if same is not None:
            return same
        found = [self.java_by_package[p][name] for p in mod.java_wildcards
                 if name in self.java_by_package.get(p, {})]
        return found[0] if len(set(found)) == 1 else None

    def java_supertypes(self, cls: Tuple[str, str]) -> List[Tuple[str, str]]:
        mod = self.modules.get(cls[0])
        if mod is None:
            return []
        out = []
        for sup in mod.bases.get(cls[1], []):
            target = self.resolve_java_type(cls[0], sup)
            if target is not None:
                out.append(target)
        return out

    # ---- keys and paths -----------------------------------------------------

    def _key(self, path: Path) -> str:
        try:
            return path.relative_to(self.root).as_posix()
        except ValueError:
            return path.as_posix()

    @staticmethod
    def _parser_language(path: Path) -> str:
        suffix = path.suffix.lower()
        if suffix == ".py":
            return "python"
        if suffix == ".java":
            return "java"
        if suffix == ".cs":
            return "csharp"
        return "typescript" if suffix in (".ts", ".tsx", ".mts", ".cts") else "javascript"

    def key_for(self, path: Path) -> Optional[str]:
        return self._by_path.get(Path(path).resolve())

    # ---- Python -------------------------------------------------------------

    def _index_python_paths(self) -> None:
        for mod in self.modules.values():
            if mod.family != "python":
                continue
            parts = list(_module_parts(mod.path, self.root))
            if parts and parts[-1] == "__init__":
                parts.pop()
            for i in range(len(parts)):
                self._py_suffixes.setdefault(tuple(parts[i:]), []).append(mod.key)

    def _python_file(self, path: Path) -> Optional[str]:
        """The file for a module at `path` (`path.py` or `path/__init__.py`)."""
        for cand in (path.with_name(path.name + ".py"), path / "__init__.py"):
            key = self._by_path.get(cand)
            if key is not None:
                return key
        return None

    def _resolve_python(self, importer: FileModule, parts: Tuple[str, ...],
                        level: int) -> Optional[str]:
        if level:
            base = importer.path.parent
            for _ in range(level - 1):
                base = base.parent
            if not parts:
                return self._by_path.get(base / "__init__.py")
            return self._python_file(base.joinpath(*parts))
        if not parts:
            return None
        usable = []
        for key in self._py_suffixes.get(parts, []):
            if self._module_root_visible(self.modules[key], parts, importer):
                usable.append(key)
        if len(usable) > 1:
            def closeness(k: str) -> int:
                a, b = self.modules[k].path.parts, importer.path.parts
                n = 0
                for x, y in zip(a, b):
                    if x != y:
                        break
                    n += 1
                return n
            best = max(closeness(k) for k in usable)
            usable = [k for k in usable if closeness(k) == best]
        return usable[0] if len(usable) == 1 else None

    def _module_root_visible(self, target: FileModule, parts: Tuple[str, ...],
                             importer: FileModule) -> bool:
        """Python finds `a.b` under a directory on its path: the importer's own
        directory or an ancestor of it, or a conventional source directory."""
        names = list(_module_parts(target.path, self.root))
        if names and names[-1] == "__init__":
            names.pop()
        depth = len(names) - len(parts)
        rel = Path(*names[:depth]) if depth > 0 else Path()
        module_root = (self.root / rel).resolve()
        importer_dir = importer.path.parent
        if module_root == importer_dir or module_root in importer_dir.parents:
            return True
        return module_root.parent == self.root and module_root.name in _PY_SOURCE_DIRS

    @staticmethod
    def _python_partial(node: Any, partial_names: Set[str]) -> Optional[Tuple[str, int]]:
        """(function, positional arguments bound) for `functools.partial(f, a, b)`; None for
        anything else, or when a keyword argument makes the parameter mapping unclear."""
        if node is None or node.type != "call" or _text(node.child_by_field_name("function")) not in partial_names:
            return None
        args = [a for a in (node.child_by_field_name("arguments") or node).named_children]
        if not args or any(a.type in ("keyword_argument", "list_splat", "dictionary_splat") for a in args) \
                or args[0].type not in ("identifier", "attribute"):
            return None
        return _text(args[0]), len(args) - 1

    def _read_python(self, mod: FileModule, root: Any) -> None:
        partial_names = {"functools.partial"} | (
            {"partial"} if any(st.type == "import_from_statement" and _text(st.child_by_field_name("module_name")) == "functools"
                               and "partial" in {_text(n) for n in st.children_by_field_name("name")}
                               for st in root.children) else set())
        for st in root.children:                      # what `from m import *` would bring in
            inner = st.named_children[-1] if st.type == "decorated_definition" and st.named_children else st
            if inner.type in ("function_definition", "class_definition"):
                mod.defined.add(_text(inner.child_by_field_name("name")))
            elif inner.type == "expression_statement" and inner.named_children:
                a = inner.named_children[0]
                if a.type == "assignment" and a.child_by_field_name("left") is not None:
                    left = _text(a.child_by_field_name("left"))
                    right = a.child_by_field_name("right")
                    if left == "__all__" and right is not None and right.type in ("list", "tuple"):
                        mod.all_names = [_text(x).strip("'\"") for x in right.named_children
                                         if x.type == "string"]
                    elif left.isidentifier():
                        mod.defined.add(left)
                        bound = self._python_partial(right, partial_names)
                        if bound is not None:
                            mod.partials[left] = bound
        stack = [root]
        while stack:
            node = stack.pop()
            if node.type == "import_statement":
                for child in node.children_by_field_name("name"):
                    if child.type == "aliased_import":
                        dotted = _text(child.child_by_field_name("name"))
                        alias = _text(child.child_by_field_name("alias"))
                    else:
                        dotted, alias = _text(child), ""
                    target = self._resolve_python(mod, tuple(dotted.split(".")), 0)
                    if target is None:
                        continue
                    mod.imports.add(target)
                    if alias:
                        mod.bindings[alias] = Binding(target)
                    else:
                        mod.bindings[dotted] = Binding(target)
                        top = dotted.split(".")[0]
                        head = self._resolve_python(mod, (top,), 0)
                        if head is not None and top not in mod.bindings:
                            mod.bindings[top] = Binding(head)
                continue
            if node.type == "import_from_statement":
                self._read_python_from(mod, node)
                continue
            stack.extend(node.children)

    def _read_python_from(self, mod: FileModule, node: Any) -> None:
        module_node = node.child_by_field_name("module_name")
        level, parts = 0, ()
        if module_node is not None and module_node.type == "relative_import":
            for c in module_node.children:
                if c.type == "import_prefix":
                    level = _text(c).count(".")
                elif c.type == "dotted_name":
                    parts = tuple(_text(c).split("."))
        elif module_node is not None:
            parts = tuple(_text(module_node).split("."))
        source = self._resolve_python(mod, parts, level)
        if source is not None:
            mod.imports.add(source)
        if source is not None and any(c.type == "wildcard_import" for c in node.children):
            mod.star_imports.append(source)
        for child in node.children_by_field_name("name"):
            if child.type == "aliased_import":
                name = _text(child.child_by_field_name("name"))
                alias = _text(child.child_by_field_name("alias"))
            else:
                name, alias = _text(child), ""
            if "." in name:
                continue
            sub = self._resolve_python(mod, parts + (name,), level)
            if sub is not None:
                mod.imports.add(sub)
            local = alias or name
            if source is not None:
                mod.bindings[local] = Binding(source, name, sub)
            elif sub is not None:
                mod.bindings[local] = Binding(sub)

    def _evidence(self, mod: FileModule, owner: Optional[str], receiver: str, cls_text: str) -> None:
        if receiver and cls_text:
            mod.receiver_types.setdefault((owner, receiver), set()).add(cls_text)

    @staticmethod
    def _dotted(node: Any) -> str:
        """`a.b.C` for an identifier / attribute / member chain, else ''."""
        if node is None:
            return ""
        if node.type == "identifier":
            return _text(node)
        if node.type in ("attribute", "member_expression"):
            obj = node.child_by_field_name("object")
            attr = node.child_by_field_name("attribute") or node.child_by_field_name("property")
            head = ProjectIndex._dotted(obj)
            return f"{head}.{_text(attr)}" if head and attr is not None else ""
        if node.type == "this":
            return "this"
        return ""

    def _read_python_types(self, mod: FileModule, root: Any) -> None:
        """Bases of each class, and the class each receiver is built from or
        annotated as: `x = C(...)`, `self.x = C(...)`, `x: C`, `def f(x: C)`."""
        stack: List[Tuple[Any, Optional[str]]] = [(root, None)]
        aliases: List[Tuple[Optional[str], str, str]] = []      # `self.repo = repo`
        while stack:
            node, owner = stack.pop()
            t = node.type
            if t == "class_definition":
                name = _text(node.child_by_field_name("name"))
                sup = node.child_by_field_name("superclasses")
                if name and sup is not None:
                    mod.bases[name] = [d for d in (self._dotted(c) for c in sup.named_children) if d]
                owner = name or owner
            elif t == "assignment":
                left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
                receiver = self._dotted(left)
                ann = node.child_by_field_name("type")
                if receiver:
                    if ann is not None:
                        self._evidence(mod, owner, receiver, self._py_type(ann))
                    value = right.children[-1] if right is not None and right.type == "await" \
                        and right.children else right
                    if value is not None and value.type == "identifier" and "." in receiver:
                        aliases.append((owner, receiver, _text(value)))
                    if value is not None and value.type == "call":
                        self._evidence(mod, owner, receiver, self._dotted(value.child_by_field_name("function")))
                        # a class-level `x = C()` is also `self.x` / `cls.x`
                        if owner is not None and "." not in receiver:
                            for prefix in ("self", "cls"):
                                self._evidence(mod, owner, f"{prefix}.{receiver}",
                                               self._dotted(value.child_by_field_name("function")))
                            # In the class body itself (`objects = PostManager()`), it is
                            # also `Post.objects` to any code that names the class.
                            body = node.parent.parent if node.parent is not None else None
                            if body is not None and body.type == "block" and body.parent is not None \
                                    and body.parent.type == "class_definition":
                                self._evidence(mod, None, f"{owner}.{receiver}",
                                               self._dotted(value.child_by_field_name("function")))
            elif t in ("typed_parameter", "typed_default_parameter"):
                nm = node.child_by_field_name("name") or (node.children[0] if node.children else None)
                ann = node.child_by_field_name("type")
                if nm is not None and nm.type == "identifier" and ann is not None:
                    self._evidence(mod, owner, _text(nm), self._py_type(ann))
            for c in node.children:
                stack.append((c, owner))
        for owner, receiver, name in aliases:       # a field built from an annotated parameter
            for text in mod.receiver_types.get((owner, name), ()):
                self._evidence(mod, owner, receiver, text)

    @staticmethod
    def _py_type(ann: Any) -> str:
        """The class an annotation names: `C`, `m.C`, `"C"`, `Optional[C]`."""
        text = _text(ann).strip().strip("'\"")
        if text.startswith(("Optional[", "typing.Optional[")) and text.endswith("]"):
            text = text[text.index("[") + 1:-1].strip()
        return text if text.replace(".", "").replace("_", "").isalnum() else ""

    # ---- JavaScript / TypeScript --------------------------------------------

    def _resolve_js(self, importer: FileModule, spec: str) -> Optional[str]:
        if spec.startswith((".", "/")):
            base = Path(_normalise((importer.path.parent / spec) if not spec.startswith("/")
                                   else Path(spec)))
            return self._resolve_js_base(base)
        for base in self._alias_candidates(importer.path.parent, spec):
            key = self._resolve_js_base(base)
            if key is not None:
                return key
        return None

    def _resolve_js_base(self, base: Path) -> Optional[str]:
        cands: List[Path] = []
        if base.suffix:
            cands.append(base)
            for alt in _JS_TO_TS.get(base.suffix.lower(), ()):
                cands.append(base.with_suffix(alt))
        for ext in _JS_TRY:
            cands.append(base.with_name(base.name + ext))
        for ext in _JS_TRY:
            cands.append(base / ("index" + ext))
        for cand in cands:
            key = self._by_path.get(cand)
            if key is not None:
                return key
        return None

    # tsconfig.json / jsconfig.json `paths` and `baseUrl`, nearest file wins
    def _alias_config(self, directory: Path) -> Optional[Tuple[Path, List[Tuple[str, List[str]]]]]:
        cache = self.__dict__.setdefault("_alias_cache", {})
        if directory in cache:
            return cache[directory]
        result = None
        for name in ("tsconfig.json", "jsconfig.json"):
            cfg = directory / name
            if cfg.is_file():
                result = self._read_alias_config(cfg)
                if result is not None:
                    break
        if result is None and directory.parent != directory and directory != self.root:
            result = self._alias_config(directory.parent)
        cache[directory] = result
        return result

    def _read_alias_config(self, cfg: Path, depth: int = 0) -> Optional[Tuple[Path, List[Tuple[str, List[str]]]]]:
        try:
            text = cfg.read_text(encoding="utf-8")
        except OSError:
            return None
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
        text = re.sub(r'(?m)^\s*//.*$|(?<=[,{\[\s])//[^"\n]*$', "", text)
        text = re.sub(r",(\s*[}\]])", r"\1", text)
        try:
            data = json.loads(text)
        except ValueError:
            return None
        opts = data.get("compilerOptions") or {}
        base_dir = (cfg.parent / opts["baseUrl"]).resolve() if opts.get("baseUrl") else None
        paths = opts.get("paths")
        ext = data.get("extends")
        if (paths is None and base_dir is None) and isinstance(ext, str) and depth < 3 \
                and ext.startswith("."):
            parent = cfg.parent / (ext if ext.endswith(".json") else ext + ".json")
            return self._read_alias_config(parent.resolve(), depth + 1)
        anchor = base_dir or cfg.parent.resolve()
        entries = [(pat, [t for t in targets if isinstance(t, str)])
                   for pat, targets in (paths or {}).items() if isinstance(targets, list)]
        if base_dir is not None:
            entries.append(("*", ["*"]))                # bare specifiers resolve under baseUrl
        return anchor, entries

    def _alias_candidates(self, directory: Path, spec: str) -> List[Path]:
        cfg = self._alias_config(directory)
        if cfg is None:
            return []
        anchor, entries = cfg
        out: List[Path] = []
        for pattern, targets in sorted(entries, key=lambda e: -len(e[0])):
            if "*" in pattern:
                head, _, tail = pattern.partition("*")
                if not (spec.startswith(head) and spec.endswith(tail) and len(spec) >= len(head) + len(tail)):
                    continue
                middle = spec[len(head): len(spec) - len(tail)]
            elif spec == pattern:
                middle = ""
            else:
                continue
            for target in targets:
                out.append(Path(_normalise(anchor / target.replace("*", middle))))
        return out

    def _read_javascript(self, mod: FileModule, root: Any) -> None:
        for st in root.children:
            if st.type == "import_statement":
                self._js_import(mod, st)
            elif st.type == "export_statement":
                self._js_export(mod, st)
            elif st.type == "expression_statement":
                self._js_assignment_export(mod, st)
            self._js_requires(mod, st)

    def _spec_of(self, node: Any) -> str:
        for c in node.children:
            if c.type == "string":
                return "".join(_text(f) for f in c.children if f.type == "string_fragment")
        return ""

    def _js_import(self, mod: FileModule, st: Any) -> None:
        spec = self._spec_of(st)
        target = self._resolve_js(mod, spec) if spec else None
        if target is None:
            return
        mod.imports.add(target)
        mod.specs[spec] = target
        for clause in st.children:
            if clause.type != "import_clause":
                continue
            for c in clause.children:
                if c.type == "identifier":
                    mod.bindings[_text(c)] = Binding(target, DEFAULT)
                elif c.type == "namespace_import":
                    for i in c.children:
                        if i.type == "identifier":
                            mod.bindings[_text(i)] = Binding(target)
                elif c.type == "named_imports":
                    for sp in c.children:
                        if sp.type != "import_specifier":
                            continue
                        names = [_text(x) for x in sp.children if x.type == "identifier"]
                        if names:
                            mod.bindings[names[-1]] = Binding(target, names[0])

    def _js_requires(self, mod: FileModule, node: Any) -> None:
        """`const m = require('./x')` and `const {a, b: c} = require('./x')`
        anywhere in the statement (module scope or not: bindings are per file)."""
        stack = [node]
        while stack:
            n = stack.pop()
            if n.type == "variable_declarator":
                name_node, value = n.child_by_field_name("name"), n.child_by_field_name("value")
                member = None
                if value is not None and value.type == "member_expression":
                    # `const Dao = require('./dao').Dao`
                    member = _text(value.child_by_field_name("property"))
                    value = value.child_by_field_name("object")
                if value is not None and value.type == "call_expression":
                    fn, args = value.child_by_field_name("function"), value.child_by_field_name("arguments")
                    if fn is not None and _text(fn) == "require" and args is not None \
                            and args.named_children and args.named_children[0].type == "string":
                        spec = self._spec_of(args)
                        target = self._resolve_js(mod, spec)
                        if target is not None:
                            mod.imports.add(target)
                            mod.specs[spec] = target
                            if member and name_node is not None and name_node.type == "identifier":
                                mod.bindings[_text(name_node)] = Binding(target, member)
                            elif not member:
                                self._js_bind_require(mod, name_node, target)
            stack.extend(n.children)

    def _js_ctor_name(self, node: Any) -> str:
        """The class text of `new C(...)` (also `new m.C(...)`)."""
        if node is not None and node.type == "await_expression" and node.named_children:
            node = node.named_children[-1]
        if node is not None and node.type == "new_expression":
            return self._dotted(node.child_by_field_name("constructor"))
        if node is not None and node.type == "call_expression":      # `createRepo()`: a factory, if it is one
            fn = self._dotted(node.child_by_field_name("function"))
            return _FACTORY_MARK + fn if fn and fn != "require" else ""
        return ""

    @staticmethod
    def _ts_type(ann: Any) -> str:
        """The class a TS type annotation names (`C`, `m.C`, `Repo<User>`)."""
        if ann is None:
            return ""
        for c in ann.named_children:
            if c.type == "type_identifier":
                return _text(c)
            if c.type == "nested_type_identifier":
                return _text(c)
            if c.type == "generic_type":
                nm = c.child_by_field_name("name")
                return _text(nm) if nm is not None else ""
            return ""
        return ""

    def _read_javascript_types(self, mod: FileModule, root: Any) -> None:
        """Bases of each class, the class each receiver is built from or typed
        as, and the methods a constructor function attaches with `this.m = fn`."""
        stack: List[Tuple[Any, Optional[str], Optional[str]]] = [(root, None, None)]
        fn_types = ("function_expression", "function", "arrow_function", "generator_function")
        while stack:
            node, owner, ctor = stack.pop()
            t = node.type
            if t in ("class_declaration", "class"):
                name = _text(node.child_by_field_name("name"))
                for h in node.children:
                    if h.type == "class_heritage":
                        exprs = [self._dotted(x) for x in h.named_children if self._dotted(x)]
                        for x in h.named_children:
                            if x.type == "extends_clause":
                                exprs += [self._dotted(v) for v in x.named_children if self._dotted(v)]
                        if name and exprs:
                            mod.bases[name] = exprs[:1]
                owner = name or owner
            elif t in ("function_declaration", "generator_function_declaration"):
                ctor = _text(node.child_by_field_name("name")) or ctor
            elif t == "variable_declarator":
                nm, val = node.child_by_field_name("name"), node.child_by_field_name("value")
                if nm is not None and nm.type == "identifier":
                    receiver = _text(nm)
                    if val is not None and val.type in fn_types:
                        ctor = receiver
                    self._evidence(mod, owner, receiver, self._js_ctor_name(val))
                    self._evidence(mod, owner, receiver, self._ts_type(node.child_by_field_name("type")))
                    if val is not None and val.type == "object":   # `{ reporter: new Reporter() }`
                        for p in val.named_children:
                            key = p.child_by_field_name("key") if p.type == "pair" else None
                            if key is not None and key.type in ("property_identifier", "string"):
                                self._evidence(mod, owner, f"{receiver}.{_text(key).strip(chr(39) + chr(34))}",
                                               self._js_ctor_name(p.child_by_field_name("value")))
            elif t == "assignment_expression":
                left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
                receiver = self._dotted(left)
                if receiver:
                    self._evidence(mod, owner, receiver, self._js_ctor_name(right))
                    if receiver.startswith("this.") and receiver.count(".") == 1 and ctor \
                            and right is not None and right.type in fn_types:
                        mod.ctor_methods.append((ctor, receiver.split(".")[1], right.start_point[0] + 1))
                    elif ".prototype." in receiver and right is not None and right.type in fn_types:
                        pass          # named `X.prototype.m` by the frontend; found by name
            elif t in ("public_field_definition", "field_definition"):
                nm = node.child_by_field_name("name") or node.child_by_field_name("property")
                if nm is not None:
                    receiver = f"this.{_text(nm)}"
                    self._evidence(mod, owner, receiver, self._ts_type(node.child_by_field_name("type")))
                    self._evidence(mod, owner, receiver, self._js_ctor_name(node.child_by_field_name("value")))
            elif t in ("required_parameter", "optional_parameter"):
                pat = node.child_by_field_name("pattern")
                if pat is not None and pat.type == "identifier":
                    typed = self._ts_type(node.child_by_field_name("type"))
                    self._evidence(mod, owner, _text(pat), typed)
                    if any(c.type == "accessibility_modifier" or c.type == "readonly" for c in node.children):
                        self._evidence(mod, owner, f"this.{_text(pat)}", typed)   # constructor parameter property
            for c in node.children:
                stack.append((c, owner, ctor))

    def _js_bind_require(self, mod: FileModule, pattern: Any, target: str) -> None:
        if pattern is None:
            return
        if pattern.type == "identifier":
            mod.bindings[_text(pattern)] = Binding(target)
        elif pattern.type == "object_pattern":
            for p in pattern.children:
                if p.type == "shorthand_property_identifier_pattern":
                    mod.bindings[_text(p)] = Binding(target, _text(p))
                elif p.type == "pair_pattern":
                    key, val = p.child_by_field_name("key"), p.child_by_field_name("value")
                    if key is not None and val is not None and val.type == "identifier":
                        mod.bindings[_text(val)] = Binding(target, _text(key))

    def _js_export(self, mod: FileModule, st: Any) -> None:
        is_default = any(c.type == "default" for c in st.children)
        spec = self._spec_of(st)
        source = self._resolve_js(mod, spec) if spec else None
        if source is not None:
            mod.imports.add(source)
        for c in st.children:
            if c.type in ("function_declaration", "generator_function_declaration",
                          "class_declaration"):
                name = _text(c.child_by_field_name("name"))
                if name:
                    mod.exports[DEFAULT if is_default else name] = name
            elif c.type == "lexical_declaration" or c.type == "variable_declaration":
                for d in c.children:
                    if d.type == "variable_declarator":
                        nm = d.child_by_field_name("name")
                        if nm is not None and nm.type == "identifier":
                            mod.exports[_text(nm)] = _text(nm)
            elif c.type == "export_clause":
                for sp in c.children:
                    if sp.type != "export_specifier":
                        continue
                    names = [_text(x) for x in sp.children if x.type == "identifier"]
                    if not names:
                        continue
                    exported = names[-1]
                    if source is not None:
                        mod.reexports[exported] = (source, names[0])
                    else:
                        mod.exports[exported] = names[0]
            elif c.type == "*" and source is not None:
                mod.star_reexports.append(source)
            elif c.type == "identifier" and is_default:
                mod.exports[DEFAULT] = _text(c)

    def _required_module(self, mod: FileModule, node: Any) -> Optional[str]:
        """The project file `require("<relative spec>")` loads, if `node` is that call."""
        if node is None or node.type != "call_expression":
            return None
        fn, args = node.child_by_field_name("function"), node.child_by_field_name("arguments")
        if fn is None or _text(fn) != "require" or args is None or len(args.named_children) != 1 \
                or args.named_children[0].type != "string":
            return None
        return self._resolve_js(mod, _text(args.named_children[0])[1:-1])

    def _js_assignment_export(self, mod: FileModule, st: Any) -> None:
        for assign in st.children:
            if assign.type != "assignment_expression":
                continue
            left, right = assign.child_by_field_name("left"), assign.child_by_field_name("right")
            if left is None or right is None:
                continue
            target = _text(left)
            if target == "module.exports":
                required = self._required_module(mod, right)
                if required is not None:              # `module.exports = require("./query")`
                    mod.star_reexports.append(required)
                    mod.imports.add(required)
                if right.type == "object":
                    for p in right.children:
                        spread = self._required_module(mod, p.named_children[0]) \
                            if p.type == "spread_element" and p.named_children else None
                        if spread is not None:        # `{ ...require("./query") }`
                            mod.star_reexports.append(spread)
                            mod.imports.add(spread)
                        elif p.type == "shorthand_property_identifier":
                            mod.exports[_text(p)] = _text(p)
                        elif p.type == "pair":
                            key, val = p.child_by_field_name("key"), p.child_by_field_name("value")
                            if key is not None:
                                k = _text(key).strip("'\"")
                                mod.exports[k] = _text(val) if val is not None \
                                    and val.type == "identifier" else k
                        elif p.type == "method_definition":
                            nm = _text(p.child_by_field_name("name"))
                            mod.exports[nm] = nm
                elif right.type == "identifier":
                    mod.exports[DEFAULT] = _text(right)
                elif right.type in ("function_expression", "function", "arrow_function",
                                    "generator_function"):
                    # A callable module. The frontend names its procedure by the
                    # function's own name, else `module.exports`.
                    name = _text(right.child_by_field_name("name"))
                    mod.exports[DEFAULT] = name or "module.exports"
            elif target.startswith(("module.exports.", "exports.")):
                name = target.rsplit(".", 1)[-1]
                mod.exports[name] = _text(right) if right.type == "identifier" else target

    # ---- procedures ---------------------------------------------------------

    def set_procedures(self, key: str, procedures: Dict[str, Any]) -> None:
        """Record which of the file's translated procedures can be called from
        another file: Python's module-level functions; for JS/TS, any procedure
        (`lookup` then goes through the export table)."""
        mod = self.modules.get(key)
        if mod is None:
            return
        if mod.family == "java":
            mod.procs = set(procedures)
            mod.java_methods = {}
            for name, p in procedures.items():
                cls, simple = getattr(p, "class_name", None), getattr(p, "simple_name", name)
                if cls and (simple == "<init>" or not simple.startswith("<")):
                    mod.java_methods.setdefault(cls.rsplit(".", 1)[-1], {}).setdefault(simple, []).append(name)
                if getattr(p, "is_extension", False):
                    mod.cs_extensions.setdefault(simple, []).append(name)
            return
        if mod.family == "python":
            mod.procs = {name for name, p in procedures.items()
                         if "." not in name and "#" not in name and not name.startswith("<")
                         and not getattr(p, "is_method", False)}
        else:
            mod.procs = {name for name in procedures if not name.startswith("<")}
        mod.classes, mod.static_procs = {c: {} for c in mod.bases}, set()   # a subclass may declare no method
        for name, p in procedures.items():
            cls = getattr(p, "class_name", None)
            if cls and getattr(p, "is_method", False) and "#" not in name:
                mod.classes.setdefault(cls, {})[p.simple_name] = name
                if getattr(p, "is_static", False):
                    mod.static_procs.add(name)
            elif ".prototype." in name and "#" not in name:
                owner, _, method = name.partition(".prototype.")
                mod.classes.setdefault(owner, {})[method] = name
        mod.factory_calls = {}
        for name, p in procedures.items():
            built = self._returned_class_text(p)
            if built:
                mod.factory_calls[name] = built
        for ctor, method, line in mod.ctor_methods:     # `this.m = fn` inside a constructor function
            for name, p in procedures.items():
                if name.startswith(f"this.{method}") and getattr(getattr(p, "loc", None), "line", None) == line:
                    mod.classes.setdefault(ctor, {})[method] = name
                    break

    @staticmethod
    def _returned_class_text(proc: Any) -> str:
        """The one callee text every non-null `return` of `proc` builds
        (`return Repo()`, `r = Repo(); return r`, `return new Repo()`), or ''.
        Whether that callee is a class is decided by the caller."""
        from frame.sil.instructions import Assign, Call, Return
        from frame.sil.types import ExpCall, ExpConst, ExpVar
        defs: Dict[str, str] = {}
        built: Set[str] = set()

        def callee(e: Any) -> str:
            name = str(getattr(e, "func", "")).strip('"')
            return name[4:] if name.startswith("new ") else name

        for i in proc.get_all_instrs():
            if isinstance(i, Call) and i.ret:
                defs[str(i.ret[0])] = i.get_full_name().removeprefix("new ")
            elif isinstance(i, Assign):
                if isinstance(i.exp, ExpCall):
                    defs[str(i.id)] = callee(i.exp)
                elif isinstance(i.exp, ExpVar) and str(i.exp.var) in defs:
                    defs[str(i.id)] = defs[str(i.exp.var)]
            elif isinstance(i, Return):
                v = i.value
                if v is None or (isinstance(v, ExpConst) and str(v).strip() in ("null", "None", "undefined")):
                    continue
                if isinstance(v, ExpCall):
                    built.add(callee(v))
                elif isinstance(v, ExpVar) and str(v.var) in defs:
                    built.add(defs[str(v.var)])
                else:
                    return ""
        return next(iter(built)) if len(built) == 1 else ""

    # ---- resolution ---------------------------------------------------------

    def lookup_symbol(self, key: str, name: str, depth: int = 0) -> Optional[ProcRef]:
        """The procedure a module exports under `name`, following re-exports."""
        mod = self.modules.get(key)
        if mod is None or depth > _MAX_REEXPORT_DEPTH:
            return None
        if mod.family == "python":
            if name in mod.procs:
                return key, name
            b = mod.bindings.get(name)
            if b is not None and b.symbol is not None:
                return self.lookup_symbol(b.file, b.symbol, depth + 1)
            return None
        local = mod.exports.get(name)
        if local is not None and local in mod.procs:
            return key, local
        if name in mod.reexports:
            target, original = mod.reexports[name]
            return self.lookup_symbol(target, original, depth + 1)
        if name != DEFAULT:
            for star in mod.star_reexports:
                found = self.lookup_symbol(star, name, depth + 1)
                if found is not None:
                    return found
        return None

    def resolve_call(self, key: str, name: str,
                     caller_class: Optional[str] = None) -> Optional[ProcRef]:
        """The procedure in another file that the call `name` (as lowered by the
        frontend) makes from file `key`, or None. `caller_class` is the class
        the calling procedure belongs to (for `self.x.m(...)` receivers)."""
        mod = self.modules.get(key)
        if mod is None or mod.family == "java":          # Java calls go through resolve_java_call
            return None
        if mod.family == "javascript":
            for spec in sorted(mod.specs, key=len, reverse=True):
                if name.startswith(spec + ".") and "." not in name[len(spec) + 1:]:
                    member = name[len(spec) + 1:]
                    found = self.lookup_symbol(mod.specs[spec], member)
                    if found is None:                 # `import C from './c'; C.m()`: the default class
                        cls = self.lookup_class(mod.specs[spec], DEFAULT)
                        found = self._find_method(cls, member) if cls else None
                    if found is None:                 # `module.exports = new Mailer()`: its instance
                        target = self.modules.get(mod.specs[spec])
                        texts = target.receiver_types.get((None, "module.exports")) if target else None
                        classes = {self.resolve_class(target.key, t) for t in texts or ()}
                        if len(classes) == 1 and None not in classes:
                            found = self._find_method(next(iter(classes)), member)
                    if found is not None:
                        return found
        b = mod.bindings.get(name)
        if b is not None:
            return self._follow(b)
        if "." not in name and "(" not in name:
            return None
        if "(" not in name:
            head, _, member = name.rpartition(".")
            hb = mod.bindings.get(head)
            module = self._module_of(hb) if hb is not None else None
            if module is not None:
                found = self.lookup_symbol(module, member)
                if found is not None:
                    return found
        return self._resolve_method_call(mod, name, caller_class)

    # ---- classes and methods ---------------------------------------------------

    def lookup_class(self, key: str, name: str, depth: int = 0) -> Optional[Tuple[str, str]]:
        """(file, class) for the class a module exports as `name`."""
        mod = self.modules.get(key)
        if mod is None or depth > _MAX_REEXPORT_DEPTH:
            return None
        if mod.family == "python":
            if name in mod.classes:
                return key, name
            b = mod.bindings.get(name)
            if b is not None and b.symbol is not None:
                return self.lookup_class(b.file, b.symbol, depth + 1)
            return None
        local = mod.exports.get(name, name if name in mod.classes else None)
        if local is not None and local in mod.classes:
            return key, local
        if name in mod.reexports:
            target, original = mod.reexports[name]
            return self.lookup_class(target, original, depth + 1)
        for star in mod.star_reexports:
            found = self.lookup_class(star, name, depth + 1)
            if found is not None:
                return found
        return None

    def resolve_class(self, key: str, text: str, depth: int = 0) -> Optional[Tuple[str, str]]:
        """(file, class) a class reference written as `text` in file `key` means:
        a class of this file, an imported class, or `module.Class` -- or, for a
        function, the one class its returns build (a factory)."""
        mark = text.startswith(_FACTORY_MARK)
        text = text[len(_FACTORY_MARK):] if mark else text
        found = None if mark else self._resolve_class_text(key, text, depth)
        if found is None and depth <= _MAX_REEXPORT_DEPTH and text:
            # Resolving a factory call can ask for the class of another receiver, which can
            # ask for this one (`a = b.make(); b = a.make()`): a cycle resolves to nothing.
            guard = self.__dict__.setdefault("_class_guard", set())
            if (key, text) in guard:
                return None
            guard.add((key, text))
            try:
                here = self.modules.get(key)
                ref = ((key, text) if here is not None and text in here.factory_calls
                       else self.resolve_call(key, text))
                if ref is not None:
                    built = self.modules[ref[0]].factory_calls.get(ref[1])
                    if built:
                        found = self.resolve_class(ref[0], built, depth + 1)
            finally:
                guard.discard((key, text))
        return found

    def _resolve_class_text(self, key: str, text: str, depth: int = 0) -> Optional[Tuple[str, str]]:
        mod = self.modules.get(key)
        if mod is None or not text or depth > _MAX_REEXPORT_DEPTH:
            return None
        if "." not in text:
            if text in mod.classes:
                return key, text
            b = mod.bindings.get(text)
            if b is not None and b.symbol is not None:
                return self.lookup_class(b.file, b.symbol, depth + 1)
            if b is not None and mod.family == "javascript":      # `const C = require('./c')`
                return self.lookup_class(b.file, DEFAULT, depth + 1)
            return None
        if mod.family == "javascript":
            for spec in sorted(mod.specs, key=len, reverse=True):
                if text.startswith(spec + ".") and "." not in text[len(spec) + 1:]:
                    return self.lookup_class(mod.specs[spec], text[len(spec) + 1:], depth + 1)
        head, _, name = text.rpartition(".")
        hb = mod.bindings.get(head)
        module = self._module_of(hb) if hb is not None else None
        return self.lookup_class(module, name, depth + 1) if module is not None else None

    def _find_method(self, cls: Tuple[str, str], method: str, depth: int = 0) -> Optional[ProcRef]:
        """The procedure for `method` on class `cls`, or on its in-project bases."""
        file, name = cls
        mod = self.modules.get(file)
        if mod is None or depth > _MAX_REEXPORT_DEPTH:
            return None
        proc = mod.classes.get(name, {}).get(method)
        if proc is not None:
            return file, proc
        for base in mod.bases.get(name, []):
            base_cls = self.resolve_class(file, base)
            if base_cls is not None:
                found = self._find_method(base_cls, method, depth + 1)
                if found is not None:
                    return found
        return None

    def _receiver_class(self, mod: FileModule, receiver: str,
                        caller_class: Optional[str]) -> Optional[Tuple[str, str]]:
        """The one class a receiver is known to have, or None if its evidence is
        missing, ambiguous, or names anything that is not a project class."""
        texts = mod.receiver_types.get((caller_class, receiver)) if caller_class is not None else None
        if not texts:
            texts = mod.receiver_types.get((None, receiver))
        if not texts:
            return None
        classes = {self.resolve_class(mod.key, t) for t in texts}
        return next(iter(classes)) if len(classes) == 1 and None not in classes else None

    def _resolve_method_call(self, mod: FileModule, name: str,
                             caller_class: Optional[str]) -> Optional[ProcRef]:
        receiver, _, method = name.rpartition(".")
        if receiver in ("super()", "super") and method and caller_class is not None:
            # `super().m(...)`: the nearest base class that defines m (never the caller's own)
            for base in mod.bases.get(caller_class, []):
                base_cls = self.resolve_class(mod.key, base)
                found = self._find_method(base_cls, method) if base_cls else None
                if found is not None:
                    return found
            return None
        inline = _INLINE_CONSTRUCTION.match(name)        # Python `C(...).m`
        if inline:
            cls = self.resolve_class(mod.key, inline.group(1))
            return self._find_method(cls, inline.group(2)) if cls else None
        if "(" in name:
            return None
        receiver, _, method = name.rpartition(".")
        if not receiver or not method:
            return None
        if receiver in ("self", "this", "cls") and caller_class is not None:
            # a method the class inherits from a base defined in another file
            return self._find_method((mod.key, caller_class), method)
        cls = self.resolve_class(mod.key, receiver)
        if cls is not None:                               # `Class.method(...)`: static/class methods only
            found = self._find_method(cls, method)
            if found is not None and found[1] in self.modules[found[0]].static_procs:
                return found
            return None
        cls = self._receiver_class(mod, receiver, caller_class) \
            or self._imported_instance_class(mod, receiver)
        return self._find_method(cls, method) if cls else None

    def _imported_instance_class(self, mod: FileModule, receiver: str) -> Optional[Tuple[str, str]]:
        """The class of an instance another module builds at its top level and this
        one imports: Python `repo = Repo()` then `from shop.repo import repo`; JS
        `module.exports = new Mailer()` then `const mailer = require("./mailer")`."""
        head, _, rest = receiver.partition(".")       # `container.reporter`: a property of it
        b = mod.bindings.get(head)
        target = self.modules.get(b.file) if b is not None else None
        if target is None:
            return None
        name = b.symbol if b.symbol is not None else (
            "module.exports" if target.family == "javascript" else None)
        if name and rest:
            name = f"{name}.{rest}"
        texts = target.receiver_types.get((None, name)) if name else None
        if not texts:
            return None
        classes = {self.resolve_class(target.key, t) for t in texts}
        return next(iter(classes)) if len(classes) == 1 and None not in classes else None

    def _module_of(self, b: Binding) -> Optional[str]:
        """The file a binding stands for when used as `name.member`: the module
        itself, or -- for `from pkg import mod` -- the submodule when `pkg`
        exports no function called `mod`."""
        if b.symbol is None:
            return b.file
        if b.alt is not None and self.lookup_symbol(b.file, b.symbol) is None:
            return b.alt
        return None

    def _follow(self, b: Binding) -> Optional[ProcRef]:
        if b.symbol is None:
            # A module is not callable -- except a JS module that is itself a
            # function (`module.exports = function (d) {...}`).
            target = self.modules.get(b.file)
            if target is not None and target.family == "javascript":
                return self.lookup_symbol(b.file, DEFAULT)
            return None
        return self.lookup_symbol(b.file, b.symbol)

    # ---- the import graph ---------------------------------------------------

    def imports_of(self, key: str) -> Set[str]:
        mod = self.modules.get(key)
        return mod.imports if mod else set()

    def importers_of(self, key: str) -> Set[str]:
        return self._importers.get(key, set())

    def closure(self, seeds: Iterable[str], limit: Optional[int] = None) -> Closure:
        """Every file whose analysis a change to `seeds` can alter, nearest
        first: the seeds, the files that (transitively) import them, and
        everything those import. The first group's results change because a
        callee's summary changed; the second is needed so those files are
        analysed with the same callee summaries a full scan would give them (a
        file analysed against a truncated view reports different findings)."""
        seeds = [s for s in dict.fromkeys(seeds) if s in self.modules]
        dist: Dict[str, int] = {s: 0 for s in seeds}
        queue = deque(seeds)
        while queue:                                   # importers, transitively
            n = queue.popleft()
            for m in sorted(self.importers_of(n)):
                if m not in dist:
                    dist[m] = dist[n] + 1
                    queue.append(m)
        queue = deque(sorted(dist, key=dist.get))
        while queue:                                   # then what they import
            n = queue.popleft()
            for m in sorted(self.imports_of(n)):
                if m not in dist or dist[m] > dist[n] + 1:
                    dist[m] = dist[n] + 1
                    queue.append(m)
        ordered = sorted(dist, key=lambda k: (dist[k], k))
        truncated = limit is not None and len(ordered) > limit
        if truncated:
            ordered = ordered[:limit]
        return Closure(files=ordered, truncated=truncated, seeds=seeds)


def _arity_fits(proc: Any, n_args: int) -> bool:
    """Whether a call with `n_args` arguments can reach this Java method (varargs included)."""
    n = len(proc.params)
    return n == n_args or (getattr(proc, "has_varargs", False) and n_args >= n - 1)


def _module_parts(path: Path, root: Path) -> Sequence[str]:
    """`path` below `root` without its extension, as module-name parts."""
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = Path(*path.parts[1:]) if path.is_absolute() else path
    parts = list(rel.parts)
    if parts:
        parts[-1] = Path(parts[-1]).stem if "." in parts[-1] else parts[-1]
    return parts


def _normalise(path: Path) -> str:
    """Collapse `.` and `..` without touching the filesystem (symlinks stay as
    the importer wrote them, matching how files were keyed)."""
    out: List[str] = []
    for part in path.parts:
        if part == ".":
            continue
        if part == ".." and out and out[-1] not in ("..", "/"):
            out.pop()
        else:
            out.append(part)
    return str(Path(*out)) if out else "."


class ProjectContext:
    """The translated files of a project and the summaries they share.

    `build` translates each file once, then computes entry taints and return
    summaries for all their procedures together (`translator.run_ipa_fixpoint`):
    attacker data a handler passes to a helper in another file reaches that
    file's sinks, and a helper that returns a request field makes its callers'
    sinks reachable. Reporting then goes file by file against the finished
    summaries, with the translator built here (`translator_for`), so what one
    file reports never depends on which file was reported first.
    """

    def __init__(self, index: ProjectIndex):
        from frame.sil.translator import IPAState
        self.index = index
        self.ipa = IPAState()
        self.programs: Dict[str, Any] = {}
        self.translators: Dict[str, Any] = {}
        self.errors: Dict[str, str] = {}

    @classmethod
    def build(cls, index: ProjectIndex, scope: Iterable[str],
              frontend_for: Callable[[str], Any], verbose: bool = False,
              display: Optional[Dict[str, str]] = None) -> "ProjectContext":
        """Translate the files named by `scope` (keys in `index`) and run the
        inter-procedural fixpoint over them. `frontend_for(language)` gives a
        frontend with `translate`; calls resolve only to files in `scope`.
        `display` maps a key to the path string findings should carry (the one
        a scan of the file alone would use), so locations do not change
        depending on whether a file was scanned in a project."""
        from frame.sil.translator import SILTranslator, run_ipa_fixpoint
        ctx = cls(index)
        for key in scope:
            mod = index.modules.get(key)
            if mod is None:
                continue
            try:
                source = mod.path.read_text(encoding="utf-8-sig")
                program = frontend_for(ProjectIndex._parser_language(mod.path)).translate(
                    source, (display or {}).get(key, str(mod.path)))
            except Exception as e:                       # a bad file is just not part of it
                ctx.errors[key] = str(e)
                continue
            ctx.programs[key] = program
            index.set_procedures(key, program.procedures)
        from frame.sil.value_origins import link_modules

        def resolve_module(key: str, spec: str) -> Optional[str]:
            mod = index.modules.get(key)
            return index._resolve_js(mod, spec) if mod is not None and mod.family == "javascript" else None
        link_modules(ctx.programs, resolve_module)
        ctx.translators = {
            key: SILTranslator(program, verbose=verbose, ipa=ctx.ipa, file_key=key, project=ctx)
            for key, program in ctx.programs.items()}
        run_ipa_fixpoint(ctx.translators, ctx.ipa)
        return ctx

    # ---- what the translators ask ---------------------------------------------

    def resolve_call(self, key: str, name: str,
                     caller_class: Optional[str] = None) -> Optional[ProcRef]:
        ref = self.index.resolve_call(key, name, caller_class)
        if ref is None:
            return None
        program = self.programs.get(ref[0])
        return ref if program is not None and ref[1] in program.procedures else None

    # ---- Java ---------------------------------------------------------------

    def resolve_java_call(self, key: str, class_name: str, method: str,
                          arg_types: Optional[List[Optional[str]]] = None) -> Optional[ProcRef]:
        """The method `class_name.method(args)` names, called from file `key`: the class's
        own, else the nearest project supertype's, else -- for an interface or abstract type --
        the one concrete implementation the project has. None when the choice is not forced
        (an overload that argument types cannot settle, two implementations)."""
        cls = self.index.resolve_java_type(key, class_name)
        if cls is None:
            return None
        return self._java_method(cls, method, arg_types, set())

    def _java_method(self, cls: Tuple[str, str], method: str, arg_types: Optional[List[Optional[str]]],
                     seen: Set[Tuple[str, str]]) -> Optional[ProcRef]:
        if cls in seen:
            return None
        seen.add(cls)
        # A C# partial class: the part that declares the method.
        for part in self.index.java_partials.get(cls, ()):
            part_mod = self.index.modules.get(part[0])
            if part_mod is not None and part_mod.java_methods.get(part[1], {}).get(method):
                cls = part
                break
        file, name = cls
        mod, program = self.index.modules.get(file), self.programs.get(file)
        if mod is None or program is None:
            return None
        declared = mod.java_methods.get(name, {}).get(method, [])
        if declared:
            fits = (declared if arg_types is None else
                    [n for n in declared if _arity_fits(program.procedures[n], len(arg_types))])
            if not fits:
                return None
            if len(fits) == 1 and len(declared) == 1:
                return file, fits[0]
            if arg_types is None:
                return None                         # several overloads and nothing to choose by
            proc = program.resolve_java_call(name, method, arg_types, assume_closed=True)
            return (file, proc.name) if proc is not None else None
        if method in ("<init>", "ctor"):            # constructors are not inherited
            return None
        for sup in self.index.java_supertypes(cls):
            found = self._java_method(sup, method, arg_types, seen)
            if found is not None:
                return found
        if mod.java_kinds.get(name) == "interface" or name in mod.java_abstract:
            impls = self._java_implementations(cls, method, arg_types)
            if len(impls) == 1:
                return impls[0]
        return None

    def resolve_partial(self, key: str, name: str) -> Optional[Tuple[ProcRef, int]]:
        """`run_echo(x)` where `run_echo = functools.partial(shell, "echo")` (in this
        file or imported): the wrapped function and how many arguments it binds."""
        mod = self.index.modules.get(key)
        if mod is None or mod.family != "python" or "." in name:
            return None
        home, symbol = (key, name) if name in mod.partials else (None, None)
        if home is None:
            b = mod.bindings.get(name)
            if b is None or b.symbol is None:
                return None
            home, symbol = b.file, b.symbol
        target = self.index.modules.get(home)
        if target is None or symbol not in target.partials:
            return None
        func, n = target.partials[symbol]
        ref = (home, func) if func in target.procs else self.index.lookup_symbol(home, func)
        program = self.programs.get(ref[0]) if ref is not None else None
        return (ref, n) if program is not None and ref[1] in program.procedures else None

    def resolve_extension(self, key: str, method: str, nargs: int) -> Optional[ProcRef]:
        """The C# extension method `x.method(...)` calls from file `key`: one declared in
        a namespace that file can see (its own, enclosing, or a `using`), taking the
        receiver plus `nargs` arguments. None unless exactly one fits."""
        mod = self.index.modules.get(key)
        if mod is None or not (mod.package or "").startswith(self.index._CS):
            return None
        visible = {mod.package, *mod.java_wildcards}
        found = []
        for other in self.index.modules.values():
            if other.package not in visible:
                continue
            program = self.programs.get(other.key)
            for name in other.cs_extensions.get(method, []):
                if program is not None and name in program.procedures \
                        and _arity_fits(program.procedures[name], nargs + 1):
                    found.append((other.key, name))
        return found[0] if len(found) == 1 else None

    def java_dispatch_targets(self, key: str, class_name: str, method: str,
                              arg_types: Optional[List[Optional[str]]] = None) -> List[ProcRef]:
        """Every project method a call through `class_name` may run: the one
        `resolve_java_call` settles on, else -- for an interface or abstract type that
        several project classes implement -- each implementation (virtual dispatch)."""
        one = self.resolve_java_call(key, class_name, method, arg_types)
        if one is not None:
            return [one]
        cls = self.index.resolve_java_type(key, class_name)
        mod = self.index.modules.get(cls[0]) if cls is not None else None
        if mod is None or not (mod.java_kinds.get(cls[1]) == "interface" or cls[1] in mod.java_abstract):
            return []
        return self._java_implementations(cls, method, arg_types)

    def _java_implementations(self, cls: Tuple[str, str], method: str,
                              arg_types: Optional[List[Optional[str]]]) -> List[ProcRef]:
        """Concrete classes below `cls` that declare `method`, as procedures."""
        out: List[ProcRef] = []
        todo, seen = list(self.index.java_implementers.get(cls, [])), set()
        while todo:
            sub = todo.pop()
            if sub in seen:
                continue
            seen.add(sub)
            file, name = sub
            mod, program = self.index.modules.get(file), self.programs.get(file)
            if mod is None or program is None:
                continue
            declared = mod.java_methods.get(name, {}).get(method, [])
            fits = (declared if arg_types is None else
                    [n for n in declared if _arity_fits(program.procedures[n], len(arg_types))])
            if len(fits) == 1:
                out.append((file, fits[0]))
            todo.extend(self.index.java_implementers.get(sub, []))
        return list(dict.fromkeys(out))

    def procedure(self, ref: Optional[ProcRef]) -> Optional[Any]:
        if ref is None:
            return None
        program = self.programs.get(ref[0])
        return program.procedures.get(ref[1]) if program is not None else None

    # ---- what the scanner asks ------------------------------------------------

    def key_for(self, path: Path) -> Optional[str]:
        key = self.index.key_for(path)
        return key if key in self.programs else None

    def program_for(self, path: Path) -> Optional[Any]:
        key = self.key_for(path)
        return self.programs.get(key) if key is not None else None

    def translator_for(self, path: Path) -> Optional[Any]:
        key = self.key_for(path)
        return self.translators.get(key) if key is not None else None
