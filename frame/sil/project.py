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
- Only plain functions (Python module level, JS exported) are callees. A method
  on an object of unknown type, a class, a callable module, or anything the
  analysis would have to guess stays unresolved: the call then keeps the
  default argument-to-result propagation it always had.

Files are named by their path relative to the project root, POSIX style; that
key is what the translator keys summaries on. `closure` computes which files a
change can affect.
"""

from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

PY_EXTENSIONS = (".py",)
JS_EXTENSIONS = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")
# Extensions tried, in order, when a JS import omits one.
_JS_TRY = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts")
# A TS import may name the emitted `.js` of a `.ts` source.
_JS_TO_TS = {".js": (".ts", ".tsx"), ".jsx": (".tsx",), ".mjs": (".mts",), ".cjs": (".cts",)}
_PY_SOURCE_DIRS = ("src", "lib", "python")
DEFAULT = "default"           # the export name of a module's default export
_MAX_REEXPORT_DEPTH = 6

ProcRef = Tuple[str, str]     # (file key, procedure name)


def language_family(path: Path) -> Optional[str]:
    """`python` or `javascript` (JS and TS share one module system), else None."""
    suffix = path.suffix.lower()
    if suffix in PY_EXTENSIONS:
        return "python"
    if suffix in JS_EXTENSIONS:
        return "javascript"
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
            else:
                self._read_javascript(mod, tree.root_node)
        for mod in self.modules.values():
            mod.imports.discard(mod.key)
            for target in mod.imports:
                self._importers.setdefault(target, set()).add(mod.key)

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

    def _read_python(self, mod: FileModule, root: Any) -> None:
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

    # ---- JavaScript / TypeScript --------------------------------------------

    def _resolve_js(self, importer: FileModule, spec: str) -> Optional[str]:
        if not spec.startswith((".", "/")):
            return None
        base = Path(_normalise((importer.path.parent / spec) if not spec.startswith("/")
                               else Path(spec)))
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
                if value is not None and value.type == "call_expression":
                    fn, args = value.child_by_field_name("function"), value.child_by_field_name("arguments")
                    if fn is not None and _text(fn) == "require" and args is not None \
                            and args.named_children and args.named_children[0].type == "string":
                        spec = self._spec_of(args)
                        target = self._resolve_js(mod, spec)
                        if target is not None:
                            mod.imports.add(target)
                            mod.specs[spec] = target
                            self._js_bind_require(mod, name_node, target)
            stack.extend(n.children)

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

    def _js_assignment_export(self, mod: FileModule, st: Any) -> None:
        for assign in st.children:
            if assign.type != "assignment_expression":
                continue
            left, right = assign.child_by_field_name("left"), assign.child_by_field_name("right")
            if left is None or right is None:
                continue
            target = _text(left)
            if target == "module.exports":
                if right.type == "object":
                    for p in right.children:
                        if p.type == "shorthand_property_identifier":
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
        if mod.family == "python":
            mod.procs = {name for name, p in procedures.items()
                         if "." not in name and "#" not in name and not name.startswith("<")
                         and not getattr(p, "is_method", False)}
        else:
            mod.procs = {name for name in procedures if not name.startswith("<")}

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

    def resolve_call(self, key: str, name: str) -> Optional[ProcRef]:
        """The procedure in another file that the call `name` (as lowered by the
        frontend) makes from file `key`, or None."""
        mod = self.modules.get(key)
        if mod is None:
            return None
        if mod.family == "javascript":
            for spec in sorted(mod.specs, key=len, reverse=True):
                if name.startswith(spec + ".") and "." not in name[len(spec) + 1:]:
                    return self.lookup_symbol(mod.specs[spec], name[len(spec) + 1:])
        b = mod.bindings.get(name)
        if b is not None:
            return self._follow(b)
        if "." not in name:
            return None
        head, _, member = name.rpartition(".")
        hb = mod.bindings.get(head)
        module = self._module_of(hb) if hb is not None else None
        return self.lookup_symbol(module, member) if module is not None else None

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
        ctx.translators = {
            key: SILTranslator(program, verbose=verbose, ipa=ctx.ipa, file_key=key, project=ctx)
            for key, program in ctx.programs.items()}
        run_ipa_fixpoint(ctx.translators, ctx.ipa)
        return ctx

    # ---- what the translators ask ---------------------------------------------

    def resolve_call(self, key: str, name: str) -> Optional[ProcRef]:
        ref = self.index.resolve_call(key, name)
        if ref is None:
            return None
        program = self.programs.get(ref[0])
        return ref if program is not None and ref[1] in program.procedures else None

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
