"""The `using` directives a C# file gets from its project, not from its own text.

A .NET 6+ project compiles every file with the namespaces of its SDK's implicit usings
(`<ImplicitUsings>enable</ImplicitUsings>`; specs/data/dotnet-sdks.toml), the `<Using>` items of
the project file and of the `Directory.Build.props` MSBuild imports for it, and every
`global using` directive in the project's files. A minimal API's `Program.cs` usually has no
using directive at all, so without these `WebApplication` is not known to be ASP.NET Core's.

Read without MSBuild, so only what is certain: the project is the nearest directory above the
file holding exactly one `.csproj` (MSBuild compiles every `.cs` below it); a property or item
under a `Condition`, or one whose value is an MSBuild expression (`$(...)`), is not read; a
`Directory.Build.props` is the nearest one at or above the project's directory (its own imports
are not followed); the project file is evaluated after it, so its `ImplicitUsings` wins."""

from __future__ import annotations

import os
try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_SDKS_PATH = Path(__file__).parent / "specs" / "data" / "dotnet-sdks.toml"
_SKIP_DIRS = frozenset({"bin", "obj", ".git", "node_modules"})


@dataclass(frozen=True)
class ProjectUsings:
    wildcards: Tuple[str, ...] = ()                        # `using X;` for every file
    aliases: Dict[str, str] = field(default_factory=dict)  # `using A = X.Y;`


_NONE = ProjectUsings()


@lru_cache(maxsize=None)
def _sdks() -> Tuple[Tuple[str, ...], Dict[str, Tuple[str, ...]]]:
    data = tomllib.loads(_SDKS_PATH.read_text(encoding="utf-8"))
    if set(data) != {"base", "sdk"} or not all(isinstance(v, list) for v in data["sdk"].values()):
        raise ValueError("dotnet-sdks.toml: `base` (a list) and [sdk] (SDK name -> list)")
    return tuple(data["base"]), {k: tuple(v) for k, v in data["sdk"].items()}


def _xml(path: Path) -> Optional[ET.Element]:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError):
        return None
    if "<!ENTITY" in text or "<!DOCTYPE" in text:
        return None                                        # a document type declaration is not read
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    for el in root.iter():                                 # old-style projects use an XML namespace
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    return root


def _unconditional(root: ET.Element, group: str):
    """The children of `<group>` elements (PropertyGroup, ItemGroup) that no Condition guards."""
    for g in root.findall(group):
        if g.get("Condition") is not None:
            continue
        for el in g:
            if el.get("Condition") is None:
                yield el


def _literal(value: Optional[str]) -> Optional[str]:
    value = (value or "").strip()
    return value if value and "$(" not in value and "@(" not in value and "%(" not in value else None


def _read(root: ET.Element, state: Dict[str, object]) -> None:
    """Apply one MSBuild file's ImplicitUsings property and Using items to `state`, in order."""
    for el in _unconditional(root, "PropertyGroup"):
        if el.tag == "ImplicitUsings":
            v = _literal(el.text)
            state["implicit"] = None if v is None else v.lower() in ("enable", "true")
    usings: Dict[Tuple[str, Optional[str]], None] = state["usings"]   # (namespace or type, alias), in order
    for el in _unconditional(root, "ItemGroup"):
        if el.tag != "Using":
            continue
        if el.get("Static", "").lower() == "true":
            continue                                       # `using static`: members, not types
        include, remove = _literal(el.get("Include")), _literal(el.get("Remove"))
        if include:
            for name in include.split(";"):
                if name.strip():
                    usings[(name.strip(), _literal(el.get("Alias")))] = None
        if remove:
            for name in remove.split(";"):
                for key in [k for k in usings if k[0] == name.strip()]:
                    del usings[key]
                state["removed"].add(name.strip())


def _sdk_of(root: ET.Element) -> Optional[str]:
    sdk = root.get("Sdk") or next((s.get("Name") for s in root.findall("Sdk") if s.get("Name")), None)
    return sdk.split("/", 1)[0].strip() if sdk else None


def project_file(cs_path: str) -> Optional[Path]:
    """The `.csproj` that compiles `cs_path`: the nearest directory above it holding one."""
    try:
        here = Path(cs_path).resolve().parent
    except OSError:
        return None
    if not Path(cs_path).is_file():
        return None
    for d in (here, *here.parents):
        try:
            found = sorted(p for p in d.iterdir() if p.suffix == ".csproj" and p.is_file())
        except OSError:
            return None
        if found:
            return found[0] if len(found) == 1 else None   # two projects in one folder: not knowable
    return None


def _global_usings(project_dir: Path) -> List[Tuple[str, Optional[str]]]:
    """`global using X;` / `global using A = X.Y;` in the project's own files."""
    try:
        import tree_sitter_c_sharp
        from tree_sitter import Language, Parser
    except ImportError:
        return []
    parser = Parser(Language(tree_sitter_c_sharp.language()))
    out: List[Tuple[str, Optional[str]]] = []
    for dirpath, dirnames, filenames in os.walk(project_dir):
        here = Path(dirpath)
        if here != project_dir and any(f.endswith(".csproj") for f in filenames):
            dirnames[:] = []                               # a nested project's files are its own
            continue
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            if not name.endswith(".cs"):
                continue
            try:
                data = (here / name).read_bytes()
            except OSError:
                continue
            if b"global" not in data:
                continue                                   # cheap filter; the parser decides
            text = lambda n: data[n.start_byte:n.end_byte].decode("utf-8", "replace")
            for node in parser.parse(data).root_node.children:
                if node.type != "using_directive" or not any(c.type == "global" for c in node.children):
                    continue
                if any(c.type == "static" or text(c) == "static" for c in node.children):
                    continue
                names = [c for c in node.named_children if c.type in ("identifier", "qualified_name")]
                if any(c.type == "=" for c in node.children) and len(names) >= 2:
                    out.append((text(names[-1]), text(names[0])))      # (target, alias)
                elif names:
                    out.append((text(names[-1]), None))
    return out


@lru_cache(maxsize=256)
def _usings_of(project: Path) -> ProjectUsings:
    root = _xml(project)
    if root is None:
        return _NONE
    state: Dict[str, object] = {"implicit": False, "usings": {}, "removed": set()}
    props = next((d / "Directory.Build.props" for d in (project.parent, *project.parent.parents)
                  if (d / "Directory.Build.props").is_file()), None)
    props_root = _xml(props) if props is not None else None
    if props_root is not None:
        _read(props_root, state)
    _read(root, state)
    entries: Dict[Tuple[str, Optional[str]], None] = {}
    if state["implicit"]:
        base, sdks = _sdks()
        sdk = _sdk_of(root)
        if sdk in sdks:                                    # an SDK not listed adds nothing known
            for ns in base + sdks[sdk]:
                if ns not in state["removed"]:
                    entries[(ns, None)] = None
    entries.update(state["usings"])
    entries.update((u, None) for u in _global_usings(project.parent))
    wildcards = tuple(ns for ns, alias in entries if alias is None)
    aliases: Dict[str, str] = {}
    for ns, alias in entries:
        if alias is not None:
            aliases[alias] = ns
    return ProjectUsings(wildcards, aliases)


def usings_for(cs_path: str) -> ProjectUsings:
    """The usings `cs_path` gets from its project (none when no project file is found)."""
    project = project_file(cs_path)
    return _usings_of(project) if project is not None else _NONE


__all__ = ["ProjectUsings", "partial_fields", "project_file", "usings_for"]


# -- the other parts of a partial class -------------------------------------------------------------

@lru_cache(maxsize=64)
def _partial_fields_in(folder: Path) -> Dict[Tuple[str, str], Dict[str, str]]:
    """(namespace, class) -> field / property name -> declared type, for every `partial` class
    declared under `folder` (bin/obj and nested projects skipped)."""
    try:
        import tree_sitter_c_sharp
        from tree_sitter import Language, Parser
    except ImportError:
        return {}
    parser = Parser(Language(tree_sitter_c_sharp.language()))
    out: Dict[Tuple[str, str], Dict[str, str]] = {}
    for dirpath, dirnames, filenames in os.walk(folder):
        here = Path(dirpath)
        if here != folder and any(f.endswith(".csproj") for f in filenames):
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            if not name.endswith(".cs"):
                continue
            try:
                data = (here / name).read_bytes()
            except OSError:
                continue
            if b"partial" not in data:
                continue                                   # cheap filter; the parser decides
            text = lambda n: data[n.start_byte:n.end_byte].decode("utf-8", "replace")
            stack = [(parser.parse(data).root_node, "")]
            while stack:
                node, ns = stack.pop()
                for c in node.named_children:
                    if c.type in ("namespace_declaration", "file_scoped_namespace_declaration"):
                        nm = c.child_by_field_name("name")
                        inner = f"{ns}.{text(nm)}" if ns and nm is not None else (text(nm) if nm is not None else ns)
                        body = c.child_by_field_name("body")
                        stack.append((body if body is not None else c, inner))
                    elif c.type == "declaration_list":
                        stack.append((c, ns))
                    elif c.type == "class_declaration" and any(m.type == "modifier" and text(m) == "partial"
                                                               for m in c.children):
                        cname = c.child_by_field_name("name")
                        fields = out.setdefault((ns, text(cname) if cname is not None else ""), {})
                        body = c.child_by_field_name("body")
                        for member in (body.named_children if body is not None else ()):
                            typ = member.child_by_field_name("type")
                            if member.type == "field_declaration":
                                decl = next((x for x in member.named_children if x.type == "variable_declaration"), None)
                                typ = decl.child_by_field_name("type") if decl is not None else None
                                for v in (decl.named_children if decl is not None else ()):
                                    vn = v.child_by_field_name("name") or next(
                                        (x for x in v.children if x.type == "identifier"), None)
                                    if v.type == "variable_declarator" and vn is not None and typ is not None:
                                        fields[text(vn)] = text(typ).split("<", 1)[0].strip()
                            elif member.type == "property_declaration" and typ is not None:
                                pn = member.child_by_field_name("name")
                                if pn is not None:
                                    fields[text(pn)] = text(typ).split("<", 1)[0].strip()
    return out


def partial_fields(cs_path: str, namespace: str, class_name: str) -> Dict[str, str]:
    """The fields and properties another part of the partial class `namespace.class_name` declares
    (a WebForms page's designer file declares its controls): the parts the compiler merges are
    the project's files (the `.csproj` folder, else the file's own folder)."""
    project = project_file(cs_path)
    try:
        folder = project.parent if project is not None else Path(cs_path).resolve().parent
    except OSError:
        return {}
    if not Path(cs_path).is_file():
        return {}
    return dict(_partial_fields_in(folder).get((namespace, class_name), {}))
