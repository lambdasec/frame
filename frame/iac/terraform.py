"""Terraform: each root module read into resources, its expressions evaluated (frame/iac/hcl.py).

A module is the `.tf` files of one directory. Every directory with `.tf` files is read as a
root module; a `module` block whose source is a local directory (or a module `terraform init`
recorded in `.terraform/modules/modules.json`) is read with the call's arguments as its
variables, its resources addressed `module.<name>.<type>.<name>`.

Values, as a plan would see them:

* a variable takes its value from the module call, else `terraform.tfvars`,
  `terraform.tfvars.json` and `*.auto.tfvars(.json)` (the files Terraform loads by itself,
  later ones winning), else its `default`; with none of these it is unknown. A value given on
  the command line (`-var`, `-var-file`, `TF_VAR_`) is not in the files: findings are for the
  values the repository gives;
* `locals` are evaluated on demand;
* a resource attribute another expression reads is the value its configuration gives it, else
  unknown, named `<address>.<attribute>`: the same unknown wherever it is read, so `bucket =
  aws_s3_bucket.logs.id` is equal (to Z3) to the bucket's own `id`;
* `count` and `for_each` known in the files expand to their instances (`count = 0` removes the
  resource); unknown ones leave one instance whose `count.index` / `each` are unknown;
* `dynamic` blocks expand over a known `for_each`, else the block list is unknown.

Each resource's document is its arguments, its nested blocks as lists of documents, and `id`.
Views: `self`, and `resources`, every resource of the same root module instance by type
(`some p in resources["aws_s3_bucket_public_access_block"]: ...`).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .engine import Unknown
from .hcl import (Block, Body, HclError, Scope, Source, contains_unknown, convert, evaluate, parse,
                  type_constraint)
from .model import ReadResult, Resource

_META = {"count", "for_each", "depends_on", "provider", "lifecycle", "provisioner", "connection"}
_MAX_EXPAND = 16
_MAX_DEPTH = 8


@dataclass
class _File:
    path: Path
    rel: str
    body: Body
    src: Source


@dataclass
class _Module:
    dir: Path
    files: List[_File] = field(default_factory=list)
    variables: Dict[str, Tuple[Block, _File]] = field(default_factory=dict)
    locals: Dict[str, Tuple[Any, _File]] = field(default_factory=dict)
    resources: List[Tuple[str, Block, _File]] = field(default_factory=list)   # (mode, block, file)
    calls: List[Tuple[Block, _File]] = field(default_factory=list)
    outputs: Dict[str, Tuple[Any, _File]] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)


class _Lazy(dict):
    """`local`, `module.x` outputs: evaluated on first read, a cycle is unknown."""

    def __init__(self, compute, names, key):
        super().__init__()
        self._compute = compute
        self._names = set(names)
        self._key = key
        self._busy: set = set()

    def __contains__(self, name):
        return name in self._names

    def __getitem__(self, name):
        if name not in self._names:
            raise KeyError(name)
        if dict.__contains__(self, name):
            return dict.__getitem__(self, name)
        if name in self._busy:
            return Unknown(f"{self._key}.{name}", "cycle")
        self._busy.add(name)
        try:
            value = self._compute(name)
        finally:
            self._busy.discard(name)
        dict.__setitem__(self, name, value)
        return value

    def keys(self):
        return sorted(self._names)


class _ResourceObject(dict):
    """A resource as another expression reads it: configured attributes, others unknown."""

    def __init__(self, address: str, attrs: Dict[str, Any], registry: Optional[Dict] = None):
        super().__init__(attrs)
        self.address = address
        if registry is not None:
            registry[address] = self

    def __contains__(self, name):
        return True

    def __getitem__(self, name):
        if dict.__contains__(self, name):
            return dict.__getitem__(self, name)
        return Unknown(f"{self.address}.{name}", f"{self.address}.{name}")


def _load(directory: Path, root: Path, out_warnings: List[str]) -> Optional[_Module]:
    files = sorted(p for p in directory.glob("*.tf") if p.is_file())
    if not files:
        return None
    mod = _Module(directory)
    for f in files:
        rel = f.relative_to(root).as_posix() if _under(f, root) else str(f)
        if f.name == "override.tf" or f.name.endswith("_override.tf"):
            out_warnings.append(f"{rel}: an override file (not merged; its settings are not checked)")
            continue
        try:
            body, src = parse(f.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError) as e:
            out_warnings.append(f"{rel}: cannot read: {e}")
            continue
        except HclError as e:
            out_warnings.append(f"{rel}: not valid HCL ({e})")
            continue
        tf = _File(f, rel, body, src)
        mod.files.append(tf)
        for b in body.blocks:
            if b.type == "variable" and b.labels:
                mod.variables[b.labels[0]] = (b, tf)
            elif b.type == "locals":
                for name, attr in b.body.attributes.items():
                    mod.locals[name] = (attr, tf)
            elif b.type in ("resource", "data") and len(b.labels) == 2:
                mod.resources.append((b.type, b, tf))
            elif b.type == "module" and b.labels:
                mod.calls.append((b, tf))
            elif b.type == "output" and b.labels and "value" in b.body.attributes:
                mod.outputs[b.labels[0]] = (b.body.attributes["value"], tf)
    for f in sorted(directory.glob("*.tf.json")):
        rel = f.relative_to(root).as_posix() if _under(f, root) else str(f)
        out_warnings.append(f"{rel}: Terraform JSON syntax is not read yet")
    return mod


def _under(p: Path, root: Path) -> bool:
    try:
        p.relative_to(root)
        return True
    except ValueError:
        return False


def _tfvars(directory: Path, warnings: List[str], root: Path) -> Dict[str, Any]:
    """The variable values Terraform loads by itself, in its order (later wins)."""
    names = ["terraform.tfvars", "terraform.tfvars.json"]
    names += sorted(p.name for p in directory.glob("*.auto.tfvars")) + \
        sorted(p.name for p in directory.glob("*.auto.tfvars.json"))
    values: Dict[str, Any] = {}
    for name in names:
        f = directory / name
        if not f.is_file():
            continue
        rel = f.relative_to(root).as_posix() if _under(f, root) else str(f)
        try:
            text = f.read_text(encoding="utf-8")
            if name.endswith(".json"):
                data = json.loads(text)
                if isinstance(data, dict):
                    values.update(data)
                continue
            body, src = parse(text)
            for attr in body.attributes.values():
                values[attr.name] = evaluate(attr.expr, Scope({}, key_prefix=f"{rel}:"), src)
        except (OSError, ValueError) as e:
            warnings.append(f"{rel}: not read ({e})")
    return values


class _Instance:
    """One evaluation of a module: a root module, or a module call's."""

    def __init__(self, reader: "_Reader", mod: _Module, prefix: str, inputs: Dict[str, Any],
                 depth: int, stack: Tuple[str, ...]):
        self.reader = reader
        self.mod = mod
        self.prefix = prefix                       # "" or "module.a.module.b."
        self.depth = depth
        self.stack = stack
        self.inputs = inputs
        self.values: Dict[str, Any] = {}
        self.var = _Lazy(self._variable, mod.variables, f"{prefix}var")
        self.local = _Lazy(self._local, mod.locals, f"{prefix}local")
        self.objects: Dict[str, Dict[str, Any]] = {}      # resource type -> name -> object
        self.data: Dict[str, Dict[str, Any]] = {}
        self.children: Dict[str, "_Instance"] = {}
        self.data_objects: Dict[str, "_ResourceObject"] = {}       # data source address -> object
        self.module = _Lazy(self._module_outputs, [b.labels[0] for b, _ in mod.calls], f"{prefix}module")
        self.stack_root = mod.dir                  # the root module's directory (installed modules)

    # -- names an expression reads ------------------------------------------------------

    def scope(self, rel: str, extra: Optional[Dict[str, Any]] = None) -> Scope:
        roots: Dict[str, Any] = {"var": self.var, "local": self.local, "module": self.module,
                                 "data": self.data,
                                 "path": {"module": str(self.mod.dir), "root": str(self.reader.root),
                                          "cwd": str(self.reader.root)},
                                 "terraform": {"workspace": "default"}}
        roots.update(self.objects)
        if extra:
            roots.update(extra)
        return Scope(roots, key_prefix=f"{self.prefix}{rel}:")

    def eval(self, expr, f: _File, extra=None):
        try:
            return evaluate(expr, self.scope(f.rel, extra), f.src)
        except HclError:
            return Unknown(f"{self.prefix}{f.rel}:{f.src.text(expr.node)}", "error")
        except RecursionError:
            return Unknown(f"{self.prefix}{f.rel}:{f.src.text(expr.node)}", "too deep")

    def _variable(self, name: str):
        block, f = self.mod.variables[name]
        attrs = block.body.attributes
        unknown = Unknown(f"{self.prefix}var.{name}", f"var.{name}")
        has_default = "default" in attrs
        default = self.eval(attrs["default"].expr, f) if has_default else None
        if name in self.inputs:
            value = self.inputs[name]
        elif name in self.values:
            value = self.values[name]
        elif has_default:
            value = default
        else:
            return unknown
        nullable = attrs.get("nullable")
        if value is None and nullable is not None and nullable.expr.kind == "lit" and nullable.expr.value is False \
                and has_default:
            value = default
        if "type" in attrs:
            try:
                t = type_constraint(attrs["type"].expr, f.src)
                return convert(value, t, f.src, self.scope(f.rel))
            except HclError:
                return unknown             # Terraform would reject the value
        return value

    def _local(self, name: str):
        attr, f = self.mod.locals[name]
        return self.eval(attr.expr, f)

    def _module_outputs(self, name: str):
        child = self.children.get(name)          # a module with count/for_each: not modelled
        if child is None:
            return Unknown(f"{self.prefix}module.{name}", f"module.{name}")
        return _Lazy(lambda o: child.eval(child.mod.outputs[o][0].expr, child.mod.outputs[o][1]),
                     list(child.mod.outputs), f"{self.prefix}module.{name}")

    # -- resources ------------------------------------------------------------------------

    def prepare(self) -> None:
        """Register every resource's object, so references between them resolve."""
        for mode, block, f in self.mod.resources:
            rtype, rname = block.labels
            target = self.data if mode == "data" else self.objects
            byname = target.setdefault(rtype, {})
            base = f"{self.prefix}{'data.' if mode == 'data' else ''}{rtype}.{rname}"
            byname[rname] = _LazyResource(self, block, f, base)
        for block, f in self.mod.calls:
            self.reader.call(self, block, f)

    def resources(self) -> List[Tuple[str, Dict[str, Any], Block, _File, Dict]]:
        out = []
        for mode, block, f in self.mod.resources:
            if mode != "resource":
                continue
            rtype, rname = block.labels
            base = f"{self.prefix}{rtype}.{rname}"
            for address, extra in self.instances(block, f, base):
                doc, lines = self.document(block.body, f, extra, address)
                out.append((address, doc, block, f, lines))
        for child in self.children.values():
            out += child.resources()
        return out

    def instances(self, block: Block, f: _File, base: str) -> List[Tuple[str, Dict[str, Any]]]:
        attrs = block.body.attributes
        if "count" in attrs:
            n = self.eval(attrs["count"].expr, f)
            if isinstance(n, int) and not isinstance(n, bool) and 0 <= n <= _MAX_EXPAND:
                return [(f"{base}[{i}]", {"count": {"index": i}}) for i in range(n)]
            return [(f"{base}[*]", {"count": {"index": Unknown(f"{base}.count.index", "count.index")}})]
        if "for_each" in attrs:
            coll = self.eval(attrs["for_each"].expr, f)
            if isinstance(coll, dict) and not contains_unknown(list(coll.keys())) and len(coll) <= _MAX_EXPAND:
                return [(f'{base}["{k}"]', {"each": {"key": k, "value": coll[k]}}) for k in sorted(coll)]
            if isinstance(coll, list) and all(isinstance(x, str) for x in coll) and len(coll) <= _MAX_EXPAND:
                return [(f'{base}["{k}"]', {"each": {"key": k, "value": k}}) for k in sorted(set(coll))]
            u = Unknown(f"{base}.each", "each")
            return [(f"{base}[*]", {"each": {"key": u.child("key"), "value": u.child("value")}})]
        return [(base, {})]

    def document(self, body: Body, f: _File, extra: Dict[str, Any], address: str,
                 path: Tuple = ()) -> Tuple[Dict[str, Any], Dict]:
        doc: Dict[str, Any] = {}
        lines: Dict = {}
        for name, attr in body.attributes.items():
            if not path and name in _META:
                continue
            doc[name] = self.eval(attr.expr, f, extra)
            lines[path + (name,)] = attr.line
        for b in body.blocks:
            if not path and b.type in _META:
                continue
            if b.type == "dynamic" and b.labels:
                self._dynamic(b, f, extra, address, path, doc, lines)
                continue
            items = doc.setdefault(b.type, [])
            if isinstance(items, Unknown):
                continue
            sub, sublines = self.document(b.body, f, extra, address, path + (b.type, len(items)))
            lines[path + (b.type, len(items))] = b.line
            lines.update(sublines)
            items.append(sub)
        if "policy" in doc:
            self._analyse_policy(doc, address, path)
        if not path:
            doc.setdefault("id", Unknown(f"{address}.id", f"{address}.id"))
        return doc, lines

    def _analyse_policy(self, doc: Dict[str, Any], address: str, path: Tuple) -> None:
        """`policy_public` and `policy_admin` beside a `policy` argument (frame/iac/aws_policy.py):
        True or False when the document is known, else unknown."""
        from . import aws_policy
        value = doc["policy"]
        structure = None
        if isinstance(value, str):
            structure = aws_policy.document(value)
        elif isinstance(value, Unknown):
            structure = self._policy_document_data(value.key)
        where = ".".join(map(str, path + ("policy",)))
        for name, fn in (("policy_public", aws_policy.is_public), ("policy_admin", aws_policy.grants_everything)):
            verdict = fn(structure) if structure is not None else None
            text = value.text if isinstance(value, Unknown) and value.text else f"the policy of {address}"
            doc[name] = verdict if verdict is not None else Unknown(f"{address}.{where}.{name}", text)

    def _policy_document_data(self, key: str):
        """The document of `data.aws_iam_policy_document.<name>[<i>].json` read in this module."""
        from . import aws_policy
        head = f"{self.prefix}data.aws_iam_policy_document."
        if not (key.startswith(head) and key.endswith((".json", ".minified_json"))):
            return None
        address = key.rsplit(".", 1)[0]
        name = address[len(head):].split("[", 1)[0]
        lazy = self.data.get("aws_iam_policy_document", {}).get(name)
        if lazy is None:
            return None
        lazy.value()                            # registers the instances
        obj = self.data_objects.get(address)
        if obj is None:
            return None
        return aws_policy.from_policy_document_data(dict(obj))

    def _dynamic(self, b: Block, f: _File, extra, address, path, doc, lines) -> None:
        name = b.labels[0]
        content = next((x for x in b.body.blocks if x.type == "content"), None)
        iterator = name
        if "iterator" in b.body.attributes:
            it = b.body.attributes["iterator"].expr
            if it.kind == "ref" and not it.steps and isinstance(it.value, str):
                iterator = it.value
        coll = self.eval(b.body.attributes["for_each"].expr, f, extra) if "for_each" in b.body.attributes else None
        items = doc.setdefault(name, [])
        if isinstance(items, Unknown) or content is None:
            return
        if isinstance(coll, dict) and not contains_unknown(list(coll)):
            pairs = [(k, coll[k]) for k in sorted(coll)]
        elif isinstance(coll, list):
            pairs = list(enumerate(coll))
        else:
            doc[name] = Unknown(f"{address}.{'.'.join(map(str, path + (name,)))}", f"dynamic {name}")
            return
        for k, v in pairs:
            inner = dict(extra)
            inner[iterator] = {"key": k, "value": v}
            sub, sublines = self.document(content.body, f, inner, address, path + (name, len(items)))
            lines[path + (name, len(items))] = b.line
            lines.update(sublines)
            items.append(sub)


class _LazyResource(dict):
    """A resource or data source as a value: its instances' configured attributes."""

    def __init__(self, inst: _Instance, block: Block, f: _File, base: str):
        super().__init__()
        self.inst, self.block, self.f, self.base = inst, block, f, base
        self.registry = inst.data_objects if base.startswith(f"{inst.prefix}data.") else None
        self._value = None
        self._busy = False

    def value(self):
        if self._value is not None:
            return self._value
        if self._busy:
            return Unknown(self.base, "cycle")
        self._busy = True
        try:
            attrs = self.block.body.attributes
            if "count" in attrs or "for_each" in attrs:
                # the same instances the resource expands to, so `x.this[0].id` is instance 0's id
                insts = self.inst.instances(self.block, self.f, self.base)
                if len(insts) == 1 and insts[0][0].endswith("[*]"):
                    self._value = Unknown(self.base, self.base)
                elif "count" in attrs:
                    self._value = [_ResourceObject(a, self.inst.document(self.block.body, self.f, extra, a)[0],
                                                   self.registry) for a, extra in insts]
                else:
                    self._value = {extra["each"]["key"]: _ResourceObject(a, self.inst.document(
                        self.block.body, self.f, extra, a)[0], self.registry) for a, extra in insts}
            else:
                doc, _ = self.inst.document(self.block.body, self.f, {}, self.base)
                self._value = _ResourceObject(self.base, doc, self.registry)
        finally:
            self._busy = False
        return self._value

    def __contains__(self, name):
        return True

    def __getitem__(self, name):
        v = self.value()
        if isinstance(v, Unknown):
            return v.child(name)
        if isinstance(v, list):
            if isinstance(name, str) and name.isdigit() and int(name) < len(v):
                return v[int(name)]
            raise KeyError(name)
        return v[name]

    def resolved(self):
        """The value itself, for index and splat steps (`x.this[0]`, `x.this[*].id`)."""
        return self.value()


class _Reader:
    def __init__(self, root: Path):
        self.root = root
        self.warnings: List[str] = []
        self.modules: Dict[Path, Optional[_Module]] = {}
        self.installed = self._installed_modules()

    def module(self, directory: Path) -> Optional[_Module]:
        directory = directory.resolve()
        if directory not in self.modules:
            self.modules[directory] = _load(directory, self.root, self.warnings)
        return self.modules[directory]

    def _installed_modules(self) -> Dict[str, Path]:
        out: Dict[str, Path] = {}
        for manifest in self.root.rglob(".terraform/modules/modules.json"):
            base = manifest.parent.parent.parent
            try:
                data = json.loads(manifest.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            for m in data.get("Modules", []) or []:
                if isinstance(m, dict) and m.get("Key") and m.get("Dir"):
                    out[f"{base.resolve()}::{m['Key']}"] = (base / m["Dir"]).resolve()
        return out

    def call(self, parent: _Instance, block: Block, f: _File) -> None:
        name = block.labels[0]
        source_attr = block.body.attributes.get("source")
        if source_attr is None or parent.depth >= _MAX_DEPTH:
            return
        source = parent.eval(source_attr.expr, f)
        if not isinstance(source, str):
            return
        if source.startswith(("./", "../")):
            target = (parent.mod.dir / source).resolve()
        else:
            # `terraform init` records installed modules by their call path (`a.b`)
            key = (re.sub(r"\[[^\]]*\]", "", parent.prefix).replace("module.", "") + name).strip(".")
            target = self.installed.get(f"{Path(parent.stack_root).resolve()}::{key}")
            if target is None:
                return
        if str(target) in parent.stack:
            self.warnings.append(f"{f.rel}: module {name} calls itself (not expanded)")
            return
        mod = self.module(target)
        if mod is None:
            return
        attrs = block.body.attributes
        base = f"{parent.prefix}module.{name}"
        # instances as a resource's: known count/for_each expand (none when empty)
        for address, extra in parent.instances(block, f, base):
            inputs = {}
            for arg, attr in attrs.items():
                if arg in ("source", "version", "providers") or arg in _META:
                    continue
                inputs[arg] = parent.eval(attr.expr, f, extra)
            child = _Instance(self, mod, f"{address}.", inputs, parent.depth + 1, parent.stack + (str(target),))
            child.stack_root = parent.stack_root
            parent.children[address[len(parent.prefix) + len("module."):]] = child
            child.prepare()


_FACTS = Path(__file__).parent / "data" / "terraform-facts.toml"


def _id_aliases() -> Dict[str, str]:
    try:
        import tomllib
    except ModuleNotFoundError:             # pragma: no cover - 3.10
        import tomli as tomllib             # type: ignore[no-redef]
    data = tomllib.loads(_FACTS.read_text(encoding="utf-8"))
    out = {}
    for i, e in enumerate(data.get("id_alias", [])):
        if set(e) != {"type", "argument", "reference"}:
            raise ValueError(f"{_FACTS.name}: id_alias {i + 1} needs exactly type, argument, reference")
        out[e["type"]] = e["argument"]
    return out


def _constraints(related: Dict[str, List[Any]]) -> List[Any]:
    """Z3 facts about the module's unknown ids: distinct within a type, and aliases."""
    import z3

    from .engine import _z3_const
    out: List[Any] = []
    aliases = _id_aliases()
    for rtype, docs in related.items():
        ids = [d["id"] for d in docs if isinstance(d.get("id"), Unknown)]
        keys = {u.key for u in ids}
        if len(keys) > 1:
            out.append(z3.Distinct(*[_z3_const(Unknown(k), z3.StringSort()) for k in sorted(keys)]))
        arg = aliases.get(rtype)
        if arg:
            for d in docs:
                if isinstance(d.get("id"), Unknown) and isinstance(d.get(arg), str):
                    out.append(_z3_const(d["id"], z3.StringSort()) == z3.StringVal(d[arg]))
    return out


def _related(resources: List[Tuple[str, Dict[str, Any], Block, _File, Dict]]) -> Dict[str, List[Any]]:
    out: Dict[str, List[Any]] = {}
    for address, doc, block, _, _ in resources:
        out.setdefault(block.labels[0], []).append(doc)
    return out


def read(paths: List[Tuple[Path, str]], root: Path) -> ReadResult:
    """Every directory holding `.tf` files among `paths`, read as a root module."""
    out = ReadResult()
    reader = _Reader(root.resolve())
    dirs = sorted({p.parent.resolve() for p, _ in paths if p.suffix == ".tf"})
    for d in dirs:
        mod = reader.module(d)
        if mod is None or not mod.files:
            continue
        inst = _Instance(reader, mod, "", {}, 0, (str(d),))
        inst.values = _tfvars(d, reader.warnings, reader.root)
        inst.prepare()
        resources = inst.resources()
        related = _related(resources)
        constraints = _constraints(related)
        for address, doc, block, f, lines in resources:
            r = Resource(format="terraform", type=block.labels[0], name=block.labels[1], file=f.rel,
                         line=block.line, document=doc, lines=lines, views={"self": (), "resources": ()},
                         address=address)
            r.related = related
            r.constraints = constraints
            out.resources.append(r)
            out.files.append(f.rel)
    out.warnings = reader.warnings
    out.files = sorted(set(out.files))
    return out


__all__ = ["read"]
