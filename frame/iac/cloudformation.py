"""CloudFormation templates (YAML with the short-form tags, or JSON), read into resources.

A template is recognised by `AWSTemplateFormatVersion` or by a `Resources` map whose entries
have an `AWS::`-style `Type`. Values are those of a deployment that takes every parameter's
`Default` (a parameter without one is unknown), as the CloudFormation template reference
defines the intrinsic functions:

* `Ref` to a parameter is its default (a list type is split on commas; values stay strings, as
  CloudFormation passes them); to a resource, its physical id, unknown (`<Logical>.Ref`; an
  S3 bucket's is its `BucketName` when it sets one, frame/iac/data/cloudformation-facts.toml);
  `AWS::NoValue` removes the property; other pseudo parameters are unknown.
* `Fn::GetAtt`, `Fn::ImportValue`, `Fn::GetAZs`, `Fn::Cidr` and anything a transform adds are
  unknown; `Fn::Sub`, `Fn::Join`, `Fn::Select`, `Fn::Split`, `Fn::FindInMap`, `Fn::Base64` are
  evaluated when their inputs are known.
* `Conditions` are evaluated (`Fn::Equals`, `Fn::And`, `Fn::Or`, `Fn::Not`, `Condition`); a
  resource whose condition is false is not created, and `Fn::If` takes its branch.

Each resource's document is its `Properties`, plus `Ref` (its physical id). Views: `self`, and
`resources` (the template's other resources by type, `resources["AWS::S3::BucketPolicy"]`).
A property holding an IAM policy document (`PolicyDocument`) gets `policy_public` and
`policy_admin` beside it (frame/iac/aws_policy.py).
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .engine import Unknown
from .model import ReadResult, Resource
from .yaml_doc import YamlError, load_all

_SHORT = ["Ref", "Condition", "Fn::Base64", "Fn::Cidr", "Fn::FindInMap", "Fn::GetAtt", "Fn::GetAZs",
          "Fn::ImportValue", "Fn::Join", "Fn::Select", "Fn::Split", "Fn::Sub", "Fn::Transform", "Fn::And",
          "Fn::Equals", "Fn::If", "Fn::Not", "Fn::Or", "Fn::Length", "Fn::ToJsonString"]


def _tag(name):
    def make(value):
        if name == "Fn::GetAtt" and isinstance(value, str):
            value = value.split(".", 1)
        return {name: value}
    return make


TAGS = {"!" + (n[4:] if n.startswith("Fn::") else n): _tag(n) for n in _SHORT}
TAGS["*"] = lambda value: {"Fn::Unmodelled": value}     # a tool's own tag (!Rain::Embed): unknown
# CloudFormation reads YAML 1.1 without the timestamp tag: 2010-09-09 is a string
# (https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/template-formats.html)
TAGS["!!timestamp"] = "string"

_NO_VALUE = object()


class _Template:
    def __init__(self, doc: Dict[str, Any], rel: str):
        self.doc = doc
        self.rel = rel
        self.params: Dict[str, Any] = {}
        for name, p in (doc.get("Parameters") or {}).items():
            if not isinstance(p, dict):
                continue
            if "Default" in p:
                default = p["Default"]
                ptype = str(p.get("Type", "String"))
                if ptype.startswith("List<") or ptype == "CommaDelimitedList":
                    default = [s.strip() for s in str(default).split(",")] if not isinstance(default, list) else default
                elif not isinstance(default, (list, dict)):
                    default = _string(default)
                self.params[name] = default
            else:
                self.params[name] = Unknown(f"{rel}#Parameters.{name}", f"parameter {name}")
        self.mappings = doc.get("Mappings") or {}
        self.conditions_src = doc.get("Conditions") or {}
        self.conditions: Dict[str, Any] = {}
        self.resources = doc.get("Resources") or {}

    # -- conditions --------------------------------------------------------------------------

    def condition(self, name: str, busy=()) -> Any:
        if name in self.conditions:
            return self.conditions[name]
        if name not in self.conditions_src or name in busy:
            return Unknown(f"{self.rel}#Conditions.{name}", f"condition {name}")
        v = self._cond(self.conditions_src[name], busy + (name,))
        self.conditions[name] = v
        return v

    def _cond(self, e: Any, busy) -> Any:
        if isinstance(e, dict) and len(e) == 1:
            (fn, arg), = e.items()
            if fn == "Condition" and isinstance(arg, str):
                return self.condition(arg, busy)
            if fn == "Fn::Equals" and isinstance(arg, list) and len(arg) == 2:
                a, b = (self.value(x) for x in arg)
                if _has_unknown(a) or _has_unknown(b):
                    return Unknown(f"{self.rel}#cond:{json.dumps(e, sort_keys=True, default=str)}", "a condition")
                return _string(a) == _string(b) if not isinstance(a, (list, dict)) else a == b
            if fn in ("Fn::And", "Fn::Or") and isinstance(arg, list):
                vals = [self._cond(x, busy) for x in arg]
                want = fn == "Fn::Or"
                if any(v is want for v in vals):
                    return want
                if any(isinstance(v, Unknown) for v in vals):
                    return Unknown(f"{self.rel}#cond:{json.dumps(e, sort_keys=True, default=str)}", "a condition")
                return not want
            if fn == "Fn::Not" and isinstance(arg, list) and len(arg) == 1:
                v = self._cond(arg[0], busy)
                return v if isinstance(v, Unknown) else (not v)
        return Unknown(f"{self.rel}#cond:{json.dumps(e, sort_keys=True, default=str)}", "a condition")

    # -- values ------------------------------------------------------------------------------

    def value(self, e: Any) -> Any:
        """A property value with its intrinsic functions evaluated; `_NO_VALUE` for AWS::NoValue."""
        if isinstance(e, list):
            out = [self.value(x) for x in e]
            return [x for x in out if x is not _NO_VALUE]
        if not isinstance(e, dict):
            return e
        if len(e) == 1:
            (fn, arg), = e.items()
            if fn == "Ref" or fn.startswith("Fn::"):
                return self._fn(fn, arg, e)
        out = {}
        for k, v in e.items():
            r = self.value(v)
            if r is not _NO_VALUE:
                out[k] = r
        return out

    def _unknown(self, e: Any, text: str) -> Unknown:
        return Unknown(f"{self.rel}#{json.dumps(e, sort_keys=True, default=str)}", text)

    def _fn(self, fn: str, arg: Any, e: Any) -> Any:
        if fn == "Ref":
            if not isinstance(arg, str):
                return self._unknown(e, "Ref")
            if arg == "AWS::NoValue":
                return _NO_VALUE
            if arg in self.params:
                return self.params[arg]
            if arg in self.resources:
                return Unknown(f"{self.rel}#{arg}.Ref", f"{arg} (Ref)")
            return Unknown(f"{self.rel}#{arg}", arg)
        if fn == "Fn::If" and isinstance(arg, list) and len(arg) == 3 and isinstance(arg[0], str):
            c = self.condition(arg[0])
            if isinstance(c, Unknown):
                return self._unknown(e, f"Fn::If {arg[0]}")
            return self.value(arg[1] if c else arg[2])
        if fn == "Fn::Sub":
            return self._sub(arg, e)
        if fn == "Fn::Join" and isinstance(arg, list) and len(arg) == 2:
            sep, items = self.value(arg[0]), self.value(arg[1])
            if not isinstance(sep, str) or not isinstance(items, list) or _has_unknown(items) \
                    or not all(isinstance(x, (str, int, float)) and not isinstance(x, bool) for x in items):
                return self._unknown(e, "Fn::Join")
            return sep.join(_string(x) for x in items)
        if fn == "Fn::Select" and isinstance(arg, list) and len(arg) == 2:
            i, items = self.value(arg[0]), self.value(arg[1])
            try:
                n = int(_string(i))
            except (ValueError, TypeError):
                return self._unknown(e, "Fn::Select")
            if isinstance(items, list) and 0 <= n < len(items):
                return items[n]
            return self._unknown(e, "Fn::Select")
        if fn == "Fn::Split" and isinstance(arg, list) and len(arg) == 2:
            sep, s = self.value(arg[0]), self.value(arg[1])
            if isinstance(sep, str) and sep and isinstance(s, str):
                return s.split(sep)
            return self._unknown(e, "Fn::Split")
        if fn == "Fn::FindInMap" and isinstance(arg, list) and len(arg) == 3:
            keys = [self.value(x) for x in arg]
            if all(isinstance(k, str) for k in keys):
                try:
                    return self.value(self.mappings[keys[0]][keys[1]][keys[2]])
                except (KeyError, TypeError):
                    pass
            return self._unknown(e, "Fn::FindInMap")
        if fn == "Fn::Base64":
            s = self.value(arg)
            if isinstance(s, str):
                return base64.b64encode(s.encode("utf-8")).decode("ascii")
            return self._unknown(e, "Fn::Base64")
        if fn == "Fn::GetAtt" and isinstance(arg, list) and len(arg) == 2 and all(isinstance(a, str) for a in arg):
            return Unknown(f"{self.rel}#{arg[0]}.{arg[1]}", f"{arg[0]}.{arg[1]}")
        return self._unknown(e, fn)

    def _sub(self, arg: Any, e: Any) -> Any:
        if isinstance(arg, list) and len(arg) == 2 and isinstance(arg[0], str) and isinstance(arg[1], dict):
            text, extra = arg[0], {k: self.value(v) for k, v in arg[1].items()}
        elif isinstance(arg, str):
            text, extra = arg, {}
        else:
            return self._unknown(e, "Fn::Sub")
        out, i = [], 0
        while i < len(text):
            j = text.find("${", i)
            if j < 0:
                out.append(text[i:])
                break
            out.append(text[i:j])
            k = text.find("}", j)
            if k < 0:
                out.append(text[j:])
                break
            name = text[j + 2:k]
            if name.startswith("!"):                 # ${!Literal} is the text ${Literal}
                out.append("${" + name[1:] + "}")
            else:
                if name in extra:
                    v = extra[name]
                elif "." in name:
                    res, att = name.split(".", 1)
                    v = Unknown(f"{self.rel}#{res}.{att}", name)
                else:
                    v = self._fn("Ref", name, {"Ref": name})
                if isinstance(v, Unknown) or v is _NO_VALUE or isinstance(v, (list, dict)):
                    return self._unknown(e, "Fn::Sub")
                out.append(_string(v))
            i = k + 1
        return "".join(out)


def _string(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float) and v == int(v):
        return str(int(v))
    return str(v)


def _has_unknown(v) -> bool:
    if isinstance(v, Unknown):
        return True
    if isinstance(v, list):
        return any(_has_unknown(x) for x in v)
    if isinstance(v, dict):
        return any(_has_unknown(x) for x in v.values())
    return False


def _annotate(doc: Any, key: str) -> None:
    """`policy_public` / `policy_admin` beside every PolicyDocument (CloudFormation takes the
    document as an object, or as a JSON string)."""
    from . import aws_policy
    if isinstance(doc, list):
        for i, x in enumerate(doc):
            _annotate(x, f"{key}[{i}]")
        return
    if not isinstance(doc, dict):
        return
    for k, v in list(doc.items()):
        _annotate(v, f"{key}.{k}")
    for name in ("PolicyDocument",):
        if name in doc:
            pd = doc[name]
            structure = aws_policy.document(pd) if not isinstance(pd, Unknown) else None
            for field, fn in (("policy_public", aws_policy.is_public), ("policy_admin", aws_policy.grants_everything)):
                verdict = fn(structure) if structure is not None else None
                doc[field] = verdict if verdict is not None else Unknown(f"{key}.{field}", f"the {name} of {key}")


def is_template(doc: Any) -> bool:
    if not isinstance(doc, dict):
        return False
    if "AWSTemplateFormatVersion" in doc:
        return True
    res = doc.get("Resources")
    return isinstance(res, dict) and bool(res) and all(
        isinstance(r, dict) and isinstance(r.get("Type"), str) and "::" in r["Type"] for r in res.values())


def _facts_data() -> Dict[str, Any]:
    try:
        import tomllib
    except ModuleNotFoundError:             # pragma: no cover - 3.10
        import tomli as tomllib             # type: ignore[no-redef]
    data = tomllib.loads((Path(__file__).parent / "data" / "cloudformation-facts.toml").read_text(encoding="utf-8"))
    if set(data) - {"ref_alias", "undocumented_default"}:
        raise ValueError(f"cloudformation-facts.toml: unknown table(s) {sorted(set(data) - {'ref_alias', 'undocumented_default'})}")
    for i, e in enumerate(data.get("undocumented_default", [])):
        if set(e) != {"type", "object", "properties", "reference"}:
            raise ValueError(f"cloudformation-facts.toml: undocumented_default {i + 1} needs exactly "
                             "type, object, properties, reference")
    return data


def _facts() -> Dict[str, str]:
    out = {}
    for i, e in enumerate(_facts_data().get("ref_alias", [])):
        if set(e) != {"type", "property", "reference"}:
            raise ValueError(f"cloudformation-facts.toml: ref_alias {i + 1} needs exactly type, property, reference")
        out[e["type"]] = e["property"]
    return out


def _undocumented(rtype: str, props: Dict[str, Any], logical: str) -> None:
    for e in _facts_data().get("undocumented_default", []):
        obj = props.get(e["object"]) if e["type"] == rtype else None
        if isinstance(obj, dict):
            for name in e["properties"]:
                if name not in obj:
                    obj[name] = Unknown(f"{logical}.{e['object']}.{name}",
                                        f"{e['object']}.{name} of {logical} (left out; its default is not documented)")


def _constraints(related: Dict[str, List[Any]]) -> List[Any]:
    import z3

    from .engine import _z3_const
    out: List[Any] = []
    aliases = _facts()
    for rtype, docs in related.items():
        keys = sorted({d["Ref"].key for d in docs if isinstance(d.get("Ref"), Unknown)})
        if len(keys) > 1:
            out.append(z3.Distinct(*[_z3_const(Unknown(k), z3.StringSort()) for k in keys]))
        prop = aliases.get(rtype)
        if prop:
            for d in docs:
                if isinstance(d.get("Ref"), Unknown) and isinstance(d.get(prop), str):
                    out.append(_z3_const(d["Ref"], z3.StringSort()) == z3.StringVal(d[prop]))
    return out


def read_text(text: str, rel: str, out: ReadResult, json_file: bool = False) -> bool:
    """The template's resources into `out`; False when the text is not a template."""
    try:
        docs = list(load_all(text, tags=TAGS))
    except YamlError as e:
        if json_file:
            try:
                docs = [(json.loads(text), {}, 1)]
            except ValueError:
                return False
        else:
            if "AWSTemplateFormatVersion" in text[:4096] or "AWS::" in text[:4096]:
                out.warnings.append(f"{rel}: not valid YAML: {e}")
            return False
    if len(docs) != 1 or not is_template(docs[0][0]):
        return False
    doc, lines, _ = docs[0]
    t = _Template(doc, rel)
    if doc.get("Transform"):
        out.warnings.append(f"{rel}: uses a transform ({doc['Transform']}); what it adds is not read")
    built: List[Tuple[str, str, Dict[str, Any], Dict, int]] = []
    for logical, res in t.resources.items():
        if not isinstance(res, dict):
            continue
        cond = res.get("Condition")
        if isinstance(cond, str):
            c = t.condition(cond)
            if c is False:
                continue                         # never created
        props = t.value(res.get("Properties") or {})
        if not isinstance(props, dict):
            props = {}
        props["Ref"] = Unknown(f"{rel}#{logical}.Ref", f"{logical} (Ref)")
        _undocumented(str(res.get("Type")), props, logical)
        _annotate(props, logical)
        prefix = ("Resources", logical, "Properties")
        sub = {p[3:]: n for p, n in lines.items() if p[:3] == prefix}
        start = lines.get(("Resources", logical), 1)
        built.append((logical, str(res.get("Type")), props, sub, start))
    related: Dict[str, List[Any]] = {}
    for _, rtype, props, _, _ in built:
        related.setdefault(rtype, []).append(props)
    constraints = _constraints(related)
    for logical, rtype, props, sub, start in built:
        r = Resource(format="cloudformation", type=rtype, name=logical, file=rel, line=start, document=props,
                     lines=sub, views={"self": (), "resources": ()}, address=f"{rtype} {logical}")
        r.related = related
        r.constraints = constraints
        out.resources.append(r)
    if built:
        out.files.append(rel)
    return True


def read(paths: List[Tuple[Path, str]]) -> ReadResult:
    out = ReadResult()
    for path, rel in paths:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        head = text[:20000]
        if "AWSTemplateFormatVersion" not in head and "AWS::" not in head:
            continue
        read_text(text, rel, out, json_file=path.suffix.lower() == ".json")
    return out


__all__ = ["TAGS", "is_template", "read", "read_text"]
