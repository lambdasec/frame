"""IAM policy documents: is a resource policy public, does an identity policy grant everything?

Both answers are True, False or None (not decided: a construct the rules here do not cover, or
a document only known at apply time). "Public" is AWS's definition for S3
(`data/aws-public-policy.toml`): every statement that allows something must be limited to
fixed values of a principal or of the listed condition keys. A policy with a Deny statement is
not decided when it would otherwise be public (AWS's evaluation weighs denies, this one does
not).
"""

from __future__ import annotations

import ipaddress
import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]

DATA = Path(__file__).parent / "data" / "aws-public-policy.toml"


@lru_cache(maxsize=1)
def _rules():
    d = tomllib.loads(DATA.read_text(encoding="utf-8"))
    return ({k.lower() for k in d["fixed_keys"]}, set(d["pinning_operators"]),
            tuple(d["public_canned_acls"]), tuple(d["public_group_uris"]))


def public_canned_acls():
    return list(_rules()[2])


def public_group_uris():
    return list(_rules()[3])


def document(value: Any) -> Optional[dict]:
    """A policy document from a JSON string (or an already parsed one); None if it is not one."""
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return None
    try:
        doc = json.loads(value)
    except ValueError:
        return None
    return doc if isinstance(doc, dict) else None


def _list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _statements(doc: dict) -> Optional[list]:
    st = doc.get("Statement")
    st = _list(st)
    return st if all(isinstance(s, dict) for s in st) else None


def _unknown(v) -> bool:
    from .hcl import contains_unknown
    return contains_unknown(v)


def _fixed(value) -> bool:
    return isinstance(value, str) and "*" not in value and "?" not in value and "${" not in value


def _narrow_ip(value) -> bool:
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    if net.version == 4:
        private = any(net.subnet_of(ipaddress.ip_network(p)) for p in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
        return private or net.prefixlen >= 8
    return net.prefixlen >= 32


def _pins(op: str, key: str, values) -> Optional[bool]:
    """Does one condition limit the statement to fixed values of a listed key?"""
    fixed_keys, pinning, _, _ = _rules()
    op_base = op.split(":")[-1]
    if op_base.endswith("IfExists") or key.lower() not in fixed_keys:
        return False
    if op_base not in pinning:
        return False if op_base.startswith(("StringNot", "ArnNot", "NotIp")) or op_base in ("Null", "Bool") else None
    vals = _list(values)
    if _unknown(vals):
        return None                             # a value known only at apply time
    if not vals or not all(_fixed(v) for v in vals):
        return False
    if key.lower() == "aws:sourceip":
        return all(_narrow_ip(v) for v in vals)
    if key.lower() == "aws:userid" and any(v.endswith(":*") for v in vals):
        return False
    return True


def _principal_public(st: dict) -> Optional[bool]:
    if "NotPrincipal" in st:
        return None
    p = st.get("Principal")
    if _unknown(p):
        return True if p == "*" or (isinstance(p, dict) and "*" in _list(p.get("AWS"))) else None
    if p == "*":
        return True
    if isinstance(p, dict):
        aws = _list(p.get("AWS"))
        return "*" in aws
    return False if p is not None else None


def is_public(value: Any) -> Optional[bool]:
    """Does this resource policy grant anything to the public, as AWS decides it for S3?"""
    doc = document(value)
    if doc is None:
        return None
    statements = _statements(doc)
    if statements is None:
        return None
    verdict: Optional[bool] = False
    for st in statements:
        if _unknown(st.get("Effect")):
            verdict = None
            continue
        if st.get("Effect") != "Allow":
            continue
        who = _principal_public(st)
        if who is False:
            continue
        if who is None:
            verdict = None
            continue
        cond = st.get("Condition") or {}
        if _unknown(list(cond.keys()) if isinstance(cond, dict) else cond):
            verdict = None
            continue
        if not isinstance(cond, dict):
            verdict = None
            continue
        pinned: Optional[bool] = False
        for op, entries in cond.items():
            if not isinstance(entries, dict):
                pinned = None
                continue
            for key, values in entries.items():
                p = _pins(op, key, values)
                if p:
                    pinned = True
                elif p is None and pinned is False:
                    pinned = None
        if pinned is True:
            continue
        if pinned is None:
            verdict = None
            continue
        if any(s.get("Effect") == "Deny" for s in statements):
            return None
        return True
    return verdict


def grants_everything(value: Any) -> Optional[bool]:
    """Does an identity policy allow every action on every resource, unconditionally?"""
    doc = document(value)
    if doc is None:
        return None
    statements = _statements(doc)
    if statements is None:
        return None
    verdict: Optional[bool] = False
    for st in statements:
        if _unknown(st.get("Effect")):
            verdict = None
            continue
        if st.get("Effect") != "Allow" or "NotResource" in st or "NotAction" in st:
            continue
        actions, resources = _list(st.get("Action")), _list(st.get("Resource"))
        every_action = any(a in ("*", "*:*") for a in actions)
        every_resource = "*" in resources
        maybe = (every_action or _unknown(actions)) and (every_resource or _unknown(resources))
        if every_action and every_resource and "Condition" not in st:
            return True
        if maybe:
            verdict = None                      # an unknown part, or only under its conditions
    return verdict


def from_policy_document_data(doc: dict) -> Optional[dict]:
    """The document a `data "aws_iam_policy_document"` makes from its blocks (the provider's
    mapping: effect defaults to Allow; principals {type, identifiers} become Principal, type
    "*" with identifier "*" the bare "*"; condition {test, variable, values} becomes
    Condition[test][variable]). None when it merges other documents or has unknown parts."""
    from .engine import Unknown
    from .hcl import contains_unknown
    for merged in ("source_policy_documents", "override_policy_documents", "source_json", "override_json"):
        if doc.get(merged):
            return None
    if isinstance(doc.get("statement"), Unknown):
        return None
    out = []
    for st in doc.get("statement", []) or []:
        if isinstance(st, Unknown) or not isinstance(st, dict):
            return None
        s: dict = {"Effect": st.get("effect") or "Allow"}
        for src, dst in (("actions", "Action"), ("not_actions", "NotAction"), ("resources", "Resource"),
                         ("not_resources", "NotResource")):
            if st.get(src) is not None:
                s[dst] = list(st[src])
        for src, dst in (("principals", "Principal"), ("not_principals", "NotPrincipal")):
            blocks = st.get(src) or []
            if not blocks:
                continue
            if len(blocks) == 1 and blocks[0].get("type") == "*" and list(blocks[0].get("identifiers") or []) == ["*"]:
                s[dst] = "*"
                continue
            principal: dict = {}
            for b in blocks:
                principal.setdefault(b.get("type"), []).extend(b.get("identifiers") or [])
            s[dst] = principal
        cond: dict = {}
        for c in st.get("condition") or []:
            cond.setdefault(c.get("test"), {}).setdefault(c.get("variable"), []).extend(c.get("values") or [])
        if cond:
            s["Condition"] = cond
        out.append(s)
    return {"Version": doc.get("version") or "2012-10-17", "Statement": out}


__all__ = ["document", "from_policy_document_data", "grants_everything", "is_public", "public_canned_acls", "public_group_uris"]
