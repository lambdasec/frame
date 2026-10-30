"""Terraform (frame/iac/hcl.py, terraform.py, addresses.py, packs/data/terraform/aws.toml).

The HCL evaluator is checked against HashiCorp's own library: `*.expected.jsonl.gz` is every
attribute of the fixture modules as hclsyntax and go-cty evaluate it (tests/iac_real/hcl). Frame
must give each the same value, or an unknown: never a different one."""

import gzip
import ipaddress
import json
import random
from pathlib import Path

import pytest

from frame.iac.addresses import may_reach
from frame.iac.engine import Unknown
from frame.iac.hcl import HclError, Scope, convert, evaluate, num_text, parse, type_constraint
from frame.iac.scan import scan

FIXTURES = Path(__file__).parent / "fixtures" / "iac" / "terraform"


# --- the evaluator against HCL ----------------------------------------------------------

class _Roots(dict):
    """The harness's context: a name that is not var or local is unknown."""

    def __contains__(self, k):
        return True

    def __getitem__(self, k):
        return dict.__getitem__(self, k) if dict.__contains__(self, k) else Unknown(f"root:{k}", k)


def _encode(v):
    if isinstance(v, Unknown):
        return {"k": "u"}
    if v is None:
        return {"k": "null"}
    if isinstance(v, bool):
        return {"k": "b", "v": v}
    if isinstance(v, (int, float)):
        return {"k": "n", "v": num_text(v)}
    if isinstance(v, str):
        return {"k": "s", "v": v}
    if isinstance(v, list):
        return {"k": "l", "v": [_encode(x) for x in v]}
    return {"k": "o", "v": {k: _encode(x) for k, x in v.items()}}


def _records(root: Path):
    """Every attribute's value under the harness's context, keyed as the harness keys it."""
    out = {}
    no_functions = Scope({}, functions={})
    for d in sorted({p.parent for p in root.rglob("*.tf")}):
        files = []
        for f in sorted(d.glob("*.tf")):
            files.append((f.relative_to(root).as_posix(), *parse(f.read_text(encoding="utf-8"))))
        var, decl, locals_ = {}, {}, {}
        for rel, body, src in files:
            for b in body.blocks:
                if b.type == "variable":
                    decl[b.labels[0]] = (b, src)
                    try:
                        var[b.labels[0]] = (evaluate(b.body.attributes["default"].expr, no_functions, src)
                                            if "default" in b.body.attributes else Unknown(b.labels[0], ""))
                    except HclError:
                        var[b.labels[0]] = Unknown(b.labels[0], "")
                elif b.type == "locals":
                    for n, a in b.body.attributes.items():
                        locals_[n] = (a, src)
        for t in [d / "terraform.tfvars"] + sorted(d.glob("*.auto.tfvars")):
            if t.is_file():
                body, src = parse(t.read_text())
                for a in body.attributes.values():
                    if a.name in var:
                        try:
                            var[a.name] = evaluate(a.expr, no_functions, src)
                        except HclError:
                            pass
        for n, (b, src) in decl.items():
            v, a = var[n], b.body.attributes
            if isinstance(v, Unknown):
                continue
            if v is None and "nullable" in a and a["nullable"].expr.value is False and "default" in a:
                v = evaluate(a["default"].expr, no_functions, src)
            if "type" in a:
                try:
                    v = convert(v, type_constraint(a["type"].expr, src), src, no_functions)
                except HclError:
                    v = Unknown(n, "")
            var[n] = v
        roots = _Roots(var=var)
        lv = {n: Unknown(f"local.{n}", n) for n in locals_}
        for _ in range(len(locals_) + 1):
            roots["local"] = dict(lv)
            nxt = {}
            for n, (a, src) in locals_.items():
                try:
                    nxt[n] = evaluate(a.expr, Scope(roots), src)
                except HclError:
                    nxt[n] = Unknown(f"local.{n}", n)
            lv = nxt
        roots["local"] = lv

        def walk(rel, src, prefix, body, top):
            for n in sorted(body.attributes):
                try:
                    rec = {"value": _encode(evaluate(body.attributes[n].expr, Scope(roots), src))}
                except HclError:
                    rec = {"error": True}
                out[(rel, prefix + n)] = rec
            counts = {}
            for b in body.blocks:
                if b.type in ("dynamic", "variable", "locals"):
                    continue
                key = b.type + ("." + ".".join(b.labels) if b.labels and top else "")
                walk(rel, src, f"{prefix}{key}#{counts.get(key, 0)}.", b.body, False)
                counts[key] = counts.get(key, 0) + 1

        for rel, body, src in files:
            for b in body.blocks:
                if b.type == "locals":
                    for n in b.body.attributes:
                        out[(rel, "locals." + n)] = {"value": _encode(lv[n])}
            walk(rel, src, "", body, True)
    return out


def _compare(go, ours) -> str:
    """same / lossy (ours unknown where HCL knows) / wrong."""
    if "error" in go:
        return "same" if "error" in ours or ours["value"]["k"] == "u" else "wrong"
    if "error" in ours:
        return "lossy"

    def cmp(g, p):
        if p["k"] == "u":
            return "same" if g["k"] == "u" else "lossy"
        if g["k"] != p["k"]:
            return "wrong"
        if g["k"] == "l":
            if len(g["v"]) != len(p["v"]):
                return "wrong"
            rs = [cmp(a, b) for a, b in zip(g["v"], p["v"])]
        elif g["k"] == "o":
            if set(g["v"]) != set(p["v"]):
                return "wrong"
            rs = [cmp(g["v"][k], p["v"][k]) for k in g["v"]]
        else:
            return "same" if g.get("v") == p.get("v") else "wrong"
        return "wrong" if "wrong" in rs else ("lossy" if "lossy" in rs else "same")
    return cmp(go["value"], ours["value"])


@pytest.mark.parametrize("name, attributes, lossy", [("terragoat", 859, 0), ("terraform-aws-rds", 2417, 0)])
def test_every_attribute_evaluates_as_hcl_evaluates_it(name, attributes, lossy):
    with gzip.open(FIXTURES / f"{name}.expected.jsonl.gz", "rt") as fh:
        expected = {(r["file"], r["path"]): r for r in map(json.loads, fh)}
    ours = _records(FIXTURES / name)
    assert set(ours) == set(expected)
    outcome = {k: _compare(expected[k], ours[k]) for k in expected}
    assert [k for k, v in outcome.items() if v == "wrong"] == []
    assert len(expected) == attributes
    assert sum(v == "lossy" for v in outcome.values()) == lossy


def _value(text, **roots):
    body, src = parse(f"x = {text}\n")
    return evaluate(body.attributes["x"].expr, Scope(_Roots(roots)), src)


@pytest.mark.parametrize("text, value", [
    ('"a\\tb\\u00e9 $${x} %%{y}"', "a\tbé ${x} %{y}"),
    ('"${1 + 2}"', 3),                                  # a lone interpolation keeps its type
    ('"n=${1.5 * 2}"', "n=3"),
    ("<<-EOT\n    one\n      two\n    EOT", "one\n  two\n"),
    ("<<EOT\nraw \\n\nEOT", "raw \\n\n"),
    ("1 == \"1\"", False),
    ('"1" + 1', 2),
    ("true ? 1 : 2", 1),
    ("-7 % 2", -1),
    ("[for k, v in {b = 2, a = 1} : \"${k}${v}\" if v > 0]", ["a1", "b2"]),
    ("{for s in [\"x\", \"y\", \"x\"] : s => s...}", {"x": ["x", "x"], "y": ["y"]}),
    ("[{a = 1}, {a = 2}][*].a", [1, 2]),
    ('coalesce("", null, "c")', "c"),
    ('jsonencode({b = [1, 1.5], a = "<&>"})', '{"a":"\\u003c\\u0026\\u003e","b":[1,1.5]}'),
    ('merge({a = var.u}, {b = 1})["b"]', 1),
    ("false && var.u", False),
    ("var.u || true", True),
])
def test_expressions(text, value):
    assert _value(text, var={"u": Unknown("u", "u")}) == value


@pytest.mark.parametrize("text", ["var.u", '"${var.u}-x"', "var.u ? 1 : 2", "true ? 1 : \"a\"",
                                  "format(\"%s\", 1)", "try(var.u, 1)", "1 / 3"])
def test_what_is_not_decided_is_unknown(text):
    assert isinstance(_value(text, var={"u": Unknown("u", "u")}), Unknown)


def test_type_constraints_convert_with_optional_defaults():
    body, src = parse('t = object({ port = number, tls = optional(bool, true), tags = optional(map(string)) })\n')
    t = type_constraint(body.attributes["t"].expr, src)
    assert convert({"port": "22", "extra": 1}, t, src) == {"port": 22, "tls": True, "tags": None}
    with pytest.raises(HclError):
        convert({"tls": False}, t, src)


# --- modules -------------------------------------------------------------------------------

def _tf(tmp_path, files):
    for name, text in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return scan(tmp_path)


SG = '''
resource "aws_security_group" "web" {
  name = "web"
  ingress {
    from_port   = var.port
    to_port     = var.port
    protocol    = "tcp"
    cidr_blocks = [var.cidr]
  }
}
'''


@pytest.mark.parametrize("files, found", [
    ({"main.tf": SG + 'variable "port" { default = 22 }\nvariable "cidr" { default = "0.0.0.0/0" }\n'}, True),
    ({"main.tf": SG + 'variable "port" { default = 22 }\nvariable "cidr" { default = "10.0.0.0/8" }\n'}, False),
    ({"main.tf": SG + 'variable "port" {\n  default = 22\n}\nvariable "cidr" {\n  default = "10.0.0.0/8"\n}\n',
      "terraform.tfvars": 'cidr = "0.0.0.0/0"\n'}, True),                               # tfvars win
    ({"main.tf": SG + 'variable "port" { default = 443 }\nvariable "cidr" { default = "0.0.0.0/0" }\n',
      "x.auto.tfvars": "port = 3389\n"}, True),
    ({"main.tf": SG + 'variable "port" {\n  type = number\n  default = "22"\n}\nvariable "cidr" { default = "::/0" }\n'},
     False),                                                         # an IPv4 rule's CIDR must be IPv4
])
def test_variables_take_the_values_terraform_would(tmp_path, files, found):
    run = _tf(tmp_path, files)
    assert ("aws-sg-admin-from-internet" in {f.rule for f in run.findings}) == found


def test_a_variable_without_a_value_leaves_the_policy_undecided(tmp_path):
    run = _tf(tmp_path, {"main.tf": SG + 'variable "port" { default = 22 }\nvariable "cidr" {}\n'})
    assert not run.findings
    assert [u["rule"] for u in run.undecided] == ["aws-sg-admin-from-internet"]


def test_local_modules_count_and_for_each(tmp_path):
    run = _tf(tmp_path, {
        "mod/main.tf": 'variable "public" {}\nresource "aws_db_instance" "db" {\n  publicly_accessible = var.public\n'
                       '  storage_encrypted = true\n}\n',
        "main.tf": 'module "a" {\n  source = "./mod"\n  public = true\n}\n'
                   'module "b" {\n  source = "./mod"\n  public = false\n}\n'
                   'module "none" {\n  source   = "./mod"\n  for_each = {}\n  public   = true\n}\n'
                   'module "each" {\n  source   = "./mod"\n  for_each = { x = true, y = false }\n  public = each.value\n}\n',
    })
    public = {f.resource for f in run.findings if f.rule == "aws-rds-public"}
    assert public == {"module.a.aws_db_instance.db", 'module.each["x"].aws_db_instance.db'}
    assert [u["resource"] for u in run.undecided] == ["aws_db_instance.db"]     # mod/ read alone


def test_an_attribute_another_resource_computes_is_one_unknown(tmp_path):
    run = _tf(tmp_path, {"main.tf": '''
resource "aws_ebs_encryption_by_default" "on" {
  enabled = true
}
resource "aws_ebs_volume" "v" {
  size = 1
}
resource "aws_ebs_volume" "copy" {
  size        = 1
  snapshot_id = aws_ebs_snapshot.s.id
}
'''})
    assert "aws-ebs-unencrypted" not in {f.rule for f in run.findings}
    run = _tf(tmp_path, {"main.tf": 'resource "aws_ebs_volume" "v" {\n  size = 1\n}\n'})
    assert [(f.rule, f.resource) for f in run.findings] == [("aws-ebs-unencrypted", "aws_ebs_volume.v")]


# --- security groups -----------------------------------------------------------------------

@pytest.mark.parametrize("rule, rid", [
    ('ingress {\n  from_port = 0\n  to_port = 0\n  protocol = "-1"\n  cidr_blocks = ["0.0.0.0/0"]\n}',
     "aws-sg-all-from-internet"),
    ('ingress {\n  from_port = 20\n  to_port = 25\n  protocol = "6"\n  ipv6_cidr_blocks = ["::/0"]\n}',
     "aws-sg-admin-from-internet"),
    ('ingress {\n  from_port = 22\n  to_port = 22\n  protocol = "tcp"\n  cidr_blocks = ["0.0.0.0/1", "10.0.0.0/8"]\n}',
     "aws-sg-admin-from-internet"),
    ('ingress {\n  from_port = 22\n  to_port = 22\n  protocol = "udp"\n  cidr_blocks = ["0.0.0.0/0"]\n}', None),
    ('ingress {\n  from_port = 80\n  to_port = 443\n  protocol = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}', None),
    ('ingress {\n  from_port = 22\n  to_port = 22\n  protocol = "tcp"\n  cidr_blocks = ["100.64.0.0/10"]\n}', None),
])
def test_inline_security_group_rules(tmp_path, rule, rid):
    run = _tf(tmp_path, {"main.tf": f'resource "aws_security_group" "g" {{\n{rule}\n}}\n'})
    assert {f.rule for f in run.findings} == ({rid} if rid else set())


def test_separate_rule_resources(tmp_path):
    run = _tf(tmp_path, {"main.tf": '''
resource "aws_security_group_rule" "ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.g.id
}
resource "aws_security_group_rule" "out" {
  type        = "egress"
  from_port   = 0
  to_port     = 0
  protocol    = "-1"
  cidr_blocks = ["0.0.0.0/0"]
  security_group_id = aws_security_group.g.id
}
resource "aws_vpc_security_group_ingress_rule" "rdp" {
  security_group_id = aws_security_group.g.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 3389
  to_port           = 3389
  ip_protocol       = "tcp"
}
'''})
    assert {(f.rule, f.resource, f.line) for f in run.findings} == {
        ("aws-sg-admin-from-internet", "aws_security_group_rule.ssh", 7),
        ("aws-sg-admin-from-internet", "aws_vpc_security_group_ingress_rule.rdp", 20)}


# --- the fixtures, as checkov's equivalent checks see them ---------------------------------

def test_terragoat():
    run = scan(FIXTURES / "terragoat")
    assert {(f.rule, f.resource) for f in run.findings} == {
        ("aws-rds-public", "aws_db_instance.default"), ("aws-rds-unencrypted", "aws_db_instance.default"),
        ("aws-ebs-unencrypted", "aws_ebs_volume.web_host_storage"),
        ("aws-sg-admin-from-internet", "aws_security_group.web-node")}


# --- addresses -------------------------------------------------------------------------------

def test_internet_reachability_agrees_with_pythons_registry_for_unicast_ipv4():
    """Python's ipaddress encodes the same IANA registry; multicast is never a source here."""
    random.seed(7)
    for _ in range(5000):
        a = ipaddress.IPv4Address(random.getrandbits(32))
        if a.is_multicast:
            assert not may_reach(str(a))
        else:
            assert may_reach(f"{a}/32") == a.is_global, a


@pytest.mark.parametrize("cidr, reachable", [
    ("0.0.0.0/0", True), ("0.0.0.0/1", True), ("10.0.0.0/8", False), ("192.0.0.0/24", True),   # 192.0.0.9
    ("192.0.0.0/29", False), ("::/0", True), ("fc00::/7", False), ("2001:db8::/32", False),
    ("2002::/16", True), ("10.0.0.1/8", False), ("not a cidr", False),
])
def test_cidrs(cidr, reachable):
    assert may_reach(cidr) is reachable


# --- S3 and IAM --------------------------------------------------------------------------

from frame.iac import aws_policy  # noqa: E402

BUCKET = 'resource "aws_s3_bucket" "b" {\n  bucket = "shop-assets"\n}\n'
ACL = 'resource "aws_s3_bucket_acl" "a" {\n  bucket = aws_s3_bucket.b.id\n  acl    = "public-read"\n}\n'
OWNERSHIP = ('resource "aws_s3_bucket_ownership_controls" "o" {\n  bucket = aws_s3_bucket.b.id\n'
             '  rule {\n    object_ownership = "ObjectWriter"\n  }\n}\n')
PAB_OFF = 'resource "aws_s3_bucket_public_access_block" "p" {\n  bucket = aws_s3_bucket.b.id\n}\n'
PAB_IGNORE = ('resource "aws_s3_bucket_public_access_block" "p" {\n  bucket = aws_s3_bucket.b.id\n'
              '  ignore_public_acls = true\n}\n')
ACCOUNT_BLOCK = 'resource "aws_s3_account_public_access_block" "acct" {\n  block_public_policy = true\n}\n'
POLICY = '''resource "aws_s3_bucket_policy" "p" {
  bucket = "shop-assets"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = "*", Action = "s3:GetObject", Resource = "arn:aws:s3:::shop-assets/*" }]
  })
}
'''


@pytest.mark.parametrize("parts, public", [
    ([ACL], False),                                    # new buckets: ACLs disabled, public access blocked
    ([ACL, OWNERSHIP], False),                         # ACLs enabled, still blocked by default
    ([ACL, PAB_OFF], False),                           # unblocked, but ACLs are disabled
    ([ACL, OWNERSHIP, PAB_OFF], True),
    ([ACL, OWNERSHIP, PAB_IGNORE], False),
    ([POLICY], False),
    ([POLICY, PAB_OFF], True),                         # the policy names the bucket by name
    ([POLICY, PAB_OFF, ACCOUNT_BLOCK], False),
])
def test_an_s3_bucket_is_public_only_when_the_defaults_are_turned_off(tmp_path, parts, public):
    run = _tf(tmp_path, {"main.tf": BUCKET + "".join(parts)})
    assert ("aws-s3-public" in {f.rule for f in run.findings}) is public
    assert not [u for u in run.undecided if u["rule"] == "aws-s3-public"]


def test_a_bucket_policy_from_a_policy_document_data_source(tmp_path):
    doc = '''data "aws_iam_policy_document" "read" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::shop-assets/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}
resource "aws_s3_bucket_policy" "p" {
  bucket = aws_s3_bucket.b.id
  policy = data.aws_iam_policy_document.read.json
}
'''
    run = _tf(tmp_path, {"main.tf": BUCKET + PAB_OFF + doc})
    assert {f.rule for f in run.findings} == {"aws-s3-public"}
    pinned = doc.replace('    principals {', '    condition {\n      test = "StringEquals"\n'
                         '      variable = "aws:SourceVpce"\n      values = ["vpce-1a2b"]\n    }\n    principals {')
    assert not _tf(tmp_path, {"main.tf": BUCKET + PAB_OFF + pinned}).findings


@pytest.mark.parametrize("statement, public", [
    # AWS's own examples (access-control-block-public-access.html, "The meaning of public")
    ({"Principal": "*", "Resource": "*", "Action": "s3:PutObject", "Effect": "Allow"}, True),
    ({"Principal": "*", "Resource": "*", "Action": "s3:PutObject", "Effect": "Allow",
      "Condition": {"StringLike": {"aws:SourceVpc": "vpc-*"}}}, True),
    ({"Principal": "*", "Resource": "*", "Action": "s3:PutObject", "Effect": "Allow",
      "Condition": {"StringEquals": {"aws:SourceVpc": "vpc-91237329"}}}, False),
    ({"Principal": "*", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*",
      "Condition": {"IpAddress": {"aws:SourceIp": "0.0.0.0/1"}}}, True),             # broader than /8
    ({"Principal": "*", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*",
      "Condition": {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}}, False),
    ({"Principal": "*", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*",
      "Condition": {"StringEqualsIfExists": {"aws:SourceVpc": "vpc-1"}}}, True),
    ({"Principal": "*", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*",
      "Condition": {"Bool": {"aws:SecureTransport": "true"}}}, True),
    ({"Principal": {"AWS": "arn:aws:iam::111122223333:root"}, "Effect": "Allow", "Action": "s3:*", "Resource": "*"},
     False),
    ({"Principal": {"Service": "cloudtrail.amazonaws.com"}, "Effect": "Allow", "Action": "s3:PutObject",
      "Resource": "*"}, False),
    ({"NotPrincipal": {"AWS": "arn:aws:iam::111122223333:root"}, "Effect": "Allow", "Action": "s3:*",
      "Resource": "*"}, None),
])
def test_what_aws_calls_a_public_policy(statement, public):
    assert aws_policy.is_public({"Statement": [statement]}) is public


def test_a_deny_leaves_a_public_grant_undecided():
    allow = {"Principal": "*", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
    deny = {"Principal": "*", "Effect": "Deny", "Action": "s3:*", "Resource": "*",
            "Condition": {"StringNotEquals": {"aws:SourceVpc": "vpc-1"}}}
    assert aws_policy.is_public({"Statement": [allow, deny]}) is None


@pytest.mark.parametrize("policy, admin", [
    ('{"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}', True),
    ('{"Statement": [{"Effect": "Allow", "Action": ["s3:*", "*:*"], "Resource": ["*"]}]}', True),
    ('{"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}', False),
    ('{"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::b"}]}', False),
])
def test_iam_policies_that_allow_everything(tmp_path, policy, admin):
    text = f'resource "aws_iam_policy" "p" {{\n  name = "p"\n  policy = <<EOF\n{policy}\nEOF\n}}\n'
    run = _tf(tmp_path, {"main.tf": text})
    assert ("aws-iam-full-admin" in {f.rule for f in run.findings}) is admin


def test_an_iam_policy_known_only_at_apply_time_is_undecided(tmp_path):
    run = _tf(tmp_path, {"main.tf": 'variable "doc" {}\nresource "aws_iam_policy" "p" {\n  policy = var.doc\n}\n'})
    assert not run.findings
    assert [(u["rule"], u["depends_on"]) for u in run.undecided] == [("aws-iam-full-admin", ["var.doc"])]


def test_references_to_counted_resources_reach_the_instance(tmp_path):
    run = _tf(tmp_path, {"main.tf": '''
resource "aws_s3_bucket" "b" {
  count  = 2
  bucket = "b-${count.index}"
}
resource "aws_s3_bucket_ownership_controls" "o" {
  bucket = aws_s3_bucket.b[1].id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}
resource "aws_s3_bucket_public_access_block" "p" {
  bucket = aws_s3_bucket.b[1].id
}
resource "aws_s3_bucket_acl" "a" {
  bucket = aws_s3_bucket.b[1].id
  acl    = "public-read-write"
}
'''})
    assert [f.resource for f in run.findings] == ["aws_s3_bucket.b[1]"]


def test_two_buckets_are_different_objects_and_an_s3_id_is_its_name(tmp_path):
    """Without these provider facts, a block on bucket A might be a block on bucket B."""
    two = BUCKET + BUCKET.replace('"b"', '"c"').replace("shop-assets", "shop-other") + OWNERSHIP + PAB_OFF + \
        ACL.replace("aws_s3_bucket.b.id", "aws_s3_bucket.c.id")
    run = _tf(tmp_path, {"main.tf": two})
    assert not run.findings and not run.undecided      # the ACL is on c; ownership and the unblock are on b
    named = BUCKET + OWNERSHIP + PAB_OFF + ACL.replace("aws_s3_bucket.b.id", '"shop-assets"')
    assert [f.rule for f in _tf(tmp_path, {"main.tf": named}).findings] == ["aws-s3-public"]
    elsewhere = BUCKET + OWNERSHIP + PAB_OFF + ACL.replace("aws_s3_bucket.b.id", '"someone-elses-bucket"')
    run = _tf(tmp_path, {"main.tf": elsewhere})        # b.id is "shop-assets", so not this bucket
    assert not run.findings and not run.undecided
