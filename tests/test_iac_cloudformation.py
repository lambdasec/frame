"""CloudFormation templates (frame/iac/cloudformation.py, packs/data/cloudformation/aws.toml).

Intrinsic functions are evaluated as the CloudFormation template reference defines them, with
every parameter at its Default; what a deployment decides (a resource's physical id, an
attribute, a parameter without a default) is unknown."""

import json

import pytest

from frame.iac.engine import Unknown
from frame.iac.model import ReadResult
from frame.iac.cloudformation import read_text
from frame.iac.scan import scan

HEAD = "AWSTemplateFormatVersion: '2010-09-09'\n"


def _props(template: str, logical: str = "R", json_file: bool = False):
    out = ReadResult()
    assert read_text(template, "t.yaml", out, json_file=json_file)
    return {r.name: r.document for r in out.resources}.get(logical), out


def _value(expr_yaml: str, extra: str = ""):
    t = HEAD + extra + f"Resources:\n  R:\n    Type: AWS::X::Y\n    Properties:\n      V: {expr_yaml}\n"
    props, _ = _props(t)
    return props.get("V", "<removed>")


PARAMS = """Parameters:
  Env:
    Type: String
    Default: prod
  Port:
    Type: Number
    Default: 22
  Nets:
    Type: CommaDelimitedList
    Default: "10.0.0.0/8, 0.0.0.0/0"
  Secret:
    Type: String
Mappings:
  Region:
    us-east-1:
      Ami: ami-123
"""


@pytest.mark.parametrize("expr, value", [
    ("!Ref Env", "prod"),
    ("!Ref Port", "22"),                                       # a parameter value is a string
    ("!Select [1, !Ref Nets]", "0.0.0.0/0"),
    ('!Sub "app-${Env}-${!Literal}"', "app-prod-${Literal}"),
    ('!Sub ["${A}-${Env}", {A: x}]', "x-prod"),
    ('!Join ["-", [a, !Ref Env, 3]]', "a-prod-3"),
    ('!Split [",", "a,b"]', ["a", "b"]),
    ("!FindInMap [Region, us-east-1, Ami]", "ami-123"),
    ('!Base64 "hi"', "aGk="),
    ("!If [IsProd, first, second]", "first"),
    ("!If [IsDev, first, !Ref AWS::NoValue]", "<removed>"),     # AWS::NoValue removes the property
    ("yes", True),                                              # CloudFormation reads YAML 1.1...
    ("2010-09-09", "2010-09-09"),                               # ...without its timestamp tag
    ('{"Fn::Join": ["", ["a", "b"]]}', "ab"),                   # the long form
])
def test_intrinsic_functions(expr, value):
    conditions = "Conditions:\n  IsProd: !Equals [!Ref Env, prod]\n  IsDev: !Not [!Condition IsProd]\n"
    assert _value(expr, PARAMS + conditions) == value


@pytest.mark.parametrize("expr", ["!Ref Secret", "!GetAtt Other.Arn", "!Ref AWS::Region", '!Sub "${Secret}-x"',
                                  "!ImportValue shared", "!GetAZs ''", "!Rain::Embed file.txt"])
def test_what_a_deployment_decides_is_unknown(expr):
    assert isinstance(_value(expr, PARAMS), Unknown)


def test_a_resource_whose_condition_is_false_is_not_created():
    t = HEAD + PARAMS + "Conditions:\n  IsDev: !Equals [!Ref Env, dev]\nResources:\n" \
        "  R:\n    Type: AWS::X::Y\n    Condition: IsDev\n  S:\n    Type: AWS::X::Y\n"
    _, out = _props(t)
    assert [r.name for r in out.resources] == ["S"]


def test_json_templates_and_files_that_are_not_templates():
    doc = {"Resources": {"R": {"Type": "AWS::RDS::DBInstance", "Properties": {"PubliclyAccessible": "true"}}}}
    props, _ = _props(json.dumps(doc), json_file=True)
    assert props["PubliclyAccessible"] == "true" and isinstance(props["Ref"], Unknown)
    assert not read_text("name: x\nResources: [1]\n", "x.yaml", ReadResult())


# --- policies ---------------------------------------------------------------------------------

def _scan(tmp_path, body: str, params: str = ""):
    (tmp_path / "stack.yaml").write_text(HEAD + params + "Resources:\n" + body)
    return scan(tmp_path)


SG = """  G:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: g
      SecurityGroupIngress:
      - IpProtocol: tcp
        FromPort: !Ref Port
        ToPort: !Ref Port
        CidrIp: !Ref Cidr
"""


@pytest.mark.parametrize("port, cidr, rule", [
    ("22", "0.0.0.0/0", "aws-sg-admin-from-internet"),
    ("3389", "0.0.0.0/1", "aws-sg-admin-from-internet"),
    ("443", "0.0.0.0/0", None),
    ("22", "10.0.0.0/8", None),
])
def test_security_groups_through_parameters(tmp_path, port, cidr, rule):
    params = f"Parameters:\n  Port:\n    Type: Number\n    Default: {port}\n  Cidr:\n    Type: String\n    Default: {cidr}\n"
    run = _scan(tmp_path, SG, params)
    assert {f.rule for f in run.findings} == ({rule} if rule else set())


def test_an_ingress_resource_and_all_traffic(tmp_path):
    run = _scan(tmp_path, """  In:
    Type: AWS::EC2::SecurityGroupIngress
    Properties:
      GroupId: !Ref G
      IpProtocol: "-1"
      CidrIpv6: "::/0"
""")
    assert [(f.rule, f.resource) for f in run.findings] == [("aws-sg-all-from-internet", "AWS::EC2::SecurityGroupIngress In")]


BUCKET = """  B:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: shop-assets
"""
POLICY = """  P:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref B
      PolicyDocument:
        Statement:
        - Effect: Allow
          Principal: "*"
          Action: s3:GetObject
          Resource: arn:aws:s3:::shop-assets/*
"""


@pytest.mark.parametrize("extra, public, undecided", [
    ("", False, False),                                                      # blocked by default
    ("      PublicAccessBlockConfiguration:\n        BlockPublicPolicy: false\n        RestrictPublicBuckets: false\n",
     True, False),
    ("      PublicAccessBlockConfiguration:\n        BlockPublicPolicy: false\n", False, True),   # one left out
    ("      AccessControl: PublicRead\n", False, False),                     # ACLs disabled: no effect
])
def test_bucket_policies_and_acls_under_the_2023_defaults(tmp_path, extra, public, undecided):
    run = _scan(tmp_path, BUCKET + extra + POLICY)
    assert ("aws-s3-public" in {f.rule for f in run.findings}) is public
    assert bool([u for u in run.undecided if u["rule"] == "aws-s3-public"]) is undecided


def test_a_public_acl_needs_acls_enabled_and_unblocked(tmp_path):
    body = BUCKET + """      AccessControl: PublicReadWrite
      OwnershipControls:
        Rules:
        - ObjectOwnership: ObjectWriter
      PublicAccessBlockConfiguration:
        BlockPublicAcls: false
        IgnorePublicAcls: false
        BlockPublicPolicy: true
        RestrictPublicBuckets: true
"""
    assert [f.rule for f in _scan(tmp_path, body).findings] == ["aws-s3-public"]


def test_a_policy_for_another_bucket_is_not_this_ones(tmp_path):
    other = POLICY.replace("Bucket: !Ref B", "Bucket: someone-elses-bucket")
    body = BUCKET + "      PublicAccessBlockConfiguration:\n        BlockPublicPolicy: false\n" \
                    "        RestrictPublicBuckets: false\n" + other
    run = _scan(tmp_path, body)
    assert not run.findings and not run.undecided


def test_databases_iam_and_volumes(tmp_path):
    run = _scan(tmp_path, """  Db:
    Type: AWS::RDS::DBInstance
    Properties:
      PubliclyAccessible: "true"
      StorageEncrypted: true
  Replica:
    Type: AWS::RDS::DBInstance
    Properties:
      SourceDBInstanceIdentifier: !Ref Db
  Admin:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument: {}
      Policies:
      - PolicyName: all
        PolicyDocument:
          Statement:
          - {Effect: Allow, Action: "*", Resource: "*"}
  Vol:
    Type: AWS::EC2::Volume
    Properties:
      Size: 10
      AvailabilityZone: us-east-1a
""")
    assert {(f.rule, f.resource) for f in run.findings} == {
        ("aws-rds-public", "AWS::RDS::DBInstance Db"), ("aws-iam-full-admin", "AWS::IAM::Role Admin"),
        ("aws-ebs-unencrypted", "AWS::EC2::Volume Vol")}


# --- AWS's template collection, against checkov ----------------------------------------------

from pathlib import Path  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures" / "iac" / "cloudformation"


def test_aws_templates_against_checkov():
    """Every checkov finding is a Frame finding but one: a read replica, which takes its
    source's encryption (checkov reports it unencrypted). Frame adds four load balancer groups
    open to the internet on every port (IpProtocol -1), which checkov's checks do not cover."""
    root = FIXTURES / "aws-cloudformation-templates"
    run = scan(root)
    recorded = json.loads((FIXTURES / "checkov.json").read_text())

    def key(rule):
        return "sg" if rule.startswith("aws-sg") else rule
    ours = {(f.file, f.resource.split(" ", 1)[1], key(f.rule)) for f in run.findings if f.format == "cloudformation"}
    theirs = {(f, r, recorded["checks"][c]) for f, r, c in recorded["failed"]}
    assert len(theirs) == 31
    assert theirs - ours == {("RDS/RDS_MySQL_With_Read_Replica.yaml", "ReplicaDB", "aws-rds-unencrypted")}
    assert ours - theirs == {(f"ECS/{launch}/clusters/{vpc}.yaml", "PublicLoadBalancerSG", "sg")
                             for launch in ("EC2LaunchType", "FargateLaunchType") for vpc in ("private-vpc", "public-vpc")}
    assert not [w for w in run.warnings if "transform" not in w]


def test_a_cidr_with_host_bits_is_undecided():
    """192.168.1.0/0 (an AWS sample's default) is all addresses if AWS takes its network, and
    nothing if it refuses the value; which is not documented."""
    run = scan(FIXTURES / "aws-cloudformation-templates" / "EC2" / "EC2InstanceWithSecurityGroupSample.yaml")
    assert not run.findings
    assert [(u["rule"], u["depends_on"]) for u in run.undecided] == [
        ("aws-sg-admin-from-internet", ["whether AWS accepts 192.168.1.0/0"])]
