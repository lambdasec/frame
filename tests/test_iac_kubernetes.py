"""Kubernetes manifests against the Pod Security Standards pack (frame/iac,
packs/data/kubernetes/pod-security.toml).

Ground truth is the Pod Security admission controller itself: `expected.tsv` beside each fixture
set is the output of its evaluator (k8s.io/pod-security-admission/policy, Kubernetes v1.38) on
every pod and workload, recorded by tests/iac_real/psa. Every check that denies each object, at
each level, must be exactly what Frame reports."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from frame.iac.engine import Subject, Unknown, decide
from frame.iac.kubernetes import read_file
from frame.iac.model import ReadResult
from frame.iac.policy import PolicyError, parse
from frame.iac.scan import scan
from frame.sil.packs import PackError, PackSet
from frame.sil.packs.loader import builtin_packs
from frame.sil.packs.schema import parse_pack

FIXTURES = Path(__file__).parent / "fixtures" / "iac" / "kubernetes"
PACK = next(p for p in builtin_packs() if (p.language, p.name) == ("kubernetes", "pod-security"))

# The evaluator's ForbiddenReason -> the check's id (seccompProfile and procMount name both the
# Baseline check and its Restricted replacement).
REASONS = {
    "allowPrivilegeEscalation != false": "allowPrivilegeEscalation", "forbidden AppArmor profile": "appArmorProfile",
    "forbidden sysctls": "sysctls", "host namespaces": "hostNamespaces", "hostPath volumes": "hostPathVolumes",
    "hostPort": "hostPorts", "hostProcess": "windowsHostProcess", "non-default capabilities": "capabilities_baseline",
    "privileged": "privileged", "probe or lifecycle host": "hostProbesAndHostLifecycle",
    "restricted volume types": "restrictedVolumes", "runAsNonRoot != true": "runAsNonRoot", "runAsUser=0": "runAsUser",
    "seLinuxOptions": "seLinuxOptions", "unrestricted capabilities": "capabilities_restricted",
    "seccompProfile": {"baseline": "seccompProfile_baseline", "restricted": "seccompProfile_restricted"},
    "procMount": {"baseline": "procMount", "restricted": "procMount_restricted"},
}

# Where the recorded evaluator and a cluster differ, and Frame follows the cluster: the evaluator
# was run on the decoded object, the API server first defaults it.
API_DEFAULTING = {
    # `- name: volume0` has no source; the API server defaults it to emptyDir, and upstream's
    # own fixture is in pass/ (it is admitted)
    ("restricted/v1.38/pass/restrictedvolumes0.yaml", "Pod/restrictedvolumes0", "restricted"): {"restrictedVolumes"},
}


def _check_id(policy) -> str:
    return next(t for t in policy.tags if t.startswith("psa:"))[4:]


def _level(level):
    """The checks the controller runs at a level: Restricted replaces the checks it overrides."""
    ps = [p for p in PACK.policies if "pss:baseline" in p.tags or level == "restricted"]
    replaced = {o for p in ps for o in p.overrides}
    return [p for p in ps if p.id not in replaced]


def _expected(tsv: Path, with_id: bool):
    out = {}
    for line in tsv.read_text().splitlines():
        cols = line.split("\t")
        rel, rid, level, reasons = (cols + [""])[:4] if with_id else (cols[0], None, cols[1], (cols + [""])[2])
        checks = set()
        for r in filter(None, reasons.split("|")):
            c = REASONS[r]
            checks.add(c[level] if isinstance(c, dict) else c)
        out.setdefault((rel, rid, level), []).append(checks)
    return out


def _denied(resource, level):
    return {_check_id(p) for p in _level(level) if decide(p.expr, resource.subject()).outcome == "fail"}


def _resources(root: Path, rel: str):
    out = ReadResult()
    read_file(root / rel, rel, out)
    return out.resources


PSS_CASES = sorted(_expected(FIXTURES / "pss" / "expected.tsv", with_id=False).items())


@pytest.mark.parametrize("key, expected", PSS_CASES, ids=[f"{k[0]}:{k[2]}" for k, _ in PSS_CASES])
def test_every_upstream_fixture_is_decided_as_the_admission_controller_decides_it(key, expected):
    rel, _, level = key
    (resource,) = _resources(FIXTURES / "pss", rel)
    want = expected[0] - API_DEFAULTING.get((rel, resource.address, level), set())
    assert _denied(resource, level) == want


def test_fixture_directories_agree_with_their_names():
    """pass/ is admitted at its level, fail/ is denied: the controller's own test contract."""
    for level in ("baseline", "restricted"):
        for kind in ("pass", "fail"):
            for f in sorted((FIXTURES / "pss" / level / "v1.38" / kind).glob("*.yaml")):
                (r,) = _resources(f.parent, f.name)
                assert bool(_denied(r, level)) == (kind == "fail"), f


REAL_CASES = sorted(_expected(FIXTURES / "real" / "expected.tsv", with_id=True).items())


def test_real_manifests_are_decided_as_the_admission_controller_decides_them():
    mine = {}
    for rel in sorted({k[0] for k, _ in REAL_CASES}):
        for r in _resources(FIXTURES / "real", rel):
            if "pod" in r.views:
                for level in ("baseline", "restricted"):
                    mine.setdefault((rel, r.address, level), []).append(_denied(r, level))
    assert len(REAL_CASES) == 52
    for key, expected in REAL_CASES:
        assert sorted(map(sorted, mine.get(key, []))) == sorted(map(sorted, expected)), key
    assert set(mine) == {k for k, _ in REAL_CASES}


# --- the engine: Z3 decides what the files do not ----------------------------------------

def _decide(text, doc, views=None):
    return decide(parse(text), Subject(doc, views or {"self": ()}))


def test_known_values_fold_without_the_solver():
    v = _decide('self.a == 1 and self.b != "x"', {"a": 1, "b": "y"})
    assert (v.outcome, v.evidence) == ("fail", "matched")
    assert _decide("self.a == true", {"a": 1}).outcome == "pass"            # a bool is not a number


def test_an_unknown_is_one_value_wherever_it_appears():
    x = Unknown("var.mode")
    assert _decide('self.a == "on"', {"a": x}).outcome == "undecided"
    assert _decide('self.a == "on" and self.b == "off"', {"a": x, "b": x}).outcome == "pass"
    v = _decide('self.a == "on" or self.b != "on"', {"a": x, "b": x})
    assert (v.outcome, v.evidence) == ("fail", "solver-verified")


def test_numeric_unknowns_are_ordered():
    port = Unknown("var.port")
    assert _decide("self.p >= 1 and self.p < 1", {"p": port}).outcome == "pass"
    assert _decide("self.p >= 1 or self.p < 1", {"p": port}).outcome == "fail"


def test_a_missing_value_compares_false_both_ways_unless_defaulted():
    assert _decide('self.a == "x"', {}).outcome == "pass"
    assert _decide('self.a != "x"', {}).outcome == "pass"
    assert _decide('default(self.a, "") != "x"', {}).outcome == "fail"
    assert _decide("absent(self.a)", {"a": None}).outcome == "fail"         # null is no value


def test_quantifiers_over_lists_maps_and_unknown_collections():
    doc = {"xs": [{"n": 1}, {"n": 5}], "m": {"k1": "a", "k2": "b"}}
    assert _decide("some x in self.xs: x.n > 4", doc).outcome == "fail"
    assert _decide("every x in self.xs: x.n > 4", doc).outcome == "pass"
    assert _decide('some (k, v) in self.m: k == "k2" and v == "b"', doc).outcome == "fail"
    assert _decide("some x in self.xs: x.n > 4", {"xs": Unknown("var.xs")}).outcome == "undecided"
    assert _decide("every x in self.missing: x.n > 4", doc).outcome == "fail"   # vacuous


def test_the_witness_names_the_element_that_decides():
    doc = {"cs": [{"p": False}, {"p": True}]}
    v = _decide("some c in self.cs: c.p == true", doc)
    assert ("cs", 1, "p") in v.why


@pytest.mark.parametrize("text", ["self.a ==", "some x self.a: true", 'starts_with(self.a, 1)', "self.a = 1",
                                  '"unterminated'])
def test_malformed_expressions_are_errors(text):
    with pytest.raises(PolicyError):
        parse(text)


def test_a_quantifier_body_extends_to_the_right():
    e = parse("some c in self.cs: c.a == 1 and c.b == 2")
    assert type(e).__name__ == "Quantifier"


# --- packs ---------------------------------------------------------------------------------

def _pack(policy: dict, language="kubernetes", **extra):
    return parse_pack({"pack": {"name": "t", "language": language}, "policy": [policy], **extra}, "t.toml")


GOOD = {"id": "p1", "title": "t", "severity": "high", "cwe": "CWE-250", "when": "pod.hostPID == true"}


def test_policy_entries_are_validated_strictly():
    assert _pack(GOOD).policies[0].id == "p1"
    with pytest.raises(PackError, match="unknown name"):
        _pack(dict(GOOD, when="podd.hostPID == true"))
    with pytest.raises(PackError, match="severity"):
        _pack(dict(GOOD, severity="urgent"))
    with pytest.raises(PackError, match="cwe"):
        _pack(dict(GOOD, cwe="250"))
    with pytest.raises(PackError, match="expected"):
        _pack(dict(GOOD, when="pod.hostPID =="))
    with pytest.raises(PackError, match="unknown key"):
        _pack(dict(GOOD, level="baseline"))
    with pytest.raises(PackError, match="infrastructure packs"):
        _pack(GOOD, language="python")
    with pytest.raises(PackError, match="only \\[\\[policy\\]\\]"):
        _pack(GOOD, sink=[{"name": "x", "kind": "sql"}])


def test_the_built_in_policies_cite_their_source():
    assert len(PACK.policies) == 19
    for p in PACK.policies:
        assert p.references and _check_id(p)


# --- scanning --------------------------------------------------------------------------------

DEPLOY = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: shop
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx
        securityContext:
          privileged: true
          capabilities:
            add: ["SYS_ADMIN"]
"""


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def test_a_finding_points_at_the_value_that_causes_it(tmp_path):
    _write(tmp_path, "k8s/web.yaml", DEPLOY)
    run = scan(tmp_path)
    f = next(f for f in run.findings if f.rule == "k8s-privileged")
    assert (f.file, f.line, f.resource, f.field) == (
        "k8s/web.yaml", 13, "Deployment/shop/web", "spec.template.spec.containers[0].securityContext.privileged")
    assert f.evidence == "matched" and f.cwe == "CWE-250"


def test_a_restricted_check_replaces_the_baseline_one_and_keeps_its_severity(tmp_path):
    _write(tmp_path, "web.yaml", DEPLOY)
    rules = {f.rule: f for f in scan(tmp_path).findings}
    assert "k8s-capabilities-baseline" not in rules
    caps = rules["k8s-capabilities-restricted"]
    assert caps.also == ["k8s-capabilities-baseline"] and caps.severity == "high"


def test_items_of_a_list_and_every_workload_kind_are_read(tmp_path):
    _write(tmp_path, "list.yaml", """\
apiVersion: v1
kind: List
items:
- apiVersion: batch/v1
  kind: CronJob
  metadata: {name: nightly}
  spec:
    jobTemplate:
      spec:
        template:
          spec:
            hostNetwork: true
            containers: [{name: c, image: busybox}]
- apiVersion: example.com/v1
  kind: Deployment
  metadata: {name: not-a-workload}
  spec: {template: {spec: {hostNetwork: true}}}
""")
    run = scan(tmp_path)
    hits = {(f.resource, f.line) for f in run.findings if f.rule == "k8s-host-namespaces"}
    assert hits == {("CronJob/nightly", 12)}         # another group's "Deployment" is not apps/v1's
    assert run.resources == 2


def test_helm_templates_with_actions_are_skipped_and_named_once(tmp_path):
    _write(tmp_path, "chart/Chart.yaml", "apiVersion: v2\nname: c\nversion: 0.1.0\n")
    _write(tmp_path, "chart/templates/a.yaml", DEPLOY.replace("nginx", "{{ .Values.image }}"))
    _write(tmp_path, "chart/templates/b.yaml", DEPLOY.replace("nginx", "{{ .Values.image }}"))
    _write(tmp_path, "chart/templates/plain.yaml", DEPLOY)
    run = scan(tmp_path)
    assert {f.file for f in run.findings} == {"chart/templates/plain.yaml"}
    assert [w for w in run.warnings if "Helm" in w] == [
        "chart: Helm chart with 2 template(s) not checked (render it with --render-helm)"]


def test_inline_suppressions(tmp_path):
    _write(tmp_path, "web.yaml", DEPLOY.replace("privileged: true", "privileged: true  # frame: ignore[k8s-privileged]"))
    run = scan(tmp_path)
    assert "k8s-privileged" not in {f.rule for f in run.findings}
    assert [f.rule for f in run.suppressed] == ["k8s-privileged"]


def test_unreadable_manifests_warn_and_other_yaml_is_ignored(tmp_path):
    _write(tmp_path, "bad.yaml", "apiVersion: v1\nkind: Pod\nspec: [unclosed\n")
    _write(tmp_path, "config.yml", "name: not kubernetes\nitems: [1, 2]\n")
    run = scan(tmp_path)
    assert run.resources == 0 and run.findings == []
    assert len(run.warnings) == 1 and run.warnings[0].startswith("bad.yaml: not valid YAML")


def test_a_project_pack_adds_policies(tmp_path):
    _write(tmp_path, "web.yaml", DEPLOY)
    _write(tmp_path, ".frame/packs/ours.toml", """\
[pack]
name = "ours"
language = "kubernetes"

[[policy]]
id = "acme-latest-image"
title = "Container image has no tag"
severity = "low"
cwe = "CWE-1357"
when = 'some c in containers: c.image == "nginx"'
""")
    run = scan(tmp_path, packs=PackSet.build(project_start=tmp_path))
    assert "acme-latest-image" in {f.rule for f in run.findings}


# --- the command line ----------------------------------------------------------------------

def _frame(*args, cwd=None):
    return subprocess.run([sys.executable, "-m", "frame.cli", *args], capture_output=True, text=True, cwd=cwd)


def test_frame_iac_reports_and_sets_the_exit_status(tmp_path):
    _write(tmp_path, "web.yaml", DEPLOY)
    r = _frame("iac", str(tmp_path), "-f", "json")
    assert r.returncode == 1, r.stderr
    doc = json.loads(r.stdout)
    assert doc["files"] == {"kubernetes": ["web.yaml"]} and doc["packs"] == ["kubernetes/pod-security"]
    assert {f["rule"] for f in doc["findings"]} >= {"k8s-privileged", "k8s-capabilities-restricted"}
    assert _frame("iac", str(tmp_path), "--fail-on", "critical").returncode == 0
    sarif = json.loads(_frame("iac", str(tmp_path), "-f", "sarif").stdout)
    result = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == "iac/k8s-privileged")
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 13


def test_frame_scan_iac_adds_the_infrastructure_section(tmp_path):
    _write(tmp_path, "web.yaml", DEPLOY)
    _write(tmp_path, "app.py", "x = 1\n")
    r = _frame("scan", str(tmp_path), "--iac", "-f", "json")
    assert r.returncode == 1, r.stderr
    infra = json.loads(r.stdout)["infrastructure"]
    assert "k8s-privileged" in {f["rule"] for f in infra["findings"]}
    plain = json.loads(_frame("scan", str(tmp_path), "-f", "json").stdout)
    assert "infrastructure" not in plain


# --- rendering Helm charts (frame/iac/helm.py) ----------------------------------------------

import os  # noqa: E402
import shutil  # noqa: E402

CHART = {"web/Chart.yaml": "apiVersion: v2\nname: web\nversion: 0.1.0\n",
         "web/values.yaml": "privileged: true\n",
         "web/templates/deploy.yaml": DEPLOY.replace("privileged: true", "privileged: {{ .Values.privileged }}"),
         "web/charts/sub/Chart.yaml": "apiVersion: v2\nname: sub\nversion: 0.1.0\n",
         "web/charts/sub/templates/x.yaml": "kind: {{ .Values.k }}\n"}


def _stand_in_helm(tmp_path, monkeypatch, output: str, status: int = 0):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "out.txt").write_text(output)
    script = bindir / "helm"
    script.write_text(f"#!/bin/sh\necho \"$@\" >> {bindir}/calls.txt\ncat {bindir}/out.txt\nexit {status}\n")
    script.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    return bindir


def test_render_helm_reads_what_helm_writes_and_points_at_the_template(tmp_path, monkeypatch):
    for name, text in CHART.items():
        _write(tmp_path / "repo", name, text)
    rendered = "---\n# Source: web/templates/deploy.yaml\n" + DEPLOY
    bindir = _stand_in_helm(tmp_path, monkeypatch, rendered)
    run = scan(tmp_path / "repo", render_helm=True)
    f = next(f for f in run.findings if f.rule == "k8s-privileged")
    assert (f.file, f.line, f.field) == ("web/templates/deploy.yaml", 1,
                                         "spec.template.spec.containers[0].securityContext.privileged")
    calls = (bindir / "calls.txt").read_text().splitlines()
    assert len(calls) == 1 and calls[0].startswith("template release ")      # the subchart renders with it
    assert "--skip-schema-validation" in calls[0]
    assert not [w for w in run.warnings if "Helm" in w]


def test_render_helm_failures_are_warnings(tmp_path, monkeypatch):
    for name, text in CHART.items():
        _write(tmp_path / "repo", name, text)
    _stand_in_helm(tmp_path, monkeypatch, "", status=1)
    run = scan(tmp_path / "repo", render_helm=True)
    assert run.findings == [] and run.warnings[0].startswith("web: Helm chart not rendered (helm template failed")
    monkeypatch.setenv("PATH", str(tmp_path / "nowhere"))
    run = scan(tmp_path / "repo", render_helm=True)
    assert run.warnings == ["web: Helm chart not rendered (helm is not installed (needed by --render-helm))"]


@pytest.mark.skipif(shutil.which("helm") is None, reason="needs Helm")
def test_render_helm_with_real_helm(tmp_path):
    for name, text in CHART.items():
        if "charts/sub" not in name:
            _write(tmp_path, name, text)
    run = scan(tmp_path, render_helm=True)
    assert "k8s-privileged" in {f.rule for f in run.findings}
    _write(tmp_path, "web/values.yaml", "privileged: false\n")
    assert "k8s-privileged" not in {f.rule for f in scan(tmp_path, render_helm=True).findings}
