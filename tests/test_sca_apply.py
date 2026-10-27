"""Applying upgrade plans: minimal manifest edits per ecosystem (formatting kept, nothing else
touched), verification by re-reading the graph, and a live re-lock through real npm."""

import gzip
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from frame.sca import read_dependencies
from frame.sca.advisories import AdvisoryDB, build_advisories, match
from frame.sca.apply import apply_plan
from frame.sca.plan import plan

ROOT = Path(__file__).resolve().parents[1]
OSV = ROOT / "tests" / "fixtures" / "sca" / "osv"
RECORDS = json.loads(gzip.decompress((OSV / "records.json.gz").read_bytes()))


def P(eco, name, cur, target, action, path, direct=True, fixes=("GHSA-x",)):
    return {"ecosystem": eco, "package": name, "current": cur, "target": target, "action": action, "path": path,
            "direct": direct, "dev": False, "fixes": list(fixes), "unfixed": [], "via": [], "major": False,
            "requirers": [], "known_requirements": True}


def edited(tmp_path, files, plans):
    for rel, text in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(text)
    out = apply_plan(plans, tmp_path, write=True)
    return {c.path: c.after for c in out.changes}, out.manual


def test_package_json_keeps_style_and_adds_the_right_override(tmp_path):
    pkg = '{\n    "name": "app",\n    "dependencies": {\n        "lodash": "~4.17.20",\n        "express": "4.18.2"\n    }\n}\n'
    out, manual = edited(tmp_path, {"package.json": pkg}, [
        P("npm", "lodash", "4.17.20", "4.18.0", "raise-requirement", "package-lock.json"),
        P("npm", "minimist", "1.2.5", "1.2.6", "override", "package-lock.json", direct=False)])
    data = json.loads(out["package.json"])
    assert data["dependencies"] == {"lodash": "~4.18.0", "express": "4.18.2"}
    assert data["overrides"] == {"minimist": "1.2.6"}
    assert out["package.json"].startswith('{\n    "name"') and not manual           # 4-space indent kept
    yarn, _ = edited(tmp_path / "y", {"package.json": pkg}, [
        P("npm", "minimist", "1.2.5", "1.2.6", "override", "yarn.lock", direct=False)])
    assert json.loads(yarn["package.json"])["resolutions"] == {"minimist": "1.2.6"}
    pnpm, _ = edited(tmp_path / "p", {"package.json": pkg}, [
        P("npm", "minimist", "1.2.5", "1.2.6", "override", "pnpm-lock.yaml", direct=False)])
    assert json.loads(pnpm["package.json"])["pnpm"] == {"overrides": {"minimist": "1.2.6"}}


def test_requirements_edits_keep_extras_markers_and_comments(tmp_path):
    req = ("# web\nDjango==3.2.0  # pinned for LTS\nPyYAML[libyaml]>=5.1,<7 ; python_version >= '3.8'\n"
           "urllib3>=1.26,<1.27\n")
    out, manual = edited(tmp_path, {"requirements.txt": req}, [
        P("PyPI", "django", "3.2.0", "3.2.25", "raise-requirement", "requirements.txt"),
        P("PyPI", "pyyaml", "5.3", "5.4", "raise-requirement", "requirements.txt"),
        P("PyPI", "urllib3", "1.26.5", "2.2.2", "raise-requirement", "requirements.txt"),
        P("PyPI", "idna", "3.6", "3.7", "override", "requirements.txt", direct=False, fixes=["GHSA-jjg7"])])
    text = out["requirements.txt"]
    assert "Django==3.2.25  # pinned for LTS\n" in text
    assert "PyYAML[libyaml]>=5.4,<7 ; python_version >= '3.8'\n" in text
    assert "urllib3>=1.26,<1.27\n" in text and manual == ["urllib3: the upper bound in requirements.txt excludes 2.2.2"]
    assert text.endswith("idna>=3.7  # frame: GHSA-jjg7\n") and text.startswith("# web\n")


def test_pyproject_edits_only_dependency_declarations(tmp_path):
    proj = ('[project]\nname = "app"\nkeywords = ["flask"]\ndependencies = [\n    "flask>=2.0,<4",\n]\n\n'
            '[tool.poetry.dependencies]\nrequests = { version = "^2.25", extras = ["socks"] }\n')
    out, manual = edited(tmp_path, {"pyproject.toml": proj}, [
        P("PyPI", "flask", "2.0.0", "3.0.3", "raise-requirement", "pyproject.toml"),
        P("PyPI", "requests", "2.25.0", "2.31.0", "raise-requirement", "poetry.lock")])
    text = out["pyproject.toml"]
    assert '"flask>=3.0.3,<4"' in text and 'keywords = ["flask"]' in text
    assert 'version = "^2.31.0"' in text and not manual
    uv, _ = edited(tmp_path / "uv", {"pyproject.toml": proj, "uv.lock": "version = 1\n"}, [
        P("PyPI", "idna", "3.6", "3.7", "override", "uv.lock", direct=False)])
    assert 'constraint-dependencies = ["idna>=3.7"]' in uv["pyproject.toml"]


POM = """<project>
  <properties>
    <jackson.version>2.9.8</jackson.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>${jackson.version}</version>
    </dependency>
    <dependency>
      <groupId>org.yaml</groupId>
      <artifactId>snakeyaml</artifactId>
      <version>1.33</version>
    </dependency>
  </dependencies>
</project>
"""


def test_pom_edits_property_literal_and_manages_a_transitive(tmp_path):
    out, manual = edited(tmp_path, {"pom.xml": POM}, [
        P("Maven", "com.fasterxml.jackson.core:jackson-databind", "2.9.8", "2.13.4.2", "raise-requirement", "pom.xml"),
        P("Maven", "org.yaml:snakeyaml", "1.33", "2.0", "raise-requirement", "pom.xml"),
        P("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1", "2.17.1", "override", "maven_dep_tree.txt",
          direct=False)])
    text = out["pom.xml"]
    assert "<jackson.version>2.13.4.2</jackson.version>" in text and "${jackson.version}" in text
    assert "<artifactId>snakeyaml</artifactId>\n      <version>2.0</version>" in text
    assert "<dependencyManagement>" in text and "<artifactId>log4j-core</artifactId>" in text
    assert text.index("<dependencyManagement>") < text.index("<artifactId>jackson-databind")
    assert not manual


def test_nuget_and_go_edits(tmp_path):
    out, manual = edited(tmp_path, {
        "App.csproj": '<Project>\n  <ItemGroup>\n    <PackageReference Include="Newtonsoft.Json" Version="12.0.1" />\n'
                      '  </ItemGroup>\n</Project>\n',
        "go.mod": "module x\n\ngo 1.22\n\nrequire (\n\tgolang.org/x/net v0.17.0 // indirect\n)\n"}, [
        P("NuGet", "Newtonsoft.Json", "12.0.1", "13.0.1", "raise-requirement", "App.csproj"),
        P("NuGet", "System.Text.Json", "8.0.0", "8.0.5", "override", "obj/project.assets.json", direct=False),
        P("Go", "golang.org/x/net", "0.17.0", "0.23.0", "raise-requirement", "go.mod", direct=False)])
    assert 'Include="Newtonsoft.Json" Version="13.0.1"' in out["App.csproj"]
    assert 'Include="System.Text.Json" Version="8.0.5"' in out["App.csproj"]
    assert "golang.org/x/net v0.23.0 // indirect" in out["go.mod"] and not manual


def test_dry_run_writes_nothing(tmp_path):
    (tmp_path / "requirements.txt").write_text("django==3.2.0\n")
    out = apply_plan([P("PyPI", "django", "3.2.0", "3.2.25", "raise-requirement", "requirements.txt")], tmp_path)
    assert out.changes and "-django==3.2.0" in out.changes[0].diff() and "+django==3.2.25" in out.changes[0].diff()
    assert (tmp_path / "requirements.txt").read_text() == "django==3.2.0\n"


@pytest.fixture
def db(tmp_path, monkeypatch):
    raw = tmp_path / "osv"
    raw.mkdir()
    (raw / "all.json").write_text(json.dumps(RECORDS))
    mirror = tmp_path / "mirror"
    build_advisories([raw], mirror, "r1")
    from frame.kb.store import pull
    monkeypatch.setenv("FRAME_KB_CACHE", str(tmp_path / "cache"))
    monkeypatch.setenv("FRAME_ADVISORIES_SOURCE", str(mirror))
    pull(None, source=str(mirror))
    return AdvisoryDB.cached(["PyPI", "npm"])


def test_applying_a_manifest_only_plan_clears_every_advisory(tmp_path, db):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "requirements.txt").write_text("django==3.2.0\npyyaml==5.3\n")
    report = read_dependencies(proj)
    before = match(report.files, db)
    plans = plan(before, report.files, db)
    apply_plan(plans, proj, write=True)
    after = match(read_dependencies(proj).files, db)
    assert before and after == []


def test_frame_deps_apply_cli_reports_what_is_fixed(tmp_path, db):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "requirements.txt").write_text("pyyaml==5.3\n")
    run = lambda *a: subprocess.run([sys.executable, "-m", "frame.cli", "deps", str(proj), "--vulns", *a],
                                    capture_output=True, text=True, env=dict(os.environ), cwd=str(ROOT))
    dry = run("--plan")
    assert "Edits (dry run" in dry.stdout and (proj / "requirements.txt").read_text() == "pyyaml==5.3\n"
    done = json.loads(run("--apply", "-f", "json").stdout)
    assert done["applied"]["remaining"] == [] and len(done["applied"]["fixed"]) >= 1
    assert (proj / "requirements.txt").read_text() == "pyyaml==5.4\n"


@pytest.mark.skipif(os.environ.get("FRAME_SCA_REAL") != "1" or not shutil.which("npm"),
                    reason="live: set FRAME_SCA_REAL=1 (runs npm against the registry)")
def test_live_npm_relock_clears_the_advisories(tmp_path, db):
    """Real npm: a direct dependency whose range excludes the fix (lodash ~4.17.20 is raised),
    and a transitive one locked at a vulnerable version its parent's range would let go
    (minimist under mkdirp's ^1.2.5 is re-locked). After --relock nothing is left."""
    proj = tmp_path / "proj"
    proj.mkdir()
    npm = lambda *a: subprocess.run(["npm", *a, "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"],
                                    cwd=proj, check=True, capture_output=True)
    (proj / "package.json").write_text(json.dumps({"name": "app", "version": "1.0.0"}, indent=2))
    npm("install", "lodash@4.17.20", "mkdirp@0.5.5", "minimist@1.2.5")
    pkg = json.loads((proj / "package.json").read_text())
    pkg["dependencies"] = {"lodash": "~4.17.20", "mkdirp": "0.5.5"}           # minimist stays locked at 1.2.5
    (proj / "package.json").write_text(json.dumps(pkg, indent=2))
    npm("install")
    report = read_dependencies(proj)
    before = match(report.files, db)
    assert {f["package"] for f in before} >= {"lodash", "minimist"}
    plans = {p["package"]: p for p in plan(before, report.files, db)}
    assert plans["lodash"]["action"] == "raise-requirement" and plans["minimist"]["action"] == "update-lockfile"
    out = apply_plan(list(plans.values()), proj, write=True, relock_=True)
    assert out.relocked == ["package-lock.json"], out.warnings
    after = match(read_dependencies(proj).files, db)
    assert after == [], [(f["package"], f["version"], f["id"]) for f in after]


def _verify_cmd(tmp_path, body):
    script = tmp_path / "check.py"
    script.write_text(body)
    return f'"{sys.executable}" "{script}"'


def test_verify_keeps_an_upgrade_that_passes(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "requirements.txt").write_text("django==3.2.0\n")
    cmd = _verify_cmd(tmp_path, "import sys; sys.exit(0)\n")
    out = apply_plan([P("PyPI", "django", "3.2.0", "3.2.25", "raise-requirement", "requirements.txt")], proj,
                     write=True, verify=cmd)
    assert out.verify == "passed" and (proj / "requirements.txt").read_text() == "django==3.2.25\n"


def test_verify_rolls_back_an_upgrade_that_breaks_a_passing_build(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "requirements.txt").write_text("django==3.2.0\n")
    (proj / "package.json").write_text('{"dependencies": {"lodash": "~4.17.20"}}\n')
    (proj / "package-lock.json").write_text('{"lockfileVersion": 3, "packages": {}}\n')
    before = {p.name: p.read_text() for p in proj.iterdir()}
    cmd = _verify_cmd(tmp_path, "import pathlib, sys\n"
                                "sys.exit(1 if '3.2.25' in pathlib.Path('requirements.txt').read_text() else 0)\n")
    out = apply_plan([P("PyPI", "django", "3.2.0", "3.2.25", "raise-requirement", "requirements.txt"),
                      P("npm", "lodash", "4.17.20", "4.18.0", "raise-requirement", "package-lock.json")],
                     proj, write=True, verify=cmd)
    assert out.verify == "rolled-back"
    assert {p.name: p.read_text() for p in proj.iterdir()} == before          # every file restored


def test_verify_does_not_blame_an_upgrade_for_an_already_failing_build(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "requirements.txt").write_text("django==3.2.0\n")
    out = apply_plan([P("PyPI", "django", "3.2.0", "3.2.25", "raise-requirement", "requirements.txt")], proj,
                     write=True, verify=_verify_cmd(tmp_path, "import sys; sys.exit(3)\n"))
    assert out.verify == "failing-before" and "3.2.25" in (proj / "requirements.txt").read_text()


@pytest.mark.skipif(os.environ.get("FRAME_SCA_REAL") != "1" or not shutil.which("npm"),
                    reason="live: set FRAME_SCA_REAL=1 (runs npm against the registry)")
def test_live_npm_upgrade_verified_by_the_projects_own_check(tmp_path, db):
    """Real npm: raise lodash, re-lock, install, and run a check that uses the package."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "package.json").write_text(json.dumps({"name": "app", "version": "1.0.0",
                                                   "dependencies": {"lodash": "~4.17.20"}}, indent=2))
    subprocess.run(["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund",
                    "lodash@4.17.20", "--save-prefix=~"], cwd=proj, check=True, capture_output=True)
    report = read_dependencies(proj)
    check = "npm ci --ignore-scripts --no-audit --no-fund >/dev/null && node -e \"require('lodash').template('<%= x %>')({x: 1})\""
    out = apply_plan(plan(match(report.files, db), report.files, db), proj, write=True, relock_=True, verify=check)
    assert out.verify == "passed", out.verify_output
    assert [f for f in match(read_dependencies(proj).files, db) if f["package"] == "lodash"] == []
