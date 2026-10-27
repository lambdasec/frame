"""Reachability of vulnerable dependencies: installed < imported < called, from the project's
own source through Frame's frontends; positive evidence only (never "unreachable")."""

import gzip
import json
from pathlib import Path

import pytest

from frame.sca import read_dependencies
from frame.sca.advisories import AdvisoryDB, build_advisories, match
from frame.sca.reachability import Usage, annotate, module_names

OSV = Path(__file__).parent / "fixtures" / "sca" / "osv"
RECORDS = json.loads(gzip.decompress((OSV / "records.json.gz").read_bytes()))
EXPECTED = json.loads((OSV / "expected.json").read_text())["queries"]


def ids_for(name, version):
    return next(q["ids"] for q in EXPECTED if q["name"] == name and q["version"] == version)


LODASH_TEMPLATE = "GHSA-35jh-r3h4-6jhm"               # CVE-2021-23337, command injection via template
LOG4SHELL = "GHSA-jfh8-c2jp-5v3q"
FUNCTIONS = {
    "npm": {LODASH_TEMPLATE: [{"id": "lodash.template", "source": "curated"}]},
    "PyPI": {i: [{"id": "yaml.load", "source": "curated"}] for i in ids_for("pyyaml", "5.3")},
    "Maven": {LOG4SHELL: [{"id": "org.apache.logging.log4j.core.lookup.JndiLookup.lookup", "source": "curated"}]},
    "NuGet": {i: [{"id": "Newtonsoft.Json.JsonConvert.DeserializeObject", "source": "fix-commit"}]
              for i in ids_for("Newtonsoft.Json", "12.0.1")},
}


@pytest.fixture
def db(tmp_path, monkeypatch):
    raw = tmp_path / "osv"
    raw.mkdir()
    (raw / "all.json").write_text(json.dumps(RECORDS))
    fns = tmp_path / "functions"
    fns.mkdir()
    for eco, data in FUNCTIONS.items():
        (fns / f"{eco}.json").write_text(json.dumps(data))
    mirror = tmp_path / "mirror"
    build_advisories([raw], mirror, "r1", functions_dir=fns)
    from frame.kb.store import pull
    monkeypatch.setenv("FRAME_KB_CACHE", str(tmp_path / "cache"))
    monkeypatch.setenv("FRAME_ADVISORIES_SOURCE", str(mirror))
    pull(None, source=str(mirror))
    return AdvisoryDB.cached(["PyPI", "npm", "Maven", "NuGet"])


def findings_for(proj, db):
    report = read_dependencies(proj)
    found = match(report.files, db)
    annotate(found, Usage(proj, {".git", "node_modules", ".venv"}), proj)
    return found


def level(found, package, adv_id=None):
    hits = [f for f in found if f["package"] == package and (adv_id is None or adv_id in [f["id"], *f["aliases"]])]
    assert hits, (package, adv_id)
    return {f["reachability"]["level"] for f in hits}


def test_called_imported_and_installed_in_python(tmp_path, db):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "requirements.txt").write_text("pyyaml==5.3\ndjango==3.2.0\nlodash-free==1.0\n")
    (proj / "app.py").write_text("import yaml\nfrom django.db import connection\n\n"
                                 "def handler(body):\n    return yaml.load(body)\n")
    found = findings_for(proj, db)
    assert level(found, "pyyaml") == {"called"}
    call = next(f for f in found if f["package"] == "pyyaml")["reachability"]["calls"][0]
    assert call == {"function": "yaml.load", "location": "app.py:5", "source": "curated"}
    assert level(found, "django") == {"imported"}
    assert next(f for f in found if f["package"] == "django")["reachability"]["imported_in"] == ["app.py"]


def test_javascript_call_through_require(tmp_path, db):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "package.json").write_text(json.dumps({"dependencies": {"lodash": "4.17.20", "minimist": "1.2.5"}}))
    (proj / "render.js").write_text("const _ = require('lodash');\nmodule.exports = (t) => _.template(t);\n")
    found = findings_for(proj, db)
    assert level(found, "lodash", LODASH_TEMPLATE) == {"called"}
    assert level(found, "minimist") == {"installed"}                  # not used: still reported, never "safe"


def test_log4shell_through_a_logging_facade_stays_installed(tmp_path, db):
    """The app imports log4j-api's Logger, never log4j-core's lookup: that is not evidence of
    safety, so the level is installed, not unreachable."""
    proj = tmp_path / "proj"
    (proj / "src").mkdir(parents=True)
    (proj / "maven_dep_tree.txt").write_text(
        "com.acme:app:jar:1.0\n+- org.springframework.boot:spring-boot-starter-log4j2:jar:2.6.1:compile\n"
        "|  \\- org.apache.logging.log4j:log4j-core:jar:2.14.1:compile\n")
    (proj / "src" / "A.java").write_text(
        "import org.apache.logging.log4j.LogManager;\nimport org.apache.logging.log4j.Logger;\n"
        "class A { static Logger log = LogManager.getLogger(A.class); void f(String x) { log.error(x); } }\n")
    found = findings_for(proj, db)
    assert level(found, "org.apache.logging.log4j:log4j-core", LOG4SHELL) == {"installed"}
    (proj / "src" / "B.java").write_text(
        "import org.apache.logging.log4j.core.lookup.JndiLookup;\n"
        "class B { String f(JndiLookup l, String k) { return l.lookup(null, k); } }\n")
    found = findings_for(proj, db)
    assert level(found, "org.apache.logging.log4j:log4j-core", LOG4SHELL) == {"called"}   # typed receiver


def test_csharp_using_and_type_call_match_the_advisorys_own_id(tmp_path, db):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "App.csproj").write_text('<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" '
                                     'Version="12.0.1" /></ItemGroup></Project>')
    (proj / "Api.cs").write_text("using Newtonsoft.Json;\nclass Api {\n  object F(string x) {\n"
                                 "    return JsonConvert.DeserializeObject(x);\n  }\n}\n")
    found = findings_for(proj, db)
    f = next(x for x in found if x["package"] == "Newtonsoft.Json")
    assert f["reachability"]["level"] == "called"
    assert f["reachability"]["calls"][0]["location"] == "Api.cs:4"


def test_code_outside_the_manifests_directory_does_not_count(tmp_path, db):
    proj = tmp_path / "proj"
    (proj / "svc").mkdir(parents=True)
    (proj / "other").mkdir()
    (proj / "svc" / "requirements.txt").write_text("pyyaml==5.3\n")
    (proj / "other" / "tool.py").write_text("import yaml\nyaml.load(open('x'))\n")
    assert level(findings_for(proj, db), "pyyaml") == {"installed"}


def test_module_names_come_from_the_projects_virtualenv_first(tmp_path):
    info = tmp_path / ".venv" / "lib" / "python3.12" / "site-packages" / "Acme_Tools-1.0.dist-info"
    info.mkdir(parents=True)
    (info / "METADATA").write_text("Metadata-Version: 2.1\nName: acme-tools\nVersion: 1.0\n")
    (info / "RECORD").write_text("acmetools/__init__.py,,\nacme_cli.py,,\nAcme_Tools-1.0.dist-info/METADATA,,\n")
    usage = Usage(tmp_path, set())
    assert module_names("PyPI", "Acme-Tools", usage.venv(tmp_path)) == {"acmetools", "acme_cli"}
    assert module_names("PyPI", "PyYAML") == {"yaml"} and module_names("PyPI", "Flask-Cors") == {"flask_cors"}
    assert module_names("Maven", "org.x:y") == set()                  # not derivable: never guessed


def test_function_files_are_validated(tmp_path):
    from frame.kb.store import KBError
    raw = tmp_path / "osv"
    raw.mkdir()
    (raw / "all.json").write_text(json.dumps(RECORDS[:5]))
    fns = tmp_path / "functions"
    fns.mkdir()
    (fns / "npm.json").write_text(json.dumps({"GHSA-x": [{"id": "a.b", "source": "guessed"}]}))
    with pytest.raises(KBError, match="source"):
        build_advisories([raw], tmp_path / "out", "r1", functions_dir=fns)
