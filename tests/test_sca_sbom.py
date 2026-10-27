"""SBOMs: CycloneDX 1.6 and SPDX 2.3 from the dependency graph, validated against the official
schemas for every real package-manager fixture project (tests/fixtures/sca/real), with the
graph, dev scope and licences checked."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from frame.sca import read_dependencies
from frame.sca.sbom import to_cyclonedx, to_spdx

jsonschema = pytest.importorskip("jsonschema")
pytest.importorskip("referencing")

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "tests" / "fixtures" / "sca" / "schemas"
REAL = ROOT / "tests" / "fixtures" / "sca" / "real"
TS = "2026-10-28T12:00:00Z"
CASES = sorted(p.name for p in REAL.iterdir() if (p / "files").is_dir())


def validate_cyclonedx(doc):
    from referencing import Registry, Resource
    resources = []
    for name in ("bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json"):
        s = json.loads((SCHEMAS / name).read_text())
        resources += [(name, Resource.from_contents(s)), (s.get("$id", name), Resource.from_contents(s))]
    schema = json.loads((SCHEMAS / "bom-1.6.schema.json").read_text())
    jsonschema.Draft7Validator(schema, registry=Registry().with_resources(resources),
                               format_checker=jsonschema.FormatChecker()).validate(doc)


def validate_spdx(doc):
    schema = json.loads((SCHEMAS / "spdx-2.3.schema.json").read_text())
    jsonschema.Draft201909Validator(schema, format_checker=jsonschema.FormatChecker()).validate(doc)


@pytest.mark.parametrize("case", CASES)
def test_sboms_of_every_real_fixture_validate_and_keep_the_graph(case):
    report = read_dependencies(REAL / case / "files")
    assert report.files, case
    distinct = {p.purl or p.name for f in report.files for p in f.packages.values()}
    cdx = to_cyclonedx(report, "pkg:generic/app", timestamp=TS)
    validate_cyclonedx(cdx)
    assert len(cdx["components"]) == len(distinct)
    refs = {c["bom-ref"] for c in cdx["components"]} | {"pkg:generic/app"}
    assert all(d["ref"] in refs and set(d.get("dependsOn", [])) <= refs for d in cdx["dependencies"])
    edges = sum(len(bs) for f in report.files for bs in f.edges.values())
    assert sum(len(d["dependsOn"]) for d in cdx["dependencies"][1:]) <= edges
    dev = {p.purl for f in report.files for p in f.packages.values() if p.dev and p.purl}
    assert {c["purl"] for c in cdx["components"] if c.get("scope") == "optional"} <= dev
    spdx = to_spdx(report, "pkg:generic/app", timestamp=TS)
    validate_spdx(spdx)
    assert len(spdx["packages"]) == len(distinct) + 1                 # plus the product itself
    ids = {p["SPDXID"] for p in spdx["packages"]} | {"SPDXRef-DOCUMENT"}
    assert all(r["spdxElementId"] in ids and r["relatedSpdxElement"] in ids for r in spdx["relationships"])


def test_licences_are_only_what_the_lockfile_says(tmp_path):
    lock = {"name": "app", "lockfileVersion": 3, "packages": {
        "": {"dependencies": {"a": "1.0.0", "b": "1.0.0", "c": "1.0.0", "d": "1.0.0"}},
        "node_modules/a": {"version": "1.0.0", "license": "MIT"},
        "node_modules/b": {"version": "1.0.0", "license": "(MIT OR Apache-2.0)"},
        "node_modules/c": {"version": "1.0.0", "license": "SEE LICENSE IN LICENSE.md"},
        "node_modules/d": {"version": "1.0.0"}}}
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    report = read_dependencies(tmp_path)
    cdx = to_cyclonedx(report, "pkg:generic/app", timestamp=TS)
    validate_cyclonedx(cdx)
    lic = {c["name"]: c.get("licenses") for c in cdx["components"]}
    assert lic == {"a": [{"license": {"id": "MIT"}}], "b": [{"expression": "(MIT OR Apache-2.0)"}],
                   "c": [{"license": {"name": "SEE LICENSE IN LICENSE.md"}}], "d": None}
    spdx = to_spdx(report, "pkg:generic/app", timestamp=TS)
    validate_spdx(spdx)
    declared = {p["name"]: p.get("licenseDeclared") for p in spdx["packages"][1:]}
    assert declared["a"] == "MIT" and declared["d"] == "NOASSERTION"


def test_maven_coordinates_and_unresolved_ranges(tmp_path):
    (tmp_path / "maven_dep_tree.txt").write_text(
        "com.acme:app:jar:1.0\n+- org.yaml:snakeyaml:jar:1.33:compile\n\\- junit:junit:jar:4.13.2:test\n")
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "package.json").write_text(json.dumps({"dependencies": {"express": "^4.18.0"}}))
    report = read_dependencies(tmp_path)
    cdx = to_cyclonedx(report, "pkg:generic/app", timestamp=TS)
    validate_cyclonedx(cdx)
    by = {c["name"]: c for c in cdx["components"]}
    assert (by["snakeyaml"]["group"], by["snakeyaml"]["purl"]) == ("org.yaml", "pkg:maven/org.yaml/snakeyaml@1.33")
    assert by["junit"]["scope"] == "optional"
    assert "purl" not in by["express"] and {"name": "frame:requirement", "value": "^4.18.0"} in by["express"]["properties"]
    spdx = to_spdx(report, "pkg:generic/app", timestamp=TS)
    validate_spdx(spdx)
    rel = {(r["relationshipType"]) for r in spdx["relationships"]}
    assert {"DESCRIBES", "DEPENDS_ON", "DEV_DEPENDENCY_OF"} <= rel


def test_frame_deps_sbom_cli(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\nflask>=2\n")
    run = lambda fmt: subprocess.run([sys.executable, "-m", "frame.cli", "deps", str(tmp_path), "--sbom", fmt,
                                      "--product", "pkg:pypi/acme@1.0"], capture_output=True, text=True,
                                     env=dict(os.environ), cwd=str(ROOT))
    cdx = json.loads(run("cyclonedx").stdout)
    validate_cyclonedx(cdx)
    assert cdx["metadata"]["component"]["name"] == "pkg:pypi/acme@1.0"
    validate_spdx(json.loads(run("spdx").stdout))


def test_the_licence_list_ships_as_package_data():
    try:
        import tomllib
    except ModuleNotFoundError:                 # Python < 3.11
        import tomli as tomllib                 # type: ignore[no-redef]
    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert {"sca/data/*.txt", "sca/data/*.json"} <= set(data["tool"]["setuptools"]["package-data"]["frame"])
    assert (ROOT / "frame" / "sca" / "data" / "cpp-repos.json").is_file()
    assert (ROOT / "frame" / "sca" / "data" / "spdx-license-ids.txt").is_file()
