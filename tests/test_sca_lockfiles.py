"""Dependency graphs from manifests and lockfiles: exact versions, direct vs transitive, dev
only, and edges, for every supported format; nothing is run or fetched."""

import json
import subprocess
import sys

import pytest

from frame.sca import read_dependencies
from frame.sca._yaml import YamlError, loads
from frame.sca.lockfiles import (LockfileError, parse_csproj, parse_gradle_lockfile, parse_nuget_lock,
                                 parse_package_lock, parse_pnpm_lock, parse_poetry_lock, parse_pom,
                                 parse_requirements, parse_yarn_lock)


def table(df):
    return {(p.name, p.version): (p.direct, p.dev) for p in df.packages.values()}


def edges(df):
    name = {k: f"{p.name}@{p.version}" for k, p in df.packages.items()}
    return {(name[a], name[b]) for a, bs in df.edges.items() for b in bs}


def test_requirements_pins_ranges_includes_and_options(tmp_path):
    (tmp_path / "base.txt").write_text("Django==4.2.1\n")
    text = ("-r base.txt\n# comment\nrequests==2.31.0 --hash=sha256:abc \\\n    --hash=sha256:def\n"
            "flask>=2.0\nPyYAML[libyaml]==6.0 ; python_version >= '3.8'\n-e git+https://x/y.git#egg=z\n"
            "pkg @ https://example.com/pkg.whl\n--index-url https://pypi.org/simple\n")
    df = parse_requirements("requirements.txt", text, lambda p: (tmp_path / "base.txt").read_text()
                            if p.endswith("base.txt") else None)
    assert table(df) == {("Django", "4.2.1"): (True, False), ("requests", "2.31.0"): (True, False),
                         ("flask", None): (True, False), ("PyYAML", "6.0"): (True, False)}
    assert [p.spec for p in df.packages.values() if p.name == "flask"] == [">=2.0"]


POETRY = '''
[[package]]
name = "flask"
version = "2.3.2"
category = "main"

[package.dependencies]
Werkzeug = ">=2.3.3"

[[package]]
name = "werkzeug"
version = "2.3.6"
category = "main"

[[package]]
name = "pytest"
version = "7.4.0"
category = "dev"
'''
PYPROJECT = '''
[tool.poetry.dependencies]
python = "^3.10"
Flask = "^2.3"

[tool.poetry.group.dev.dependencies]
pytest = "^7"
'''


def test_poetry_lock_with_pyproject_names_the_direct_dependencies(tmp_path):
    (tmp_path / "poetry.lock").write_text(POETRY)
    (tmp_path / "pyproject.toml").write_text(PYPROJECT)
    r = read_dependencies(tmp_path)
    assert [f.path for f in r.files] == ["poetry.lock"]          # the manifest is not read twice
    df = r.files[0]
    assert table(df) == {("flask", "2.3.2"): (True, False), ("werkzeug", "2.3.6"): (False, False),
                         ("pytest", "7.4.0"): (True, True)}
    assert edges(df) == {("flask@2.3.2", "werkzeug@2.3.6")}


def test_a_lockfile_alone_does_not_guess_which_packages_are_direct():
    df = parse_poetry_lock("poetry.lock", POETRY)
    assert {p.direct for p in df.packages.values()} == {None}


UV = '''
version = 1

[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "httpx" }]

[package.dev-dependencies]
dev = [{ name = "pytest" }]

[[package]]
name = "httpx"
version = "0.27.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "idna" }]

[[package]]
name = "idna"
version = "3.7"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "8.2.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "pluggy" }]

[[package]]
name = "pluggy"
version = "1.5.0"
source = { registry = "https://pypi.org/simple" }
'''


def test_uv_lock_roots_and_dev_reachability(tmp_path):
    (tmp_path / "uv.lock").write_text(UV)
    df = read_dependencies(tmp_path).files[0]
    assert table(df) == {("httpx", "0.27.0"): (True, False), ("idna", "3.7"): (False, False),
                         ("pytest", "8.2.0"): (True, True), ("pluggy", "1.5.0"): (False, True)}
    assert edges(df) == {("httpx@0.27.0", "idna@3.7"), ("pytest@8.2.0", "pluggy@1.5.0")}


NPM_V3 = {
    "name": "app", "lockfileVersion": 3,
    "packages": {
        "": {"name": "app", "dependencies": {"express": "^4.18.0"}, "devDependencies": {"jest": "^29"}},
        "node_modules/express": {"version": "4.18.2", "dependencies": {"debug": "2.6.9"}},
        "node_modules/debug": {"version": "4.3.4"},
        "node_modules/express/node_modules/debug": {"version": "2.6.9"},
        "node_modules/jest": {"version": "29.7.0", "dev": True},
        "node_modules/@scope/util": {"version": "1.0.0", "dev": True},
        "packages/lib": {"name": "lib"},
        "node_modules/lib": {"resolved": "packages/lib", "link": True},
    },
}


def test_package_lock_v3_nested_resolution_and_scopes():
    df = parse_package_lock("package-lock.json", json.dumps(NPM_V3))
    assert table(df) == {("express", "4.18.2"): (True, False), ("debug", "4.3.4"): (False, False),
                         ("debug", "2.6.9"): (False, False), ("jest", "29.7.0"): (True, True),
                         ("@scope/util", "1.0.0"): (False, True)}
    assert edges(df) == {("express@4.18.2", "debug@2.6.9")}          # the nested copy, not the hoisted one
    assert {p.purl for p in df.packages.values() if p.name == "@scope/util"} == {"pkg:npm/%40scope/util@1.0.0"}


def test_package_lock_v1_is_nested_and_direct_comes_from_package_json(tmp_path):
    lock = {"lockfileVersion": 1, "dependencies": {
        "lodash": {"version": "4.17.20"},
        "request": {"version": "2.88.0", "requires": {"qs": "~6.5.2"},
                    "dependencies": {"qs": {"version": "6.5.2"}}}}}
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"request": "^2.88.0"},
                                                       "devDependencies": {"lodash": "^4"}}))
    df = read_dependencies(tmp_path).files[0]
    assert table(df) == {("lodash", "4.17.20"): (True, True), ("request", "2.88.0"): (True, False),
                         ("qs", "6.5.2"): (False, False)}
    assert edges(df) == {("request@2.88.0", "qs@6.5.2")}


YARN_V1 = '''# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":
  version "7.12.13"
  resolved "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.12.13.tgz#abc"
  integrity sha512-xyz
  dependencies:
    "@babel/highlight" "^7.12.13"

"@babel/highlight@^7.12.13":
  version "7.13.10"
  resolved "https://registry.yarnpkg.com/@babel/highlight/-/highlight-7.13.10.tgz#def"

lodash@^4.17.21:
  version "4.17.21"
'''

YARN_BERRY = '''# This file is generated by running "yarn install" inside your project.

__metadata:
  version: 6
  cacheKey: 8

"@babel/code-frame@npm:^7.0.0, @babel/code-frame@npm:^7.10.4":
  version: 7.12.13
  resolution: "@babel/code-frame@npm:7.12.13"
  dependencies:
    "@babel/highlight": ^7.12.13
  checksum: abc
  languageName: node
  linkType: hard

"@babel/highlight@npm:^7.12.13":
  version: 7.13.10
  resolution: "@babel/highlight@npm:7.13.10"
  languageName: node
  linkType: hard

"app@workspace:.":
  version: 0.0.0-use.local
  resolution: "app@workspace:."
  dependencies:
    "@babel/code-frame": ^7.0.0
  languageName: unknown
  linkType: soft
'''


@pytest.mark.parametrize("text", [YARN_V1, YARN_BERRY])
def test_yarn_lock_classic_and_berry(text):
    df = parse_yarn_lock("yarn.lock", text)
    got = {(p.name, p.version) for p in df.packages.values()}
    assert {("@babel/code-frame", "7.12.13"), ("@babel/highlight", "7.13.10")} <= got
    assert ("app", "0.0.0-use.local") not in got                      # the workspace itself
    assert ("@babel/code-frame@7.12.13", "@babel/highlight@7.13.10") in edges(df)


PNPM_V9 = '''lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      express:
        specifier: ^4.18.0
        version: 4.18.2
    devDependencies:
      typescript:
        specifier: ^5
        version: 5.4.5

packages:

  express@4.18.2:
    resolution: {integrity: sha512-a}
    engines: {node: '>= 0.10.0'}

  accepts@1.3.8:
    resolution: {integrity: sha512-b}

  typescript@5.4.5:
    resolution: {integrity: sha512-c}
    hasBin: true

snapshots:

  express@4.18.2:
    dependencies:
      accepts: 1.3.8

  accepts@1.3.8: {}

  typescript@5.4.5: {}
'''

PNPM_V6 = '''lockfileVersion: '6.0'

dependencies:
  react-dom:
    specifier: ^18
    version: 18.2.0(react@18.2.0)
  react:
    specifier: ^18
    version: 18.2.0

packages:

  /react-dom@18.2.0(react@18.2.0):
    resolution: {integrity: sha512-d}
    peerDependencies:
      react: ^18.2.0
    dependencies:
      loose-envify: 1.4.0
      react: 18.2.0
    dev: false

  /react@18.2.0:
    resolution: {integrity: sha512-e}
    dev: false

  /loose-envify@1.4.0:
    resolution: {integrity: sha512-f}
    dev: false
'''


def test_pnpm_lock_v9_and_v6():
    v9 = parse_pnpm_lock("pnpm-lock.yaml", PNPM_V9)
    assert table(v9) == {("express", "4.18.2"): (True, False), ("accepts", "1.3.8"): (False, False),
                         ("typescript", "5.4.5"): (True, True)}
    assert edges(v9) == {("express@4.18.2", "accepts@1.3.8")}
    v6 = parse_pnpm_lock("pnpm-lock.yaml", PNPM_V6)
    assert table(v6) == {("react-dom", "18.2.0"): (True, False), ("react", "18.2.0"): (True, False),
                         ("loose-envify", "1.4.0"): (False, False)}
    assert edges(v6) == {("react-dom@18.2.0", "loose-envify@1.4.0"), ("react-dom@18.2.0", "react@18.2.0")}


POM = '''<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.acme</groupId>
  <artifactId>app</artifactId>
  <version>1.0</version>
  <properties><spring.version>5.3.20</spring.version></properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId>
      <version>2.13.3</version></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>org.springframework</groupId><artifactId>spring-web</artifactId>
      <version>${spring.version}</version></dependency>
    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId></dependency>
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13.2</version>
      <scope>test</scope></dependency>
    <dependency><groupId>org.acme</groupId><artifactId>lib</artifactId><version>${undefined}</version></dependency>
    <dependency><groupId>org.acme</groupId><artifactId>ranged</artifactId><version>[1.0,2.0)</version></dependency>
  </dependencies>
</project>'''


def test_pom_properties_management_and_scopes():
    df = parse_pom("pom.xml", POM)
    assert table(df) == {("org.springframework:spring-web", "5.3.20"): (True, False),
                         ("com.fasterxml.jackson.core:jackson-databind", "2.13.3"): (True, False),
                         ("junit:junit", "4.13.2"): (True, True),
                         ("org.acme:lib", None): (True, False), ("org.acme:ranged", None): (True, False)}
    assert {p.purl for p in df.packages.values() if p.name == "junit:junit"} == {"pkg:maven/junit/junit@4.13.2"}


def test_xml_with_a_doctype_is_refused():
    with pytest.raises(LockfileError, match="document type"):
        parse_pom("pom.xml", '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><project/>')


def test_gradle_lockfile():
    df = parse_gradle_lockfile("gradle.lockfile", (
        "# This is a Gradle generated file\n"
        "com.google.guava:guava:31.1-jre=compileClasspath,runtimeClasspath\n"
        "junit:junit:4.13.2=testCompileClasspath,testRuntimeClasspath\n"
        "empty=annotationProcessor\n"))
    assert table(df) == {("com.google.guava:guava", "31.1-jre"): (None, False), ("junit:junit", "4.13.2"): (None, True)}


def test_nuget_lock_and_csproj():
    lock = {"version": 1, "dependencies": {"net8.0": {
        "Newtonsoft.Json": {"type": "Direct", "requested": "[13.0.1, )", "resolved": "13.0.1"},
        "Serilog.Sinks.File": {"type": "Direct", "requested": "[5.0.0, )", "resolved": "5.0.0",
                               "dependencies": {"Serilog": "2.10.0"}},
        "Serilog": {"type": "Transitive", "resolved": "2.10.0"},
        "MyLib": {"type": "Project"}}}}
    df = parse_nuget_lock("packages.lock.json", json.dumps(lock))
    assert table(df) == {("Newtonsoft.Json", "13.0.1"): (True, False), ("Serilog.Sinks.File", "5.0.0"): (True, False),
                         ("Serilog", "2.10.0"): (False, False)}
    assert edges(df) == {("Serilog.Sinks.File@5.0.0", "Serilog@2.10.0")}
    proj = parse_csproj("App.csproj", '''<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Dapper" Version="2.0.123" />
    <PackageReference Include="xunit"><Version>2.4.2</Version><PrivateAssets>all</PrivateAssets></PackageReference>
    <PackageReference Include="Floating" Version="1.*" />
  </ItemGroup>
</Project>''')
    assert table(proj) == {("Dapper", "2.0.123"): (True, False), ("xunit", "2.4.2"): (True, True),
                           ("Floating", None): (True, False)}


def test_manifest_without_a_lockfile_is_read_and_nested_dirs_are_separate(tmp_path):
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "package.json").write_text(json.dumps({"dependencies": {"lodash": "4.17.21", "x": "^1"}}))
    (tmp_path / "node_modules" / "y").mkdir(parents=True)                # never read
    (tmp_path / "node_modules" / "y" / "package.json").write_text(json.dumps({"dependencies": {"z": "1.0.0"}}))
    (tmp_path / "requirements.txt").write_text("Django==4.2.1\n")
    (tmp_path / "pyproject.toml").write_text("[tool.ruff]\nline-length = 100\n")   # no dependencies
    r = read_dependencies(tmp_path)
    assert [f.path for f in r.files] == ["requirements.txt", "web/package.json"]
    assert table(r.files[1]) == {("lodash", "4.17.21"): (True, False), ("x", None): (True, False)}
    assert r.summary() == {"PyPI": {"packages": 1, "direct": 1, "dev": 0},
                           "npm": {"packages": 2, "direct": 2, "dev": 0}}


def test_a_broken_file_is_a_warning_not_a_failure(tmp_path):
    (tmp_path / "package-lock.json").write_text("{not json")
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    r = read_dependencies(tmp_path)
    assert [f.path for f in r.files] == ["requirements.txt"]
    assert r.warnings and r.warnings[0].startswith("package-lock.json: could not be read")


def test_yaml_reader_refuses_what_it_does_not_understand():
    assert loads("a:\n  - x\n  - y\nb: 'q''s'\n") == {"a": ["x", "y"], "b": "q's"}
    with pytest.raises(YamlError):
        loads("a: 1\n  b: 2\n")


def test_frame_deps_cli_json(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    out = subprocess.run([sys.executable, "-m", "frame.cli", "deps", str(tmp_path), "-f", "json"],
                         capture_output=True, text=True, check=True).stdout
    data = json.loads(out)
    assert data["files"][0]["packages"][0]["purl"] == "pkg:pypi/requests@2.31.0"
    assert data["summary"] == {"PyPI": {"packages": 1, "direct": 1, "dev": 0}}


GO_MOD = '''module example.com/app

go 1.22

require (
	github.com/gin-gonic/gin v1.9.1
	golang.org/x/net v0.17.0 // indirect
	example.com/local v0.0.0
)

require github.com/stretchr/testify v1.8.4

replace golang.org/x/net => golang.org/x/net v0.23.0

replace example.com/local => ../local
'''


def test_go_mod_direct_indirect_and_replacements():
    from frame.sca.lockfiles import parse_go_mod
    df = parse_go_mod("go.mod", GO_MOD)
    assert table(df) == {("github.com/gin-gonic/gin", "1.9.1"): (True, False),
                         ("golang.org/x/net", "0.23.0"): (False, False),          # the replacement's version
                         ("github.com/stretchr/testify", "1.8.4"): (True, False)}
    assert {p.purl for p in df.packages.values() if "gin" in p.name} == {"pkg:golang/github.com/gin-gonic/gin@v1.9.1"}


CARGO_LOCK = '''version = 3

[[package]]
name = "app"
version = "0.1.0"
dependencies = ["serde", "tokio", "proptest"]

[[package]]
name = "serde"
version = "1.0.190"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.33.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = ["bytes 1.5.0"]

[[package]]
name = "bytes"
version = "1.5.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "proptest"
version = "1.3.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = ["bytes"]
'''
CARGO_TOML = '''[package]
name = "app"

[dependencies]
serde = "1"
tokio = { version = "1", features = ["full"] }

[dev-dependencies]
proptest = "1"
'''


def test_cargo_lock_roots_edges_and_dev_from_cargo_toml(tmp_path):
    (tmp_path / "Cargo.lock").write_text(CARGO_LOCK)
    (tmp_path / "Cargo.toml").write_text(CARGO_TOML)
    df = read_dependencies(tmp_path).files[0]
    assert table(df) == {("serde", "1.0.190"): (True, False), ("tokio", "1.33.0"): (True, False),
                         ("bytes", "1.5.0"): (False, False), ("proptest", "1.3.1"): (True, True)}
    assert edges(df) == {("tokio@1.33.0", "bytes@1.5.0"), ("proptest@1.3.1", "bytes@1.5.0")}


@pytest.mark.parametrize("doc", [
    {"object": {"pins": [{"package": "NIO", "repositoryURL": "https://github.com/apple/swift-nio.git",
                          "state": {"branch": None, "revision": "abc", "version": "2.58.0"}}]}, "version": 1},
    {"pins": [{"identity": "swift-nio", "kind": "remoteSourceControl",
               "location": "https://github.com/apple/swift-nio.git", "state": {"revision": "abc", "version": "2.58.0"}},
              {"identity": "local", "kind": "localSourceControl", "location": "/src/local", "state": {}}],
     "version": 2},
])
def test_package_resolved_v1_and_v2(doc):
    from frame.sca.lockfiles import parse_package_resolved
    df = parse_package_resolved("Package.resolved", json.dumps(doc))
    assert table(df) == {("github.com/apple/swift-nio", "2.58.0"): (None, False)}
    assert {p.purl for p in df.packages.values()} == {"pkg:swift/github.com/apple/swift-nio@2.58.0"}
