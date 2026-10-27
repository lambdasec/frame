"""Resolved graphs: Maven and Gradle reports, .NET restore output and central versions, and
`--resolve`, which runs the build tools (stand-ins on PATH here, writing real-format output)."""

import json
import os
import stat
import sys
import textwrap

import pytest

from frame.sca import read_dependencies
from frame.sca.jvm import parse_gradle_report, parse_maven_tree, parse_maven_tree_json
from frame.sca.lockfiles import parse_project_assets


def table(df):
    return {(p.name, p.version): (p.direct, p.dev) for p in df.packages.values()}


def edges(df):
    name = {k: f"{p.name}@{p.version}" for k, p in df.packages.items()}
    return {(name[a], name[b]) for a, bs in df.edges.items() for b in bs}


MAVEN_TREE = """\
[INFO] com.acme:app:jar:1.0
[INFO] +- org.springframework.boot:spring-boot-starter-web:jar:3.1.0:compile
[INFO] |  +- org.springframework.boot:spring-boot-starter-logging:jar:3.1.0:compile
[INFO] |  |  \\- org.apache.logging.log4j:log4j-to-slf4j:jar:2.20.0:compile
[INFO] |  \\- io.netty:netty-transport-native-epoll:jar:linux-x86_64:4.1.92.Final:runtime (optional)
[INFO] \\- junit:junit:jar:4.13.2:test
[INFO]    \\- org.hamcrest:hamcrest-core:jar:1.3:test
com.acme:lib:jar:1.0
\\- com.google.guava:guava:jar:31.1-jre:compile
"""


def test_maven_tree_text_with_modules_classifiers_and_log_prefixes():
    df = parse_maven_tree("maven_dep_tree.txt", MAVEN_TREE)
    assert table(df) == {
        ("org.springframework.boot:spring-boot-starter-web", "3.1.0"): (True, False),
        ("org.springframework.boot:spring-boot-starter-logging", "3.1.0"): (False, False),
        ("org.apache.logging.log4j:log4j-to-slf4j", "2.20.0"): (False, False),
        ("io.netty:netty-transport-native-epoll", "4.1.92.Final"): (False, False),
        ("junit:junit", "4.13.2"): (True, True), ("org.hamcrest:hamcrest-core", "1.3"): (False, True),
        ("com.google.guava:guava", "31.1-jre"): (True, False)}
    assert ("org.springframework.boot:spring-boot-starter-logging@3.1.0",
            "org.apache.logging.log4j:log4j-to-slf4j@2.20.0") in edges(df)
    assert not any("com.acme" in p.name for p in df.packages.values())        # modules are not packages


def test_maven_tree_json():
    doc = {"groupId": "com.acme", "artifactId": "app", "version": "1.0", "children": [
        {"groupId": "org.yaml", "artifactId": "snakeyaml", "version": "1.33", "scope": "compile", "children": []},
        {"groupId": "junit", "artifactId": "junit", "version": "4.13.2", "scope": "test", "children": [
            {"groupId": "org.hamcrest", "artifactId": "hamcrest-core", "version": "1.3", "scope": "test"}]}]}
    df = parse_maven_tree_json("maven_dep_tree.json", json.dumps(doc))
    assert table(df) == {("org.yaml:snakeyaml", "1.33"): (True, False), ("junit:junit", "4.13.2"): (True, True),
                         ("org.hamcrest:hamcrest-core", "1.3"): (False, True)}


def test_maven_tree_json_of_a_multi_module_build_is_one_document_per_module():
    # `-DappendOutput=true` writes the modules' JSON documents back to back
    api = {"groupId": "com.acme", "artifactId": "api", "version": "1", "children": [
        {"groupId": "org.yaml", "artifactId": "snakeyaml", "version": "1.33", "scope": "compile"}]}
    web = {"groupId": "com.acme", "artifactId": "web", "version": "1", "children": [
        {"groupId": "junit", "artifactId": "junit", "version": "4.13.2", "scope": "test"}]}
    df = parse_maven_tree_json("maven_dep_tree.json", json.dumps(api, indent=2) + "\n" + json.dumps(web, indent=2))
    assert table(df) == {("org.yaml:snakeyaml", "1.33"): (True, False), ("junit:junit", "4.13.2"): (True, True)}


GRADLE = """\

------------------------------------------------------------
Root project 'app'
------------------------------------------------------------

compileClasspath - Compile classpath for source set 'main'.
+--- org.springframework.boot:spring-boot-starter-web -> 3.1.0
|    +--- org.springframework.boot:spring-boot-starter:3.1.0
|    |    \\--- org.yaml:snakeyaml:1.33
|    \\--- com.fasterxml.jackson.core:jackson-databind:2.15.0 -> 2.15.2
+--- project :lib
|    \\--- com.google.guava:guava:31.1-jre
+--- org.springframework.boot:spring-boot-starter-web:3.1.0 (*)
\\--- com.fasterxml.jackson.core:jackson-databind:{strictly 2.15.2} -> 2.15.2 (c)

implementation - Implementation only dependencies for source set 'main'. (n)
\\--- org.springframework.boot:spring-boot-starter-web (n)

testRuntimeClasspath - Runtime classpath of source set 'test'.
+--- org.springframework.boot:spring-boot-starter-web -> 3.1.0
\\--- org.junit.jupiter:junit-jupiter:5.9.3
     \\--- org.junit.jupiter:junit-jupiter-api:5.9.3

(c) - A dependency constraint, not a dependency.
(*) - Indicates repeated occurrences of a transitive dependency subtree.
"""


def test_gradle_report_resolution_projects_markers_and_test_configurations():
    df = parse_gradle_report("gradle-dependencies.txt", GRADLE)
    assert table(df) == {
        ("org.springframework.boot:spring-boot-starter-web", "3.1.0"): (True, False),
        ("org.springframework.boot:spring-boot-starter", "3.1.0"): (False, False),
        ("org.yaml:snakeyaml", "1.33"): (False, False),
        ("com.fasterxml.jackson.core:jackson-databind", "2.15.2"): (False, False),   # the resolved version
        ("com.google.guava:guava", "31.1-jre"): (True, False),                        # through project :lib
        ("org.junit.jupiter:junit-jupiter", "5.9.3"): (True, True),
        ("org.junit.jupiter:junit-jupiter-api", "5.9.3"): (False, True)}
    assert ("org.springframework.boot:spring-boot-starter@3.1.0", "org.yaml:snakeyaml@1.33") in edges(df)


def test_a_tree_report_beside_a_pom_replaces_it(tmp_path):
    (tmp_path / "pom.xml").write_text("<project><dependencies><dependency><groupId>a</groupId>"
                                      "<artifactId>b</artifactId><version>1</version></dependency>"
                                      "</dependencies></project>")
    (tmp_path / "maven_dep_tree.txt").write_text(MAVEN_TREE)
    r = read_dependencies(tmp_path)
    assert [f.path for f in r.files] == ["maven_dep_tree.txt"]
    assert r.summary()["Maven"]["packages"] == 7


ASSETS = {
    "version": 3,
    "targets": {"net8.0": {
        "Microsoft.Data.SqlClient/5.1.0": {"type": "package", "dependencies": {"Azure.Identity": "1.7.0"}},
        "Azure.Identity/1.7.0": {"type": "package"},
        "xunit/2.4.2": {"type": "package"},
        "MyLib/1.0.0": {"type": "project"}}},
    "project": {"frameworks": {"net8.0": {"dependencies": {
        "Microsoft.Data.SqlClient": {"target": "Package", "version": "[5.1.0, )"},
        "xunit": {"target": "Package", "version": "[2.4.2, )", "suppressParent": "All"}}}}},
}


def test_project_assets_from_obj_counts_for_the_project_directory(tmp_path):
    (tmp_path / "obj").mkdir()
    (tmp_path / "obj" / "project.assets.json").write_text(json.dumps(ASSETS))
    (tmp_path / "App.csproj").write_text('<Project><ItemGroup><PackageReference Include="Microsoft.Data.SqlClient" '
                                         'Version="5.1.0" /></ItemGroup></Project>')
    r = read_dependencies(tmp_path)
    assert [f.path for f in r.files] == ["obj/project.assets.json"]           # the csproj is not read twice
    assert table(r.files[0]) == {("Microsoft.Data.SqlClient", "5.1.0"): (True, False),
                                 ("Azure.Identity", "1.7.0"): (False, False), ("xunit", "2.4.2"): (True, True)}
    assert edges(parse_project_assets("a", json.dumps(ASSETS))) == {
        ("Microsoft.Data.SqlClient@5.1.0", "Azure.Identity@1.7.0")}


def test_central_package_versions_fill_csproj_references(tmp_path):
    (tmp_path / "Directory.Packages.props").write_text(
        '<Project><ItemGroup><PackageVersion Include="Dapper" Version="2.0.123" />'
        '<PackageVersion Include="Serilog" Version="3.0.1" /></ItemGroup></Project>')
    (tmp_path / "src" / "Api").mkdir(parents=True)
    (tmp_path / "src" / "Api" / "Api.csproj").write_text(
        '<Project><ItemGroup><PackageReference Include="Dapper" />'
        '<PackageReference Include="Serilog" VersionOverride="3.1.0" /></ItemGroup></Project>')
    r = read_dependencies(tmp_path)
    assert table(r.files[0]) == {("Dapper", "2.0.123"): (True, False), ("Serilog", "3.1.0"): (True, False)}


def _stand_in(bin_dir, name, script):
    path = bin_dir / name
    path.write_text("#!" + sys.executable + "\n" + textwrap.dedent(script))
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


@pytest.fixture
def fake_path(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + os.environ.get("PATH", ""))
    return bin_dir


@pytest.mark.skipif(sys.platform == "win32", reason="stand-in executables use a shebang")
def test_resolve_runs_maven_once_for_a_multi_module_build(tmp_path, fake_path):
    calls = tmp_path / "calls.txt"
    _stand_in(fake_path, "mvn", f"""
        import sys
        open({str(calls)!r}, "a").write(" ".join(sys.argv[1:]) + "\\n")
        out = next(a.split("=", 1)[1] for a in sys.argv if a.startswith("-DoutputFile="))
        open(out, "a").write({MAVEN_TREE!r})
    """)
    proj = tmp_path / "proj"
    (proj / "lib").mkdir(parents=True)
    (proj / "pom.xml").write_text("<project><modules><module>lib</module></modules></project>")
    (proj / "lib" / "pom.xml").write_text("<project/>")
    r = read_dependencies(proj, resolve=True)
    assert calls.read_text().count("dependency:tree") == 1
    assert [(f.path, f.kind) for f in r.files] == [("pom.xml", "resolved")]
    assert r.summary()["Maven"] == {"packages": 7, "direct": 3, "dev": 2}


@pytest.mark.skipif(sys.platform == "win32", reason="stand-in executables use a shebang")
def test_resolve_runs_gradle_for_every_project(tmp_path, fake_path):
    _stand_in(fake_path, "gradle", f"""
        import sys
        if "projects" in sys.argv:
            print("Root project 'app'\\n+--- Project ':lib'")
        else:
            assert ":lib:dependencies" in sys.argv
            print({GRADLE!r})
    """)
    (tmp_path / "settings.gradle").write_text("include 'lib'")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "build.gradle").write_text("")
    r = read_dependencies(tmp_path, resolve=True)
    assert [(f.path, f.kind) for f in r.files] == [("settings.gradle", "resolved")]


def test_resolve_without_the_tool_warns_and_keeps_the_manifest(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    (tmp_path / "pom.xml").write_text("<project><dependencies><dependency><groupId>a</groupId>"
                                      "<artifactId>b</artifactId><version>1</version></dependency>"
                                      "</dependencies></project>")
    r = read_dependencies(tmp_path, resolve=True)
    assert [(f.path, f.kind) for f in r.files] == [("pom.xml", "manifest")]
    assert any("needs Maven" in w for w in r.warnings)


PIP_REPORT = {"version": "1", "install": [
    {"requested": True, "metadata": {"name": "Flask", "version": "3.0.0",
                                     "requires_dist": ["Werkzeug>=3.0.0", "click>=8.1.3", "asgiref>=3.2; extra == 'async'"]}},
    {"requested": False, "metadata": {"name": "werkzeug", "version": "3.0.1", "requires_dist": ["MarkupSafe>=2.1.1"]}},
    {"requested": False, "metadata": {"name": "MarkupSafe", "version": "2.1.3"}},
    {"requested": False, "metadata": {"name": "click", "version": "8.1.7"}},
]}


def test_resolve_python_uses_pips_report_without_installing(tmp_path, monkeypatch):
    from frame.sca import resolve as R
    fake = tmp_path / "fakepip.py"
    fake.write_text(textwrap.dedent(f"""
        import sys, json
        args = sys.argv[1:]
        assert args[:2] == ["install", "--dry-run"] and "--only-binary" in args
        json.dump({PIP_REPORT!r}, open(args[args.index("--report") + 1], "w"))
    """))
    monkeypatch.setattr(R, "_pip_command", lambda: [sys.executable, str(fake)])
    (tmp_path / "proj").mkdir()
    (tmp_path / "proj" / "requirements.txt").write_text("flask>=3\n")
    r = read_dependencies(tmp_path / "proj", resolve=True)
    df = r.files[0]
    assert (df.path, df.kind) == ("requirements.txt", "resolved")
    assert table(df) == {("Flask", "3.0.0"): (True, False), ("werkzeug", "3.0.1"): (False, False),
                         ("MarkupSafe", "2.1.3"): (False, False), ("click", "8.1.7"): (False, False)}
    assert edges(df) == {("Flask@3.0.0", "werkzeug@3.0.1"), ("Flask@3.0.0", "click@8.1.7"),
                         ("werkzeug@3.0.1", "MarkupSafe@2.1.3")}


def test_resolving_a_pyproject_includes_extras_but_not_the_project_itself(tmp_path, monkeypatch):
    from frame.sca import resolve as R
    seen = {}

    def fake(project_dir, rel, requirements=None, specs=()):
        seen["specs"] = list(specs)
        return None, None
    monkeypatch.setattr(R, "resolve_python", fake)
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "my_app"\ndependencies = ["z3-solver>=4.8"]\n'
        '[project.optional-dependencies]\nscan = ["tree-sitter>=0.21"]\ndev = ["My-App[scan]", "pytest>=7"]\n')
    read_dependencies(tmp_path, resolve=True)
    assert seen["specs"] == ["z3-solver>=4.8", "tree-sitter>=0.21", "pytest>=7"]


def test_a_maven_report_covers_the_poms_of_its_modules(tmp_path):
    """A multi-module build's dependency:tree at the root resolves every module: the module
    poms (versions managed by the parent) must not add version-less duplicates."""
    (tmp_path / "maven_dep_tree.txt").write_text(MAVEN_TREE)
    (tmp_path / "pom.xml").write_text("<project><modules><module>api</module></modules></project>")
    (tmp_path / "api").mkdir()
    (tmp_path / "api" / "pom.xml").write_text("<project><dependencies><dependency><groupId>junit</groupId>"
                                              "<artifactId>junit</artifactId></dependency></dependencies></project>")
    r = read_dependencies(tmp_path)
    assert [f.path for f in r.files] == ["maven_dep_tree.txt"]
