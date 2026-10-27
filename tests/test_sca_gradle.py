"""build.gradle / build.gradle.kts and the version catalog, read without running Gradle.

Ground truth: Gradle's own answer for the real-tool fixture projects (`tests/fixtures/sca/real/
gradle-*`, produced by Gradle itself) and Now in Android's real catalog and app build
(`tests/fixtures/sca/ecosystems/gradle-nowinandroid`, Apache-2.0)."""

import json
import shutil
from pathlib import Path

import pytest

from frame.sca import read_dependencies
from frame.sca.gradle import parse_gradle, read_catalog

REAL = Path(__file__).parent / "fixtures" / "sca" / "real"
NIA = Path(__file__).parent / "fixtures" / "sca" / "ecosystems" / "gradle-nowinandroid"


def pkgs(df):
    return {p.name: (p.version, p.dev) for p in df.packages.values()}


@pytest.mark.parametrize("case", ["gradle-groovy", "gradle-kotlin"])
def test_declared_dependencies_are_gradles_direct_dependencies(case, tmp_path):
    """Only the build scripts (no report, no lockfile): the names declared across the build are
    the direct dependencies Gradle reported, and the dev-only ones are Gradle's dev-only ones."""
    truth = json.loads((REAL / case / "expected.json").read_text())
    src = REAL / case / "files"
    for p in src.rglob("*"):
        if p.is_file() and p.name.startswith(("build.gradle", "settings.gradle")):
            (tmp_path / p.relative_to(src)).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(p, tmp_path / p.relative_to(src))
    report = read_dependencies(tmp_path)
    assert {f.path for f in report.files} >= {"build.gradle" + (".kts" if "kotlin" in case else "")}
    declared = {p.name: p for f in report.files for p in f.packages.values()}
    assert set(declared) == set(truth["direct"])
    truth_dev = {n for n, _ in truth["dev"]}
    assert {n for n, p in declared.items() if p.dev} == truth_dev & set(declared)


def test_a_lockfile_or_report_wins_over_the_build_script():
    for case in ("gradle-groovy", "gradle-kotlin"):
        if not (REAL / case / "files").is_dir():
            continue
        report = read_dependencies(REAL / case / "files")
        assert not any(f.kind == "manifest" and f.path.endswith(("build.gradle", "build.gradle.kts"))
                       for f in report.files), case


def test_now_in_android_catalog_and_app_build():
    report = read_dependencies(NIA)
    (df,) = [f for f in report.files if f.path == "app/build.gradle.kts"]
    got = pkgs(df)
    # each checked against the catalog text by hand: version.ref chains, explicit test configs
    assert got["androidx.core:core-ktx"] == ("1.15.0", False)
    assert got["io.coil-kt:coil"] == ("2.7.0", False)
    assert got["com.google.dagger:hilt-compiler"] == ("2.59", True)            # ksp
    assert got["org.robolectric:robolectric"] == ("4.16", True)                # testImplementation
    assert got["androidx.test.espresso:espresso-core"] == ("3.6.1", True)      # androidTestImplementation
    assert got["androidx.compose.material3:material3"] == (None, False)        # versioned by the BOM
    assert not any(":" not in n for n in got)                                  # projects.* are not packages
    assert len(got) == 28


def test_notations_variables_and_configurations():
    text = '''
    buildscript {
        dependencies { classpath "com.android.tools.build:gradle:8.1.0" }
    }
    ext { jacksonVersion = '2.15.2' }
    def guavaVersion = "32.1.3-jre"
    dependencies {
        // implementation 'commented:out:1.0'
        implementation "com.google.guava:guava:$guavaVersion"
        implementation "com.fasterxml.jackson.core:jackson-databind:${jacksonVersion}"
        implementation group: 'org.apache.commons', name: 'commons-text', version: '1.10.0'
        api platform('org.springframework.boot:spring-boot-dependencies:3.1.0')
        implementation 'org.springframework.boot:spring-boot-starter-web'
        implementation project(':lib')
        implementation files('libs/x.jar')
        compileOnly "org.projectlombok:lombok:${lombokVersion}"
        annotationProcessor 'org.projectlombok:lombok:1.18.30'
        testImplementation('junit:junit:4.13.2') { exclude group: 'org.hamcrest' }
        /* implementation 'block:comment:1.0' */
    }
    '''
    got = pkgs(parse_gradle("build.gradle", text, {"lombokVersion": "1.18.30"}))
    assert got == {
        "com.android.tools.build:gradle": ("8.1.0", True),
        "com.google.guava:guava": ("32.1.3-jre", False),
        "com.fasterxml.jackson.core:jackson-databind": ("2.15.2", False),
        "org.apache.commons:commons-text": ("1.10.0", False),
        "org.springframework.boot:spring-boot-dependencies": ("3.1.0", False),
        "org.springframework.boot:spring-boot-starter-web": (None, False),
        "org.projectlombok:lombok": ("1.18.30", False),    # compileOnly and annotationProcessor merge
        "junit:junit": ("4.13.2", True),
    }


def test_an_unknown_variable_is_never_guessed():
    got = pkgs(parse_gradle("build.gradle", 'dependencies { implementation "g:a:$nowhere" }'))
    assert got == {"g:a": (None, False)}


def test_kotlin_dsl_with_catalog_bundles_and_named_arguments():
    catalog = '''
    [versions]
    ktor = "2.3.5"
    [libraries]
    ktor-core = { module = "io.ktor:ktor-server-core", version.ref = "ktor" }
    ktor-netty = { group = "io.ktor", name = "ktor-server-netty", version.ref = "ktor" }
    slf4j = "org.slf4j:slf4j-api:2.0.9"
    strict = { module = "com.x:y", version = { strictly = "1.2.3" } }
    [bundles]
    ktor = ["ktor-core", "ktor-netty"]
    '''
    libs, bundles = read_catalog(catalog)
    assert libs["ktor.core"] == ("io.ktor:ktor-server-core", "2.3.5") and bundles["ktor"] == ["ktor.core", "ktor.netty"]
    text = '''
    val kotestVersion = "5.7.2"
    dependencies {
        implementation(libs.bundles.ktor)
        implementation(libs.slf4j)
        implementation(libs.strict.get())
        implementation(group = "com.h2database", name = "h2", version = "2.2.224")
        testImplementation("io.kotest:kotest-runner-junit5:$kotestVersion")
        implementation(kotlin("stdlib"))
    }
    '''
    got = pkgs(parse_gradle("build.gradle.kts", text, catalog=catalog))
    assert got == {
        "io.ktor:ktor-server-core": ("2.3.5", False), "io.ktor:ktor-server-netty": ("2.3.5", False),
        "org.slf4j:slf4j-api": ("2.0.9", False), "com.x:y": ("1.2.3", False),
        "com.h2database:h2": ("2.2.224", False), "io.kotest:kotest-runner-junit5": ("5.7.2", True),
    }


# --- applying an upgrade -------------------------------------------------------------------

def _plan(name, cur, target, path):
    return {"ecosystem": "Maven", "package": name, "current": cur, "target": target, "action": "raise-requirement",
            "path": path, "direct": True, "dev": False, "fixes": ["GHSA-x"], "unfixed": [], "via": [],
            "major": False, "requirers": [], "known_requirements": True}


def _apply(tmp_path, files, plans):
    from frame.sca.apply import apply_plan
    for rel, text in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(text)
    out = apply_plan(plans, tmp_path, write=True)
    return out, {rel: (tmp_path / rel).read_text() for rel in files}


def test_apply_edits_a_literal_coordinate(tmp_path):
    out, got = _apply(tmp_path, {"build.gradle": "dependencies {\n  implementation 'org.yaml:snakeyaml:1.33'\n"
                                                 "  testImplementation 'junit:junit:4.13.2'\n}\n"},
                      [_plan("org.yaml:snakeyaml", "1.33", "2.0", "build.gradle")])
    assert not out.manual and "'org.yaml:snakeyaml:2.0'" in got["build.gradle"] and "junit:4.13.2" in got["build.gradle"]


def test_apply_edits_the_catalog_and_only_this_library(tmp_path):
    catalog = ('[versions]\njackson = "2.14.0"\nktor = "2.3.0"\n[libraries]\n'
               'jackson-databind = { module = "com.fasterxml.jackson.core:jackson-databind", version.ref = "jackson" }\n'
               'ktor-core = { module = "io.ktor:ktor-server-core", version.ref = "ktor" }\n'
               'ktor-netty = { module = "io.ktor:ktor-server-netty", version.ref = "ktor" }\n'
               'snake = { module = "org.yaml:snakeyaml", version = "2.3.0" }\n')
    build = ("dependencies {\n  implementation(libs.jackson.databind)\n  implementation(libs.ktor.core)\n"
             "  implementation(libs.ktor.netty)\n  implementation(libs.snake)\n}\n")
    out, got = _apply(tmp_path, {"gradle/libs.versions.toml": catalog, "app/build.gradle.kts": build}, [
        _plan("com.fasterxml.jackson.core:jackson-databind", "2.14.0", "2.15.2", "app/build.gradle.kts"),
        _plan("org.yaml:snakeyaml", "2.3.0", "2.4.0", "app/build.gradle.kts"),       # same "2.3.0" text as ktor
        _plan("io.ktor:ktor-server-core", "2.3.0", "2.3.5", "app/build.gradle.kts"),  # ref shared with netty
    ])
    toml = got["gradle/libs.versions.toml"]
    assert 'jackson = "2.15.2"' in toml and 'version = "2.4.0"' in toml and 'ktor = "2.3.0"' in toml
    assert len(out.manual) == 1 and out.manual[0].startswith("io.ktor:ktor-server-core")
    assert got["app/build.gradle.kts"] == build
