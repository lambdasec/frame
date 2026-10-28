"""OS packages of container images (`frame deps --image` / `--rootfs`), matched against OSV's
distribution advisories. Ground truth: the images' own package managers (dpkg-query, apk list),
and OSV's API answer for every package (tests/fixtures/sca/container, recorded from the official
debian:12.0 and alpine:3.18.0 images)."""

import gzip
import io
import json
import os
import shutil
import tarfile
import zipfile
from pathlib import Path

import pytest

from frame.sca.advisories import AdvisoryDB, match
from frame.sca.container import ecosystem_of, os_release, read_files, read_image, read_image_tar, read_rootfs
from frame.sca.osv import compact

F = Path(__file__).parent / "fixtures" / "sca" / "container"
IMAGES = json.loads((F / "images.json").read_text())


@pytest.mark.parametrize("ref,rootfs", [("debian:12.0", "debian-12.0"), ("alpine:3.18.0", "alpine-3.18.0")])
def test_the_rootfs_reads_as_the_package_manager_does(ref, rootfs):
    files, warnings = read_rootfs(F / rootfs)
    assert not warnings and len(files) == 1
    assert files[0].ecosystem == IMAGES[ref]["ecosystem"]
    assert sorted([p.name, p.version] for p in files[0].packages.values()) == IMAGES[ref]["packages"]


def test_os_release_to_ecosystem():
    assert ecosystem_of(os_release('ID=ubuntu\nVERSION_ID="22.04"\nVERSION="22.04.4 LTS (Jammy Jellyfish)"')) == "Ubuntu:22.04:LTS"
    assert ecosystem_of(os_release('ID=ubuntu\nVERSION_ID="23.10"\nVERSION="23.10 (Mantic Minotaur)"')) == "Ubuntu:23.10"
    assert ecosystem_of(os_release("ID=alpine\nVERSION_ID=3.18.4")) == "Alpine:v3.18"
    assert ecosystem_of(os_release('ID=debian\nVERSION_ID="12"')) == "Debian:12"
    assert ecosystem_of(os_release('ID="rhel"\nVERSION_ID="9.3"')) is None           # no advisories: said, not guessed


@pytest.mark.parametrize("ref,rootfs", [("debian:12.0", "debian-12.0"), ("alpine:3.18.0", "alpine-3.18.0")])
def test_matching_agrees_with_the_osv_api(ref, rootfs):
    """For every package, the advisories OSV's API gives at that version (by id or alias) are the
    ones Frame matches offline from the same records, and a package OSV calls clean is clean."""
    records = json.loads(gzip.decompress((F / "osv_records.json.gz").read_bytes()))
    expected = json.loads((F / "osv_expected.json").read_text())
    files, _ = read_rootfs(F / rootfs)
    eco = files[0].ecosystem
    db = AdvisoryDB(tables={eco: compact(records, eco)["packages"]})
    found = {}
    for f in match(files, db):
        found.setdefault(f"{eco}|{f['package']}|{f['version']}", set()).update([f["id"], *f.get("aliases", [])])
    checked = 0
    for key, ids in expected.items():
        if not key.startswith(eco + "|"):
            continue
        checked += 1
        got = found.get(key, set())
        assert set(ids) <= got, (key, sorted(set(ids) - got)[:5])
        assert bool(ids) == bool(got), key
    assert checked == len(IMAGES[ref]["packages"])


def _layer(files: dict) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_image_layers_apply_in_order_with_whiteouts(tmp_path):
    base = F / "alpine-3.18.0"
    layers = [_layer({"etc/os-release": (base / "etc/os-release").read_text(),
                      "lib/apk/db/installed": (base / "lib/apk/db/installed").read_text()}),
              _layer({"lib/apk/db/.wh.installed": ""}),                            # removed...
              _layer({"lib/apk/db/installed": "P:zlib\nV:1.2.13-r1\no:zlib\n"})]    # ...and written again
    tar = tmp_path / "image.tar"
    with tarfile.open(tar, "w") as t:
        names = []
        for i, data in enumerate(layers):
            info = tarfile.TarInfo(f"layer{i}/layer.tar")
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
            names.append(info.name)
        m = json.dumps([{"Config": "c.json", "RepoTags": ["x:1"], "Layers": names}]).encode()
        info = tarfile.TarInfo("manifest.json")
        info.size = len(m)
        t.addfile(info, io.BytesIO(m))
    files, _ = read_image_tar(tar)
    assert [(p.name, p.version) for p in files[0].packages.values()] == [("zlib", "1.2.13-r1")]


def test_a_distribution_without_advisories_is_said(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/os-release").write_text('ID="rhel"\nVERSION_ID="9.3"\nPRETTY_NAME="Red Hat Enterprise Linux 9.3"\n')
    files, warnings = read_rootfs(tmp_path)
    assert files == [] and "Red Hat Enterprise Linux 9.3 has no advisories in Frame" in warnings[0]


@pytest.mark.skipif(os.environ.get("FRAME_SCA_REAL") != "1" or not shutil.which("docker"),
                    reason="live: set FRAME_SCA_REAL=1 (docker save of the real images)")
@pytest.mark.parametrize("ref", ["debian:12.0", "alpine:3.18.0"])
def test_live_docker_save_of_the_real_image(ref):
    files, warnings = read_image(ref)
    assert not warnings
    assert sorted([p.name, p.version] for p in files[0].packages.values()) == IMAGES[ref]["packages"]


LANG = json.loads((F / "lang-image.json").read_text())


def _by_place(files):
    return {f.ecosystem if f.kind == "installed" else f.path.split(":/", 1)[1]:
            sorted([p.name, p.version] for p in f.packages.values()) for f in files}


def test_language_packages_in_an_image_read_as_their_tools_do():
    """pip's /usr/local packages, the npm tree, and the jar's Maven coordinates equal what
    importlib.metadata, `npm ls` and the jar's pom.properties say; Debian's own python3-urllib3
    and python3-six (owned by dpkg) are left to Debian's advisories."""
    files, warnings = read_rootfs(F / "lang-image")
    assert _by_place(files) == LANG
    assert {f.kind for f in files if f.ecosystem in ("PyPI", "npm", "Maven")} == {"image"}
    assert any("2 language package(s) installed by the OS package manager" in w for w in warnings)
    assert ["urllib3", "1.26.4"] in LANG["usr/local/lib/python3.12/site-packages"]           # pip's, not Debian's 1.26.12


def _jar(entries: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return buf.getvalue()


def test_jars_inside_jars_and_jars_without_coordinates():
    from frame.sca.container import read_language_packages
    pom = "groupId=org.yaml\nartifactId=snakeyaml\nversion=1.33\n"
    boot = _jar({"BOOT-INF/lib/snakeyaml-1.33.jar": _jar({"META-INF/maven/org.yaml/snakeyaml/pom.properties": pom}),
                 "BOOT-INF/lib/homemade.jar": _jar({"a/B.class": b""}),
                 "META-INF/maven/com.acme/app/pom.properties": "groupId=com.acme\nartifactId=app\nversion=1.0\n"})
    files, warnings = read_language_packages({"srv/app.jar": boot, "opt/log4j-core-2.14.1.jar": _jar({"x": b""})}, "img")
    assert {(p.name, p.version) for f in files for p in f.packages.values()} == {
        ("org.yaml:snakeyaml", "1.33"), ("com.acme:app", "1.0")}
    # named only from pom.properties, never from a file name
    assert any("opt/log4j-core-2.14.1.jar: 1 jar(s) without Maven coordinates" in w for w in warnings)
    assert any("srv/app.jar: 1 jar(s) without" in w for w in warnings)


def test_npm_package_json_must_be_the_package_itself():
    from frame.sca.container import read_language_packages
    files, _ = read_language_packages({
        "app/node_modules/@scope/x/package.json": '{"name": "@scope/x", "version": "1.0.0"}',
        "app/node_modules/x/node_modules/y/package.json": '{"name": "y", "version": "2.0.0"}',
        "app/node_modules/z/package.json": '{"name": "not-z", "version": "3.0.0"}',      # not this directory's package
        "app/node_modules/w/package.json": '{"name": "w"}'}, "img")
    assert [(f.path, sorted((p.name, p.version) for p in f.packages.values())) for f in files] == [
        ("img:/app/node_modules", [("@scope/x", "1.0.0"), ("y", "2.0.0")])]


def test_apk_owned_python_packages_are_the_distributions():
    from frame.sca.container import read_language_packages
    files, warnings = read_language_packages({
        "lib/apk/db/installed": "P:py3-urllib3\nV:1.26.18-r0\no:py3-urllib3\n"
                                "F:usr/lib/python3.11/site-packages/urllib3-1.26.18.dist-info\nR:METADATA\n",
        "usr/lib/python3.11/site-packages/urllib3-1.26.18.dist-info/METADATA": "Name: urllib3\nVersion: 1.26.18\n",
        "usr/lib/python3.11/site-packages/flask-2.0.0.dist-info/METADATA": "Name: Flask\nVersion: 2.0.0\n"}, "img")
    assert [(p.name, p.version) for f in files for p in f.packages.values()] == [("Flask", "2.0.0")]
    assert "1 language package(s)" in warnings[0]


def test_an_image_without_a_distribution_still_has_its_language_packages():
    files, warnings = read_files({"app/node_modules/x/package.json": '{"name": "x", "version": "1.0.0"}'}, "img")
    assert [f.ecosystem for f in files] == ["npm"] and warnings == []


@pytest.mark.skipif(os.environ.get("FRAME_SCA_REAL") != "1" or not shutil.which("docker"),
                    reason="live: set FRAME_SCA_REAL=1 (docker build of lang-image.Dockerfile)")
def test_live_language_packages_of_the_rebuilt_image(tmp_path):
    import subprocess
    shutil.copy(F / "lang-image.Dockerfile", tmp_path / "Dockerfile")
    subprocess.run(["docker", "build", "-q", "-t", "frame-lang-fixture:test", str(tmp_path)], check=True,
                   capture_output=True, timeout=1800)
    files, _ = read_image("frame-lang-fixture:test")
    got = _by_place(files)
    for place in ("usr/local/lib/python3.12/site-packages", "app/node_modules", "app/lib/commons-text-1.9.jar"):
        assert got[place] == LANG[place], place


BIN = F / "binaries"


def _go_truth():
    """`go version -m`'s own listing: dep lines, a `=>` line replacing the dep above it."""
    text = (BIN / "go-version-m.txt").read_text()
    deps = []
    for line in text.splitlines():
        parts = line.strip().split("\t")
        if parts[0] == "dep":
            deps.append((parts[1], parts[2].lstrip("v")))
        elif parts[0] == "=>":
            deps[-1] = (parts[1], parts[2].lstrip("v"))
    return {("stdlib", text.split(": go", 1)[1].split()[0])} | set(deps)


def test_go_and_rust_binaries_read_as_their_tools_do():
    """Real binaries (Go 1.21.0 with a replaced module; Rust built with cargo auditable) give
    what `go version -m` and `rust-audit-info` print; the Go standard library is `stdlib`."""
    from frame.sca.binaries import read_binary
    go = read_binary(gzip.decompress((BIN / "svc-go.gz").read_bytes()))
    assert go.kind == "go" and go.main == "example.com/svc" and go.toolchain == "go1.21.0"
    assert {(n, v) for _, n, v in go.packages} == _go_truth()
    assert ("gopkg.in/yaml.v2", "2.2.7") in {(n, v) for _, n, v in go.packages}        # the replacement, not 2.2.8
    rust = read_binary(gzip.decompress((BIN / "svc-rust.gz").read_bytes()))
    truth = json.loads((BIN / "rust-audit-info.json").read_text())["packages"]
    assert rust.main == "svc"
    assert {(e, n, v) for e, n, v in rust.packages} == {
        ("crates.io", p["name"], p["version"]) for p in truth if p["source"] == "crates.io"}


def test_binaries_in_a_root_filesystem(tmp_path):
    (tmp_path / "usr/local/bin").mkdir(parents=True)
    for name in ("svc-go", "svc-rust"):
        p = tmp_path / "usr/local/bin" / name
        p.write_bytes(gzip.decompress((BIN / f"{name}.gz").read_bytes()))
        p.chmod(0o755)
    (tmp_path / "usr/local/bin/not-run").write_bytes(gzip.decompress((BIN / "svc-go.gz").read_bytes()))  # not executable
    files, warnings = read_rootfs(tmp_path)
    got = {f.path.split(":/", 1)[1]: (f.ecosystem, f.kind, sorted(p.name for p in f.packages.values())) for f in files}
    assert got == {"usr/local/bin/svc-go": ("Go", "image", ["gopkg.in/yaml.v2", "stdlib"]),
                   "usr/local/bin/svc-rust": ("crates.io", "image", ["smallvec"])}


def test_a_binary_without_build_info_and_an_old_go_binary():
    from frame.sca.binaries import GO_MAGIC, read_binary
    assert read_binary(b"\x7fELF" + b"\0" * 2000) is None                  # plain C, or Rust without auditable
    assert read_binary(b"MZ" + b"\0" * 2000) is None                       # not ELF
    old = b"\x7fELF" + b"\0" * 60 + GO_MAGIC + bytes([8, 0]) + b"\0" * 64  # flags without bit 1: Go < 1.18
    assert read_binary(old).kind == "go-old"


def test_go_replacement_by_a_local_directory_is_not_a_module_version():
    from frame.sca.binaries import go_modinfo
    main, deps = go_modinfo("path\tx\nmod\tx\t(devel)\t\ndep\ta.io/m\tv1.0.0\th1:x\n=>\t../m\t\n"
                            "dep\tb.io/n\tv2.0.0\th1:y\n")
    assert main == "x" and deps == [("b.io/n", "v2.0.0")]


@pytest.mark.skipif(os.environ.get("FRAME_SCA_REAL") != "1" or not shutil.which("docker"),
                    reason="live: set FRAME_SCA_REAL=1 (docker build of binaries/Dockerfile)")
def test_live_binaries_of_the_rebuilt_image():
    import subprocess
    subprocess.run(["docker", "build", "-q", "-t", "frame-bin-fixture:test", str(BIN)], check=True,
                   capture_output=True, timeout=3600)
    files, _ = read_image("frame-bin-fixture:test")
    got = {f.path.split(":/", 1)[1]: {(p.name, p.version) for p in f.packages.values()} for f in files if f.kind == "image"}
    assert got["usr/local/bin/svc-go"] == _go_truth()
    assert got["usr/local/bin/svc-rust"] == {("smallvec", "1.6.0")}
