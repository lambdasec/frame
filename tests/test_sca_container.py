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
import xml.etree.ElementTree as ET
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
    assert ecosystem_of(os_release('ID="sles"\nVERSION_ID="12.5"')) is None          # no advisories: said, not guessed


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
    (tmp_path / "etc/os-release").write_text('ID="sles"\nVERSION_ID="12.5"\nPRETTY_NAME="SUSE Linux Enterprise Server 12 SP5"\n')
    files, warnings = read_rootfs(tmp_path)
    assert files == [] and "SUSE Linux Enterprise Server 12 SP5 has no advisories in Frame" in warnings[0]


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
    out = subprocess.run(["docker", "run", "--rm", "frame-bin-fixture:test", "cat", "/truth/govulncheck.json"],
                         check=True, capture_output=True, text=True, timeout=300).stdout
    dec, docs, i = json.JSONDecoder(), [], 0
    while i < len(out):
        while i < len(out) and out[i].isspace():
            i += 1
        if i < len(out):
            o, i = dec.raw_decode(out, i)
            docs.append(o)
    called = {o["finding"]["osv"] for o in docs if "finding" in o and o["finding"]["trace"][0].get("function")}
    binary = subprocess.run(["docker", "run", "--rm", "frame-bin-fixture:test", "cat", "/usr/local/bin/svc-go"],
                            check=True, capture_output=True, timeout=300).stdout
    tmp = Path(subprocess.check_output(["mktemp", "-d"], text=True).strip()) / "svc-go"
    tmp.write_bytes(binary)
    assert _govulncheck_called(tmp, [o["osv"] for o in docs if "osv" in o]) == called


def _govulncheck_called(binary: Path, records: list) -> set:
    """What Frame marks `called` in a Go binary: read it from a root filesystem, match it against
    a table built from these OSV records, and annotate reachability as `frame deps` does."""
    import tempfile
    from frame.sca.osv import compact
    from frame.sca.reachability import Usage, annotate
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "usr/local/bin").mkdir(parents=True)
        (root / "usr/local/bin/svc").write_bytes(binary.read_bytes() if binary.suffix != ".gz"
                                                 else gzip.decompress(binary.read_bytes()))
        (root / "usr/local/bin/svc").chmod(0o755)
        files, _ = read_rootfs(root)
        findings = match(files, AdvisoryDB(tables={"Go": compact(records, "Go")["packages"]}))
        annotate(findings, Usage(root, set()), root,
                 {df.path: (df.binary_functions, df.binary_platform) for df in files if df.binary_functions})
    called = set()
    for f in findings:
        if f["reachability"]["level"] == "called":
            called.update(i for i in [f["id"], *f.get("aliases", [])] if i.startswith("GO-"))
    return called


def test_go_functions_in_a_stripped_binary_agree_with_govulncheck():
    """govulncheck -mode binary on the unstripped twin of svc-go (on a stripped binary it falls
    back to every symbol of each package present) and Frame on the stripped svc-go itself, from
    the same OSV records: the same advisories are reached through a function the binary contains."""
    gv = json.loads(gzip.decompress((BIN / "govulncheck.json.gz").read_bytes()))
    assert gv["config"]["scanner_version"] == "v1.1.4" and gv["config"]["scan_mode"] == "binary"
    assert _govulncheck_called(BIN / "svc-go.gz", gv["osv"]) == set(gv["called"])
    assert len(gv["called"]) == 4                                          # three standard-library, one yaml.v2


def test_go_runtime_names_as_advisories_write_them():
    from frame.sca.binaries import advisory_name
    assert advisory_name("net/http.(*Server).Serve") == "net/http.Server.Serve"
    assert advisory_name("sync/atomic.(*Pointer[...]).Load") == "sync/atomic.Pointer.Load"
    assert advisory_name("pkg.F[...].func2.1") == "pkg.F"                  # a closure belongs to its function
    assert advisory_name("gopkg.in/yaml%2ev2.(*decoder).unmarshal") == "gopkg.in/yaml.v2.decoder.unmarshal"


def test_a_function_vulnerable_on_another_platform_is_not_called():
    from frame.sca.reachability import _platform_admits
    windows_only = {"id": "os.Chdir", "goos": ["windows"]}
    assert not _platform_admits(windows_only, ("linux", "arm64"))
    assert _platform_admits(windows_only, ("windows", "amd64"))
    assert not _platform_admits({"id": "x.F", "goarch": ["ppc64le"]}, ("linux", "amd64"))
    assert _platform_admits({"id": "x.F"}, ("linux", "amd64"))


RPM = json.loads((F / "rpm_images.json").read_text())


@pytest.mark.parametrize("rootfs", ["rocky-9.4", "alma-8.9", "ubi-9.4", "sles-15.6"])
def test_the_rpm_database_reads_as_rpm_does(rootfs):
    """rpm 4.16's sqlite database (Rocky Linux 9.4) and rpm 4.14's Berkeley DB (AlmaLinux 8.9),
    made by rpm itself from the official images: every package equals `rpm -qa`."""
    from frame.sca.rpmdb import read_rpmdb, RPMDB_PATHS
    files = {rel: (F / rootfs / rel).read_bytes() for rel in RPMDB_PATHS if (F / rootfs / rel).is_file()}
    _, rpms, warnings = read_rpmdb(files)
    assert not warnings
    assert sorted([n, evr] for n, _, evr, _ in rpms) == RPM[rootfs]["rpm_qa"]


@pytest.mark.parametrize("rootfs", ["rocky-9.4", "alma-8.9", "ubi-9.4", "azl-3.0", "leap-15.6", "ubi-10.0",
                                    "tumbleweed"])
def test_rpm_matching_agrees_with_the_osv_api(rootfs):
    """Rocky Linux's records name source packages (RLSA-2024:6783: `openssl`), AlmaLinux's
    binary ones (`openssl-libs`): each package is named as its distribution's advisories name it,
    and the advisories found offline are OSV's API answer for every package at its version."""
    from frame.sca.osv import compact
    records = json.loads(gzip.decompress((F / "rpm_osv_records.json.gz").read_bytes()))
    expected = json.loads((F / "rpm_osv_expected.json").read_text())
    files, warnings = read_rootfs(F / rootfs)
    assert not warnings and files[0].ecosystem == RPM[rootfs]["ecosystem"]
    eco = files[0].ecosystem
    db = AdvisoryDB(tables={eco: compact(records, eco)["packages"]})
    found = {}
    for f in match(files, db):
        found.setdefault(f"{eco}|{f['package']}|{f['version']}", set()).update([f["id"], *f.get("aliases", [])])
    keys = [k for k in expected if k.startswith(eco + "|")]
    assert len(keys) == len(files[0].packages)
    for key in keys:
        assert set(expected[key]) <= found.get(key, set()), (key, sorted(set(expected[key]) - found.get(key, set())))
        assert bool(expected[key]) == bool(found.get(key)), key
    names = {p.name for p in files[0].packages.values()}
    if eco.startswith("openSUSE"):                  # NDB; libopenssl3 is built from openssl-3
        assert "openssl-3" in names and "libopenssl3" not in names
    else:
        by_source = eco.split(":")[0] in ("Rocky Linux", "Azure Linux")
        assert ("openssl" in names) == by_source and ("openssl-libs" in names) == (not by_source)


def test_rpm_release_and_purl():
    from frame.sca.model import Package
    assert ecosystem_of(os_release('ID="rocky"\nVERSION_ID="9.4"')) == "Rocky Linux:9"
    assert ecosystem_of(os_release('ID="almalinux"\nVERSION_ID="8.9"')) == "AlmaLinux:8"
    assert ecosystem_of(os_release('ID="rhel"\nVERSION_ID="9.4"')) == "Red Hat:enterprise_linux:9"   # RHEL, UBI
    assert ecosystem_of(os_release('ID="rhel"\nVERSION_ID="7.9"')) is None              # streams disagree: not read
    # RHEL 10 is filed per minor release; the minors are one update line, so one table
    assert ecosystem_of(os_release('ID="rhel"\nVERSION_ID="10.0"')) == "Red Hat:enterprise_linux:10"
    assert ecosystem_of(os_release('ID="rhel"\nVERSION_ID="10.2"')) == "Red Hat:enterprise_linux:10"
    assert Package("Red Hat:enterprise_linux:9", "openssl-libs", "1:3.0.7-28.el9_4").purl == \
        "pkg:rpm/redhat/openssl-libs@3.0.7-28.el9_4?distro=rhel-9&epoch=1"
    assert Package("Rocky Linux:9", "openssl", "1:3.0.7-27.el9").purl == \
        "pkg:rpm/rocky-linux/openssl@3.0.7-27.el9?distro=rocky-linux-9&epoch=1"
    assert Package("AlmaLinux:8", "bash", "4.4.20-4.el8_6").purl == "pkg:rpm/almalinux/bash@4.4.20-4.el8_6?distro=almalinux-8"


def test_rpm_source_package_names():
    from frame.sca.rpmdb import source_name
    assert source_name("openssl-3.0.7-27.el9.src.rpm") == "openssl"
    assert source_name("python3.9-3.9.18-3.el9.src.rpm") == "python3.9"
    assert source_name("") == ""


@pytest.mark.skipif(os.environ.get("FRAME_SCA_REAL") != "1" or not shutil.which("docker"),
                    reason="live: set FRAME_SCA_REAL=1 (docker save of the real images, rpm -qa)")
@pytest.mark.parametrize("ref", ["rockylinux/rockylinux:9.4", "almalinux:8.9", "registry.access.redhat.com/ubi9/ubi:9.4"])
def test_live_rpm_images_read_as_rpm_does(ref):
    import subprocess
    from frame.sca.rpmdb import RPMDB_PATHS, read_rpmdb
    qa = subprocess.run(["docker", "run", "--rm", ref, "rpm", "-qa", "--qf",
                         "%{NAME} %|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\\n"],
                        check=True, capture_output=True, text=True, timeout=600).stdout
    truth = sorted(line.split(" ", 1) for line in qa.splitlines() if not line.startswith("gpg-pubkey "))
    files, warnings = read_image(ref)
    assert files[0].ecosystem in ("Rocky Linux:9", "AlmaLinux:8", "Red Hat:enterprise_linux:9")
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        cid = subprocess.run(["docker", "create", ref], check=True, capture_output=True, text=True).stdout.strip()
        try:
            subprocess.run(["docker", "cp", f"{cid}:/var/lib/rpm", tmp], check=True, capture_output=True)
        finally:
            subprocess.run(["docker", "rm", cid], capture_output=True)
        raw = {rel: (Path(tmp) / "rpm" / rel.split("/")[-1]).read_bytes() for rel in RPMDB_PATHS
               if rel.startswith("var/lib/rpm/") and (Path(tmp) / "rpm" / rel.split("/")[-1]).is_file()}
    _, rpms, _ = read_rpmdb(raw)
    assert sorted([n, evr] for n, _, evr, _ in rpms) == truth


def test_the_pull_hint_survives_a_shell():
    import shlex
    from frame.sca.advisories import pull_hint
    hint = pull_hint(["Rocky Linux:9", "Debian:12"])
    assert shlex.split(hint)[-2:] == ["--ecosystems", "Debian:12,Rocky Linux:9"]



def test_rhel_streams_merge_into_one_release_table():
    """`Red Hat:enterprise_linux:9::baseos` and `::appstream` (any stream) become one table for the
    release; RHEL 7 and the extended-support products are not read."""
    from frame.sca.osv import entries
    rec = {"id": "RHSA-X", "affected": [
        {"package": {"ecosystem": "Red Hat:enterprise_linux:9::baseos", "name": "openssl-libs"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1:3.0.7-29.el9_4"}]}]},
        {"package": {"ecosystem": "Red Hat:enterprise_linux:9::appstream", "name": "openssl-devel"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1:3.0.7-29.el9_4"}]}]},
        {"package": {"ecosystem": "Red Hat:rhel_eus:9.2::baseos", "name": "openssl-libs"}, "ranges": []},
        {"package": {"ecosystem": "Red Hat:enterprise_linux:7::server", "name": "openssl-libs"}, "ranges": []}]}
    got = [(eco, name) for eco, name, _ in entries(rec, ["Red Hat"])]
    assert got == [("Red Hat:enterprise_linux:9", "openssl-libs"), ("Red Hat:enterprise_linux:9", "openssl-devel")]


@pytest.mark.skipif(os.environ.get("FRAME_SCA_REAL") != "1", reason="live: set FRAME_SCA_REAL=1 (OSV's Red Hat export)")
def test_live_rhel_streams_still_agree(tmp_path):
    """Merging a RHEL release's streams is right only while no advisory gives one package two
    ranges in two streams. Checked over OSV's whole, current Red Hat export."""
    import re
    import urllib.request
    import zipfile
    data = tmp_path / "rh.zip"
    data.write_bytes(urllib.request.urlopen("https://osv-vulnerabilities.storage.googleapis.com/Red%20Hat/all.zip",
                                            timeout=600).read())
    seen: dict = {}
    differ = []
    with zipfile.ZipFile(data) as z:
        for n in z.namelist():
            rec = json.loads(z.read(n))
            for a in rec.get("affected", []):
                m = re.fullmatch(r"Red Hat:enterprise_linux:(8|9)::\w+", a["package"]["ecosystem"])
                if not m:
                    continue
                ev = sorted(json.dumps(e, sort_keys=True) for r in a.get("ranges", []) for e in r.get("events", []))
                key = (m.group(1), a["package"]["name"], rec["id"])
                if seen.setdefault(key, ev) != ev:
                    differ.append(key)
    assert len(seen) > 50000 and differ == [], differ[:5]


# -- Wolfi (and Chainguard's images, which say ID=wolfi) -----------------------------------------

WOLFI = json.loads((F / "wolfi_osv_expected.json").read_text())


@pytest.mark.parametrize("rootfs", ["wolfi-base", "wolfi-python"])
def test_wolfi_matching_agrees_with_the_osv_api(rootfs):
    """Wolfi's records (Chainguard's CGA advisories) name each package itself, a subpackage too
    (`ld-linux-2.44`, not its origin `glibc-2.44`; they differ), so a package is keyed by its own
    name. OSV's API answer for every installed package at its version, compared at the
    vulnerability level: CGA records about the same CVE for one package are one advisory
    (their `upstream` CVE is an alias), so every id OSV gives is in one of Frame's, and each of
    Frame's holds one OSV gives. The records are OSV's, cut to the installed packages' entries."""
    from frame.sca.osv import compact
    records = json.loads(gzip.decompress((F / "wolfi_osv_records.json.gz").read_bytes()))
    files, warnings = read_rootfs(F / rootfs)
    assert not warnings and [f.ecosystem for f in files] == ["Wolfi"]
    db = AdvisoryDB(tables={"Wolfi": compact(records, "Wolfi")["packages"]})
    groups = {}
    for f in match(files, db):
        groups.setdefault(f"{f['package']}@{f['version']}", []).append({f["id"], *f["aliases"]})
    expected = WOLFI["images"][rootfs]
    for key, ids in expected.items():
        for i in ids:
            assert any(i in g for g in groups.get(key, [])), (key, i)
    for key, gs in groups.items():
        for g in gs:
            assert g & set(expected.get(key, [])), (key, sorted(g))
    names = {p.name for p in files[0].packages.values()}
    assert {"ld-linux-2.44", "glibc-2.44"} <= names                     # each package, not its origin
    assert any(a.startswith("CVE-") for gs in groups.values() for g in gs for a in g)   # the upstream CVE


def test_wolfi_release_and_purl():
    from frame.sca.model import Package
    assert ecosystem_of(os_release('ID=wolfi\nVERSION_ID="20230201"')) == "Wolfi"
    assert Package("Wolfi", "glibc-2.44", "2.44-r11").purl == "pkg:apk/wolfi/glibc-2.44@2.44-r11"


def test_azure_linux_versions_are_compared_without_the_dist_tag():
    """Azure Linux's OSV records omit the `.azl3` every installed package (and Microsoft's own
    OVAL) carries: the build a record calls last affected is the installed one, and a fixed
    release one above it is newer. Read with the tag, `21.azl3` would sort after `21`."""
    from frame.sca.model import Package
    from frame.sca.osv import is_affected
    unfixed = {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"last_affected": "2.38-21"}]}]}
    fixed = {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.38-21"}]}]}
    assert is_affected("Azure Linux:3", "2.38-21.azl3", unfixed)
    assert not is_affected("Azure Linux:3", "2.38-22.azl3", unfixed)
    assert not is_affected("Azure Linux:3", "2.38-21.azl3", fixed) and is_affected("Azure Linux:3", "2.38-20.azl3", fixed)
    assert not is_affected("Rocky Linux:9", "2.38-21.el9", unfixed)         # other rpm distributions keep their tags
    assert ecosystem_of(os_release('ID=azurelinux\nVERSION_ID="3.0"')) == "Azure Linux:3"
    assert ecosystem_of(os_release('ID=mariner\nVERSION_ID="2.0"')) == "Azure Linux:2"        # CBL-Mariner 2.0
    assert ecosystem_of(os_release('ID=mariner\nVERSION_ID="1.0"')) is None                    # not in OSV
    assert is_affected("Azure Linux:2", "2.35-10.cm2", {"ranges": [{"type": "ECOSYSTEM", "events": [
        {"introduced": "0"}, {"last_affected": "2.35-10"}]}]})
    assert Package("Azure Linux:3", "glibc", "2.38-21.azl3").purl == "pkg:rpm/azure-linux/glibc@2.38-21.azl3?distro=azure-linux-3"


def test_suse_releases_and_purl():
    """openSUSE Leap's advisories are per release (`openSUSE:Leap 15.6`) under source package
    names; SLES and BCI images are `SUSE:Linux Enterprise 15 SPn`, read from SUSE's OVAL under
    binary package names. OSV's own SUSE records are not read: they file each patch under a module
    the image does not record."""
    from frame.sca.model import Package
    assert ecosystem_of(os_release('ID="opensuse-leap"\nVERSION_ID="15.6"')) == "openSUSE:Leap 15.6"
    assert ecosystem_of(os_release('ID="sles"\nVERSION_ID="15.6"')) == "SUSE:Linux Enterprise 15 SP6"
    assert ecosystem_of(os_release('ID="sles"\nVERSION_ID="12.5"')) is None
    assert ecosystem_of(os_release('ID="opensuse-tumbleweed"\nVERSION_ID="20261020"')) == "openSUSE:Tumbleweed"
    from frame.sca.osv import entries

    def eco_of(name, family="openSUSE"):
        rec = {"id": "x", "affected": [{"package": {"name": "opera", "ecosystem": name},
                                        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]}
        return [e for e, _, _ in entries(rec, [family])]
    assert eco_of("openSUSE:Leap 15.6 NonFree") == ["openSUSE:Leap 15.6"]   # the non-OSS repository: same system
    assert eco_of("openSUSE:Leap Micro 5.5") == []                          # a host OS, not an image
    assert eco_of("SUSE:Linux Enterprise Module for Basesystem 15 SP6", "SUSE") == []
    assert Package("openSUSE:Leap 15.6", "openssl-3", "3.1.4-150600.5.21.1").purl == \
        "pkg:rpm/opensuse/openssl-3@3.1.4-150600.5.21.1?distro=opensuse-leap-15.6"
    assert Package("SUSE:Linux Enterprise 15 SP6", "libopenssl3", "3.1.4-150600.5.39.1").purl == \
        "pkg:rpm/suse/libopenssl3@3.1.4-150600.5.39.1?distro=sles-15-sp6"


def test_sles_matching_agrees_with_openscap(tmp_path):
    """A SLES 15 SP6 image (BCI base, trimmed by rpm itself) matched against a table built from
    SUSE's patch OVAL finds exactly the CVEs OpenSCAP's `oscap oval eval` found true in the image
    (the OVAL is cut down to the definitions naming its packages, true and false)."""
    from frame.sca.advisories import build_advisories
    oval = F / "sles-oval" / "suse.linux.enterprise.15-sp6-patch.xml.gz"
    build_advisories([oval], tmp_path / "kb", "t", ecosystems=["SUSE"])
    files, warnings = read_rootfs(F / "sles-15.6")
    assert not warnings and files[0].ecosystem == "SUSE:Linux Enterprise 15 SP6"
    assert sorted([p.name, p.version] for p in files[0].packages.values()) == RPM["sles-15.6"]["rpm_qa"]
    found = match(files, AdvisoryDB.from_dir(tmp_path / "kb", [files[0].ecosystem]))
    cves = {a for f in found for a in [f["id"], *f["aliases"]] if a.startswith("CVE-")}
    truth = json.loads((F / "sles-oval" / "oscap_expected.json").read_text())["true"]
    assert cves == {c for d in truth.values() for c in d["cves"]}
    ids = {a for f in found for a in [f["id"], *f["aliases"]]}
    assert {d["advisory"] for d in truth.values() if d["advisory"]} <= ids
    assert {f["package"] for f in found} >= {"libexpat1", "libopenssl3", "glibc"}      # binary names


def test_suse_oval_reader():
    """A patch definition gives each binary package it tests (`less than` the fixed EVR, epoch 0
    dropped) an advisory named by its SUSE-SU id, its CVEs as aliases and SUSE's severity; a
    definition only for another product (SAP, HA, LTSS) is left out; a file not named as SUSE
    names a service pack's patch OVAL is not read as one."""
    from frame.sca.suse_oval import ecosystem_of as oval_eco, entries as oval_entries
    oval = F / "sles-oval" / "suse.linux.enterprise.15-sp6-patch.xml.gz"
    assert oval_eco(oval) == "SUSE:Linux Enterprise 15 SP6"
    assert oval_eco(Path("suse.linux.enterprise.15-sp6-affected.xml.gz")) is None
    rows = [(n, e) for _, n, e in oval_entries(oval)]
    expat = [e for n, e in rows if n == "libexpat1" and e["id"] == "SUSE-SU-2025:03624-1"]
    assert expat and expat[0]["aliases"] == ["CVE-2025-59375"] and expat[0]["severity"] == "high"
    assert expat[0]["ranges"] == [{"type": "ECOSYSTEM", "events": [{"introduced": "0"},
                                                                   {"fixed": "2.7.1-150400.3.31.1"}]}]
    assert not any(e["ranges"][0]["events"][1]["fixed"].startswith("0:") for _, e in rows)


@pytest.mark.skipif(os.environ.get("FRAME_SCA_REAL") != "1", reason="live: set FRAME_SCA_REAL=1 (needs docker)")
def test_live_sles_matching_agrees_with_openscap_on_today_s_oval(tmp_path):
    """SUSE's current SP6 patch OVAL, evaluated by OpenSCAP inside the pinned BCI image and matched
    by Frame against that image's own rpm database: the same CVEs."""
    import re
    import subprocess
    import urllib.request
    if shutil.which("docker") is None:
        pytest.fail("docker is not installed")
    oval = tmp_path / "suse.linux.enterprise.15-sp6-patch.xml.gz"
    oval.write_bytes(urllib.request.urlopen("https://ftp.suse.com/pub/projects/security/oval/"
                                            "suse.linux.enterprise.15-sp6-patch.xml.gz", timeout=300).read())
    (tmp_path / "p.xml").write_bytes(gzip.decompress(oval.read_bytes()))
    out = subprocess.run(["docker", "run", "--rm", "-v", f"{tmp_path}:/data", RPM["sles-15.6"]["image"], "sh", "-c",
                          "zypper -n -q in openscap-utils >/dev/null 2>&1; oscap oval eval /data/p.xml; "
                          "cp /usr/lib/sysimage/rpm/Packages.db /data/Packages.db"],
                         capture_output=True, text=True, timeout=1800).stdout
    true_defs = set(re.findall(r"Definition (oval:\S+): true", out))
    root = ET.parse(tmp_path / "p.xml").getroot()
    o = "{http://oval.mitre.org/XMLSchema/oval-definitions-5}"
    truth = {r.get("ref_id") for d in root.iter(o + "definition") if d.get("id") in true_defs
             for r in d.iter(o + "reference") if (r.get("ref_id") or "").startswith("CVE-")}
    rootfs = tmp_path / "rootfs"
    (rootfs / "etc").mkdir(parents=True)
    (rootfs / "etc" / "os-release").write_text('ID="sles"\nVERSION_ID="15.6"\n')
    (rootfs / "usr/lib/sysimage/rpm").mkdir(parents=True)
    shutil.copy(tmp_path / "Packages.db", rootfs / "usr/lib/sysimage/rpm/Packages.db")
    from frame.sca.advisories import build_advisories
    build_advisories([oval], tmp_path / "kb", "t", ecosystems=["SUSE"])
    files, _ = read_rootfs(rootfs)                 # the image has openscap-utils too, as oscap saw it
    found = match(files, AdvisoryDB.from_dir(tmp_path / "kb", [files[0].ecosystem]))
    assert {a for f in found for a in [f["id"], *f["aliases"]] if a.startswith("CVE-")} == truth


def test_an_ndb_database_is_read_without_rpm():
    """SUSE's NDB `Packages.db` (rpm's lib/backend/ndb): the fixture was trimmed by rpm itself,
    and the packages equal its `rpm -qa` (signing keys are not packages)."""
    from frame.sca.rpmdb import read_rpmdb
    db = (F / "leap-15.6" / "usr/lib/sysimage/rpm/Packages.db").read_bytes()
    path, rows, warnings = read_rpmdb({"usr/lib/sysimage/rpm/Packages.db": db}, set())
    assert not warnings and sorted([n, evr] for n, _, evr, _ in rows) == RPM["leap-15.6"]["rpm_qa"]
    assert ("libopenssl3", "openssl-3") in {(n, s) for n, s, _, _ in rows}
    bad = bytearray(db)
    bad[32:36] = b"XXXX"                                  # a corrupt slot is said, never read past
    assert "bad NDB slot" in read_rpmdb({"usr/lib/sysimage/rpm/Packages.db": bytes(bad)}, set())[2][0]


def test_rhel_10_minor_releases_are_one_table():
    """A fix filed under RHEL 10.2 is one a 10.0 system still lacks: the minors' records are one
    table, so the last UBI 10.0 image (patched within 10.0, nothing in OSV's 10.0 answer) has the
    advisories filed for 10.1 and 10.2 (the union of OSV's answers, in the rpm test above)."""
    from frame.sca.osv import entries
    rec = {"id": "RHSA-X", "affected": [
        {"package": {"name": "glibc", "ecosystem": "Red Hat:enterprise_linux:10.2"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0:2.39-58.el10_2"}]}]},
        {"package": {"name": "glibc", "ecosystem": "Red Hat:enterprise_linux_eus:10.0"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0:2.39-46.el10_0.2"}]}]}]}
    assert [e for e, _, _ in entries(rec, ["Red Hat"])] == ["Red Hat:enterprise_linux:10"]   # EUS is not read
    expected = json.loads((F / "rpm_osv_expected.json").read_text())
    assert expected["Red Hat:enterprise_linux:10|glibc|2.39-46.el10_0"]
