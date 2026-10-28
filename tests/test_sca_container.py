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
from pathlib import Path

import pytest

from frame.sca.advisories import AdvisoryDB, match
from frame.sca.container import ecosystem_of, os_release, read_image, read_image_tar, read_rootfs
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
