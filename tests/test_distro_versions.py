"""Debian/Ubuntu (dpkg), Alpine (apk) and AlmaLinux/Rocky Linux (rpm) version order, checked
against the real tools: every pair of tests/fixtures/sca/distro/{dpkg,apk}.txt as
`dpkg --compare-versions` and `apk version -t` answered it, and rpm's own `labelCompare` on
rpm_truth.json.gz (recorded), and live in Docker with FRAME_SCA_REAL=1."""

import gzip
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from frame.sca.distro_versions import apk_compare, dpkg_compare, rpm_compare
from frame.sca.versions import compare, sorted_versions

F = Path(__file__).parent / "fixtures" / "sca" / "distro"
SYMBOL = {-1: "<", 0: "=", 1: ">"}


@pytest.mark.parametrize("name,cmp", [("dpkg", dpkg_compare), ("apk", apk_compare)])
def test_every_recorded_pair_agrees_with_the_real_tool(name, cmp):
    rows = [line.split(" ") for line in (F / f"{name}_truth.txt").read_text().splitlines()]
    assert len(rows) > 900
    wrong = [(a, r, b, SYMBOL[cmp(a, b)]) for a, r, b in rows if SYMBOL[cmp(a, b)] != r]
    assert not wrong, wrong[:10]


def test_every_recorded_rpm_pair_agrees_with_rpm():
    """Edge cases (`~`, `^`, leading zeros, alpha against numeric, a missing release) in every
    combination, and 6,000 pairs of the versions installed in the Rocky Linux and AlmaLinux 8 and 9
    images, as rpm 4.16's `rpm.labelCompare` answered them."""
    rows = json.loads(gzip.decompress((F / "rpm_truth.json.gz").read_bytes()))
    assert len(rows) > 6800
    assert [(a, b, r) for a, b, r in rows if rpm_compare(a, b) != r] == []


def test_the_ecosystem_family_picks_the_order():
    assert compare("Rocky Linux:9", "1:3.0.7-25.el9_3", "1:3.0.7-28.el9_4") < 0
    assert compare("AlmaLinux:9", "3.0.7-25.el9", "1:1.0-1") < 0                   # the epoch wins
    assert compare("Debian:12", "1.0~rc1", "1.0") < 0 and compare("Ubuntu:22.04:LTS", "1:0.9", "2.0") > 0
    assert compare("Alpine:v3.18", "1.0_rc1", "1.0") < 0 and compare("Alpine:v3.20", "1.0", "1.0-r0") < 0
    assert sorted_versions("Debian:12", ["3.0.11-1", "3.0.11-1~deb12u1", "3.0.11-1~deb12u2"]) == \
        ["3.0.11-1~deb12u1", "3.0.11-1~deb12u2", "3.0.11-1"]


def _docker(image, script, mount):
    out = subprocess.run(["docker", "run", "--rm", "-v", f"{mount}:/w", image, "sh", "-c", script],
                         capture_output=True, text=True, timeout=1200, check=True).stdout
    return [line.split(" ") for line in out.splitlines() if len(line.split(" ")) == 3]


@pytest.mark.skipif(os.environ.get("FRAME_SCA_REAL") != "1" or not shutil.which("docker"),
                    reason="live: set FRAME_SCA_REAL=1 (runs dpkg and apk in Docker)")
def test_live_against_dpkg_and_apk(tmp_path):
    for name in ("dpkg.txt", "apk.txt"):
        shutil.copy(F / name, tmp_path / name)
    dpkg = _docker("debian:12-slim", "cd /w; while read a; do while read b; do if dpkg --compare-versions \"$a\" lt \"$b\"; "
                   "then r='<'; elif dpkg --compare-versions \"$a\" eq \"$b\"; then r='='; else r='>'; fi; "
                   "echo \"$a $r $b\"; done < dpkg.txt; done < dpkg.txt", tmp_path)
    apk = _docker("alpine:3.20", "cd /w; while read a; do while read b; do echo \"$a $(apk version -t \"$a\" \"$b\") $b\"; "
                  "done < apk.txt; done < apk.txt", tmp_path)
    for rows, cmp in ((dpkg, dpkg_compare), (apk, apk_compare)):
        rows = [r for r in rows if r[1] in "<=>"]
        assert len(rows) > 900
        assert [(a, r, b) for a, r, b in rows if SYMBOL[cmp(a, b)] != r] == []


@pytest.mark.skipif(os.environ.get("FRAME_SCA_REAL") != "1" or not shutil.which("docker"),
                    reason="live: set FRAME_SCA_REAL=1 (runs rpm in Docker)")
def test_live_against_rpm(tmp_path):
    rows = json.loads(gzip.decompress((F / "rpm_truth.json.gz").read_bytes()))
    (tmp_path / "pairs.json").write_text(json.dumps([[a, b] for a, b, _ in rows]))
    script = ("import json, rpm\n"
              "def evr(s):\n"
              "    e, _, rest = s.partition(':') if ':' in s else ('0', '', s)\n"
              "    v, sep, r = rest.rpartition('-')\n"
              "    return (e, v if sep else rest, r if sep else None)\n"
              "print(json.dumps([rpm.labelCompare(evr(a), evr(b)) for a, b in json.load(open('/w/pairs.json'))]))\n")
    out = subprocess.run(["docker", "run", "--rm", "-i", "-v", f"{tmp_path}:/w", "rockylinux/rockylinux:9.4", "python3", "-"],
                         input=script, capture_output=True, text=True, timeout=1200, check=True).stdout
    answers = json.loads(out)
    assert [(a, b, r) for (a, b, _), r in zip(rows, answers) if rpm_compare(a, b) != r] == []
