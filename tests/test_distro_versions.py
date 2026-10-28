"""Debian/Ubuntu (dpkg) and Alpine (apk) version order, checked against the real tools: every
pair of tests/fixtures/sca/distro/{dpkg,apk}.txt as `dpkg --compare-versions` and
`apk version -t` answered it (recorded), and live in Docker with FRAME_SCA_REAL=1."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from frame.sca.distro_versions import apk_compare, dpkg_compare
from frame.sca.versions import compare, sorted_versions

F = Path(__file__).parent / "fixtures" / "sca" / "distro"
SYMBOL = {-1: "<", 0: "=", 1: ">"}


@pytest.mark.parametrize("name,cmp", [("dpkg", dpkg_compare), ("apk", apk_compare)])
def test_every_recorded_pair_agrees_with_the_real_tool(name, cmp):
    rows = [line.split(" ") for line in (F / f"{name}_truth.txt").read_text().splitlines()]
    assert len(rows) > 900
    wrong = [(a, r, b, SYMBOL[cmp(a, b)]) for a, r, b in rows if SYMBOL[cmp(a, b)] != r]
    assert not wrong, wrong[:10]


def test_the_ecosystem_family_picks_the_order():
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
