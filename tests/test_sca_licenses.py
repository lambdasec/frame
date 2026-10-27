"""Licences of dependencies and the licence policy (`frame deps --licenses`).

Ground truth: the lockfiles' own fields (BookStack's real composer.lock), the installed
metadata Python reads through importlib.metadata, and, live, pnpm's own
`pnpm licenses list` (`FRAME_SCA_REAL=1`)."""

import gzip
import importlib.metadata as md
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from frame.sca import read_dependencies
from frame.sca.licenses import (OK, UNKNOWN, VIOLATION, Leaf, Op, Policy, SpdxError, check, composer_license,
                                enrich, evaluate, failing, is_spdx, parse_expression)
from frame.sca.model import PYPI, normalize_name

ECOS = Path(__file__).parent / "fixtures" / "sca" / "ecosystems"


# --- SPDX expressions -------------------------------------------------------------------------

def test_expression_grammar():
    assert parse_expression("MIT") == Leaf("MIT")
    assert parse_expression("MIT OR Apache-2.0 AND BSD-3-Clause") == \
        Op("OR", (Leaf("MIT"), Op("AND", (Leaf("Apache-2.0"), Leaf("BSD-3-Clause")))))      # AND binds tighter
    assert parse_expression("(MIT OR Apache-2.0) AND BSD-3-Clause") == \
        Op("AND", (Op("OR", (Leaf("MIT"), Leaf("Apache-2.0"))), Leaf("BSD-3-Clause")))
    assert parse_expression("GPL-2.0-or-later WITH Classpath-exception-2.0") == \
        Leaf("GPL-2.0-or-later", "Classpath-exception-2.0")
    assert parse_expression("(mit or isc)") == Op("OR", (Leaf("mit"), Leaf("isc")))         # npm's lower case
    for bad in ("", "MIT OR", "(MIT", "MIT)", "AND MIT", "MIT WITH", "MIT, Apache-2.0"):
        with pytest.raises(SpdxError):
            parse_expression(bad)
    assert is_spdx("Apache-2.0 OR MIT") and is_spdx("GPL-2.0+") and is_spdx("LicenseRef-Acme")
    assert not is_spdx("BSD") and not is_spdx("Apache License 2.0")


def test_policy_follows_the_expression():
    deny = Policy(deny=["GPL-*", "AGPL-*"])
    assert evaluate("MIT", deny)[0] == OK
    assert evaluate("GPL-3.0-only", deny)[0] == VIOLATION
    assert evaluate("MIT OR GPL-3.0-only", deny)[0] == OK                   # the user may choose MIT
    assert evaluate("MIT AND GPL-3.0-only", deny)[0] == VIOLATION           # both apply
    assert evaluate("GPL-2.0-only WITH Classpath-exception-2.0", deny)[0] == VIOLATION
    exact = Policy(deny=["GPL-2.0-only"])
    assert evaluate("GPL-2.0-only WITH Classpath-exception-2.0", exact)[0] == VIOLATION
    only_with = Policy(deny=["GPL-2.0-only WITH Classpath-exception-2.0"])
    assert evaluate("GPL-2.0-only", only_with)[0] == OK
    allow = Policy(allow=["MIT", "Apache-2.0", "BSD-*", "ISC"])
    assert evaluate("BSD-3-Clause", allow)[0] == OK
    assert evaluate("MPL-2.0", allow)[0] == VIOLATION
    assert evaluate("MPL-2.0 OR Apache-2.0", allow)[0] == OK
    assert evaluate("", allow)[0] == UNKNOWN
    assert evaluate("BSD", allow)[0] == UNKNOWN                              # not an SPDX id: never guessed
    assert evaluate("Commercial", Policy(deny=["commercial"]))[0] == VIOLATION   # deny may name it anyway
    assert evaluate("BSD OR GPL-3.0-only", deny)[0] == UNKNOWN               # one choice unknown, the other denied


# --- evidence ---------------------------------------------------------------------------------

def test_composer_lock_licences_are_read_from_the_lockfile():
    lock = json.loads(gzip.decompress((ECOS / "php-bookstack" / "composer.lock.gz").read_bytes()))
    expected = {}
    for section in ("packages", "packages-dev"):
        for p in lock[section]:
            lic = p.get("license") or []
            expected[p["name"].lower()] = lic[0] if len(lic) == 1 else " OR ".join(lic)
    from frame.sca.morelocks import parse_composer_lock
    df = parse_composer_lock("composer.lock", json.dumps(lock))
    got = {p.name.lower(): p.license for p in df.packages.values()}
    assert got == expected and sum(1 for v in got.values() if v) > 100
    assert composer_license(["LGPL-2.1-only", "GPL-3.0-or-later"]) == "LGPL-2.1-only OR GPL-3.0-or-later"


def test_installed_npm_metadata_of_the_same_version_only(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"a": "1.0.0", "b": "2.0.0", "c": "1.0.0"}}')
    (tmp_path / "yarn.lock").write_text('a@1.0.0:\n  version "1.0.0"\n\nb@2.0.0:\n  version "2.0.0"\n\n'
                                        'c@1.0.0:\n  version "1.0.0"\n')
    for name, meta in {"a": {"version": "1.0.0", "license": "ISC"},
                       "b": {"version": "1.9.0", "license": "MIT"},          # another version installed
                       "c": {"version": "1.0.0", "licenses": [{"type": "MIT"}, {"type": "Apache-2.0"}]}}.items():
        (tmp_path / "node_modules" / name).mkdir(parents=True)
        (tmp_path / "node_modules" / name / "package.json").write_text(json.dumps({"name": name, **meta}))
    r = read_dependencies(tmp_path)
    enrich(r.files, tmp_path)
    got = {p.name: (p.license, p.license_source) for f in r.files for p in f.packages.values()}
    assert got == {"a": ("ISC", "installed"), "b": ("", ""), "c": ("MIT OR Apache-2.0", "installed")}


def test_a_project_virtualenv_gives_python_licences(tmp_path):
    """The repository's own environment, read the way importlib.metadata reads it."""
    if sys.prefix == sys.base_prefix:
        pytest.skip("needs a virtualenv")
    site = [str(p) for p in Path(sys.prefix).glob("lib/python*/site-packages")] + \
        [str(p) for p in [Path(sys.prefix) / "Lib" / "site-packages"] if p.is_dir()]
    expected, pins = {}, []
    for dist in md.distributions(path=site):                # the venv's own, not the source tree's egg-info
        name, version = dist.metadata.get("Name"), dist.version
        if not name:
            continue
        expr = (dist.metadata.get("License-Expression") or "").strip()
        raw = (dist.metadata.get("License") or "").strip()
        lic = expr or (raw if raw and "\n" not in raw and is_spdx(raw) else "")
        pins.append(f"{name}=={version}")
        expected[normalize_name(PYPI, name)] = lic
    assert any(expected.values())
    (tmp_path / "requirements.txt").write_text("\n".join(pins) + "\n")
    os.symlink(sys.prefix, tmp_path / ".venv")
    r = read_dependencies(tmp_path)
    enrich(r.files, tmp_path)
    got = {normalize_name(PYPI, p.name): p.license for f in r.files for p in f.packages.values()}
    assert {k: v for k, v in got.items() if k in expected} == {k: v for k, v in expected.items() if k in got}


# --- policy over a project and the CLI --------------------------------------------------------

def _project(tmp_path, policy_toml):
    (tmp_path / "package.json").write_text('{"dependencies": {"a": "1.0.0", "g": "1.0.0"}, '
                                           '"devDependencies": {"d": "1.0.0"}}')
    lock = {"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"a": "1.0.0", "g": "1.0.0"}, "devDependencies": {"d": "1.0.0"}},
        "node_modules/a": {"version": "1.0.0", "license": "MIT"},
        "node_modules/g": {"version": "1.0.0", "license": "GPL-3.0-only"},
        "node_modules/d": {"version": "1.0.0", "license": "AGPL-3.0-only", "dev": True}}}
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    if policy_toml is not None:
        (tmp_path / ".frame.toml").write_text(policy_toml)


def _cli(tmp_path, *extra):
    return subprocess.run([sys.executable, "-m", "frame.cli", "deps", str(tmp_path), "--licenses", *extra],
                          capture_output=True, text=True)


def test_cli_fails_on_a_denied_licence_and_skips_dev_by_default(tmp_path):
    _project(tmp_path, '[licenses]\ndeny = ["GPL-*", "AGPL-*"]\n')
    proc = _cli(tmp_path, "-f", "json")
    assert proc.returncode == 1, proc.stderr
    data = json.loads(proc.stdout)
    status = {x["package"]: x["status"] for x in data["licenses"]}
    assert status == {"a": OK, "g": VIOLATION}                               # d is dev only
    policy = Policy(deny=["GPL-*", "AGPL-*"], include_dev=True)
    r = read_dependencies(tmp_path)
    assert {f.package.name: f.status for f in check(r.files, policy)}["d"] == VIOLATION


def test_cli_without_a_policy_lists_and_passes(tmp_path):
    _project(tmp_path, None)
    proc = _cli(tmp_path)
    assert proc.returncode == 0 and "no policy" in proc.stdout


def test_unknown_fails_only_when_asked(tmp_path):
    findings = check(read_dependencies(ECOS / "ruby-devise").files, Policy(allow=["MIT"]))
    assert findings and all(f.status == UNKNOWN for f in findings)                        # Gemfile.lock carries no licences
    assert not failing(findings, Policy(allow=["MIT"]))
    assert failing(findings, Policy(allow=["MIT"], unknown="fail"))


def test_config_is_strict(tmp_path):
    _project(tmp_path, '[licenses]\ndenny = ["GPL-*"]\n')
    proc = _cli(tmp_path)
    assert proc.returncode == 2 and "licenses" in proc.stderr


# --- live: pnpm's own answer ------------------------------------------------------------------

@pytest.mark.skipif(os.environ.get("FRAME_SCA_REAL") != "1" or not shutil.which("corepack"),
                    reason="live: set FRAME_SCA_REAL=1 (installs from the npm registry)")
def test_live_pnpm_licences_match_pnpm_licenses_list(tmp_path):
    """pnpm-lock.yaml has no licences, so every one comes from the installed store."""
    env = {**os.environ, "COREPACK_ENABLE_DOWNLOAD_PROMPT": "0", "CI": "1"}
    pnpm = ["corepack", "pnpm@9.12.0"]
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "x", "version": "1.0.0", "dependencies": {"express": "4.18.2", "jsonwebtoken": "9.0.0"},
        "devDependencies": {"mocha": "10.2.0"}}))
    subprocess.run(pnpm + ["install", "--ignore-scripts"], cwd=tmp_path, env=env, check=True, capture_output=True)
    truth = {}
    for flag in ("--prod", "--dev"):
        out = subprocess.run(pnpm + ["licenses", "list", "--json", flag], cwd=tmp_path, env=env, check=True,
                             capture_output=True, text=True).stdout
        for lic, pkgs in json.loads(out).items():
            for p in pkgs:
                for v in p["versions"]:
                    truth[(p["name"], v)] = lic
    r = read_dependencies(tmp_path)
    enrich(r.files, tmp_path)
    got = {(p.name, p.version): p.license or "Unknown" for f in r.files for p in f.packages.values()}
    both = set(truth) & set(got)
    assert len(both) > 100 and len(both) >= len(truth) - 2       # pnpm omits skipped optional packages
    assert {k: got[k] for k in both} == {k: truth[k] for k in both}
