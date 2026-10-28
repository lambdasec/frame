"""Licences from registries (`frame deps --licenses --registry`).

Ground truth, live (FRAME_SCA_REAL=1): the artifact the package manager installs -- each .gem's
own gemspec metadata, `cargo metadata`, each .nupkg's nuspec. (An old `gem specification
--remote` reads a reduced spec index and reports rack 2.2.8 with no licence; the .gem says MIT.)"""

import gzip
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import urllib.request
import zipfile
from pathlib import Path

import pytest

from frame.sca import read_dependencies
from frame.sca.licreg import RegistryLicences, enrich_from_registry
from frame.sca.model import CARGO, HEX, NUGET, RUBYGEMS

ECOS = Path(__file__).parent / "fixtures" / "sca" / "ecosystems"
REAL = Path(__file__).parent / "fixtures" / "sca" / "real"
LIVE = os.environ.get("FRAME_SCA_REAL") == "1"


def test_cached_including_an_empty_answer_and_offline_never_fetches(tmp_path, monkeypatch):
    monkeypatch.setenv("FRAME_REGISTRY_CACHE", str(tmp_path))
    calls = []

    def fetch(name, version):
        calls.append((name, version))
        return "MIT" if name == "rack" else ""
    lic = RegistryLicences(fetchers={RUBYGEMS: fetch})
    assert lic.license(RUBYGEMS, "rack", "2.2.8") == "MIT"
    assert lic.license(RUBYGEMS, "nolicense", "1.0") == ""
    assert lic.license(RUBYGEMS, "rack", "2.2.8") == "MIT" and len(calls) == 2         # cached
    assert lic.license(HEX, "jason", "1.4.1") is None                                    # not per version: not read
    assert RegistryLicences(offline=True, fetchers={RUBYGEMS: fetch}).license(RUBYGEMS, "other", "1") is None
    assert len(calls) == 2


def test_fills_only_what_the_lockfile_and_installed_metadata_left_unknown(tmp_path, monkeypatch):
    monkeypatch.setenv("FRAME_REGISTRY_CACHE", str(tmp_path / "cache"))
    files = read_dependencies(ECOS / "ruby-devise").files
    assert all(not p.license for f in files for p in f.packages.values())               # Gemfile.lock has none
    seen = {}

    def fetch(name, version):
        seen[name] = version
        return "MIT" if name != "warden" else "MIT OR Ruby"
    warnings = enrich_from_registry(files, RegistryLicences(fetchers={RUBYGEMS: fetch}))
    pkgs = {p.name: p for f in files for p in f.packages.values()}
    assert not warnings and pkgs["warden"].license == "MIT OR Ruby" and pkgs["warden"].license_source == "registry"
    assert all(seen[n] == pkgs[n].version for n in seen)                                 # the locked version


def test_an_unreachable_registry_is_a_warning(tmp_path, monkeypatch):
    from frame.sca.registry import RegistryError
    monkeypatch.setenv("FRAME_REGISTRY_CACHE", str(tmp_path))

    def fail(name, version):
        raise RegistryError("offline")
    files = read_dependencies(ECOS / "ruby-devise").files
    warnings = enrich_from_registry(files, RegistryLicences(fetchers={RUBYGEMS: fail}))
    assert len(warnings) == 1 and "offline" in warnings[0]


# --- live: against the artifacts the package managers install ------------------------------

def _gem_licences(name, version):
    with urllib.request.urlopen(f"https://rubygems.org/downloads/{name}-{version}.gem", timeout=60) as r:
        gem = tarfile.open(fileobj=io.BytesIO(r.read()))
    meta = gzip.decompress(gem.extractfile("metadata.gz").read()).decode()
    m = re.search(r"^licenses:\n((?:- .*\n)*)", meta, re.M)
    return [x[2:].strip().strip("'\"") for x in (m.group(1).splitlines() if m else [])]


@pytest.mark.skipif(not LIVE, reason="live: set FRAME_SCA_REAL=1 (rubygems.org)")
def test_live_rubygems_agrees_with_each_gem(tmp_path, monkeypatch):
    monkeypatch.setenv("FRAME_REGISTRY_CACHE", str(tmp_path))
    lic = RegistryLicences()
    gems = sorted({(p.name, p.version) for f in read_dependencies(ECOS / "ruby-devise").files
                   for p in f.packages.values()})[:20]
    for name, version in gems:
        truth = _gem_licences(name, version)
        want = truth[0] if len(truth) == 1 else " OR ".join(truth)
        assert lic.license(RUBYGEMS, name, version) == want, (name, version, truth)


@pytest.mark.skipif(not LIVE or not shutil.which("cargo"), reason="live: set FRAME_SCA_REAL=1 (cargo, crates.io)")
def test_live_crates_agree_with_cargo_metadata(tmp_path, monkeypatch):
    monkeypatch.setenv("FRAME_REGISTRY_CACHE", str(tmp_path / "cache"))
    proj = tmp_path / "proj"
    shutil.copytree(REAL / "cargo" / "files", proj)
    (proj / "src").mkdir(exist_ok=True)
    (proj / "src" / "main.rs").write_text("fn main() {}\n")
    meta = json.loads(subprocess.run(["cargo", "metadata", "--format-version", "1", "--locked"], cwd=proj,
                                     check=True, capture_output=True, text=True).stdout)
    truth = {(p["name"], p["version"]): p.get("license") or "" for p in meta["packages"] if p.get("source")}
    lic = RegistryLicences()
    for (name, version), want in sorted(truth.items()):
        assert lic.license(CARGO, name, version) == want, (name, version)


@pytest.mark.skipif(not LIVE, reason="live: set FRAME_SCA_REAL=1 (nuget.org)")
def test_live_nuget_agrees_with_each_nuspec(tmp_path, monkeypatch):
    monkeypatch.setenv("FRAME_REGISTRY_CACHE", str(tmp_path))
    lic = RegistryLicences()
    for name, version in [("Newtonsoft.Json", "13.0.1"), ("Serilog", "3.1.1"), ("Dapper", "2.1.24")]:
        url = f"https://api.nuget.org/v3-flatcontainer/{name.lower()}/{version}/{name.lower()}.{version}.nupkg"
        with urllib.request.urlopen(url, timeout=60) as r:
            pkg = zipfile.ZipFile(io.BytesIO(r.read()))
        nuspec = pkg.read(next(n for n in pkg.namelist() if n.endswith(".nuspec"))).decode("utf-8", "replace")
        m = re.search(r'<license\s+type="expression"\s*>([^<]+)</license>', nuspec)
        assert lic.license(NUGET, name, version) == (m.group(1).strip() if m else ""), (name, version)
