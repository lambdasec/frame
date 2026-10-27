"""Ruby, PHP, Dart and Elixir dependencies, on real lockfiles (devise, BookStack, Flutter Gallery,
Phoenix; tests/fixtures/sca/ecosystems/*/SOURCE): package counts checked independently, dev
flags, version order and requirements checked against Ruby's own Gem::Version / Gem::Requirement,
and matching checked against the OSV API's answers for every package version in the four."""

import gzip
import itertools
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from frame.sca import read_dependencies
from frame.sca.advisories import AdvisoryDB, build_advisories, match
from frame.sca.morelocks import gemfile_groups, mix_exs_deps
from frame.sca.ranges import satisfies
from frame.sca.versions import compare

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures" / "sca" / "ecosystems"


@pytest.fixture(scope="module")
def projects(tmp_path_factory):
    d = tmp_path_factory.mktemp("eco")
    for p in FIX.iterdir():
        if p.is_dir():
            shutil.copytree(p, d / p.name)
    gz = d / "php-bookstack" / "composer.lock.gz"
    (d / "php-bookstack" / "composer.lock").write_bytes(gzip.decompress(gz.read_bytes()))
    gz.unlink()
    return d


def only(projects, name):
    [f] = read_dependencies(projects / name).files
    return f


def test_real_lockfiles_count_like_an_independent_reading(projects):
    lock = json.loads((projects / "php-bookstack" / "composer.lock").read_text())
    php = only(projects, "php-bookstack")
    assert len(php.packages) == len(lock["packages"]) + len(lock["packages-dev"])
    assert sum(p.dev for p in php.packages.values()) == len(lock["packages-dev"])
    assert {p.name for p in php.packages.values() if p.direct} == {
        n for n in {**json.loads((projects / "php-bookstack" / "composer.json").read_text())["require"],
                    **json.loads((projects / "php-bookstack" / "composer.json").read_text())["require-dev"]}
        if "/" in n}
    gem = only(projects, "ruby-devise")
    specs = (projects / "ruby-devise" / "Gemfile.lock").read_text().split("GEM\n", 1)[1].split("\nPLATFORMS")[0]
    assert len(gem.packages) == sum(1 for ln in specs.splitlines() if ln.startswith("    ") and not ln.startswith("     ")
                                    and "(" in ln)
    pub = only(projects, "dart-gallery")
    assert len(pub.packages) == (projects / "dart-gallery" / "pubspec.lock").read_text().count("source: hosted")
    hex_ = only(projects, "elixir-phoenix")
    assert len(hex_.packages) == (projects / "elixir-phoenix" / "mix.lock").read_text().count("{:hex,")
    assert gem.edges and php.edges and hex_.edges


def test_dev_flags_follow_the_manifests(projects):
    gem = {p.name: p for p in only(projects, "ruby-devise").packages.values()}
    assert gem["mocha"].dev and gem["timecop"].dev                       # group :test
    assert not gem["minitest"].dev                                       # in :test, but rails needs it at runtime
    assert not gem["bcrypt"].dev and gem["bcrypt"].direct                # the gemspec's runtime dependency
    assert not gem["bson"].dev                                           # reached through a git gem (mongoid)
    import re
    pub_lock = (projects / "dart-gallery" / "pubspec.lock").read_text()
    labelled = dict(re.findall(r'^  (\S+):\n    dependency: "?([^"\n]+)"?$', pub_lock, re.M))
    pub = {p.name: p for p in only(projects, "dart-gallery").packages.values()}
    assert all(p.dev == (labelled[n] == "direct dev") and p.direct == labelled[n].startswith("direct")
               for n, p in pub.items())                                  # pub's own labels
    hex_ = {p.name: p for p in only(projects, "elixir-phoenix").packages.values()}
    exs = {app: dev for app, _, dev in mix_exs_deps((projects / "elixir-phoenix" / "mix.exs").read_text())}
    # dev only in mix.exs and not needed (non-optionally) by anything production: dev in the graph
    assert all(hex_[a].dev for a, d in exs.items() if a in hex_ and d)


def test_gemfile_groups_and_mix_deps():
    g = gemfile_groups('gem "rails"\ngroup :development, :test do\n  gem "rspec"\nend\n'
                       'gem "pry", group: :development\ngem "puma", groups: [:production]\n'
                       'platforms :ruby do\n  gem "sqlite3"\nend\n')
    assert g == {"rails": False, "rspec": True, "pry": True, "puma": False, "sqlite3": False}
    deps = mix_exs_deps('defp deps do\n  [\n    {:phoenix, "~> 1.7"},\n    {:floki, ">= 0.30.0", only: :test},\n'
                        '    {:credo, "~> 1.7", only: [:dev, :test], runtime: false},\n    {:mylib, github: "x/y"}\n  ]\nend')
    assert deps == [("phoenix", "~> 1.7", False), ("floki", ">= 0.30.0", True), ("credo", "~> 1.7", True),
                    ("mylib", "", False)]


RUBY_VERSIONS = ["1.0", "1", "1.0.0", "1.0.a", "1.0.0.pre", "1.0.0.rc1", "1.0.0.beta.2", "1.0.0.beta.10", "0.9.9",
                 "1.0.1", "1.10", "1.9", "2.0.0.alpha", "6.1.4", "6.1.4.1", "6.1.7.3", "7.0.0.rc1", "7.0.0",
                 "1.0.0-x86", "3.2.0.pre1", "0.0.0"]
RUBY_REQS = ["~> 2.2", "~> 2.2.0", ">= 2.2, < 3", "~> 6.1, >= 6.1.4", "= 2.2", "!= 2.2", "> 2", "<= 3.0",
             "~> 1.0", ">= 0", "~> 3.0.0.beta", "~> 6.1.0"]


@pytest.mark.skipif(not shutil.which("ruby"), reason="needs ruby (Gem::Version)")
def test_rubygems_order_and_requirements_match_ruby():
    pairs = list(itertools.product(RUBY_VERSIONS, RUBY_VERSIONS))
    rb = ('require "json"; v=JSON.parse(ARGV[0]); r=JSON.parse(ARGV[1]); o={}; '
          'v.product(v).each{|a,b| o["c|#{a}|#{b}"]=(Gem::Version.new(a)<=>Gem::Version.new(b))}; '
          'v.product(r).each{|a,b| o["s|#{a}|#{b}"]=Gem::Requirement.new(*b.split(",").map(&:strip)).satisfied_by?(Gem::Version.new(a))}; '
          'puts o.to_json')
    ref = json.loads(subprocess.run(["ruby", "-e", rb, json.dumps(RUBY_VERSIONS), json.dumps(RUBY_REQS)],
                                    capture_output=True, text=True, check=True).stdout)
    assert [k for a, b in pairs if compare("RubyGems", a, b) != ref[(k := f"c|{a}|{b}")]] == []
    assert [k for a, r in itertools.product(RUBY_VERSIONS, RUBY_REQS)
            if satisfies("RubyGems", a, r) != ref[(k := f"s|{a}|{r}")]] == []


@pytest.mark.parametrize("eco,version,spec,want", [
    ("Packagist", "1.2.9", "~1.2", True), ("Packagist", "2.0.0", "~1.2", False),      # Composer's ~ differs from npm's
    ("Packagist", "1.3.0", "~1.2.3", False), ("Packagist", "0.4.0", "^0.3", False),
    ("Packagist", "1.2.7", "1.2.*", True), ("Packagist", "3.0.0", "^1.0 || ^3.0", True),
    ("Packagist", "v5.4.2", ">=5.4,<6", True), ("Packagist", "1.5", "1.0 - 2.0", True),
    ("Hex", "2.1.5", "~> 2.1.2", True), ("Hex", "2.2.0", "~> 2.1.2", False), ("Hex", "2.9.0", "~> 2.1", True),
    ("Hex", "2.5.0", "~> 1.0 or ~> 2.5", True), ("Hex", "1.5.0", ">= 1.0.0 and < 2.0.0", True),
    ("Pub", "1.9.0", "^1.2.3", True), ("Pub", "2.0.0", "^1.2.3", False), ("Pub", "5.0.0", "any", True),
])
def test_composer_hex_and_pub_requirements(eco, version, spec, want):
    assert satisfies(eco, version, spec) is want


def test_composer_versions_follow_stability_order():
    seq = ["1.0.0-dev", "1.0.0-alpha1", "1.0.0-alpha2", "1.0.0-beta1", "1.0.0-RC1", "1.0.0", "1.0.0-p1", "1.0.1", "1.10.0"]
    assert all(compare("Packagist", a, b) < 0 for a, b in zip(seq, seq[1:]))
    assert compare("Packagist", "v1.0.0", "1.0.0") == 0


def test_matching_agrees_with_the_osv_api_on_four_real_projects(projects, tmp_path, monkeypatch):
    from frame.kb.store import pull
    raw = tmp_path / "osv"
    raw.mkdir()
    (raw / "all.json").write_bytes(gzip.decompress((FIX / "osv_records.json.gz").read_bytes()))
    mirror = tmp_path / "mirror"
    build_advisories([raw], mirror, "r1", ["RubyGems", "Packagist", "Pub", "Hex"])
    monkeypatch.setenv("FRAME_KB_CACHE", str(tmp_path / "cache"))
    monkeypatch.setenv("FRAME_ADVISORIES_SOURCE", str(mirror))
    pull(None, source=str(mirror))
    db = AdvisoryDB.cached(["RubyGems", "Packagist", "Pub", "Hex"])
    record_ids = {r["id"] for r in json.loads(gzip.decompress((FIX / "osv_records.json.gz").read_bytes()))}
    expected = json.loads((FIX / "osv_expected.json").read_text())["vulnerable"]
    found = {}
    for proj in projects.iterdir():
        for f in match(read_dependencies(proj).files, db):
            found.setdefault((f["ecosystem"], f["package"], f["version"]), []).append(
                {f["id"], *f["aliases"]} & record_ids)
    for q in expected:
        groups = found.get((q["ecosystem"], q["name"], q["version"]), [])
        got = set().union(*groups) if groups else set()
        assert set(q["ids"]) <= got, (q["name"], q["version"], sorted(set(q["ids"]) - got))
        assert all(g & set(q["ids"]) for g in groups), (q["name"], q["version"])
    vulnerable = {(q["ecosystem"], q["name"], q["version"]) for q in expected}
    assert set(found) <= vulnerable                                      # nothing the API calls clean
