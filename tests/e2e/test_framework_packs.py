"""Every framework fixture under benchmarks/exemplars/frameworks, scanned like a user would.

Layout (see that directory's README):

    <language>/<framework>/framework.toml
    <language>/<framework>/vulnerable/...   lines marked `frame-expect: CWE-n`
    <language>/<framework>/safe/...         the same app done correctly

For each fixture:
  * every marked line is reported with the marked CWE;
  * nothing else of those CWEs is reported in the vulnerable app (no unlabelled finding);
  * the safe twin has no finding of those CWEs;
  * the packs the manifest names were applied, and -- when the manifest says the pack
    is what makes the difference -- scanning with --no-packs misses at least one marker.
"""

from pathlib import Path

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib

from e2e_helpers import expectations, scan

ROOT = Path(__file__).resolve().parents[2] / "benchmarks" / "exemplars" / "frameworks"
FIXTURES = sorted(p.parent for p in ROOT.glob("*/*/framework.toml"))


def _ids(paths):
    return [f"{p.parent.name}/{p.name}" for p in paths]


def _manifest(d: Path) -> dict:
    return tomllib.loads((d / "framework.toml").read_text(encoding="utf-8"))


def _hits(result, expected):
    return {key for key, cwes in expected.items() if cwes <= result.at(*key)}


@pytest.mark.parametrize("fixture", FIXTURES, ids=_ids(FIXTURES))
def test_framework_fixture(fixture):
    manifest = _manifest(fixture)
    vulnerable, safe = fixture / "vulnerable", fixture / "safe"
    expected = expectations(vulnerable)
    assert expected, f"{fixture}: the vulnerable app has no `frame-expect:` markers"
    wanted = set().union(*expected.values())

    result = scan(vulnerable)
    assert result.exit_code == 0, result.stderr
    missed = sorted(set(expected) - _hits(result, expected))
    assert not missed, (
        f"{fixture.name}: expected findings not reported: "
        f"{[(p, n, sorted(expected[(p, n)])) for p, n in missed]}\n"
        f"reported: {sorted((f['path'], f['line'], f['cwe_id']) for f in result.findings)}")
    unlabelled = sorted((f["path"], f["line"], f["cwe_id"]) for f in result.findings
                        if f["cwe_id"] in wanted and f["cwe_id"] not in expected.get((f["path"], f["line"]), ()))
    assert not unlabelled, f"{fixture.name}: findings with no `frame-expect` marker: {unlabelled}"

    twin = scan(safe)
    assert twin.exit_code == 0, twin.stderr
    leaked = sorted((f["path"], f["line"], f["cwe_id"]) for f in twin.findings if f["cwe_id"] in wanted)
    assert not leaked, f"{fixture.name}: the safe twin is still flagged: {leaked}"

    for pack in manifest.get("packs", []):
        assert pack in result.packs_applied, (
            f"{fixture.name}: pack {pack} did not apply (applied: {sorted(result.packs_applied)})")

    if manifest.get("requires_pack", True):
        without = scan(vulnerable, "--no-packs")
        assert len(_hits(without, expected)) < len(expected), (
            f"{fixture.name}: scanning with --no-packs finds every marker, so the pack adds nothing here; "
            f"set requires_pack = false if the fixture only guards existing coverage")
