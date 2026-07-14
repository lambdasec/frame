"""Anti-overfitting guardrail (study spec sec.9).

Production authorization-analysis code and the frozen prompts must be GENERIC:
they must not reference any benchmark-specific repository, function, class, route,
or case identifier. Those identifiers may appear ONLY in the manifest, READMEs,
scoring/report code, test metadata, and generated reports.

If this test fails, the analyzer or a prompt has been tuned to the frozen cases,
which invalidates the study. Fix by making the detection generic.
"""

from pathlib import Path

BENCH = Path(__file__).resolve().parent.parent
REPO = BENCH.parent.parent  # frame repo root

# The authorization analysis is a generic Frame-core capability, not benchmark code;
# it must be scanned for benchmark-specific identifiers just like the harness.
FRAME_CORE_PRODUCTION = [REPO / "frame" / "sil" / "authz.py"]

# Repository slugs + labelled function/class names from the frozen manifest.
FORBIDDEN = [
    "vampi", "dvblab", "vulpy", "dvga",
    "do_post_list", "update_password", "editpaste", "deletepaste",
    "get_transactions",
]

# Files that constitute production analysis + prompt code. Benchmark identifiers
# are allowed only OUTSIDE this set (manifest.yaml, README*, REPORT*, score.py,
# report.py, tests/, results/).
PRODUCTION_GLOBS = [
    "authz/**/*.py",
    "systems/**/*.py",
    "adapters/**/*.py",
    "prompts/**/*.md",
    "run.py",
    "prepare.py",
]
EXCLUDE_BASENAMES = {"score.py", "report.py"}


def _production_files():
    seen = set()
    for pattern in PRODUCTION_GLOBS:
        for p in BENCH.glob(pattern):
            if not p.is_file():
                continue
            if p.name in EXCLUDE_BASENAMES or "__pycache__" in p.parts or "tests" in p.parts:
                continue
            seen.add(p)
    seen.update(p for p in FRAME_CORE_PRODUCTION if p.is_file())
    return sorted(seen)


def test_no_benchmark_identifiers_in_production_code():
    offenders = []
    for p in _production_files():
        text = p.read_text(encoding="utf-8", errors="replace").lower()
        for ident in FORBIDDEN:
            if ident in text:
                offenders.append(f"{p.relative_to(BENCH)} contains benchmark identifier '{ident}'")
    assert not offenders, (
        "Benchmark-specific identifiers leaked into production analyzer/prompt code "
        "(overfitting):\n  " + "\n  ".join(offenders)
    )


def test_there_is_production_code_to_scan():
    # Guards against the check silently passing because it scanned nothing.
    assert _production_files(), "no production files found to scan"
