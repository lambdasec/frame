"""`frame deps` on lockfiles and reports real package managers wrote, against what those tools
said they resolved (tests/fixtures/sca/real/, written by tests/sca_real/refresh.py). Offline:
no tool and no network, so it runs in every CI job."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from frame.sca import read_dependencies  # noqa: E402
from frame.sca.resolve import parse_pip_report  # noqa: E402
from sca_real.harness import CASES, CORPUS, Truth, compare  # noqa: E402

CASE_DIRS = sorted(p for p in CORPUS.iterdir() if (p / "expected.json").is_file()) if CORPUS.is_dir() else []


def test_every_case_has_a_corpus_entry():
    # the corpus is refreshed from live runs; a case without one has never passed for real
    assert {p.name for p in CASE_DIRS} == {c.name for c in CASES}


@pytest.mark.parametrize("case_dir", CASE_DIRS, ids=[p.name for p in CASE_DIRS])
def test_frame_matches_what_the_tool_resolved(case_dir):
    doc = json.loads((case_dir / "expected.json").read_text())
    truth = Truth.from_json(doc)
    files_dir = case_dir / "files"
    if doc.get("pip_report"):
        files = [parse_pip_report("requirements.txt", (files_dir / "pip-report.json").read_text())]
    else:
        report = read_dependencies(files_dir)
        assert not report.warnings, report.warnings
        files = report.files
    assert truth.packages
    problems = compare(truth, files, doc["ecosystem"])
    assert not problems, "\n".join(problems)


@pytest.mark.parametrize("case_dir", CASE_DIRS, ids=[p.name for p in CASE_DIRS])
def test_corpus_entries_stay_small(case_dir):
    size = sum(f.stat().st_size for f in case_dir.rglob("*") if f.is_file())
    assert size < 200_000, f"{case_dir.name}: {size} bytes"
