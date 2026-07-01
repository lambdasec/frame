"""Tests for the Endor Labs public-corpus evaluation harness.

These tests are network-free and fast: they exercise the pure helpers
(SARIF parsing, file classification, aggregation, ground-truth matching,
manifest integrity, lock handling) without cloning or scanning anything.
"""

import json
from pathlib import Path

import pytest

from benchmarks.endor_corpus import summarize as S
from benchmarks.endor_corpus import run_endor_corpus as R
from benchmarks.endor_corpus import owasp_benchmark as OB
from benchmarks.endor_corpus import compare_findings as CF
from benchmarks.endor_corpus import judge_ground_truth as JGT
from benchmarks.endor_corpus import generate_report as GR
from benchmarks.endor_corpus import build_ground_truth as BGT

CORPUS_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "endor_corpus"

EXPECTED_SLUGS = {
    "anonymous-github", "demo-netflicks", "doublestar", "benchmarkjava",
    "juice-shop", "webgoat", "shopizer", "xbow-validation-benchmarks",
}


# --------------------------------------------------------------------------- #
# Manifest integrity
# --------------------------------------------------------------------------- #

def test_corpus_manifest_has_all_eight_repos():
    repos = R.load_corpus()
    slugs = {r["name"] for r in repos}
    assert slugs == EXPECTED_SLUGS
    for r in repos:
        assert r["url"].endswith(".git")
        assert "supported_patterns" in r
        assert isinstance(r["supported_patterns"], list)
        assert "unsupported_languages" in r


def test_doublestar_marked_go_unsupported():
    repos = {r["name"]: r for r in R.load_corpus()}
    ds = repos["doublestar"]
    assert ds["supported_patterns"] == []
    assert "go" in ds["unsupported_languages"]


def test_xbow_marks_php_unsupported():
    repos = {r["name"]: r for r in R.load_corpus()}
    xbow = repos["xbow-validation-benchmarks"]
    assert "php" in xbow["unsupported_languages"]
    # PHP must NOT be in supported patterns.
    assert not any("php" in p for p in xbow["supported_patterns"])


def test_ground_truth_example_is_marked_example_only():
    data = json.loads((CORPUS_DIR / "ground_truth.example.json").read_text())
    # Every entry must be an example (carry a _comment) so the runner filters it.
    assert data
    assert all("_comment" in entry for entry in data)


# --------------------------------------------------------------------------- #
# File classification
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("ext,expected", [
    (".py", "supported"), (".java", "supported"), (".ts", "supported"),
    (".tsx", "supported"), (".cs", "supported"), (".cpp", "supported"),
    (".go", "unsupported"), (".php", "unsupported"), (".rb", "unsupported"),
    (".html", "other"), (".json", "other"), (".xyz", "unknown"),
])
def test_classify_extension(ext, expected):
    assert S.classify_extension(ext) == expected


def test_patterns_to_extensions():
    exts = R.patterns_to_extensions(["**/*.js", "**/*.ts", "**/*.java"])
    assert exts == {".js", ".ts", ".java"}
    assert R.patterns_to_extensions([]) == set()


def test_count_files_classifies_supported_and_unsupported(tmp_path):
    (tmp_path / "a.py").write_text("x = 1")
    (tmp_path / "b.go").write_text("package main")
    (tmp_path / "c.php").write_text("<?php ?>")
    (tmp_path / "d.html").write_text("<html></html>")
    (tmp_path / "e.unknownext").write_text("?")
    files = R.collect_files(tmp_path)
    counts = R.count_files(files)
    assert counts["supported_total"] == 1
    assert counts["unsupported_total"] == 2
    assert counts["unsupported_by_language"] == {"go": 1, "php": 1}
    assert counts["other_total"] == 1
    assert counts["unknown_total"] == 1


def test_collect_files_prunes_vendor_dirs(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.js").write_text("//")
    nm = tmp_path / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    (nm / "index.js").write_text("//")
    files = {f.name for f in R.collect_files(tmp_path)}
    assert "app.js" in files
    # node_modules content must be pruned.
    assert all("node_modules" not in str(f) for f in R.collect_files(tmp_path))


# --------------------------------------------------------------------------- #
# SARIF parsing
# --------------------------------------------------------------------------- #

def _write_sarif(tmp_path, results):
    sarif = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "Frame Security Scanner", "rules": []}},
                  "results": results}],
    }
    p = tmp_path / "frame.sarif"
    p.write_text(json.dumps(sarif))
    return p


def test_parse_frame_sarif_extracts_fields_and_derives_cwe(tmp_path):
    p = _write_sarif(tmp_path, [
        {"ruleId": "frame/sql_injection", "level": "error",
         "message": {"text": "tainted -> sql"},
         "locations": [{"physicalLocation": {
             "artifactLocation": {"uri": "a.py"}, "region": {"startLine": 10}}}]},
    ])
    recs = S.parse_frame_sarif(p, repo="demo", commit="abc")
    assert len(recs) == 1
    r = recs[0]
    assert r["rule_id"] == "frame/sql_injection"
    assert r["cwe"] == "CWE-89"          # derived from Frame's CWE_MAP
    assert r["severity"] == "high"        # error -> high (approx)
    assert r["path"] == "a.py"
    assert r["line"] == 10
    assert r["repo"] == "demo"
    assert r["commit"] == "abc"
    assert r["sarif_result_index"] == 0


def test_parse_frame_sarif_unknown_rule_has_no_cwe(tmp_path):
    p = _write_sarif(tmp_path, [
        {"ruleId": "frame/totally_unknown_rule", "level": "warning",
         "message": {"text": "x"},
         "locations": [{"physicalLocation": {
             "artifactLocation": {"uri": "b.js"}, "region": {"startLine": 2}}}]},
    ])
    recs = S.parse_frame_sarif(p, repo="demo", commit="abc")
    # No CWE is invented for an unknown rule id.
    assert recs[0]["cwe"] is None


def test_parse_frame_sarif_indices_are_sequential(tmp_path):
    p = _write_sarif(tmp_path, [
        {"ruleId": "frame/xss", "level": "warning", "message": {"text": "a"},
         "locations": [{"physicalLocation": {
             "artifactLocation": {"uri": "a.js"}, "region": {"startLine": 1}}}]},
        {"ruleId": "frame/xss", "level": "warning", "message": {"text": "b"},
         "locations": [{"physicalLocation": {
             "artifactLocation": {"uri": "a.js"}, "region": {"startLine": 2}}}]},
    ])
    recs = S.parse_frame_sarif(p, repo="demo", commit="abc")
    assert [r["sarif_result_index"] for r in recs] == [0, 1]


def test_level_to_severity():
    assert S.level_to_severity("error") == "high"
    assert S.level_to_severity("warning") == "medium"
    assert S.level_to_severity("note") == "low"
    assert S.level_to_severity(None) is None


# --------------------------------------------------------------------------- #
# Aggregation and ground truth
# --------------------------------------------------------------------------- #

def test_summarize_findings():
    findings = [
        {"repo": "a", "cwe": "CWE-89", "severity": "critical"},
        {"repo": "a", "cwe": "CWE-79", "severity": "medium"},
        {"repo": "b", "cwe": "CWE-89", "severity": "critical"},
    ]
    agg = S.summarize_findings(findings)
    assert agg["total_findings"] == 3
    assert agg["by_repo"] == {"a": 2, "b": 1}
    assert agg["by_cwe"]["CWE-89"] == 2
    assert agg["by_severity"]["critical"] == 2


def test_ground_truth_metrics_basic_match():
    gt = [
        {"repo": "a", "cwe": "89", "path": "src/a.py", "line": 11},
        {"repo": "a", "cwe": "CWE-89", "path": "missing.py", "line": 1},
    ]
    findings = [
        {"repo": "a", "cwe": "CWE-89", "path": "proj/src/a.py", "line": 10},
        {"repo": "a", "cwe": "CWE-79", "path": "src/a.py", "line": 10},
    ]
    m = S.compute_ground_truth_metrics(findings, gt)
    assert m["true_positives"] == 1     # a.py CWE-89 within +/-5 lines
    assert m["false_positives"] == 1    # the CWE-79 finding
    assert m["false_negatives"] == 1    # missing.py label unmatched
    assert m["precision"] == 0.5
    assert m["recall"] == 0.5


def test_ground_truth_no_double_counting():
    # One label, two candidate findings -> at most one TP.
    gt = [{"repo": "a", "cwe": "CWE-89", "path": "a.py", "line": 10}]
    findings = [
        {"repo": "a", "cwe": "CWE-89", "path": "a.py", "line": 10},
        {"repo": "a", "cwe": "CWE-89", "path": "a.py", "line": 11},
    ]
    m = S.compute_ground_truth_metrics(findings, gt)
    assert m["true_positives"] == 1
    assert m["false_positives"] == 1
    assert m["false_negatives"] == 0


# --------------------------------------------------------------------------- #
# Summary rendering + Endor context
# --------------------------------------------------------------------------- #

def test_build_and_render_summary_contains_required_sections():
    summary = S.build_summary(
        repo_reports=[{"repo": "doublestar", "display_name": "doublestar",
                       "url": "u", "commit": "abc123", "cloned": True,
                       "files_scanned": 0, "file_counts": {
                           "supported_total": 0, "unsupported_total": 5,
                           "unsupported_by_language": {"go": 5},
                           "supported_by_language": {}}, "findings": 0}],
        findings=[],
        run_meta={"mode": "lock", "verify": True, "timeout_ms": 5000,
                  "finished_at": "t"},
        scanner_errors=[],
    )
    md = S.render_summary_md(summary)
    # Endor context + warning must be present, and no fabricated F1 for Frame.
    assert "Endor published numbers for context only" in md
    assert S.ENDOR_WARNING in md
    assert "192 real vulnerabilities" in md
    assert "precision, recall, and F1 are not computed" in md
    assert "https://www.endorlabs.com/learn/" in md
    # Unsupported Go must be surfaced.
    assert "go:5" in md


def test_summary_without_ground_truth_omits_metrics():
    summary = S.build_summary([], [], {"mode": "unpinned", "finished_at": "t"}, [])
    assert summary["ground_truth_metrics"] is None
    md = S.render_summary_md(summary)
    assert "precision, recall, and F1 are not computed" in md


# --------------------------------------------------------------------------- #
# Lock handling
# --------------------------------------------------------------------------- #

def test_load_lock_missing_exits(monkeypatch, tmp_path):
    monkeypatch.setattr(R, "LOCK_FILE", tmp_path / "nope.json")
    with pytest.raises(SystemExit):
        R.load_lock()


def test_write_then_load_lock_roundtrip(monkeypatch, tmp_path):
    monkeypatch.setattr(R, "LOCK_FILE", tmp_path / "corpus.lock.json")
    R.write_lock([{"name": "doublestar", "url": "u",
                   "commit": "deadbeef", "branch": "master"}])
    lock = R.load_lock()
    assert lock["repos"]["doublestar"]["commit"] == "deadbeef"


def test_write_lock_merges_existing(monkeypatch, tmp_path):
    monkeypatch.setattr(R, "LOCK_FILE", tmp_path / "corpus.lock.json")
    R.write_lock([{"name": "a", "url": "ua", "commit": "aaa", "branch": "main"}])
    R.write_lock([{"name": "b", "url": "ub", "commit": "bbb", "branch": "main"}])
    lock = R.load_lock()
    # A subset --lock run must not clobber the other repo's entry.
    assert set(lock["repos"]) == {"a", "b"}


# --------------------------------------------------------------------------- #
# OWASP BenchmarkJava scoring
# --------------------------------------------------------------------------- #

def test_cwe_to_int():
    assert OB.cwe_to_int("CWE-89") == 89
    assert OB.cwe_to_int("89") == 89
    assert OB.cwe_to_int(89) == 89
    assert OB.cwe_to_int("CWE-89: SQL Injection") == 89   # Semgrep metadata form
    assert OB.cwe_to_int("frame/sql") is None
    assert OB.cwe_to_int(None) is None


def test_parse_semgrep_findings(tmp_path):
    doc = {"results": [
        {"path": "a/BenchmarkTest00001.java", "check_id": "java.sqli",
         "extra": {"severity": "ERROR",
                   "metadata": {"cwe": ["CWE-89: SQL Injection"]}}},
        {"path": "a/BenchmarkTest00002.java", "check_id": "multi",
         "extra": {"metadata": {"cwe": ["CWE-79: XSS", "CWE-116: Encoding"]}}},
        {"path": "a/BenchmarkTest00003.java", "check_id": "no-cwe",
         "extra": {"metadata": {}}},   # dropped (no CWE)
    ]}
    p = tmp_path / "semgrep.json"
    p.write_text(json.dumps(doc))
    findings = OB.parse_semgrep_findings(p)
    # 1 + 2 CWEs = 3 findings; the no-cwe result is dropped.
    assert len(findings) == 3
    assert {OB.cwe_to_int(f["cwe"]) for f in findings} == {89, 79, 116}


def test_load_expected_results(tmp_path):
    (tmp_path / OB.EXPECTED_CSV).write_text(
        "# header line\n"
        "BenchmarkTest00001,pathtraver,true,22\n"
        "BenchmarkTest00002,sqli,false,89\n")
    exp = OB.load_expected_results(tmp_path)
    assert len(exp) == 2
    assert exp[0]["name"] == "BenchmarkTest00001"
    assert exp[0]["is_real"] is True
    assert exp[0]["cwe"] == "CWE-22"
    assert exp[1]["is_real"] is False
    assert exp[0]["path"].endswith("BenchmarkTest00001.java")


def test_load_expected_results_missing_csv(tmp_path):
    with pytest.raises(FileNotFoundError):
        OB.load_expected_results(tmp_path)


def test_score_owasp_confusion_matrix():
    expected = [
        {"name": "BenchmarkTest00001", "category": "sqli", "cwe": "CWE-89",
         "cwe_int": 89, "is_real": True, "repo": "benchmarkjava"},   # -> TP (flagged)
        {"name": "BenchmarkTest00002", "category": "sqli", "cwe": "CWE-89",
         "cwe_int": 89, "is_real": True, "repo": "benchmarkjava"},   # -> FN (not flagged)
        {"name": "BenchmarkTest00003", "category": "sqli", "cwe": "CWE-89",
         "cwe_int": 89, "is_real": False, "repo": "benchmarkjava"},  # -> FP (flagged trap)
        {"name": "BenchmarkTest00004", "category": "sqli", "cwe": "CWE-89",
         "cwe_int": 89, "is_real": False, "repo": "benchmarkjava"},  # -> TN
    ]
    findings = [
        {"path": "src/.../testcode/BenchmarkTest00001.java", "cwe": "CWE-89"},
        {"path": "src/.../testcode/BenchmarkTest00003.java", "cwe": "CWE-89"},
    ]
    sc = OB.score(findings, expected)
    ov = sc["overall"]
    assert (ov["tp"], ov["fp"], ov["tn"], ov["fn"]) == (1, 1, 1, 1)
    assert ov["precision"] == 0.5
    assert ov["tpr_recall"] == 0.5
    assert ov["youden_score"] == 0.0


def test_score_ignores_cross_category_findings():
    expected = [
        {"name": "BenchmarkTest00001", "category": "sqli", "cwe": "CWE-89",
         "cwe_int": 89, "is_real": True, "repo": "benchmarkjava"},
    ]
    # A finding of a DIFFERENT CWE in that file must not count as detection.
    findings = [{"path": ".../BenchmarkTest00001.java", "cwe": "CWE-79"}]
    sc = OB.score(findings, expected)
    assert sc["overall"]["fn"] == 1
    assert sc["overall"]["tp"] == 0


def test_compare_findings_agreement():
    frame = [
        {"path": "a/x.js", "cwe": "CWE-79", "severity": "high"},   # agree
        {"path": "a/y.js", "cwe": "CWE-89", "severity": "high"},   # frame-only
        {"path": "a/z.js", "cwe": None, "severity": "low"},        # no CWE -> not keyed
    ]
    semgrep = [
        {"path": "a/x.js", "cwe": "CWE-79: XSS", "severity": "ERROR"},  # agree (alias form)
        {"path": "a/w.js", "cwe": "CWE-22", "severity": "WARNING"},     # semgrep-only
    ]
    c = CF.compare_repo("demo", frame, semgrep)
    assert c["frame_total"] == 3
    assert c["semgrep_total"] == 2
    assert c["agree_file_cwe"] == 1      # x.js / CWE-79 matches despite text suffix
    assert c["frame_only_file_cwe"] == 1
    assert c["semgrep_only_file_cwe"] == 1
    assert c["frame_by_cwe"]["CWE-79"] == 1


def test_compare_findings_normalizes_absolute_semgrep_paths():
    # Frame emits repo-relative paths; Semgrep emits absolute paths. They must
    # still be recognized as the same file.
    frame = [{"path": "src/a.java", "cwe": "CWE-89", "severity": "high"}]
    semgrep = [{"path": "/tmp/ws/webgoat/src/a.java", "cwe": "CWE-89",
                "severity": "ERROR"}]
    c = CF.compare_repo("webgoat", frame, semgrep)
    assert c["agree_file_cwe"] == 1
    assert c["frame_only_file_cwe"] == 0
    assert c["semgrep_only_file_cwe"] == 0


# --------------------------------------------------------------------------- #
# Claude Code judge (pure helpers only; no CLI invocation)
# --------------------------------------------------------------------------- #

def test_judge_extract_json_object():
    assert JGT._extract_json_object('{"verdict":"true_positive"}')["verdict"] == "true_positive"
    assert JGT._extract_json_object('```json\n{"verdict":"false_positive"}\n```')["verdict"] == "false_positive"
    assert JGT._extract_json_object('note: {"verdict":"uncertain"} end')["verdict"] == "uncertain"
    assert JGT._extract_json_object("no json") is None


def test_judge_extract_context(tmp_path):
    f = tmp_path / "a.py"
    f.write_text("l1\nl2\nl3\nl4\nl5\n")
    ctx = JGT.extract_context(tmp_path, "a.py", 3, context_lines=1)
    assert ">>    3: l3" in ctx
    assert "l2" in ctx and "l4" in ctx
    assert JGT.extract_context(tmp_path, "missing.py", 1).startswith("(source file not found")


def test_judge_summarize_precision():
    recs = [{"status": "true_positive"}, {"status": "true_positive"},
            {"status": "false_positive"}, {"status": "uncertain"}, {"status": "error"}]
    s = JGT.summarize(recs)
    assert s["counts"]["true_positive"] == 2
    assert s["judged_precision"] == round(2 / 3, 4)   # uncertain/error excluded


def test_judge_ground_truth_record_labels_source_and_status():
    rec = JGT.to_ground_truth_record(
        {"repo": "webgoat", "cwe": "CWE-89", "path": "src/a.java", "line": 5,
         "message": "sqli", "tool": "frame", "rule_id": "frame/sql_injection"},
        {"verdict": "true_positive", "confidence": 0.9, "reasoning": "concat",
         "model": "claude-sonnet-5"},
        commit="abc123")
    assert rec["status"] == "true_positive"
    assert rec["source"] == "claude_code:claude-sonnet-5"   # model-adjudicated, labeled
    assert rec["judge_confidence"] == 0.9


def test_report_precision_and_judged_dir(tmp_path):
    (tmp_path / "ground_truth.webgoat.json").write_text(json.dumps([
        {"status": "true_positive"}, {"status": "true_positive"},
        {"status": "false_positive"}, {"status": "uncertain"}]))
    (tmp_path / "ground_truth.webgoat.summary.json").write_text("{}")  # must be skipped
    loaded = GR._load_judged_dir(tmp_path)
    assert set(loaded) == {"webgoat"}          # .summary.json not treated as a repo
    assert GR._precision(loaded["webgoat"]) == round(2 / 3, 4)
    assert GR._precision([]) is None


def test_build_ground_truth_pools_and_dedupes(tmp_path):
    # Frame and Semgrep both confirm the same webgoat SQLi (should merge to 1,
    # found_by both); Semgrep confirms a unique one; a false_positive is excluded.
    (tmp_path / "ground_truth.webgoat.json").write_text(json.dumps([
        {"repo": "webgoat", "commit": "c1", "cwe": "CWE-89",
         "path": "src/A.java", "line": 43, "status": "true_positive"},
        {"repo": "webgoat", "commit": "c1", "cwe": "CWE-79",
         "path": "src/B.java", "line": 10, "status": "false_positive"},
    ]))
    (tmp_path / "ground_truth.webgoat.semgrep.json").write_text(json.dumps([
        {"repo": "webgoat", "commit": "c1", "cwe": "CWE-89: SQLi",
         "path": "/tmp/ws/webgoat/src/A.java", "line": 44, "status": "true_positive"},
        {"repo": "webgoat", "commit": "c1", "cwe": "CWE-502",
         "path": "/tmp/ws/webgoat/src/C.java", "line": 5, "status": "true_positive"},
    ]))
    pooled, cache, summary = BGT.build(tmp_path)
    # A.java SQLi merged across tools (line 43 vs 44 within window) -> 1 entry
    sqli = [p for p in pooled if p["cwe"] == "CWE-89"]
    assert len(sqli) == 1
    assert sqli[0]["found_by"] == ["frame", "semgrep"]
    # unique Semgrep deserialization TP present; FP excluded
    assert any(p["cwe"] == "CWE-502" for p in pooled)
    assert all(p["status"] == "true_positive" for p in pooled)
    assert len(pooled) == 2
    # verdict cache keeps everything (incl. the FP)
    assert len(cache) == 4
    # semgrep absolute path normalized to repo-relative
    assert sqli[0]["path"] == "src/A.java"


def test_report_md_table_escapes_pipes():
    out = GR._md_table(["A", "B"], [["x|y", "z"]])
    assert "x\\|y" in out                       # pipe escaped so table isn't broken
    assert out.splitlines()[1].startswith("| ---")   # markdown header separator row


def test_to_ground_truth_json_only_real_positives():
    expected = [
        {"name": "T1", "category": "sqli", "cwe": "CWE-89", "cwe_int": 89,
         "is_real": True, "path": "p/T1.java", "repo": "benchmarkjava"},
        {"name": "T2", "category": "sqli", "cwe": "CWE-89", "cwe_int": 89,
         "is_real": False, "path": "p/T2.java", "repo": "benchmarkjava"},
    ]
    gt = OB.to_ground_truth_json(expected, commit="abc")
    assert len(gt) == 1          # only the real vuln becomes a positive label
    assert gt[0]["status"] == "true_positive"
    assert gt[0]["commit"] == "abc"
