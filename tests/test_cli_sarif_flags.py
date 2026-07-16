"""Regression tests for two CLI/SARIF gaps found while wiring Frame into the
XBOW/ZeroPath benchmark harness:

1. The `scan` subcommand consumed `args.ai` / `args.llm_detect` / `args.llm_triage`
   downstream but never registered the flags, so `frame scan --ai` errored.
2. `to_sarif()` emitted only `startLine`; SARIF consumers (and the benchmark's
   judge) expect `endLine` too.
"""

from frame.sil.cli import create_parser
from frame.sil import FrameScanner


def test_scan_registers_ai_flags():
    parser = create_parser()
    args = parser.parse_args(["scan", "app.py", "--ai"])
    assert args.ai is True
    assert args.llm_detect is False and args.llm_triage is False

    args = parser.parse_args(["scan", "app.py", "--llm-detect", "--llm-triage"])
    assert args.ai is False
    assert args.llm_detect is True and args.llm_triage is True


def test_scan_language_not_restricted_to_python():
    # A symbolic frontend language and an LLM-only language both parse (the CLI
    # must not hard-restrict to python -- Frame supports 5 symbolic frontends and
    # any language under --ai).
    parser = create_parser()
    for lang in ("java", "javascript", "csharp", "php", "go"):
        args = parser.parse_args(["scan", "src/", "--language", lang])
        assert args.language == lang


def test_sarif_region_has_end_line():
    # A SQL-injection taint flow (no secret-like literal, to avoid tripping
    # push-protection scanners) is enough to exercise the SARIF region.
    src = (
        "from flask import request\n"
        "def handler(db):\n"
        "    uid = request.args.get('id')\n"
        "    return db.execute('SELECT * FROM users WHERE id=' + uid)\n"
    )
    scanner = FrameScanner(language="python", verify=False)
    result = scanner.scan(src, "app.py")
    assert result.vulnerabilities, "expected at least one finding to exercise SARIF"
    sarif = result.to_sarif()
    for run in sarif["runs"]:
        for r in run["results"]:
            region = r["locations"][0]["physicalLocation"]["region"]
            assert "startLine" in region and "endLine" in region
            assert region["endLine"] >= region["startLine"]
