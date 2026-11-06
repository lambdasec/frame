"""`frame diff OLD.json NEW.json`: introduced / fixed findings by fingerprint."""
import json
from frame.cli import _diff_findings, cmd_diff, create_parser


def _f(fp, loose, line, type="sql_injection", sev="high", ev="data-flow"):
    return {"fingerprint": fp, "fingerprint_loose": loose, "line": line,
            "type": type, "severity": sev, "evidence": ev, "location": "a.py"}


def test_introduced_fixed_unchanged():
    old = [_f("A", "la", 10), _f("B", "lb", 20)]
    new = [_f("A", "la", 10), _f("C", "lc", 30)]
    intro, fixed, unchanged = _diff_findings(old, new)
    assert [v["fingerprint"] for v in intro] == ["C"]
    assert [v["fingerprint"] for v in fixed] == ["B"]
    assert unchanged == 1


def test_loose_match_tolerates_line_shift():
    # same loose key, line moved -> unchanged, not introduced+fixed
    old = [_f("A", "la", 10)]
    new = [_f("A2", "la", 14)]       # different exact fp (line text moved), same loose
    intro, fixed, unchanged = _diff_findings(old, new)
    assert intro == [] and fixed == [] and unchanged == 1


def test_cmd_diff_exit_code(tmp_path):
    old = tmp_path / "old.json"; new = tmp_path / "new.json"
    old.write_text(json.dumps({"vulnerabilities": [_f("A", "la", 10)]}))
    new.write_text(json.dumps({"vulnerabilities": [_f("A", "la", 10), _f("C", "lc", 30)]}))
    args = create_parser().parse_args(["diff", str(old), str(new)])
    assert cmd_diff(args) == 1      # a finding was introduced
    # no new findings -> exit 0
    new.write_text(json.dumps({"vulnerabilities": [_f("A", "la", 10)]}))
    args = create_parser().parse_args(["diff", str(old), str(new)])
    assert cmd_diff(args) == 0


def test_diff_parses():
    args = create_parser().parse_args(["diff", "o.json", "n.json", "-f", "json"])
    assert args.command == "diff" and args.old == "o.json" and args.format == "json"
