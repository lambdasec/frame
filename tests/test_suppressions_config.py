"""Inline `frame: ignore` suppressions and .frame.toml / [tool.frame] config."""

import json

import pytest

from frame.sil.scanner import FrameScanner
from frame.sil.cli import create_parser, main
from frame.sil.suppressions import (
    ConfigError, find_config, load_config_file, matches_rules, split_suppressed,
)

VULN = (
    "import os\n"
    "from flask import request\n"
    "def f():\n"
    "    cmd = request.args.get('c')\n"
    "    os.system(cmd){tail}\n"
)


def _scan(src, **kw):
    return FrameScanner(language="python", **kw).scan(src, "t.py")


def _baseline():
    r = _scan(VULN.format(tail=""))
    assert r.vulnerabilities, "fixture must produce a finding"
    return r


def test_baseline_has_finding_and_no_suppressed():
    r = _baseline()
    assert r.suppressed == []


def test_bare_inline_ignore_suppresses_all_on_line():
    r = _scan(VULN.format(tail="  # frame: ignore"))
    assert not r.vulnerabilities
    assert r.suppressed


def test_ignore_on_comment_line_above():
    src = VULN.replace("    os.system", "    # frame: ignore\n    os.system").format(tail="")
    r = _scan(src)
    assert not r.vulnerabilities and r.suppressed


def test_ignore_with_matching_cwe_suppresses():
    cwe = _baseline().vulnerabilities[0].cwe_id
    r = _scan(VULN.format(tail=f"  # frame: ignore[{cwe}]"))
    assert not r.vulnerabilities


def test_ignore_with_other_cwe_does_not_suppress():
    r = _scan(VULN.format(tail="  # frame: ignore[CWE-1]"))
    assert r.vulnerabilities and not r.suppressed


def test_ignore_two_lines_away_does_not_apply():
    src = "# frame: ignore\n" + VULN.format(tail="")
    assert _scan(src).vulnerabilities


def test_no_suppress_option_reports_everything():
    r = _scan(VULN.format(tail="  # frame: ignore"), respect_suppressions=False)
    assert r.vulnerabilities and not r.suppressed


def test_disabled_rules_by_cwe_and_bare_number():
    cwe = _baseline().vulnerabilities[0].cwe_id          # e.g. "CWE-78"
    for rule in (cwe, cwe.lower(), cwe.split("-")[1]):
        r = _scan(VULN.format(tail=""), disabled_rules=[rule])
        assert not r.vulnerabilities and r.suppressed, rule


def test_disabled_rule_for_other_cwe_keeps_finding():
    assert _scan(VULN.format(tail=""), disabled_rules=["CWE-1"]).vulnerabilities


def test_summary_counts_suppressed():
    r = _scan(VULN.format(tail="  # frame: ignore"))
    assert r.to_dict()["summary"]["suppressed"] == len(r.suppressed) >= 1


def test_js_style_comment_marker():
    class V:
        line, cwe_id, type = 2, "CWE-79", None
    kept, supp = split_suppressed([V()], "a\nb(); // frame: ignore[79]\n")
    assert supp and not kept


def test_matches_rules_none_means_all():
    class V:
        cwe_id, type, line = "CWE-89", None, 1
    assert matches_rules(V(), None)
    assert not matches_rules(V(), ["CWE-90"])


# ---- config files ----------------------------------------------------------

def test_frame_toml_loaded(tmp_path):
    (tmp_path / ".frame.toml").write_text(
        'min_severity = "medium"\nfail_on = "none"\ndisable = ["CWE-798"]\nexclude = ["vendor"]\n')
    cfg = find_config(tmp_path)
    assert (cfg.min_severity, cfg.fail_on, cfg.disable, cfg.exclude) == (
        "medium", "none", ["CWE-798"], ["vendor"])


def test_pyproject_tool_frame_table(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[tool.frame]\nfail_on = "any"\n')
    assert find_config(tmp_path).fail_on == "any"


def test_pyproject_without_tool_frame_is_skipped(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n')
    assert load_config_file(tmp_path / "pyproject.toml") is None


def test_config_found_from_parent_of_file(tmp_path):
    (tmp_path / ".frame.toml").write_text('fail_on = "low"\n')
    (tmp_path / "src").mkdir()
    f = tmp_path / "src" / "a.py"
    f.write_text("x = 1\n")
    assert find_config(f).fail_on == "low"


@pytest.mark.parametrize("body", [
    'bogus = 1\n', 'min_severity = "scary"\n', 'fail_on = "sometimes"\n',
    'disable = "CWE-1"\n', 'disable = [1]\n', 'this is not toml\n',
])
def test_invalid_config_rejected(tmp_path, body):
    p = tmp_path / ".frame.toml"
    p.write_text(body)
    with pytest.raises(ConfigError):
        load_config_file(p)


# ---- CLI integration -------------------------------------------------------

def _project(tmp_path, toml=None, tail=""):
    if toml is not None:
        (tmp_path / ".frame.toml").write_text(toml)
    f = tmp_path / "app.py"
    f.write_text(VULN.format(tail=tail))
    return f


def test_cli_parser_defaults_defer_to_config():
    args = create_parser().parse_args(["scan", "x.py"])
    assert args.min_severity is None and args.fail_on is None
    assert args.disable == [] and args.no_suppress is False


def test_cli_fail_on_from_config(tmp_path, capsys):
    f = _project(tmp_path, 'fail_on = "none"\n')
    assert main(["scan", str(f), "-f", "json"]) == 0


def test_cli_flag_overrides_config(tmp_path, capsys):
    f = _project(tmp_path, 'fail_on = "none"\n')
    assert main(["scan", str(f), "-f", "json", "--fail-on", "any"]) == 1


def test_cli_no_config_ignores_file(tmp_path, capsys):
    f = _project(tmp_path, 'fail_on = "none"\n')
    assert main(["scan", str(f), "-f", "json", "--no-config", "--fail-on", "any"]) == 1


def test_cli_disable_flag_and_exit_code(tmp_path, capsys):
    f = _project(tmp_path)
    cwe = _baseline().vulnerabilities[0].cwe_id
    assert main(["scan", str(f), "-f", "json", "--fail-on", "any"]) == 1
    capsys.readouterr()
    assert main(["scan", str(f), "-f", "json", "--fail-on", "any", "--disable", cwe]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["summary"]["suppressed"] >= 1


def test_cli_inline_suppression_and_no_suppress(tmp_path, capsys):
    f = _project(tmp_path, tail="  # frame: ignore")
    assert main(["scan", str(f), "-f", "json", "--fail-on", "any"]) == 0
    capsys.readouterr()
    assert main(["scan", str(f), "-f", "json", "--fail-on", "any", "--no-suppress"]) == 1


def test_cli_bad_config_is_error(tmp_path, capsys):
    f = _project(tmp_path, 'bogus = 1\n')
    assert main(["scan", str(f), "-f", "json"]) == 1
    assert "unknown key" in capsys.readouterr().err


def test_cli_config_exclude_skips_directory(tmp_path, capsys):
    (tmp_path / ".frame.toml").write_text('exclude = ["vendor"]\nfail_on = "any"\n')
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "bad.py").write_text(VULN.format(tail=""))
    (tmp_path / "ok.py").write_text("x = 1\n")
    assert main(["scan", str(tmp_path), "-f", "json"]) == 0


def test_frame_entrypoint_accepts_new_flags(tmp_path, capsys):
    """`frame scan` (frame/cli.py) has its own parser; it must accept the same flags."""
    from frame.cli import create_parser as frame_parser
    args = frame_parser().parse_args(
        ["scan", "x.py", "--config", "c.toml", "--no-config", "--disable", "CWE-1",
         "--disable", "weak_hash", "--no-suppress"])
    assert args.disable == ["CWE-1", "weak_hash"] and args.no_suppress and args.no_config
    assert args.min_severity is None and args.fail_on is None
