"""Sink kinds and finding types as data (`frame/sil/specs/data/kinds.toml`, `frame/sil/kinds.py`):
the finding type each sink kind reports, the other spellings of a sink kind, each finding type's
CWE and category. The table covers both enums exactly, and a malformed table is an error naming
what is wrong."""

import pytest

from frame.sil import findings
from frame.sil.instructions import SinkKind, resolve_sink_kind
from frame.sil.kinds import check, load
from frame.sil.scanner import FrameScanner
from frame.sil.translator import VulnType


def test_the_table_covers_both_enums_exactly():
    k = load()
    check([s.value for s in SinkKind], [v.value for v in VulnType], k)
    assert set(k.sink_vuln) == {s.value for s in SinkKind}
    assert set(k.category) == {v.value for v in VulnType}


def test_what_the_engine_reads_comes_from_the_table():
    assert VulnType.from_sink_kind(SinkKind.SQL_QUERY) == VulnType.SQL_INJECTION
    assert VulnType.from_sink_kind(SinkKind.MEMORY) == VulnType.TAINT_FLOW      # no finding type of its own
    assert FrameScanner.CWE_MAP[VulnType.SQL_INJECTION] == "CWE-89"
    assert VulnType.TAINT_FLOW not in FrameScanner.CWE_MAP                     # a type without a CWE
    assert findings.category_of("use_after_free") == "memory"
    assert findings.category_of("sql_injection") == "taint"
    assert findings.category_of("sql_injection", "hardening") == "hardening"  # an explicit one wins
    assert resolve_sink_kind("redos") == SinkKind.REGEX                        # an alias
    assert resolve_sink_kind("file") == SinkKind.FILE_PATH                     # every language, not only JS
    assert resolve_sink_kind("log_injection") == SinkKind.LOG


@pytest.mark.parametrize("text,error", [
    ('[[sink]]\nkind = "sql"\nvuln = "nope"\n', "unknown finding type 'nope'"),
    ('[[sink]]\nkind = "sql"\n[[sink]]\nkind = "sql"\n', "listed twice"),
    ('[[sink]]\nkind = "sql"\naliases = ["shell"]\n[[sink]]\nkind = "shell"\n', "aliases that are kinds"),
    ('[[sink]]\nkind = "sql"\naliases = ["q"]\n[[sink]]\nkind = "nosql"\naliases = ["q"]\n', "also names"),
    ('[[sink]]\nkind = "sql"\ncolour = "red"\n', "unknown keys ['colour']"),
    ('[[vuln]]\ntype = "x"\ncategory = "misc"\n', "category in"),
    ('[[vuln]]\ntype = "x"\ncategory = "taint"\ncwe = "89"\n', "CWE-<n>"),
    ('[[rule]]\n', "unknown tables"),
])
def test_a_malformed_table_is_an_error(tmp_path, text, error):
    p = tmp_path / "kinds.toml"
    p.write_text(text)
    with pytest.raises(ValueError, match=error.replace("[", r"\[").replace("]", r"\]")):
        load(p)


def test_a_table_missing_a_kind_fails_the_check(tmp_path):
    p = tmp_path / "kinds.toml"
    p.write_text('[[sink]]\nkind = "sql"\n[[vuln]]\ntype = "x"\ncategory = "taint"\n')
    with pytest.raises(ValueError, match="sink kinds missing"):
        check([s.value for s in SinkKind], ["x"], load(p))
