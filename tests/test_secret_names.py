"""Hardcoded credentials by name as data (`frame/sil/specs/data/secret-names.toml`,
`frame/sil/secret_names.py`): the shipped file loads, the scanner reads it, and a malformed file is
an error naming what is wrong. The rules themselves are tested through scans (test_cwe*.py)."""

import pytest

from frame.sil.scanner import FrameScanner
from frame.sil.secret_names import PATH, load


def test_the_shipped_file_is_what_the_scanner_uses():
    names = load()
    assert FrameScanner._SECRET_NAME_RULES is names.name_rules
    assert [cwe for _, cwe, _ in names.name_rules] == ["CWE-259", "CWE-321", "CWE-798"]
    assert names.credential_prefix.search("token ghp_x") and not names.credential_prefix.search("aghp_x")
    assert names.known_credential.search("AKIA" + "ABCDEFGHIJKLMNOP")
    assert names.pem_with_body.search("-----BEGIN RSA PRIVATE KEY-----\n" + "A" * 20)   # across lines
    assert "algorithm" in names.metadata_heads and "x-api-key" in names.http_auth_names


def _with(tmp_path, old, new):
    p = tmp_path / "secret-names.toml"
    text = PATH.read_text()
    assert old in text
    p.write_text(text.replace(old, new, 1))
    return p


@pytest.mark.parametrize("old,new,error", [
    ('cwe = "CWE-259"', 'cwe = "259"', "CWE-<n>"),
    ("connection_string = ", "connection_strin = ", r"\[value\] needs exactly"),
    ('label = "Hardcoded password"', 'label = "Hardcoded password"\nnote = "x"', "needs exactly"),
    ("pattern = '\\bglpat-", "pattern = '(\\bglpat-", "does not compile"),
    ("structural_words = ", "structure_words = ", r"\[words\] needs exactly"),
])
def test_a_malformed_file_is_an_error(tmp_path, old, new, error):
    with pytest.raises(ValueError, match=error):
        load(_with(tmp_path, old, new))
