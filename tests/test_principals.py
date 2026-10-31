"""The caller's own credential as data (`frame/sil/specs/data/principals.toml`): the headers that
carry it. Who the authenticated caller is, is pack data read as values (TaintKind.IDENTITY:
tests/test_identity.py), never a list of names matched in source text."""

import pytest

from frame.sil.specs.principals import load
from frame.sil.translator import SILTranslator


def test_the_translator_reads_the_one_list():
    p = load()
    assert SILTranslator._AUTH_HEADER_NAMES == p.credential_headers
    assert {"authorization", "x-session-token", "api-key"} <= set(p.credential_headers)
    assert not hasattr(SILTranslator, "_PRINCIPAL_TOKENS")


@pytest.mark.parametrize("text,error", [
    ('credential_headers = ["Authorization"]\n', "lower case"),
    ('credential_headers = []\n', "non-empty"),
    ('credential_headers = ["cookie"]\nprincipal_tokens = ["current_user"]\n', "needs exactly"),
])
def test_a_malformed_file_is_an_error(tmp_path, text, error):
    f = tmp_path / "p.toml"
    f.write_text(text)
    with pytest.raises(ValueError, match=error):
        load(f)
