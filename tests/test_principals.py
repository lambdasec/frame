"""The caller's own identity as data (`frame/sil/specs/data/principals.toml`): one list of
credential headers and principal names for the Python frontend and the translator, which kept
copies that had drifted apart."""

import pytest

from frame.sil.frontends.python_frontend import PythonFrontend
from frame.sil.specs.principals import load
from frame.sil.translator import SILTranslator


def test_both_consumers_read_the_one_list():
    p = load()
    assert PythonFrontend._AUTH_HEADER_NAMES == SILTranslator._AUTH_HEADER_NAMES == p.credential_headers
    assert {"authorization", "x-session-token", "api-key"} <= set(p.credential_headers)
    assert SILTranslator._PRINCIPAL_TOKENS == p.principal_tokens and "current_user" in p.principal_tokens


@pytest.mark.parametrize("text,error", [
    ('credential_headers = ["Authorization"]\nprincipal_tokens = ["current_user"]\n', "lower case"),
    ('credential_headers = []\nprincipal_tokens = ["current_user"]\n', "non-empty"),
    ('credential_headers = ["cookie"]\n', "needs exactly"),
])
def test_a_malformed_file_is_an_error(tmp_path, text, error):
    f = tmp_path / "p.toml"
    f.write_text(text)
    with pytest.raises(ValueError, match=error):
        load(f)
