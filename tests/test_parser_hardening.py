"""Parser and deserializer configuration is data (`specs/data/parser-hardening.toml`), read by
the translator's XXE tracking and by the Python and Java frontends; the loader is strict."""

import pytest

from frame.sil.scanner import FrameScanner
from frame.sil.specs import parser_hardening


def test_the_shipped_file_loads():
    h = parser_hardening.load()
    assert h.xxe_features["disallow-doctype-decl"] == "true"
    assert "ObjectInputStream" in h.unsafe_deserializers
    assert h.lxml_safe_keyword == "resolve_entities"


@pytest.mark.parametrize("cut, needle", [
    ('parser_products = ["newDocumentBuilder", "newSAXParser", "getXMLReader", "newTransformer"]\n', "[xxe]"),
    ('safe_constructors = ["SafeConstructor"]', "[deserialization.snakeyaml]"),
])
def test_a_missing_key_is_an_error(tmp_path, cut, needle):
    text = parser_hardening.PATH.read_text()
    assert cut in text
    bad = tmp_path / "parser-hardening.toml"
    bad.write_text(text.replace(cut, ""))
    with pytest.raises(ValueError, match=needle.replace("[", r"\[").replace(".", r"\.")):
        parser_hardening.load(bad)


def test_an_unknown_section_is_an_error(tmp_path):
    bad = tmp_path / "parser-hardening.toml"
    bad.write_text(parser_hardening.PATH.read_text() + "\n[extra]\nx = 1\n")
    with pytest.raises(ValueError, match="needs exactly"):
        parser_hardening.load(bad)


def _cwes(code, lang, name):
    return {v.cwe_id for v in FrameScanner(language=lang, verify=False).scan(code, name).vulnerabilities}


_JAXP = """import javax.servlet.http.*;
import javax.xml.parsers.*;
class X extends HttpServlet {
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {
    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
%s    DocumentBuilder b = f.newDocumentBuilder();
    b.parse(req.getInputStream());
  }
}
"""


@pytest.mark.parametrize("line, xxe", [
    ("", True),
    ('    f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n', False),
    ('    f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);\n', True),
    ('    f.setAttribute(javax.xml.XMLConstants.ACCESS_EXTERNAL_DTD, "");\n', False),
])
def test_jaxp_features_harden_the_parser(line, xxe):
    assert ("CWE-611" in _cwes(_JAXP % line, "java", "X.java")) == xxe


_LXML = """from flask import request
from lxml import etree

def view():
    parser = etree.XMLParser(%s)
    return etree.fromstring(request.data, parser)
"""


@pytest.mark.parametrize("kwargs, xxe", [("", True), ("resolve_entities=False", False)])
def test_lxml_parser_keyword(kwargs, xxe):
    assert ("CWE-611" in _cwes(_LXML % kwargs, "python", "v.py")) == xxe
