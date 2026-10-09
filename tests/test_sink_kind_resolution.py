"""Every spec sink kind resolves to its own vulnerability class.

The Java, Python and JavaScript frontends used to fall back to SQL injection for
any spec sink kind that was not literally a SinkKind value, so a tainted
`response.setHeader(...)` was reported twice -- header injection AND SQL
injection -- and a tainted regex (`Pattern.compile`) as SQL injection. All
frontends now go through `resolve_sink_kind`, and every kind used by any
frontend's spec table is known to it, so the SQL default is never reached.
"""

import pytest

from frame.sil.instructions import SinkKind, _SINK_KIND_ALIASES, resolve_sink_kind
from frame.sil.scanner import FrameScanner
from frame.sil.translator import VulnType

LANGUAGES = ["python", "java", "javascript", "csharp", "c", "cpp"]
SQL_KINDS = {"sql", "orm", "nosql"}


@pytest.mark.parametrize("lang", LANGUAGES)
def test_every_spec_sink_kind_is_known(lang):
    specs = FrameScanner(language=lang).frontend.specs
    known = {k.value for k in SinkKind} | set(_SINK_KIND_ALIASES)
    unknown = {name: s.is_sink for name, s in specs.items() if s.is_sink and s.is_sink not in known}
    assert not unknown, unknown


@pytest.mark.parametrize("lang", LANGUAGES)
def test_no_non_sql_spec_sink_becomes_sql_injection(lang):
    specs = FrameScanner(language=lang).frontend.specs
    wrong = {name: s.is_sink for name, s in specs.items()
             if s.is_sink and s.is_sink not in SQL_KINDS
             and VulnType.from_sink_kind(resolve_sink_kind(s.is_sink)) == VulnType.SQL_INJECTION}
    assert not wrong, wrong


@pytest.mark.parametrize("kind, vuln", [
    ("redos", VulnType.REGEX_DOS), ("buffer", VulnType.BUFFER_OVERFLOW),
    ("assertion", VulnType.ASSERTION_FAILURE), ("race", VulnType.RACE_CONDITION),
    ("sensitive_exposure", VulnType.SENSITIVE_DATA_EXPOSURE),
    ("network", VulnType.SENSITIVE_DATA_EXPOSURE), ("privilege", VulnType.PRIVILEGE_MANAGEMENT),
    ("header_injection", VulnType.HEADER_INJECTION),
])
def test_formerly_unresolved_kinds_map_to_their_own_class(kind, vuln):
    assert VulnType.from_sink_kind(resolve_sink_kind(kind)) == vuln


def _java(body):
    return ("import javax.servlet.http.*;\nimport java.util.regex.*;\n"
            "public class T extends HttpServlet {\n"
            "  public void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {\n"
            "    String v = req.getHeader(\"Upgrade\");\n" + body + "\n  }\n}\n")


def _cwes(lang, src, name):
    r = FrameScanner(language=lang, verify=False).scan(src, name)
    assert not r.errors, r.errors
    return {v.cwe_id for v in r.vulnerabilities}


def test_tainted_response_header_is_header_injection_only():
    # Tomcat Http11Processor: response.setHeader("Upgrade", requestedProtocol).
    found = _cwes("java", _java('    resp.setHeader("Upgrade", v);'), "T.java")
    assert "CWE-113" in found
    assert "CWE-89" not in found


def test_tainted_regex_is_redos_not_sql_injection():
    found = _cwes("java", _java("    Pattern p = Pattern.compile(v);"), "T.java")
    assert "CWE-89" not in found
    assert "CWE-1333" in found
