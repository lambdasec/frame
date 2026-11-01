"""Java request sources are the servlet interfaces' methods, reached through a receiver's declared
type and its documented supertypes, never through a bare method name or a variable called
`request`; an Enumeration hands out what it holds."""

import pytest

from frame.sil.frontends.java_frontend import JavaFrontend
from frame.sil.scanner import FrameScanner
from frame.sil.specs.java_specs import type_spec_receivers

SERVLET = """import javax.servlet.http.*;
public class S extends HttpServlet {
  public void doPost(%s request, HttpServletResponse response) throws Exception {
    %s
    java.sql.Statement st = java.sql.DriverManager.getConnection("jdbc:x").createStatement();
    st.execute("SELECT * FROM t WHERE a = '" + v + "'");
  }
}
"""


def _sqli(param_type, body):
    code = SERVLET % (param_type, body)
    return "CWE-89" in {v.cwe_id for v in FrameScanner(language="java", verify=False).scan(code, "S.java").vulnerabilities}


@pytest.mark.parametrize("param_type", ["HttpServletRequest", "HttpServletRequestWrapper", "javax.servlet.ServletRequest"])
def test_a_request_source_through_the_declared_type_and_its_supertypes(param_type):
    assert _sqli(param_type, 'String v = request.getParameter("a");')


def test_a_method_of_another_type_with_a_request_methods_name_is_no_source():
    assert not _sqli("Form", 'String v = request.getParameter("a");')


@pytest.mark.parametrize("body, flagged", [
    ('java.util.Enumeration<String> e = request.getHeaders("h");\n    String v = (String) e.nextElement();', True),
    ('java.util.Enumeration<String> e = java.util.Collections.enumeration(java.util.List.of("x"));\n'
     '    String v = (String) e.nextElement();', False),
])
def test_an_enumeration_hands_out_what_it_holds(body, flagged):
    assert _sqli("HttpServletRequest", body) == flagged


def test_supertypes_extend_the_spec_receivers():
    assert "ServletRequest" in type_spec_receivers("HttpServletRequestWrapper")
    assert "Statement" in type_spec_receivers("CallableStatement")


def test_a_package_qualified_call_and_a_constructed_value_have_ids():
    code = ("public class A { void m() {\n  org.acme.Db.TEMPLATE.query(\"x\");\n"
            "  org.acme.Wrapper w = new org.acme.Wrapper(null);\n  w.read();\n} }\n")
    p = JavaFrontend().translate(code, "A.java")
    ids = {i.get_full_name(): i.canonical for pr in p.procedures.values() for n in pr.nodes.values()
           for i in n.instrs if type(i).__name__ == "Call"}
    assert ids["org.acme.Db.TEMPLATE.query"] == "org.acme.Db.TEMPLATE.query"
    assert ids["w.read"] == "org.acme.Wrapper.read"
