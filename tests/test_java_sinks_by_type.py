"""Java sinks are rows on the type that declares the method, reached through the receiver's
declared type; HTML output is the writer a servlet response hands out, not every PrintWriter; a
variable's name or a bare method name never makes a sink."""

import pytest

from frame.sil.scanner import FrameScanner

TEMPLATE = """import javax.servlet.http.*;
import java.io.*;
public class S extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String v = request.getParameter("a");
    %s
  }
}
"""


def _found(body):
    code = TEMPLATE % body
    return {v.cwe_id for v in FrameScanner(language="java", verify=False).scan(code, "S.java").vulnerabilities}


@pytest.mark.parametrize("body, cwe", [
    ("response.getWriter().println(v);", "CWE-79"),
    ("PrintWriter out = response.getWriter();\n    out.format(v);", "CWE-79"),
    ("response.getOutputStream().print(v);", "CWE-79"),
    ("java.sql.DriverManager.getConnection(\"jdbc:x\").createStatement().executeQuery(\"SELECT \" + v);", "CWE-89"),
    ("java.sql.Connection c = null;\n    c.prepareStatement(\"SELECT \" + v);", "CWE-89"),
    ("response.sendRedirect(v);", "CWE-601"),
    ("javax.naming.directory.InitialDirContext ctx = null;\n    ctx.search(\"ou=u\", \"(uid=\" + v + \")\", null);", "CWE-90"),
])
def test_sinks_through_the_declared_type_or_the_value(body, cwe):
    assert cwe in _found(body)


@pytest.mark.parametrize("body, cwe", [
    ("FileWriter fw = new FileWriter(\"/tmp/log\");\n    fw.write(v);", "CWE-79"),       # a file, not the response
    ("PrintWriter out = new PrintWriter(new StringWriter());\n    out.println(v);", "CWE-79"),
    ("System.out.println(v);", "CWE-79"),
    ("Form statement = new Form();\n    statement.execute(v);", "CWE-89"),            # a variable's name
    ("java.util.concurrent.Executor ex = null;\n    ex.execute(() -> {});", "CWE-89"),
])
def test_names_alone_make_no_sink(body, cwe):
    assert cwe not in _found(body)


def test_a_local_rebound_to_something_else_is_not_the_response_writer():
    body = ("PrintWriter out = response.getWriter();\n    if (v.isEmpty()) out = new PrintWriter(new StringWriter());\n"
            "    out.println(v);")
    assert "CWE-79" not in _found(body)
