"""Java specs are keyed on a receiver's conventional name (`documentBuilder.parse`,
`jdbcTemplate.query`); the frontend matches a call through the receiver's
DECLARED type, so `DocumentBuilder b; b.parse(x)` is the same sink whatever the
variable is called. Each positive is paired with a near miss that must stay
clean (another type with the same method, an unknown or conflicting type).
"""

import pytest

from frame.sil.frontends.java_frontend import JavaFrontend
from frame.sil.scanner import FrameScanner
from frame.sil.specs.java_specs import type_spec_receivers

_HEADER = ("import javax.xml.parsers.*;\n"
           "import javax.servlet.http.*;\n"
           "import org.springframework.jdbc.core.*;\n"
           "class W extends HttpServlet {\n")


def _servlet(body, fields=""):
    return (_HEADER + fields
            + "  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {\n"
            + body + "  }\n}\n")


def cwes(code):
    r = FrameScanner(language="java").scan(code, "W.java")
    assert not r.errors, r.errors
    return {v.cwe_id for v in r.vulnerabilities}


_NEW_BUILDER = ("    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n"
                "    DocumentBuilder b = f.newDocumentBuilder();\n")


@pytest.mark.parametrize("body,fields", [
    (_NEW_BUILDER + "    b.parse(req.getInputStream());\n", ""),
    (_NEW_BUILDER + "    org.w3c.dom.Document d = b.parse(req.getInputStream());\n", ""),
    ("    javax.xml.parsers.DocumentBuilder b = make();\n    b.parse(req.getInputStream());\n", ""),
    ("    var f = DocumentBuilderFactory.newInstance();\n    var b = f.newDocumentBuilder();\n"
     "    b.parse(req.getInputStream());\n", ""),
    ("    parser.parse(req.getInputStream());\n", "  private DocumentBuilder parser;\n"),
    ("    this.parser.parse(req.getInputStream());\n", "  private DocumentBuilder parser;\n"),
    ("    SAXParser p = SAXParserFactory.newInstance().newSAXParser();\n"
     "    p.parse(req.getInputStream(), handler);\n", ""),
])
def test_xml_parser_found_by_declared_type(body, fields):
    assert "CWE-611" in cwes(_servlet(body, fields))


@pytest.mark.parametrize("body,fields", [
    # Hardened: the receiver tracking of the XXE checker works on any name.
    ("    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n"
     "    f.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n"
     "    DocumentBuilder b = f.newDocumentBuilder();\n"
     "    b.parse(req.getInputStream());\n", ""),
    # Another type with a `parse` method.
    ("    MyParser b = new MyParser();\n    b.parse(req.getInputStream());\n", ""),
    # `var` of an unknown class.
    ("    var b = new SAXParserImpl();\n    b.parse(req.getInputStream());\n", ""),
    # A local of another type shadows the DocumentBuilder field.
    ("    MyParser parser = new MyParser();\n    parser.parse(req.getInputStream());\n",
     "  private DocumentBuilder parser;\n"),
])
def test_other_types_are_not_xml_parsers(body, fields):
    assert "CWE-611" not in cwes(_servlet(body, fields))


def test_jdbc_template_found_by_declared_type():
    body = ("    String id = req.getParameter(\"id\");\n"
            "    JdbcTemplate t = tmpl;\n"
            "    t.queryForList(\"select * from u where id=\" + id);\n")
    assert "CWE-89" in cwes(_servlet(body))


# ---- the type map itself -------------------------------------------------

def _types(src, method="f"):
    """The name -> declared type map the frontend uses inside `method`."""
    fe = JavaFrontend()
    seen = {}
    orig = fe._method_var_types

    def spy(node):
        types = orig(node)
        seen[fe._get_text(node.child_by_field_name("name"))] = types
        return types

    fe._method_var_types = spy
    fe.translate(src, "A.java")
    return seen[method]


def test_type_map_records_declarations_and_drops_conflicts():
    src = ("class A {\n"
           "  java.util.Map<String, Integer> field;\n"
           "  void f(DocumentBuilder p, int n, String... rest) throws Exception {\n"
           "    List<String> xs = null;\n"
           "    int[] arr = null;\n"
           "    for (Item it : items) { }\n"
           "    try (Reader r = open()) { } catch (IOException e) { }\n"
           "    if (n > 0) { Foo dup = null; } else { Bar dup = null; }\n"
           "    Runnable g = () -> { };\n"
           "    java.util.function.Function<String, String> h = q -> q;\n"
           "    Object anon = new Object() { void m(Secret s) { } };\n"
           "  }\n"
           "}\n")
    types = _types(src)
    assert types["field"] == "Map"
    assert types["p"] == "DocumentBuilder"
    assert types["xs"] == "List"
    assert types["it"] == "Item"
    assert types["r"] == "Reader"
    for untyped in ("n", "arr", "dup", "q", "e"):
        assert untyped not in types, untyped
    assert "s" not in types  # declared in a nested class body


@pytest.mark.parametrize("type_name,expected", [
    ("DocumentBuilder", "documentBuilder"),
    ("SAXParser", "saxParser"),
    ("XMLReader", "xmlReader"),
    ("URL", "url"),
    ("XPath", "xpath"),
    ("JdbcTemplate", "jdbcTemplate"),
    ("HttpServletRequest", "request"),
])
def test_type_spec_receivers(type_name, expected):
    assert expected in type_spec_receivers(type_name)


# ---- reflection: the method NAME is the sink, not Method.invoke's target ---

def test_invoking_a_fixed_method_on_tainted_object_is_not_code_injection():
    # Tomcat SessionUtils: a session object, a fixed method name.
    body = ("    Object engine = req.getParameter(\"e\");\n"
            "    java.lang.reflect.Method method = engine.getClass().getMethod(\"getLocale\");\n"
            "    Object locale = method.invoke(engine, (Object[]) null);\n")
    assert "CWE-94" not in cwes(_servlet(body))


def test_choosing_a_method_by_tainted_name_is_code_injection():
    body = ("    String name = req.getParameter(\"m\");\n"
            "    Class<?> c = Class.forName(\"com.example.Ops\");\n"
            "    java.lang.reflect.Method m = c.getMethod(name);\n")
    assert "CWE-94" in cwes(_servlet(body))


# ---- a declared supertype is not the implementation ----------------------

def test_random_declared_type_holding_securerandom_is_not_weak_random():
    # OWASP BenchmarkJava weakrand negatives: a SecureRandom passed as Random.
    code = ("class R {\n"
            "  void f() throws Exception {\n"
            "    java.util.Random numGen = java.security.SecureRandom.getInstance(\"SHA1PRNG\");\n"
            "    byte[] b = new byte[40];\n"
            "    next(numGen, b);\n"
            "  }\n"
            "  void next(java.util.Random generator, byte[] barray) {\n"
            "    generator.nextBytes(barray);\n"
            "  }\n"
            "}\n")
    assert "CWE-330" not in cwes(code)


def test_new_random_is_still_weak_random():
    code = ("class R {\n"
            "  int f() {\n"
            "    return new java.util.Random().nextInt();\n"
            "  }\n"
            "}\n")
    assert "CWE-330" in cwes(code)


# ---- a call in a return expression is analysed like any other call -------

def _returns(stmt):
    return ("import java.sql.*;\nimport javax.servlet.http.*;\n"
            "class Q {\n"
            "  ResultSet find(HttpServletRequest req, Connection c) throws Exception {\n"
            "    String id = req.getParameter(\"id\");\n"
            "    Statement st = c.createStatement();\n"
            f"    {stmt}\n"
            "  }\n"
            "}\n")


def test_sink_called_in_return_is_reported():
    assert "CWE-89" in cwes(_returns('return st.executeQuery("SELECT * FROM t WHERE id = \'" + id + "\'");'))


def test_constant_query_in_return_is_clean():
    assert "CWE-89" not in cwes(_returns('return st.executeQuery("SELECT * FROM t");'))


@pytest.mark.parametrize("body,weak", [
    # Runtime class known: new Random, never re-assigned.
    ("    java.util.Random r = new java.util.Random();\n    return r.nextInt();\n", True),
    ("    var r = new java.util.Random();\n    return r.nextInt();\n", True),
    # Only the declared type is known: may be a SecureRandom.
    ("    java.util.Random r = pick();\n    return r.nextInt();\n", False),
    # Re-assigned after `new Random()`: runtime class unknown.
    ("    java.util.Random r = new java.util.Random();\n    r = pick();\n    return r.nextInt();\n", False),
    # Declared SecureRandom.
    ("    java.security.SecureRandom r = new java.security.SecureRandom();\n    return r.nextInt();\n", False),
    # A type that merely has a nextInt method.
    ("    java.util.Scanner sc = new java.util.Scanner(System.in);\n    return sc.nextInt();\n", False),
])
def test_weak_random_needs_the_runtime_class(body, weak):
    # Asserted on spec resolution for the nextInt call itself: constructing a
    # Random is reported on its own, and findings are deduplicated per method.
    from frame.sil.instructions import Call
    code = "class R {\n  int f() {\n" + body + "  }\n}\n"
    program = JavaFrontend().translate(code, "R.java")
    calls = [i for p in program.procedures.values() for n in p.nodes.values()
             for i in n.instrs if isinstance(i, Call) and i.get_full_name().endswith(".nextInt")]
    assert len(calls) == 1
    spec = program.spec_for_call(calls[0])
    assert (spec is not None and spec.is_sink == "insecure_random") == weak


# ---- own-class calls, attributes ------------------------------------------

def test_unqualified_call_to_own_overload_is_not_the_library_api():
    # commons-lang3 RandomUtils.nextDouble() delegates to its own overload.
    code = ("public class RandomUtils {\n"
            "  public static double nextDouble() {\n"
            "    return nextDouble(0, Double.MAX_VALUE);\n"
            "  }\n"
            "  public static double nextDouble(double a, double b) {\n"
            "    return a;\n"
            "  }\n"
            "}\n")
    assert "CWE-330" not in cwes(code)


def test_own_getter_named_like_a_request_api_is_not_a_source():
    # Tomcat's Request implements getPathInfo(); calling it is not user input
    # arriving, it is the container computing a path.
    code = ("import javax.servlet.*;\n"
            "public class Req {\n"
            "  String pathInfo;\n"
            "  public String getPathInfo() {\n"
            "    return pathInfo;\n"
            "  }\n"
            "  public RequestDispatcher dispatch(ServletContext ctx) {\n"
            "    String p = getPathInfo();\n"
            "    return ctx.getRequestDispatcher(p);\n"
            "  }\n"
            "}\n")
    assert "CWE-22" not in cwes(code)


@pytest.mark.parametrize("receiver_decl,receiver", [
    ("HttpSession s = req.getSession();", "s"),
    ("javax.management.MBeanServer m = server();", "m"),
])
def test_server_side_attributes_are_not_user_input(receiver_decl, receiver):
    body = (f"    {receiver_decl}\n"
            f"    Object v = {receiver}.getAttribute(\"k\");\n"
            "    resp.getWriter().print(v);\n")
    assert "CWE-79" not in cwes(_servlet(body))


def test_attribute_of_untrusted_xml_element_is_user_input():
    # A hardened parser (no XXE) still yields attacker data. (An unhardened one
    # reports CWE-611, and the scanner then drops plain HTML-output XSS in the
    # same method by design.)
    body = ("    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n"
            "    f.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n"
            "    DocumentBuilder documentBuilder = f.newDocumentBuilder();\n"
            "    org.w3c.dom.Document d = documentBuilder.parse(req.getInputStream());\n"
            "    org.w3c.dom.Element e = d.getDocumentElement();\n"
            "    String v = e.getAttribute(\"name\");\n"
            "    resp.getWriter().print(v);\n")
    assert "CWE-79" in cwes(_servlet(body))


def test_request_attribute_is_not_a_trust_boundary_but_session_is():
    store = "    String id = req.getParameter(\"id\");\n    {target}.setAttribute(\"id\", id);\n"
    assert "CWE-501" not in cwes(_servlet(store.replace("{target}", "req")))
    assert "CWE-501" in cwes(_servlet(store.replace("{target}", "req.getSession()")))


def test_taint_flows_through_own_helper_method():
    # OWASP BenchmarkJava shape: bar = doSomething(request, param) must carry
    # param's taint (default propagation for program calls).
    code = ("import javax.servlet.http.*;\n"
            "public class B extends HttpServlet {\n"
            "  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {\n"
            "    String param = request.getParameter(\"p\");\n"
            "    String bar = doSomething(request, param);\n"
            "    java.sql.Statement st = conn().createStatement();\n"
            "    st.execute(\"SELECT * FROM u WHERE n = '\" + bar + \"'\");\n"
            "  }\n"
            "  private static String doSomething(HttpServletRequest request, String param) {\n"
            "    String bar = param;\n"
            "    return bar;\n"
            "  }\n"
            "}\n")
    assert "CWE-89" in cwes(code)


def test_writing_to_an_in_memory_writer_is_not_output():
    # Spring CssLinkResourceTransformer builds CSS in a StringWriter.
    body = ("    String link = req.getParameter(\"l\");\n"
            "    java.io.StringWriter writer = new java.io.StringWriter();\n"
            "    writer.write(link);\n")
    assert "CWE-79" not in cwes(_servlet(body))


def test_in_memory_writer_carries_taint_to_real_output():
    body = ("    String link = req.getParameter(\"l\");\n"
            "    java.io.StringWriter writer = new java.io.StringWriter();\n"
            "    writer.write(link);\n"
            "    String html = writer.toString();\n"
            "    resp.getWriter().print(html);\n")
    assert "CWE-79" in cwes(_servlet(body))


@pytest.mark.parametrize("target,value,secret", [
    ("secretKeyAlgorithm", "DESede", False),       # Tomcat PEMFile
    ("privateKeyFormat", "PKCS8Format", False),
    ("secretKey", "Zq8vN2rT5wLk", True),
    ("signingKey", "c2VjcmV0LWtleS1tYXRlcmlhbA==", True),
])
def test_credential_named_metadata_is_not_a_secret(target, value, secret):
    code = ("class K {\n"
            "  void f() {\n"
            f"    String {target} = \"{value}\";\n"
            "  }\n"
            "}\n")
    found = cwes(code)
    assert bool(found & {"CWE-321", "CWE-798"}) == secret, found


def test_guessed_receiver_type_does_not_make_a_usage_sink():
    # Tomcat LogFactory.getLog: getFactory().getInstance(clazz).
    code = ("class L {\n"
            "  static Object getLog(Class<?> clazz) {\n"
            "    return getFactory().getInstance(clazz);\n"
            "  }\n"
            "}\n")
    assert "CWE-328" not in cwes(code)
