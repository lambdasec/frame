"""Java frontend lowering that framework code depends on (each positive paired with a near miss):

* a chained call (`em.createQuery(q).getResultList()`) is analysed link by link;
* a builder chain (`sb.append(a).append(b)`) acts on the one builder;
* a call nested in an argument is a call of its own (its sanitizer / callee applies);
* a call on a project class is not the library API a bare method name shares (`service.search`);
* lambdas handed to a framework registration are handler procedures with typed parameters;
* a `return "redirect:" + x` / HTML-literal return from a handler is a sink;
* comments between arguments are not arguments;
* a MyBatis `@Select("... ${p}")` mapper method sinks the parameter.
"""

import pytest

from frame.sil.frontends.java_frontend import JavaFrontend
from frame.sil.scanner import FrameScanner


def cwes(code, name="W.java"):
    r = FrameScanner(language="java").scan(code, name)
    assert not r.errors, r.errors
    return {v.cwe_id for v in r.vulnerabilities}


_SERVLET = ("import javax.servlet.http.*;\nimport javax.persistence.EntityManager;\n"
            "class W extends HttpServlet {\n  EntityManager em;\n"
            "  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {\n"
            "    String n = req.getParameter(\"n\");\n%s  }\n}\n")


@pytest.mark.parametrize("body,expected", [
    ('    em.createQuery("from U where n = \'" + n + "\'").getResultList();\n', True),
    ('    em.createQuery("from U where n = :n").setParameter("n", n).getResultList();\n', False),
    ('    StringBuilder sb = new StringBuilder("from U where n = \'");\n'
     '    sb.append(n).append("\'");\n    em.createQuery(sb.toString());\n', True),
    ('    StringBuilder sb = new StringBuilder("from U where n = 1");\n'
     '    sb.append(" and x = 2").append(" order by id");\n    em.createQuery(sb.toString());\n', False),
    ('    Object o = (Object) em.createQuery("from U where n = \'" + n + "\'").getSingleResult();\n', True),
])
def test_chained_and_builder_calls(body, expected):
    assert ("CWE-89" in cwes(_SERVLET % body)) is expected


@pytest.mark.parametrize("body,expected", [
    ('    em.createQuery(String.valueOf(n)).getResultList();\n', True),
    ('    em.createQuery(org.owasp.esapi.ESAPI.encoder().encodeForSQL(null, n)).getResultList();\n', False),
])
def test_nested_call_arguments_are_calls(body, expected):
    assert ("CWE-89" in cwes(_SERVLET % body)) is expected


def test_comment_between_arguments_is_not_an_argument():
    code = _SERVLET % ('    em.createNativeQuery("select * from t where n = \'" + n + "\'", // trailing comment\n'
                       '        Object.class);\n')
    assert "CWE-89" in cwes(code)


def _project(root):
    res = FrameScanner(verify=False).scan_directory(str(root), None, project_root=str(root))
    return sorted((v.cwe_id, v.line) for r in res for v in r.vulnerabilities)


def test_project_class_receiver_is_not_a_library_sink(tmp_path):
    (tmp_path / "Svc.java").write_text("package p;\npublic class Svc { public String search(String q) { return q; } }\n")
    (tmp_path / "C.java").write_text(
        "package p;\nimport javax.servlet.http.*;\n"
        "public class C extends HttpServlet {\n  private Svc svc = new Svc();\n"
        "  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {\n"
        "    svc.search(req.getParameter(\"q\"));\n  }\n}\n")
    assert not _project(tmp_path)      # `search` is not an LDAP query here


_SPARK = ("package p;\nimport static spark.Spark.get;\nimport java.sql.*;\n"
          "public class A {\n  Connection c;\n  void routes() {\n    get(\"/x\", (req, res) -> {\n%s    });\n  }\n}\n")


def test_lambda_handler_is_a_procedure_with_typed_parameters():
    p = JavaFrontend().translate(_SPARK % '      return req.queryParams("q");\n', "A.java")
    lam = [pr for n, pr in p.procedures.items() if "lambda@" in n]
    assert len(lam) == 1
    assert lam[0].param_types == {"req": "Request", "res": "Response"}
    assert lam[0].registered_via == ["get"]
    calls = [i for nd in lam[0].nodes.values() for i in nd.instrs if type(i).__name__ == "Call"]
    assert calls and calls[0].canonical == "spark.Request.queryParams"


def test_handler_return_sinks():
    html = ('import org.springframework.web.bind.annotation.*;\n@RestController class R {\n'
            '  @GetMapping("/a") public String a(@RequestParam String n) { return "<p>" + n + "</p>"; }\n}\n')
    redir = ('import org.springframework.web.bind.annotation.*;\n@org.springframework.stereotype.Controller class R {\n'
             '  @GetMapping("/a") public String a(@RequestParam String n) { return "redirect:" + n; }\n}\n')
    safe = ('import org.springframework.web.bind.annotation.*;\n@RestController class R {\n'
            '  @GetMapping("/a") public String a(@RequestParam String n) { return "<p>hello</p>"; }\n}\n')
    assert "CWE-79" in cwes(html)
    assert "CWE-601" in cwes(redir)
    assert not cwes(safe)


def test_handler_annotations_come_from_the_packs(tmp_path):
    """What marks a handler is the entry points' annotations in the Java packs (built-in and the
    project's own), not a list in the frontend."""
    code = ('import acme.web.*;\nclass R {\n'
            '  @Route("/a") public String a(String n) { return "<p>" + n + "</p>"; }\n}\n')
    pack = tmp_path / "acme.toml"
    pack.write_text('[pack]\nname = "acme-web"\nlanguage = "java"\ndetect = { imports = ["acme.web"] }\n'
                    '[[entrypoint]]\nannotation = ["Route"]\nparams = "all"\n')
    by_method = tmp_path / "by_method.toml"
    by_method.write_text(pack.read_text().replace('annotation = ["Route"]', 'method = ["a"]'))

    def found(p):
        return {v.cwe_id for v in FrameScanner(language="java", packs=[str(p)]).scan(code, "R.java").vulnerabilities}
    assert "CWE-79" in found(pack)
    assert "CWE-79" not in found(by_method)          # `n` is tainted, but nothing says `a` is a handler


def test_mybatis_dollar_substitution(tmp_path):
    (tmp_path / "M.java").write_text(
        "package p;\nimport org.apache.ibatis.annotations.*;\n"
        "@Mapper public interface M {\n"
        "  @Select(\"select * from t where n = '${n}'\") java.util.List<Object> byName(@Param(\"n\") String n);\n"
        "  @Select(\"select * from t where n = #{n}\") java.util.List<Object> safe(@Param(\"n\") String n);\n}\n")
    (tmp_path / "C.java").write_text(
        "package p;\nimport javax.servlet.http.*;\n"
        "public class C extends HttpServlet {\n  M m;\n"
        "  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {\n"
        "    m.byName(req.getParameter(\"a\"));\n    m.safe(req.getParameter(\"b\"));\n  }\n}\n")
    assert [v for v in _project(tmp_path) if v[0] == "CWE-89"] == [("CWE-89", 4)]      # `${n}`, not `#{n}`


def _lambda_types(src):
    program = JavaFrontend().translate(src, "A.java")
    return [p.param_types for n, p in program.procedures.items() if ".lambda@" in n]


@pytest.mark.parametrize("imp, call, types", [
    ("spark.Spark", 'Spark.get("/x", (req, res) -> req.body());', {"req": "Request", "res": "Response"}),
    ("spark.Spark", 'Spark.notFound((req, res) -> "x");', {"req": "Request", "res": "Response"}),
    ("io.javalin.Javalin", 'app.post("/x", ctx -> ctx.body());', {"ctx": "Context"}),
    ("io.jooby.Jooby", 'app.get("/x", ctx -> ctx.query());', {"ctx": "Context"}),
    ("io.vertx.ext.web.Router", 'router.route("/x").handler(ctx -> ctx.end());', {"ctx": "RoutingContext"}),
    ("ratpack.server.RatpackServer", 'chain.path("x", ctx -> ctx.render("y"));', {"ctx": "Context"}),
    ("org.springframework.web.reactive.function.server.RouterFunctions",
     'RouterFunctions.route().GET("/x", req -> ok());', {"req": "ServerRequest"}),
])
def test_route_lambdas_are_typed_by_the_framework_pack(imp, call, types):
    """`[[lambda_handler]]` in the framework's pack: the registration method and the file's imports
    give the lambda its parameters' types."""
    src = f"import {imp};\nclass A {{\n  void m(Object app, Object router, Object chain) {{\n    {call}\n  }}\n}}\n"
    assert _lambda_types(src) == [types]


@pytest.mark.parametrize("imp, call", [
    ("java.util.List", 'Spark.get("/x", (req, res) -> req.body());'),              # no framework import
    ("spark.Spark", 'Spark.map("/x", (req, res) -> req.body());'),                  # not a route method
    ("io.vertx.ext.web.Router", 'handler(ctx -> ctx.end());'),                        # needs a receiver
    ("io.vertx.core.Vertx", 'router.route("/x").handler(ctx -> ctx.end());'),       # not vertx-web
])
def test_other_lambdas_are_not_typed(imp, call):
    src = f"import {imp};\nclass A {{\n  void m(Object router) {{\n    {call}\n  }}\n}}\n"
    assert all(not t for t in _lambda_types(src))


def test_lambda_handlers_are_java_only_and_say_when_they_apply():
    from frame.sil.packs.schema import PackError, parse_pack
    with pytest.raises(PackError, match="Java packs"):
        parse_pack({"pack": {"name": "x", "language": "python"},
                    "lambda_handler": [{"methods": ["get"], "param_types": ["T"], "imports": ["x"]}]}, "x.toml")
    with pytest.raises(PackError, match="detect.imports"):
        parse_pack({"pack": {"name": "x", "language": "java"},
                    "lambda_handler": [{"methods": ["get"], "param_types": ["T"]}]}, "x.toml")
