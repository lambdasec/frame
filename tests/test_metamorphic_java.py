"""Metamorphic tests for Java: a vulnerability rewritten without changing its meaning is still found.

The Java side of tests/test_metamorphic.py. An adversarial review found Java constructs the
frontend lowered wrongly: `x += e` as `x = e`, a ternary as its consequence, a chained
assignment, an array initializer and an instanceof binding as variables named by their source
text, an assignment inside a loop condition never executed, the bodies of `synchronized`, `do`,
labelled statements and switch rules dropped, and a call on a cast receiver typed as nothing.
Each seed flow (request data reaching a sink) is rewritten by every transform below and the
finding must survive; the same transform applied to a constant must stay clean, so a fix cannot
buy recall with noise. A guard written inside each statement kind must still clear the flow.

A transform Frame does not handle yet is in KNOWN_GAPS with the reason, as a strict xfail: fixing
it makes the test pass and CI asks for the entry to be removed.
"""

import re

import pytest

from frame.sil.scanner import FrameScanner

JAVA_HEAD = """import java.io.*;
import java.sql.*;
import java.util.*;
import javax.servlet.ServletRequest;
import javax.servlet.http.*;

public class App extends HttpServlet {
    private static final Set<String> ALLOWED = Set.of("id", "name");
    private String val;
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String q = request.getParameter("q");
        Statement st = DriverManager.getConnection("jdbc:x").createStatement();
        ServletRequest r = request;
{body}
    }
{members}
}
"""
JAVA_SINKS = {
    "CWE-89": "st.executeQuery(\"SELECT * FROM t WHERE n = '\" + {v} + \"'\");",
    "CWE-78": 'Runtime.getRuntime().exec("ping " + {v});',
    "CWE-22": 'new FileInputStream("/srv/files/" + {v});',
    "CWE-79": 'response.getWriter().println("<p>" + {v} + "</p>");',
}
# Each transform: statements that leave q's value in v.
JAVA_TRANSFORMS = {
    "plain": ["String v = q;"],
    "compound-assignment": ['String v = "";', "v += q;"],
    "compound-assignment-chain": ['String v = "a";', "v += q;", 'v += "b";'],
    "ternary": ['String v = q != null ? q : "";'],
    "ternary-alternative": ['String v = q == null ? "" : q;'],
    "ternary-in-concat": ['String v = "x" + (q.isEmpty() ? "" : q);'],
    "chained-assignment": ["String v, w;", "v = w = q;"],
    "assignment-as-value": ["String v;", "String w = (v = q);"],
    "array-initializer": ['String[] a = {q, "x"};', "String v = a[0];"],
    "array-creation": ['String[] a = new String[]{"x", q};', "String v = a[1];"],
    "array-element-write": ["String[] a = new String[2];", "a[0] = q;", "String v = a[0];"],
    "array-2d": ['String[][] a = {{q}, {"x"}};', "String v = a[0][0];"],
    "instanceof-pattern": ["Object o = q;", 'String v = "";', "if (o instanceof String s) {", "    v = s;", "}"],
    "instanceof-negated": ["Object o = q;", "if (!(o instanceof String s)) {", "    return;", "}", "String v = s;"],
    "while-condition-assignment": ["BufferedReader br = new BufferedReader(new StringReader(q));", "String line;",
                                   'String v = "";', "while ((line = br.readLine()) != null) {",
                                   "    v = v + line;", "}"],
    "if-condition-assignment": ["String v;", "if ((v = q) == null) {", "    return;", "}"],
    "synchronized": ['String v = "";', "synchronized (this) {", "    v = q;", "}"],
    "do-while": ['String v = "";', "do {", "    v = q;", "} while (v.isEmpty());"],
    "labeled": ['String v = "";', "outer:", "for (int i = 0; i < 1; i++) {", "    v = q;", "}"],
    "for-update": ['String v = "";', "for (int i = 0; i < 1; i++, v = q) {", "}"],
    "for-init-expression": ["String v;", "int i;", "for (i = 0, v = q; i < q.length(); i++) {", "}"],
    "replace-replacement": ['String v = "X".replace("X", q);'],
    "replace-all-replacement": ['String v = "X".replaceAll("X", q);'],
    "replace-first-replacement": ['String v = "X".replaceFirst("X", q);'],
    "builder-insert": ['StringBuilder sb = new StringBuilder("x");', "sb.insert(0, q);", "String v = sb.toString();"],
    "builder-append": ["StringBuilder sb = new StringBuilder();", "sb.append(q);", "String v = sb.toString();"],
    "parenthesized": ["String v = (q);"],
    "cast": ["String v = (String) (Object) q;"],
    "switch-rule": ["String v;", "switch (q.length()) {", '    case 0 -> v = "";', "    default -> v = q;", "}"],
    "switch-rule-block": ['String v = "";', "switch (q.length()) {", "    case 0 -> { v = q; }",
                          '    default -> { v = ""; }', "}"],
    "switch-expression": ["String v = switch (q.length()) {", '    case 0 -> "";', "    default -> q;", "};"],
    "switch-expression-yield": ["String v = switch (q.length()) {", '    case 0: yield "";',
                                "    default: { String t = q.trim(); yield t; }", "};"],
    "switch-classic-later-case": ['String v = "";', "switch (q.length()) {", "    case 0: v = q; break;",
                                  '    default: v = "";', "}"],
    "switch-fallthrough": ['String v = "";', "switch (q.length()) {", "    case 0: v = q;",
                           "    case 1: break;", '    default: v = "x";', "}"],
    "try-catch": ['String v = "";', "try {", "    v = q;", "} catch (RuntimeException e) {", "}"],
    "enhanced-for": ['String v = "";', "for (String s : List.of(q)) {", "    v = s;", "}"],
    "concat-method": ['String v = "".concat(q);'],
    "string-format": ['String v = String.format("%s", q);'],
    "value-of": ["String v = String.valueOf(q);"],
}
# Transforms that read the request themselves (no constant twin).
JAVA_SOURCE_TRANSFORMS = {
    "cast-receiver": ['String v = ((HttpServletRequest) r).getParameter("n");'],
    "cast-receiver-chain": ['String v = ((HttpServletRequest) r).getHeader("n").trim();'],
}
# Sink arguments written inline (the value never passes through a variable).
JAVA_INLINE = {
    "ternary-argument": ("Runtime.getRuntime().exec(q.isEmpty() ? \"ls\" : \"ping \" + q);", "CWE-78"),
    "compound-in-argument": ('String v = "ping ";\n        Runtime.getRuntime().exec(v += q);', "CWE-78"),
    "array-argument-shell": ('Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", "ping " + q});', "CWE-78"),
    "array-variable-shell": ('String[] cmd = {"sh", "-c", "ping " + q};\n        Runtime.getRuntime().exec(cmd);',
                             "CWE-78"),
    "array-environment": ('String[] env = {q};\n        Runtime.getRuntime().exec(new String[]{"ls"}, env);',
                          "CWE-78"),
    "process-builder-command": ('ProcessBuilder pb = new ProcessBuilder();\n        pb.command("ping", q);', "CWE-78"),
    "process-builder-array": ('new ProcessBuilder(new String[]{"sh", "-c", q}).start();', "CWE-78"),
    "creation-statement": ('new FileOutputStream("/srv/out/" + q);', "CWE-22"),
}

KNOWN_GAPS: dict = {}


def _scan(code, name="App.java"):
    r = FrameScanner(language="java").scan(code, name)
    assert not r.errors, r.errors
    return {v.cwe_id for v in r.vulnerabilities}


def _java(lines, members=""):
    return JAVA_HEAD.replace("{body}", "\n".join("        " + ln for ln in lines)).replace("{members}", members)


def _gap(transform):
    reason = KNOWN_GAPS.get(transform)
    return [pytest.mark.xfail(reason=reason, strict=True)] if reason else []


_ALL = {**JAVA_TRANSFORMS, **JAVA_SOURCE_TRANSFORMS}


@pytest.mark.parametrize("transform,cwe", [
    pytest.param(t, c, id=f"{t}-{c}", marks=_gap(t)) for t in _ALL for c in JAVA_SINKS])
def test_java_flow_survives_the_rewrite(transform, cwe):
    sink = JAVA_SINKS[cwe].replace("{v}", "v")
    assert cwe in _scan(_java(_ALL[transform] + [sink]))


@pytest.mark.parametrize("transform", [pytest.param(t, id=t, marks=_gap(t)) for t in JAVA_INLINE])
def test_java_inline_flow_survives_the_rewrite(transform):
    stmt, cwe = JAVA_INLINE[transform]
    assert cwe in _scan(_java([stmt]))


def _constant(lines):
    """The transform applied to a constant instead of the request value."""
    return [re.sub(r"\bq\b", '"localhost"', ln) for ln in lines]


@pytest.mark.parametrize("transform", list(JAVA_TRANSFORMS))
def test_java_rewrite_of_a_constant_stays_clean(transform):
    lines = _constant(JAVA_TRANSFORMS[transform])
    found = _scan(_java(lines + [JAVA_SINKS["CWE-89"].replace("{v}", "v"),
                                 JAVA_SINKS["CWE-78"].replace("{v}", "v")]))
    assert not found & {"CWE-89", "CWE-78"}


@pytest.mark.parametrize("transform", [t for t in JAVA_INLINE if "q" in JAVA_INLINE[t][0]])
def test_java_inline_rewrite_of_a_constant_stays_clean(transform):
    stmt, cwe = JAVA_INLINE[transform]
    assert cwe not in _scan(_java([re.sub(r"\bq\b", '"localhost"', stmt)]))


# The nearest safe idioms: each must stay clean.
JAVA_SAFE = {
    # an argument vector runs its program without a shell: the other elements are arguments
    "argv-no-shell": ['Runtime.getRuntime().exec(new String[]{"ping", "-c", "1", q});'],
    "argv-variable-no-shell": ['String[] cmd = {"ping", "-c", "1", q};', "Runtime.getRuntime().exec(cmd);"],
    # a request accessor that is not client data, on a cast receiver
    "cast-receiver-not-a-source": ["String v = String.valueOf(((HttpServletRequest) r).getLocalPort());",
                                   JAVA_SINKS["CWE-89"].replace("{v}", "v")],
    # the replacement is a constant: the receiver is
    "replace-constant-replacement": ['String v = "SELECT 1 X".replace("X", "2");',
                                     JAVA_SINKS["CWE-89"].replace("{v}", "v")],
    # the element written is a constant, read back from a constant array
    "array-constant-element": ['String[] a = new String[1];', 'a[0] = "x";', "String v = a[0];",
                               JAVA_SINKS["CWE-89"].replace("{v}", "v")],
    # a constant switch selects the safe case (fall-through included)
    "switch-constant-selects-safe": ['String g = "ABC";', "char c = g.charAt(1);", 'String v = "";',
                                     "switch (c) {", "    case 'A': v = q; break;", "    case 'B':",
                                     '    case \'C\': v = "safe"; break;', "    default: v = q;", "}",
                                     JAVA_SINKS["CWE-89"].replace("{v}", "v")],
    "switch-expression-constant": ["int k = 1;", "String v = switch (k) {", '    case 1 -> "safe";',
                                   "    default -> q;", "};", JAVA_SINKS["CWE-89"].replace("{v}", "v")],
    # an assignment in a condition re-reads a constant each time
    "while-condition-constant": ['String line = "x";', 'String v = "";', "int i = 0;",
                                 'while ((line = "y") != null && i < 2) {', "    v = line;", "    i++;", "}",
                                 JAVA_SINKS["CWE-89"].replace("{v}", "v")],
}
# A guard inside each statement kind still clears the flow (it vanished with the dropped body).
_GUARD = ['if (!q.matches("[a-z]+")) {', "    return;", "}"]
JAVA_GUARDED = {
    "synchronized": ["synchronized (this) {"] + ["    " + g for g in _GUARD] + ["}"],
    "labeled": ["check:", "{"] + ["    " + g for g in _GUARD] + ["}"],
    "do-while": ["do {"] + ["    " + g for g in _GUARD] + ["} while (false);"],
    "switch-rule": ["switch (q.length()) {", "    default -> {"] + ["        " + g for g in _GUARD] + ["    }", "}"],
    "plain": _GUARD,
}


@pytest.mark.parametrize("case", list(JAVA_SAFE))
def test_java_safe_idiom_stays_clean(case):
    found = _scan(_java(JAVA_SAFE[case]))
    assert not found & {"CWE-89", "CWE-78"}, found


@pytest.mark.parametrize("case", list(JAVA_GUARDED))
def test_java_guard_inside_a_statement_still_counts(case):
    found = _scan(_java(JAVA_GUARDED[case] + [JAVA_SINKS["CWE-89"].replace("{v}", "q")]))
    assert "CWE-89" not in found


# Flows through receivers, helpers, fields, method references, jumps and declarations (once known
# gaps; a shape that is not handled yet goes in KNOWN_GAPS). Each has a safe twin in JAVA_GAP_SAFE:
# the same code with a constant in place of the request value, or the nearest correct idiom.
_SQL_V = JAVA_SINKS["CWE-89"].replace("{v}", "v")
_OWN_GETTER = ("    private Statement getSt() throws Exception {\n"
               "        return DriverManager.getConnection(\"x\").createStatement();\n    }")
_RUN = ("    private void run(Statement st) throws Exception {\n"
        "        st.executeQuery(\"SELECT '\" + val + \"'\");\n    }")
_QUERY = ("    private String query() {\n"
          "        return \"SELECT * FROM t WHERE n = '\" + val + \"'\";\n    }")
_BOX = ("    static class Box {\n        private String name;\n"
        "        void setName(String n) { this.name = n; }\n        String getName() { return name; }\n    }\n"
        "    static class Dao {\n        void find(Statement st, Box b) throws Exception {\n"
        "            st.executeQuery(\"SELECT * FROM t WHERE n = '\" + b.getName() + \"'\");\n        }\n    }")
_RUN_QUERY = ("    private void runQuery(String s) {\n        try {\n"
              "            DriverManager.getConnection(\"x\").createStatement().executeQuery(\"SELECT '\" + s + \"'\");\n"
              "        } catch (Exception e) {\n        }\n    }")
_REPO = ("    static class Repo {\n        String find(String s) {\n            try {\n"
         "                DriverManager.getConnection(\"x\").createStatement().executeQuery(\"SELECT '\" + s + \"'\");\n"
         "            } catch (Exception e) {\n            }\n            return \"\";\n        }\n    }")
_PICK = ("    private class Helper {\n        String pick(String s) {\n"
         "            List<String> l = new ArrayList<>();\n            l.add(\"safe\");\n"
         "            l.add(s);\n            return l.get(INDEX);\n        }\n    }")
_WRAP = ("    private static String wrap(String s) {\n        String r = \"x\";\n"
         "        if ((7 * 42) - 86 > LIMIT) r = s;\n        return \"'\" + r + \"'\";\n    }")
_BASE = ("    static class Base {\n        Base(String p) throws Exception { new FileInputStream(p); }\n    }\n"
         "    static class Child extends Base {\n        Child(String p) throws Exception { super(ARG); }\n    }")
_THIS = ("    static class Child {\n        Child(String p) throws Exception { this(ARG, 0); }\n"
         "        Child(String p, int n) throws Exception { new FileInputStream(\"/srv/files/\" + p); }\n    }")
_LOCAL = ["class Local {", "    void run(Statement s, String x) throws Exception {",
          "        s.executeQuery(\"SELECT '\" + x + \"'\");", "    }", "}"]
_SWITCH_BREAK = ['String v = "";', "switch (q.length()) {", "    case 0:", "        if (q.isEmpty()) {",
                 "            v = VALUE;", "            break;", "        }", '        v = "x";', "        break;",
                 '    default: v = "y";', "}", _SQL_V]
JAVA_GAP_CASES = {
    # `var` typed from the documented (or the class's own) return type of its initializer call
    "var-from-call": (['var c2 = DriverManager.getConnection("jdbc:x");', "var st2 = c2.createStatement();",
                       "st2.executeQuery(\"SELECT * FROM t WHERE n = '\" + q + \"'\");"], "", "CWE-89"),
    "var-from-own-getter": (["var st2 = getSt();", "st2.executeQuery(\"SELECT * FROM t WHERE n = '\" + q + \"'\");"],
                            _OWN_GETTER, "CWE-89"),
    # a call on the result of the class's own method, typed by its declared return type
    "own-getter-receiver": (["getSt().executeQuery(\"SELECT * FROM t WHERE n = '\" + q + \"'\");"],
                            _OWN_GETTER, "CWE-89"),
    "this-own-getter-receiver": (["this.getSt().executeQuery(\"SELECT * FROM t WHERE n = '\" + q + \"'\");"],
                                 _OWN_GETTER, "CWE-89"),
    # field taint across a call: on `this` (written `this.f` and read bare, or the other way round),
    # returned by the class's own method, and through the fields of an object passed as an argument
    "field-across-call": (["this.val = q;", "run(st);"], _RUN, "CWE-89"),
    "bare-field-across-call": (["val = q;", "this.run(st);"], _RUN, "CWE-89"),
    "field-returned-across-call": (["this.val = q;", "String v = query();", "st.executeQuery(v);"], _QUERY, "CWE-89"),
    "argument-field-across-call": (["Box b = new Box();", "b.setName(q);", "new Dao().find(st, b);"], _BOX, "CWE-89"),
    "this-field-in-method": (["this.val = q;", "st.executeQuery(\"SELECT '\" + val + \"'\");"], "", "CWE-89"),
    "counted-loop-exit": (["for (int i = 0; i < 1; i++) {", "}",
                           "st.executeQuery(\"SELECT * FROM t WHERE n = '\" + q + \"'\");"], "", "CWE-89"),
    # a method reference is called with what the call it is passed to holds
    "method-reference": (["List.of(q).forEach(this::runQuery);"], _RUN_QUERY, "CWE-89"),
    "method-reference-variable": (["Repo repo = new Repo();", "Optional.ofNullable(q).map(repo::find);"],
                                  _REPO, "CWE-89"),
    # a same-file helper's result carries what its return does: here the request's element
    "helper-returns-tainted-element": (["String v = new Helper().pick(q);", _SQL_V],
                                       _PICK.replace("INDEX", "1"), "CWE-89"),
    "helper-live-branch": (["String v = wrap(q);", "st.executeQuery(\"SELECT * FROM t WHERE n = \" + v);"],
                           _WRAP.replace("LIMIT", "100"), "CWE-89"),
    # break / continue are edges: the path that leaves keeps its value, the code after is skipped
    "break-out-of-switch-arm": ([ln.replace("VALUE", "q") for ln in _SWITCH_BREAK], "", "CWE-89"),
    "break-out-of-labeled-block": (["String v = q;", "check: {", "    if (v.isEmpty()) break check;",
                                    '    v = "safe";', "}", _SQL_V], "", "CWE-89"),
    "continue-after-a-passed-check": (["for (String v : List.of(q)) {", '    if (v.matches("[a-z]+")) continue;',
                                       "    " + _SQL_V, "}"], "", "CWE-89"),
    # a local class's methods, and constructor calls of super / this
    "local-class": (_LOCAL + ["new Local().run(st, q);"], "", "CWE-89"),
    "super-constructor-call": (["new Child(q);"], _BASE.replace("ARG", '"/srv/files/" + p'), "CWE-22"),
    "this-constructor-call": (["new Child(q);"], _THIS.replace("ARG", "p"), "CWE-22"),
}
JAVA_GAP_SAFE = {
    "ternary-allowlist-guard": (['String col = ALLOWED.contains(q) ? q : "id";',
                                 'st.executeQuery("SELECT * FROM t ORDER BY " + col);'], ""),
    "ternary-allowlist-guard-inline": (['st.executeQuery("SELECT * FROM t ORDER BY " + (ALLOWED.contains(q) ? q : "id"));'],
                                       ""),
    "var-from-call": (['var c2 = DriverManager.getConnection("jdbc:x");', "var st2 = c2.createStatement();",
                       "st2.executeQuery(\"SELECT * FROM t WHERE n = 'x'\");"], ""),
    "own-getter-receiver": (["getSt().executeQuery(\"SELECT * FROM t WHERE n = 'x'\");"], _OWN_GETTER),
    "field-across-call": (['this.val = "x";', "run(st);"], _RUN),
    "field-overwritten-before-call": (["this.val = q;", 'val = "x";', "run(st);"], _RUN),
    "field-returned-across-call": (['this.val = "x";', "String v = query();", "st.executeQuery(v);"], _QUERY),
    "argument-field-across-call": (["Box b = new Box();", 'b.setName("x");', "new Dao().find(st, b);"], _BOX),
    "method-reference": (['List.of("x").forEach(this::runQuery);'], _RUN_QUERY),
    "method-reference-variable": (["Repo repo = new Repo();", 'Optional.ofNullable("x").map(repo::find);'], _REPO),
    # the helper returns a constant list element, or a constant on the only branch that runs
    "helper-returns-constant": (["String v = new Helper().pick(q);", _SQL_V], _PICK.replace("INDEX", "0")),
    "helper-dead-branch": (["String v = wrap(q);", "st.executeQuery(\"SELECT * FROM t WHERE n = \" + v);"],
                           _WRAP.replace("LIMIT", "300")),
    "break-out-of-switch-arm": ([ln.replace("VALUE", '"z"') for ln in _SWITCH_BREAK], ""),
    "break-out-of-labeled-block": (["String v = q;", "check: {", '    if (!v.matches("[a-z]+")) {',
                                    '        v = "safe";', "        break check;", "    }", "}", _SQL_V], ""),
    # without the continue edge, the code after it also ran on the path whose check failed
    "continue-past-a-failed-check": (["for (String v : List.of(q)) {", '    if (!v.matches("[a-z]+")) continue;',
                                      "    " + _SQL_V, "}"], ""),
    "local-class": (_LOCAL + ['new Local().run(st, "x");'], ""),
    "super-constructor-call": (["new Child(q);"], _BASE.replace("ARG", '"/srv/files/fixed"')),
    "this-constructor-call": (["new Child(q);"], _THIS.replace("ARG", '"fixed"')),
}


@pytest.mark.parametrize("case", [pytest.param(c, id=c, marks=_gap(c)) for c in JAVA_GAP_CASES])
def test_java_known_gap_flows(case):
    lines, members, cwe = JAVA_GAP_CASES[case]
    assert cwe in _scan(_java(lines, members))


@pytest.mark.parametrize("case", [pytest.param(c, id=c, marks=_gap(c)) for c in JAVA_GAP_SAFE])
def test_java_known_gap_safe(case):
    lines, members = JAVA_GAP_SAFE[case]
    assert not _scan(_java(lines, members)) & {"CWE-89", "CWE-78", "CWE-22"}


# Receivers typed through the class's own methods and fields, and through a library base class's
# documented methods (Spring's JdbcDaoSupport hands its subclasses their JdbcTemplate).
_DAO = """import java.sql.*;
import javax.sql.DataSource;
import org.springframework.jdbc.core.support.JdbcDaoSupport;
import javax.servlet.http.*;

public class Dao extends JdbcDaoSupport {
    private Connection conn;
    private DataSource ds;
    private Connection getConn() throws Exception { return DriverManager.getConnection("x"); }
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String q = request.getParameter("q");
        BODY
    }
}
"""
_Q = "\"SELECT * FROM t WHERE n = '\" + VALUE + \"'\""
_RECEIVERS = {
    "own-getter": "getConn().createStatement().executeQuery(" + _Q + ");",
    "this-field": "this.conn.createStatement().executeQuery(" + _Q + ");",
    "this-field-chain": "this.ds.getConnection().createStatement().executeQuery(" + _Q + ");",
    "inherited-library-getter": "getJdbcTemplate().queryForList(" + _Q + ");",
    "this-inherited-library-getter": "this.getJdbcTemplate().update(" + _Q + ");",
    "var-from-own-getter": "var c = getConn();\n        var s = c.createStatement();\n        s.executeQuery(" + _Q + ");",
    "var-from-inherited-getter": "var t = getJdbcTemplate();\n        t.execute(" + _Q + ");",
}


@pytest.mark.parametrize("case", list(_RECEIVERS))
def test_java_receiver_typed_through_the_class(case):
    def cwes(value):
        code = _DAO.replace("BODY", _RECEIVERS[case].replace("VALUE", value))
        return {v.cwe_id for v in FrameScanner(language="java").scan(code, "Dao.java").vulnerabilities}
    assert "CWE-89" in cwes("q")
    assert "CWE-89" not in cwes('"x"')


def test_constant_return_is_decided_on_the_expression():
    # A helper returns a constant only when its return expression is a literal, or a local that only
    # ever holds one: `"'" + s + "'"` starts and ends with a quote but carries s.
    from frame.sil.frontends.java_frontend import JavaFrontend
    from frame.sil.translator import SILTranslator
    prog = JavaFrontend().translate("""class A {
    String quoted(String s) { return "'" + s + "'"; }
    String fixed() { String r = "x"; return r; }
    String reassigned(String s) { String r = "x"; r = s; return r; }
    String called(String s) { String r = "x"; r = s.trim(); return r; }
    void none() { return; }
}""", "A.java")
    t = SILTranslator(prog)
    assert not t._proc_always_returns_constant("A.quoted")
    assert t._proc_always_returns_constant("A.fixed")
    assert not t._proc_always_returns_constant("A.reassigned")
    assert not t._proc_always_returns_constant("A.called")
    assert t._proc_always_returns_constant("A.none")
    # a call is never matched to a procedure that merely shares the method name
    assert not t._proc_always_returns_constant("other.fixed")
