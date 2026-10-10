"""A sink spec names an API, but whether a call is that API -- or is dangerous --
can depend on the receiver or on an argument. Each case below came from a
false positive on real code, and each is paired with the nearest true positive.

- JS `setTimeout`/`setInterval`/`eval`/`Function` are global functions. Suffix
  matching made any same-named method a code-injection sink: request.js's
  `self.req.setTimeout(timeout, fn)` is the HTTP request timeout.
- Java `setHostnameVerifier(v)` is CWE-295 only when `v` accepts every host
  (Tomcat JNDIRealm installs a configured verifier through a getter).
- Java `documentBuilder.parse(x)` is XXE only when the parser can resolve
  external entities (Tomcat WebdavServlet builds it in a same-class helper that
  installs an EntityResolver).
"""

import pytest

from frame.sil.scanner import FrameScanner


def findings(code, language, name):
    r = FrameScanner(language=language).scan(code, name)
    assert not r.errors, r.errors
    return {(v.cwe_id, v.line) for v in r.vulnerabilities}


def cwes(code, language, name):
    return {c for c, _ in findings(code, language, name)}


# ---- JS: global functions are not methods --------------------------------

def _express(stmt):
    return ("app.get('/x', function (req, res) {\n"
            "  var code = req.query.code;\n"
            f"  {stmt}\n"
            "  res.send('ok');\n"
            "});\n")


@pytest.mark.parametrize("stmt", [
    "req.socket.setTimeout(code, function () {});",
    "var self = this;\n  self.req.setTimeout(code, function () { self.abort(); });",
    "var timer = makeTimer();\n  timer.setInterval(code, 10);",
    "var scope = makeScope();\n  scope.eval(code);",
])
def test_js_method_sharing_a_global_name_is_not_code_injection(stmt):
    assert "CWE-94" not in cwes(_express(stmt), "javascript", "t.js")


@pytest.mark.parametrize("stmt", [
    "setTimeout(code, 10);",
    "setInterval(code, 10);",
    "window.setTimeout(code, 10);",
    "globalThis.eval(code);",
    "eval(code);",
])
def test_js_global_code_sinks_still_flagged(stmt):
    assert "CWE-94" in cwes(_express(stmt), "javascript", "t.js")


def test_js_suffix_matching_still_reaches_member_specs():
    # Non-global specs keep suffix matching (models.sequelize.query -> query).
    code = ("app.get('/u', function (req, res) {\n"
            "  var id = req.query.id;\n"
            "  models.sequelize.query('SELECT * FROM u WHERE id = ' + id);\n"
            "  res.send('ok');\n"
            "});\n")
    assert "CWE-89" in cwes(code, "javascript", "t.js")


# ---- Java: only a permissive hostname verifier is CWE-295 ----------------

def _verifier(body, fields=""):
    return ("import javax.net.ssl.*;\n"
            "class A {\n"
            f"{fields}"
            "  void f(HttpsURLConnection c, HostnameVerifier param) {\n"
            f"{body}"
            "  }\n"
            "}\n")


@pytest.mark.parametrize("body,fields", [
    # Tomcat JNDIRealm: the configured verifier, through a getter.
    ("    c.setHostnameVerifier(getHostnameVerifier());\n",
     "  HostnameVerifier v;\n  HostnameVerifier getHostnameVerifier() {\n    return v;\n  }\n"),
    ("    c.setHostnameVerifier(param);\n", ""),
    ("    c.setHostnameVerifier((h, s) -> h.equals(\"example.com\"));\n", ""),
    ("    c.setHostnameVerifier(new HostnameVerifier() {\n"
     "      public boolean verify(String h, SSLSession s) {\n"
     "        if (h == null) {\n"
     "          return false;\n"
     "        }\n"
     "        return true;\n"
     "      }\n"
     "    });\n", ""),
    # A local that is re-assigned has no single (permissive) value.
    ("    HostnameVerifier hv = (h, s) -> true;\n"
     "    hv = param;\n"
     "    c.setHostnameVerifier(hv);\n", ""),
])
def test_java_non_permissive_verifier_is_clean(body, fields):
    found = cwes(_verifier(body, fields), "java", "A.java")
    assert not found & {"CWE-295", "CWE-327"}, found


@pytest.mark.parametrize("body,fields", [
    ("    c.setHostnameVerifier((h, s) -> true);\n", ""),
    ("    c.setHostnameVerifier((h, s) -> {\n      return true;\n    });\n", ""),
    ("    c.setHostnameVerifier(new HostnameVerifier() {\n"
     "      public boolean verify(String h, SSLSession s) {\n"
     "        return true;\n"
     "      }\n"
     "    });\n", ""),
    ("    HostnameVerifier hv = (h, s) -> true;\n    c.setHostnameVerifier(hv);\n", ""),
    ("    c.setHostnameVerifier(ALL);\n",
     "  static final HostnameVerifier ALL = (h, s) -> true;\n"),
    ("    c.setHostnameVerifier(NoopHostnameVerifier.INSTANCE);\n", ""),
    ("    c.setHostnameVerifier(new AllowAllHostnameVerifier());\n", ""),
    ("    HttpsURLConnection.setDefaultHostnameVerifier((h, s) -> true);\n", ""),
])
def test_java_permissive_verifier_is_cwe_295(body, fields):
    assert "CWE-295" in cwes(_verifier(body, fields), "java", "A.java")


# ---- Java: a hardened XML parser is not an XXE sink ----------------------

_XML_HEADER = ("import javax.xml.parsers.*;\n"
               "import org.xml.sax.*;\n"
               "import org.w3c.dom.*;\n"
               "import javax.servlet.http.*;\n"
               "class W extends HttpServlet {\n")

_PARSE_FROM_HELPER = (
    "  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {\n"
    "    DocumentBuilder documentBuilder = getDocumentBuilder();\n"
    "    Document document = documentBuilder.parse(new InputSource(req.getInputStream()));\n"
    "  }\n")


def _helper(*config, ret="documentBuilder"):
    lines = "".join(f"    {c}\n" for c in config)
    return ("  protected DocumentBuilder getDocumentBuilder() throws Exception {\n"
            "    DocumentBuilder documentBuilder = null;\n"
            "    DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();\n"
            "    documentBuilderFactory.setNamespaceAware(true);\n"
            f"{lines}"
            f"    return {ret};\n"
            "  }\n")


def _inline(*config):
    lines = "".join(f"    {c}\n" for c in config)
    return ("  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {\n"
            "    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n"
            f"{lines}"
            "    DocumentBuilder documentBuilder = f.newDocumentBuilder();\n"
            "    Document d = documentBuilder.parse(req.getInputStream());\n"
            "  }\n")


def _xxe(body):
    return "CWE-611" in cwes(_XML_HEADER + body + "}\n", "java", "W.java")


def test_tomcat_webdav_helper_with_entity_resolver_is_clean():
    # WebdavServlet.getDocumentBuilder(): the resolver decides every entity.
    helper = _helper(
        "documentBuilderFactory.setExpandEntityReferences(false);",
        "documentBuilder = documentBuilderFactory.newDocumentBuilder();",
        "documentBuilder.setEntityResolver(new WebdavResolver(getServletContext()));")
    assert not _xxe(helper + _PARSE_FROM_HELPER)


def test_helper_with_hardened_factory_is_clean():
    helper = _helper(
        'documentBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);',
        "documentBuilder = documentBuilderFactory.newDocumentBuilder();")
    assert not _xxe(helper + _PARSE_FROM_HELPER)


@pytest.mark.parametrize("helper", [
    # No hardening at all.
    _helper("documentBuilder = documentBuilderFactory.newDocumentBuilder();"),
    # setExpandEntityReferences(false) alone does not stop XXE.
    _helper("documentBuilderFactory.setExpandEntityReferences(false);",
            "documentBuilder = documentBuilderFactory.newDocumentBuilder();"),
    # A null resolver restores the default (resolving) behaviour.
    _helper("documentBuilder = documentBuilderFactory.newDocumentBuilder();",
            "documentBuilder.setEntityResolver(null);"),
    # Hardened on one path only.
    _helper("documentBuilder = documentBuilderFactory.newDocumentBuilder();",
            'if (System.getenv("STRICT") != null) {',
            "  documentBuilder.setEntityResolver(new WebdavResolver(getServletContext()));",
            "}"),
    # Hardens one builder, returns another.
    _helper("documentBuilder = documentBuilderFactory.newDocumentBuilder();",
            "documentBuilder.setEntityResolver(new WebdavResolver(getServletContext()));",
            ret="documentBuilderFactory.newDocumentBuilder()"),
])
def test_helper_returning_an_unhardened_parser_is_xxe(helper):
    assert _xxe(helper + _PARSE_FROM_HELPER)


@pytest.mark.parametrize("config", [
    ['f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);'],
    ['f.setFeature("http://xml.org/sax/features/external-general-entities", false);'],
    ['f.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);'],
    ['f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");'],
])
def test_inline_hardened_factory_is_clean(config):
    assert not _xxe(_inline(*config))


@pytest.mark.parametrize("config", [
    [],
    ['f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);'],
    ['f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);'],
    ['f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all");'],
    ['if (req.getParameter("strict") != null) {',
     '  f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);',
     '}'],
])
def test_inline_unhardened_factory_is_xxe(config):
    assert _xxe(_inline(*config))


# ---- Java: catch handlers are branches, throw is not a return value ------
# Handlers used to be lowered in sequence after the try body, and `throw` as
# `return <exception>`: a handler that rethrows ended EVERY path through the
# method, and a helper "returned" its exception object.

def test_tomcat_webdav_helper_in_try_catch_is_clean():
    helper = (
        "  protected DocumentBuilder getDocumentBuilder() throws ServletException {\n"
        "    DocumentBuilder documentBuilder = null;\n"
        "    DocumentBuilderFactory documentBuilderFactory = null;\n"
        "    try {\n"
        "      documentBuilderFactory = DocumentBuilderFactory.newInstance();\n"
        "      documentBuilderFactory.setExpandEntityReferences(false);\n"
        "      documentBuilder = documentBuilderFactory.newDocumentBuilder();\n"
        "      documentBuilder.setEntityResolver(new WebdavResolver(this.getServletContext()));\n"
        "    } catch (ParserConfigurationException e) {\n"
        "      throw new ServletException(\"jaxp failed\");\n"
        "    }\n"
        "    return documentBuilder;\n"
        "  }\n")
    assert not _xxe(helper + _PARSE_FROM_HELPER)
    assert _xxe(helper.replace(
        "      documentBuilder.setEntityResolver(new WebdavResolver(this.getServletContext()));\n", "")
        + _PARSE_FROM_HELPER)


_SERVLET = ("import javax.servlet.http.*;\n"
            "import java.sql.*;\n"
            "class S extends HttpServlet {\n"
            "  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {\n"
            "    String id = request.getParameter(\"id\");\n"
            "{body}"
            "  }\n"
            "}\n")


def _sqli(body):
    return "CWE-89" in cwes(_SERVLET.replace("{body}", body), "java", "S.java")


def test_sink_after_try_whose_catch_rethrows_is_reached():
    assert _sqli("    int n = 0;\n"
                 "    try {\n"
                 "      n = Integer.parseInt(id);\n"
                 "    } catch (NumberFormatException e) {\n"
                 "      throw new ServletException(\"bad\");\n"
                 "    }\n"
                 "    Statement statement = connection.createStatement();\n"
                 "    statement.executeQuery(\"SELECT * FROM t WHERE id = '\" + id + \"'\");\n")


def test_sink_inside_catch_is_reached():
    assert _sqli("    try {\n"
                 "      helper();\n"
                 "    } catch (Exception e) {\n"
                 "      Statement statement = connection.createStatement();\n"
                 "      statement.executeQuery(\"SELECT * FROM t WHERE id = '\" + id + \"'\");\n"
                 "    }\n")


# ---- a static call on a named class is that class ------------------------

def test_static_getinstance_on_another_class_is_not_a_weak_hash():
    code = ("import org.ietf.jgss.*;\n"
            "class G {\n"
            "  void f() throws Exception {\n"
            "    GSSManager manager = GSSManager.getInstance();\n"
            "    KeyStore ks = KeyStore.getInstance(\"PKCS12\");\n"
            "  }\n"
            "}\n")
    assert "CWE-328" not in cwes(code, "java", "G.java")


@pytest.mark.parametrize("call", [
    'MessageDigest.getInstance("MD5")',
    'java.security.MessageDigest.getInstance("MD5")',
])
def test_weak_messagedigest_still_flagged(call):
    code = ("import java.security.*;\n"
            "class G {\n"
            "  void f() throws Exception {\n"
            f"    MessageDigest md = {call};\n"
            "  }\n"
            "}\n")
    assert "CWE-328" in cwes(code, "java", "G.java")


# ---- JS module bindings: calls are named after the module they come from --

def _route(head, stmt):
    return (head + "app.get('/x', function (req, res) {\n  var c = req.query.c;\n  "
            + stmt + "\n  res.send('ok');\n});\n")


@pytest.mark.parametrize("head,stmt", [
    ("const cp = require('child_process');\n", "cp.exec(c);"),
    ("const childProcess = require('node:child_process');\n", "childProcess.execSync(c);"),
    ("const {exec} = require('child_process');\n", "exec(c);"),
    ("const {spawn: run} = require('child_process');\n", "run(c);"),
    ("import * as cp from 'child_process';\n", "cp.spawn(c);"),
    ("import {execSync as es} from 'child_process';\n", "es(c);"),
])
def test_js_child_process_through_any_binding_is_command_injection(head, stmt):
    assert "CWE-78" in cwes(_route(head, stmt), "javascript", "t.js")


@pytest.mark.parametrize("stmt", [
    "/[a-z]+/.exec(c);",                 # RegExp.prototype.exec
    "var re = /x/;\n  re.exec(c);",
    "const pattern = new RegExp('^a');\n  pattern.exec(c);",
])
def test_js_regex_exec_is_not_command_injection(stmt):
    # A receiver the file declares is a known object, not child_process; an
    # undeclared one (`cp.exec` in a snippet) may be bound elsewhere and still
    # matches by suffix.
    assert "CWE-78" not in cwes(_route("", stmt), "javascript", "t.js")


def test_js_sqlite_exec_is_sql_injection():
    head = "const Database = require('better-sqlite3');\nconst db = new Database('x.db');\n"
    assert "CWE-89" in cwes(_route(head, "db.exec('DELETE FROM t WHERE id = ' + c);"),
                            "javascript", "t.js")


def test_js_division_is_not_a_path_join():
    # chalk ansi-styles: arithmetic on a (library-mode tainted) parameter.
    code = ("module.exports = function (code) {\n"
            "  const remainder = code % 36;\n"
            "  const green = Math.floor(remainder / 6) / 5;\n"
            "  return green;\n"
            "};\n")
    r = FrameScanner(language="javascript", library_mode=True).scan(code, "a.js")
    assert "CWE-22" not in {v.cwe_id for v in r.vulnerabilities}


def test_js_request_timeout_through_bound_self_is_not_code_injection():
    # request.js:813 -- `self` is `var self = this`, a local, not the global.
    code = ("function Request(options) {\n"
            "  var self = this;\n"
            "  var timeout = options.timeout;\n"
            "  self.req.setTimeout(timeout, function () {\n"
            "    self.abort();\n"
            "  });\n"
            "}\n"
            "module.exports = Request;\n")
    r = FrameScanner(language="javascript", library_mode=True).scan(code, "request.js")
    assert "CWE-94" not in {v.cwe_id for v in r.vulnerabilities}


def test_js_declared_names_cover_bindings():
    from frame.sil.frontends.javascript_frontend import JavaScriptFrontend
    fe = JavaScriptFrontend()
    fe.translate("const {a, b: c} = require('m');\n"
                 "function f(x, {y}, z = 1, ...r) { let [p, q] = x; try {} catch (e) {} }\n"
                 "const g = w => w;\nclass K {}\n"
                 "import d, * as ns from 'n';\nimport {h as i} from 'o';\n", "t.js")
    assert {"a", "c", "f", "x", "y", "z", "r", "p", "q", "e", "g", "w", "K",
            "d", "ns", "i"} <= set(fe._declared_names)
    assert "b" not in fe._declared_names and "h" not in fe._declared_names


# ---- JS NoSQL sinks are methods of a database handle ----------------------

def _nosql(head, stmt, library=False):
    if library:
        code = head + "module.exports = function (q) {\n  " + stmt + "\n};\n"
    else:
        code = head + ("app.get('/x', function (req, res) {\n  var q = req.query.q;\n  "
                       + stmt + "\n  res.send('ok');\n});\n")
    r = FrameScanner(language="javascript", library_mode=library).scan(code, "t.js")
    assert not r.errors, r.errors
    return "CWE-943" in {v.cwe_id for v in r.vulnerabilities}


@pytest.mark.parametrize("head,stmt", [
    # A model imported from another file: unknown kind, still a sink.
    ("const User = require('./models/user');\n", "User.find({name: q});"),
    ("const User = require('./models/user');\n", "User.findOne({name: q}, function (err, u) {});"),
    ("const mongoose = require('mongoose');\nconst User = mongoose.model('User', schema);\n",
     "User.find({name: q});"),
    ("", "db.collection('users').find({name: q});"),
    ("", "const users = db.collection('users');\n  users.deleteMany({name: q});"),
    ("", "req.app.locals.db.collection('u').updateOne({a: q}, {$set: {b: 1}});"),
    ("", "Model.where(q);"),
])
def test_js_nosql_on_database_handles_is_reported(head, stmt):
    assert _nosql(head, stmt)


@pytest.mark.parametrize("head,stmt", [
    # Hashes from the crypto core module (request.js, uuid).
    ("const crypto = require('crypto');\n", "crypto.createHash('md5').update(q).digest('hex');"),
    ("const crypto = require('crypto');\n", "var h = crypto.createHash('sha1');\n  h.update(q);"),
    ("import { createHash } from 'crypto';\n", "createHash('md5').update(q).digest();"),
    # Arrays, strings, maps, local objects.
    ("", "var xs = [1, 2];\n  xs.find(function (x) { return x === q; });"),
    ("", "items.find(x => x.id === q);"),
    ("", "var parts = q.split(',');\n  parts.find(q);"),
    ("", "var m = new Map();\n  m.remove(q);"),
    ("", "var tasks = {queue: new DLL()};\n  tasks.queue.remove(q);"),
    # In-memory utility library, and calls without a receiver (lodash core,
    # multer's `remove` parameter).
    ("const _ = require('lodash');\n", "_.find(list, {name: q});"),
    ("", "find(list, q);"),
])
def test_js_nosql_names_on_other_values_are_not_sinks(head, stmt):
    assert not _nosql(head, stmt)


def test_js_library_queue_remove_is_not_nosql():
    # async internal/queue.js: q._tasks is a DLL, testFn a library parameter.
    assert not _nosql("", "var q2 = { _tasks: new DLL() };\n  q2._tasks.remove(q);", library=True)
    assert not _nosql("", "remove(q, function () {});", library=True)


def test_db_method_rule():
    from frame.sil.procedure import DB_HANDLE, RECEIVER_UNKNOWN, ProcSpec, db_method_applies
    spec = ProcSpec(is_sink="nosql", db_method=True)
    assert db_method_applies(spec, "User.find", None)
    assert db_method_applies(spec, "find", RECEIVER_UNKNOWN)       # chained call
    assert db_method_applies(spec, "x.find", DB_HANDLE)
    assert not db_method_applies(spec, "find", None)               # no receiver
    assert not db_method_applies(spec, "xs.find", "Array")
    assert db_method_applies(ProcSpec(is_sink="sql"), "find", None)  # not a db method


def test_js_assigning_a_function_named_like_a_db_method_is_not_a_sink():
    # lodash.js: `lodash.find = find;` installs a method, it queries nothing.
    code = ("function find(collection, predicate) {\n"
            "  return collection.filter(predicate)[0];\n"
            "}\n"
            "module.exports = function (lodash) {\n"
            "  lodash.find = find;\n"
            "  return lodash;\n"
            "};\n")
    r = FrameScanner(language="javascript", library_mode=True).scan(code, "l.js")
    assert "CWE-943" not in {v.cwe_id for v in r.vulnerabilities}


def test_js_lexical_scope_resolves_shadowed_names():
    # The bundled async.js declares `q` in many functions; each use resolves
    # to its own scope's `var q = { _tasks: new DLL() }`.
    code = ("function a(x) {\n"
            "  var q = db.collection('jobs');\n"
            "  q.remove(x);\n"
            "}\n"
            "function b(x) {\n"
            "  var q = { _tasks: new DLL() };\n"
            "  q._tasks.remove(x);\n"
            "}\n"
            "module.exports = { a: a, b: b };\n")
    r = FrameScanner(language="javascript", library_mode=True).scan(code, "s.js")
    lines = {v.line for v in r.vulnerabilities if v.cwe_id == "CWE-943"}
    assert 3 in lines and 7 not in lines
