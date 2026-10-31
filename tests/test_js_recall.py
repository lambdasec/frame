"""Recall regressions for JS/Java/C# found by probing real-world patterns.

Each positive case was a miss before; each negative pins a nearby safe shape so
the recall gain does not turn into noise.
"""

import random
import string

import pytest

from frame.sil.scanner import FrameScanner

_rng = random.Random(2)
SECRET = "".join(_rng.choice(string.ascii_letters + string.digits) for _ in range(32))
SECRET_CWES = {"CWE-798", "CWE-259"}


def cwes(code, language="javascript", library_mode=False, name="t"):
    r = FrameScanner(language=language, library_mode=library_mode).scan(code, name)
    assert not r.errors, r.errors
    return {v.cwe_id for v in r.vulnerabilities}


# ---- module-scope code is analyzed ---------------------------------------

def test_toplevel_argv_to_exec():
    assert "CWE-78" in cwes("const cp=require('child_process'); cp.execSync('git clone '+process.argv[2]);")


def test_toplevel_env_to_exec():
    assert "CWE-78" in cwes(
        "const {exec}=require('child_process'); const h=process.env.HOST; exec('ping '+h);")


def test_toplevel_constant_command_is_clean():
    assert "CWE-78" not in cwes("const cp=require('child_process'); cp.execSync('git status');")


def test_export_declaration_is_analyzed():
    assert cwes(f'export const password = "{SECRET}";') & SECRET_CWES


# ---- prototype pollution ---------------------------------------------------

NESTED_SETTER = """
module.exports = function set(obj, path, val) {
  const ks = path.split('.'); let o = obj;
  for (let i = 0; i < ks.length - 1; i++) { o = o[ks[i]] = o[ks[i]] || {}; }
  o[ks[ks.length - 1]] = val; return obj;
};"""


def test_split_path_nested_setter_is_flagged():
    assert "CWE-1321" in cwes(NESTED_SETTER, library_mode=True)


def test_split_path_setter_with_guard_is_clean():
    guarded = NESTED_SETTER.replace(
        "const ks", "if (path.indexOf('__proto__') !== -1) return obj;\n  const ks"
    ).replace("path.indexOf('__proto__') !== -1", "path === '__proto__'")
    assert "CWE-1321" not in cwes(guarded, library_mode=True)


def test_recursive_merge_is_not_mislabelled_code_injection():
    merge = ("function merge(t,s){ for(const k in s){ if(typeof s[k]==='object'){ "
             "merge(t[k],s[k]); } else t[k]=s[k]; } return t; }\nmodule.exports=merge;")
    found = cwes(merge, library_mode=True)
    assert "CWE-1321" in found
    assert "CWE-94" not in found, "prototype-pollution sinks must not be reported as eval"


def test_guarded_recursive_merge_is_clean():
    merge = ("function merge(t,s){ for(const k in s){ if(k==='__proto__'||k==='constructor') continue; "
             "if(typeof s[k]==='object'){ merge(t[k],s[k]); } else t[k]=s[k]; } return t; }\n"
             "module.exports=merge;")
    assert not cwes(merge, library_mode=True)


# ---- command injection through argument arrays ----------------------------

def test_spawn_shell_dash_c_tainted_second_element():
    code = ("const {spawn}=require('child_process');\nconst app = require('express')();\n"
            "app.get('/x',(req,res)=>{ spawn('sh',['-c',req.query.cmd]); res.end(); });")
    assert "CWE-78" in cwes(code)


def test_spawn_constant_args_are_clean():
    code = ("const {spawn}=require('child_process');\nconst app = require('express')();\n"
            "app.get('/x',(req,res)=>{ spawn('ls',['-l','/tmp']); res.end(); });")
    assert "CWE-78" not in cwes(code)


# ---- property-name false positive ------------------------------------------

@pytest.mark.parametrize("code", ["exports.md5 = md5", "exports.sha1 = sha1;"])
def test_exporting_a_hash_helper_is_not_a_weak_hash_call(code):
    assert "CWE-328" not in cwes(code)


def test_calling_a_weak_hash_helper_is_still_flagged():
    assert "CWE-328" in cwes("function f(x){ return md5(x) }")


# ---- hardcoded secrets outside method bodies ---------------------------------

@pytest.mark.parametrize("code", [
    f'const cfg = {{ host: "localhost", password: "{SECRET}" }};',
    f'app.use(session({{ secret: "{SECRET}", resave: false }}));',
    f'module.exports = {{ db: {{ user: "admin", pass: "{SECRET}" }} }};',
    f'class A {{ apiKey = "{SECRET}"; }}',
])
def test_js_literal_property_secret(code):
    assert cwes(code) & SECRET_CWES


def test_js_label_properties_are_not_secrets():
    code = ('const f = { passwordField: "password", usernameField: "email", '
            'name: "bob", type: "token" };')
    assert not cwes(code)


@pytest.mark.parametrize("code", [
    f'class A {{ String password = "{SECRET}"; }}',
    f'class A {{ private static final String API_KEY = "{SECRET}"; }}',
])
def test_java_field_secret(code):
    assert cwes(code, language="java") & SECRET_CWES


@pytest.mark.parametrize("code", [
    f'class A {{ private string password = "{SECRET}"; }}',
    f'class A {{ const string ApiKey = "{SECRET}"; }}',
    f'class A {{ public string Token {{ get; set; }} = "{SECRET}"; }}',
])
def test_csharp_field_and_property_secret(code):
    assert cwes(code, language="csharp") & SECRET_CWES


def test_java_and_csharp_label_constants_are_clean():
    assert not cwes('class A { static final String PASSWORD_PARAM = "password"; static final String NAME = "bob"; }',
                    language="java")
    assert not cwes('class A { const string PasswordField = "password"; string Name = "bob"; }',
                    language="csharp")


# ---- chained calls, await, destructuring, Prisma ---------------------------

def test_call_chained_on_sink_call_in_declaration():
    code = ("const { execSync } = require('child_process');\n"
            "function handler(req, res) {\n"
            "  const out = execSync('git log ' + req.query.cmd).toString();\n"
            "  res.json({ out });\n}\nrequire('express').Router().get('/log', handler);")
    assert "CWE-78" in cwes(code)


def test_awaited_sink_call_in_declaration():
    code = ("const express = require('express'); const app = express();\n"
            "app.get('/u', async (req, res) => {\n"
            "  const rows = await prisma.$queryRawUnsafe('SELECT * FROM u WHERE id = ' + req.query.id);\n"
            "  res.json(rows);\n});")
    assert "CWE-89" in cwes(code)


def test_prisma_tagged_template_query_raw_is_clean():
    code = ("const express = require('express'); const app = express();\n"
            "app.get('/u', async (req, res) => {\n"
            "  const rows = await prisma.$queryRaw`SELECT * FROM u WHERE id = ${req.query.id}`;\n"
            "  res.json(rows);\n});")
    assert "CWE-89" not in cwes(code)


DESTRUCTURE = ("const express = require('express'); const { exec } = require('child_process');\n"
               "const app = express();\n"
               "app.get('/a', (req, res) => {\n"
               "  const BINDING = VALUE;\n"
               "  exec('ls ' + dir);\n"
               "});")


def destructure(binding, value):
    return DESTRUCTURE.replace("BINDING", binding).replace("VALUE", value)


def test_destructured_request_field_to_exec():
    assert "CWE-78" in cwes(destructure("{ dir }", "req.query"))


def test_destructured_renamed_request_field_to_exec():
    assert "CWE-78" in cwes(destructure("{ path: dir, x = 1 }", "req.body"))


def test_destructured_constant_object_is_clean():
    assert "CWE-78" not in cwes(destructure("{ dir }", "{ dir: '/tmp' }"))


def test_anonymous_procedure_names_are_deterministic():
    code = ("const app = require('express')();\n"
            "app.get('/a', (req, res) => { res.send('a'); });\n"
            "app.get('/b', (req, res) => { res.send('b'); });")
    from frame.sil.frontends.javascript_frontend import JavaScriptFrontend
    names = [sorted(JavaScriptFrontend().translate(code, "t.js").procedures) for _ in range(2)]
    assert names[0] == names[1]
    assert not any(any(ch.isdigit() for ch in n.split("_L")[0]) for n in names[0])


# ---- a sink constructed inside another call's argument (Java, C#) ----------

def test_java_nested_filereader_in_bufferedreader():
    code = """
import org.springframework.web.bind.annotation.*;
import java.io.*;

@RestController
public class F {
    @GetMapping("/file")
    public String file(@RequestParam String name) throws IOException {
        BufferedReader r = new BufferedReader(new FileReader("/data/" + name));
        return r.readLine();
    }
}
"""
    assert "CWE-22" in cwes(code, language="java", name="F.java")


def test_csharp_file_read_inside_content_result():
    code = """
using Microsoft.AspNetCore.Mvc;

public class HController : Controller {
    public IActionResult Q(string id) {
        return Content(System.IO.File.ReadAllText("/data/" + id));
    }
}
"""
    assert "CWE-22" in cwes(code, language="csharp", name="H.cs")


def test_session_user_id_is_server_state_not_a_source():
    from frame.sil.scanner import FrameScanner
    code = ("const express = require('express');\nconst app = express();\n"
            "app.get('/a', (req, res) => { db.collection('u').findOne({ _id: req.session.userId }); });\n")
    r = FrameScanner(language="javascript").scan(code, "t.js")
    assert not [v for v in r.vulnerabilities if v.cwe_id == "CWE-943"]


# ---- a request is what a framework hands a handler, never a parameter's name -----------------

def _cmd(code, lang="typescript", name="c.ts"):
    from frame.sil.scanner import FrameScanner
    return [v for v in FrameScanner(language=lang).scan(code, name).vulnerabilities if v.cwe_id == "CWE-78"]


SINK = "require('child_process').exec('ls ' + req.query.dir);"


def test_a_parameter_named_req_is_not_a_source():
    assert not _cmd(f"export class C {{ list(req: any) {{ {SINK} }} }}")


def test_an_express_handler_request_is_a_source():
    code = f"import express from 'express';\nconst app = express();\napp.get('/', (req, res) => {{ {SINK} }});"
    assert _cmd(code, "javascript", "a.js")


def test_a_parameter_typed_as_express_request_is_a_request():
    assert _cmd(f"import {{ Request }} from 'express';\nexport function h(req: Request) {{ {SINK} }}")
    # the Fetch API's global Request is another type (a Next.js route handler's is the nextjs pack's)
    assert not _cmd(f"export function h(req: Request) {{ {SINK} }}")


def test_a_handler_passing_its_request_to_another_files_method(tmp_path):
    from frame.sil.scanner import FrameScanner
    (tmp_path / "ctl.ts").write_text(f"export class C {{ list(req: any) {{ {SINK} }} }}\n")
    (tmp_path / "app.ts").write_text(
        "import express from 'express';\nimport { C } from './ctl';\nconst app = express();\n"
        "const c = new C();\napp.get('/', (req, res) => c.list(req));\n")
    res = FrameScanner(verify=False).scan_directory(str(tmp_path), None)
    assert ("ctl.ts", "CWE-78") in {(r.filename.rsplit("/", 1)[-1], v.cwe_id) for r in res for v in r.vulnerabilities}


def test_findings_carry_no_naming_convention_tag():
    from frame.sil.scanner import FrameScanner
    code = f"import express from 'express';\nconst app = express();\napp.get('/', (req, res) => {{ {SINK} }});"
    r = FrameScanner(language="javascript").scan(code, "a.js")
    assert r.vulnerabilities and all("source_evidence" not in v.to_dict() for v in r.vulnerabilities)


def _js(code):
    from frame.sil.scanner import FrameScanner
    r = FrameScanner(language="javascript").scan(code, "a.js")
    return {(v.line, v.cwe_id) for v in r.vulnerabilities}


def test_shell_escape_libraries_are_sanitizers():
    base = ("const express = require('express');\nconst {{ exec }} = require('child_process');\n"
            "const shellEscape = require('shell-escape');\nconst app = express();\n"
            "app.get('/', (req, res) => {{ exec('grep ' + {arg} + ' f'); res.send('ok'); }});\n")
    assert any(c == "CWE-78" for _, c in _js(base.format(arg="req.query.p")))
    assert not any(c == "CWE-78" for _, c in _js(base.format(arg="shellEscape([req.query.p])")))


# ---- findings from the independent seed files and the real apps ---------------------------

def _scan_js(code, name="a.js", lang="javascript"):
    from frame.sil.scanner import FrameScanner
    r = FrameScanner(language=lang).scan(code, name)
    return {(v.line, v.cwe_id) for v in r.vulnerabilities}


REDIR = ("const express = require('express');\nconst app = express();\n"
         "app.get('/r', (req, res) => {{\n  const next = req.query.u || '/';\n{body}\n}});")


@pytest.mark.parametrize("body", [
    "  if (!next.startsWith('/') || next.startsWith('//')) { return res.redirect('/'); }\n  res.redirect(next);",
    "  if (next.startsWith('/') && !next.startsWith('//')) { res.redirect(next); }",
])
def test_same_origin_path_guard_clears_an_open_redirect(body):
    assert not any(c == "CWE-601" for _, c in _scan_js(REDIR.format(body=body)))


@pytest.mark.parametrize("body", [
    "  res.redirect(next);",
    "  if (next.startsWith('/')) { res.redirect(next); }",          # '//host' still passes
    "  if (!next.startsWith('//')) { res.redirect(next); }",        # 'http://evil' still passes
    "  res.redirect('//' + req.query.id);",
])
def test_incomplete_or_missing_redirect_guard_is_still_reported(body):
    assert any(c == "CWE-601" for _, c in _scan_js(REDIR.format(body=body)))


def test_redirect_to_a_constant_local_path_with_a_dynamic_tail_is_not_open():
    assert not any(c == "CWE-601" for _, c in _scan_js(REDIR.format(body="  res.redirect('/p/' + req.query.id);")))


def test_a_regex_literal_named_like_a_password_is_not_a_secret():
    assert not _scan_js("const PASS_RE = /^.{1,20}$/;")
    assert _scan_js('const PASSWORD = "Sup3rS3cret!2024";')


def test_verifying_an_untrusted_jwt_is_not_a_finding():
    code = ("const jwt = require('jsonwebtoken');\nconst app = require('express')();\nfunction auth(req, res, next) {\n"
            "  req.user = jwt.verify(req.query.token, 'k');\n  next();\n}\napp.use(auth);\n")
    assert not any(c == "CWE-863" for _, c in _scan_js(code))


@pytest.mark.parametrize("arg,flagged", [("md5", True), ("sha1", True), ("sha256", False)])
def test_create_hash_flags_only_weak_algorithms(arg, flagged):
    code = f"const crypto = require('crypto');\nfunction h(p) {{ return crypto.createHash('{arg}').update(p).digest('hex'); }}\n"
    assert any(c == "CWE-328" for _, c in _scan_js(code)) == flagged


@pytest.mark.parametrize("alg,flagged", [("des-ecb", True), ("aes-256-gcm", False)])
def test_create_cipheriv_flags_only_weak_algorithms(alg, flagged):
    code = ("const crypto = require('crypto');\nfunction e(n, k, iv) {\n"
            f"  const c = crypto.createCipheriv('{alg}', k, iv);\n  return c.update(n);\n}}\n")
    assert any(c == "CWE-327" for _, c in _scan_js(code)) == flagged


def test_sink_through_a_member_chain_is_found_in_an_assignment_too():
    code = ("function f(name) { const rows = this.db.query(\"SELECT * FROM u WHERE n = '\" + name + \"'\"); return rows; }\n"
            "function h(req) { f(req.query.n); }\nrequire('express')().get('/u', h);\n")
    assert any(c == "CWE-89" for _, c in _scan_js(code))


def test_file_named_prototype_something_is_not_the_prototype_library():
    src = ("function deepMerge(t, s) { for (const k of Object.keys(s)) {"
           " if (typeof s[k] === 'object') { if (!t[k]) t[k] = {}; deepMerge(t[k], s[k]); } else { t[k] = s[k]; } }"
           " return t; }\nfunction apply(req) { return deepMerge({}, req.body.prefs); }\n")
    assert any(c == "CWE-1321" for _, c in _scan_js(src, "/x/seeds/prototype-pollution.js"))
    assert not any(c == "CWE-1321" for _, c in _scan_js(src, "/x/js/prototype.min.js"))


# ---- request data inside an object literal, property stores, allowlists -------------------------

NOSQL = ("const express = require('express');\nconst router = express.Router();\n"
         "router.post('/t', async (req, res) => {{\n const col = db.collection('p');\n{body}\n"
         " const docs = await col.find(filter).toArray();\n res.json(docs);\n}});")


@pytest.mark.parametrize("body", [
    " const filter = { origin: req.body.tags };",
    " const filter = {};\n filter.origin = req.body.tags;",
    " const q = {};\n q.a = 1;\n const filter = { $and: [{ a: 1 }, { b: req.query.b }] };",
])
def test_request_data_inside_a_query_object_reaches_a_nosql_sink(body):
    assert any(c == "CWE-943" for _, c in _scan_js(NOSQL.format(body=body)))


@pytest.mark.parametrize("body", [
    " const filter = { origin: 'x' };",
    " const filter = { n: parseInt(req.body.n, 10) };",
    " const filter = {};\n filter.n = 5;",
])
def test_constant_or_converted_query_objects_are_clean(body):
    assert not any(c == "CWE-943" for _, c in _scan_js(NOSQL.format(body=body)))


FILE_ROUTE = ("const fs = require('fs');\nconst path = require('path');\nconst express = require('express');\n"
              "const router = express.Router();\nconst DOC_FILES = {{ a: 'a.md' }};\nconst allowed = ['a.md'];\n"
              "router.get('/d/:file', (req, res) => {{\n const file = req.params.file;\n{guard}\n"
              " const full = path.join(__dirname, 'docs', file);\n fs.readFile(full, 'utf8', (e, d) => res.send(d));\n}});")


@pytest.mark.parametrize("guard", [
    " if (!Object.values(DOC_FILES).includes(file)) { return res.status(404).send('no'); }",
    " if (!DOC_FILES_LIST.includes(file)) { return res.end(); }",
])
def test_membership_in_a_constant_allowlist_clears_path_traversal(guard):
    assert not any(c == "CWE-22" for _, c in _scan_js(FILE_ROUTE.format(guard=guard)))


@pytest.mark.parametrize("guard", [
    "",
    " if (!allowed.includes(file)) { return res.end(); }",     # lower-case: not a recognisable constant
])
def test_no_or_unrecognised_allowlist_is_still_reported(guard):
    assert any(c == "CWE-22" for _, c in _scan_js(FILE_ROUTE.format(guard=guard)))


_LIB_CTOR = '''const shell = require("shelljs");

function PdfInfo(filename) {
  this.options = { additional: [{arg}] };
}

PdfInfo.prototype.run = function () {
  var self = this;
  return shell.exec("pdfinfo " + self.options.additional.join(" "));
};

module.exports = PdfInfo;
'''


def test_library_mode_constructor_field_reaches_a_method_sink():
    # In library mode a constructor's parameters are untrusted, and so are the fields it
    # fills from them, in every method of the class (read through `var self = this`).
    from frame.sil.scanner import FrameScanner
    scan = lambda code: {v.cwe_id for v in FrameScanner(language="javascript", verify=False,
                                                         library_mode=True).scan(code, "lib.js").vulnerabilities}
    assert "CWE-78" in scan(_LIB_CTOR.replace("{arg}", "'\"' + filename + '\"'"))
    assert "CWE-78" not in scan(_LIB_CTOR.replace("{arg}", "'\"report.pdf\"'"))


# ---- a call whose callee is itself a call: f(x)(y) -------------------------

_TEMPLATE_APP = ("const _ = require('lodash');\nconst express = require('express');\nconst app = express();\n"
                 "app.get('/t', (req, res) => { BODY });\n")


@pytest.mark.parametrize("body", [
    " return res.send(_.template(req.query.tpl)({})); ",                  # nested in an argument
    " res.send(_.template(req.query.tpl)({})); ",                         # statement
    " const out = _.template(req.query.tpl)({}); res.send(out); ",        # assignment
    " _.template(req.query.tpl)({}); ",                                   # bare
])
def test_the_inner_call_of_a_curried_call_is_a_sink(body):
    """`_.template(src)(data)`: the inner call compiles attacker-controlled template source.
    It used to be named as one opaque string, so its sink never matched."""
    assert "CWE-1336" in cwes(_TEMPLATE_APP.replace("BODY", body))


def test_a_constant_template_called_with_request_data_is_not_template_injection():
    code = _TEMPLATE_APP.replace("BODY", " res.send(_.template('<b><%- n %></b>')({ n: req.query.n })); ")
    assert "CWE-1336" not in cwes(code)


# ---- lodash's escaping template: <%- %> output is HTML-safe, nothing else is -----------

_LODASH_APP = ("const _ = require('lodash');\nconst express = require('express');\nconst app = express();\n"
               "const mysql = require('mysql');\nconst conn = mysql.createConnection({});\n"
               "app.get('/t', (req, res) => { BODY });\n")


@pytest.mark.parametrize("body", [
    " res.send(_.template('<b><%- n %></b>')({ n: req.query.n })); ",
    " const t = _.template('<b><%- n %></b>'); res.send(t({ n: req.query.n })); ",
])
def test_an_escaping_only_template_is_not_xss(body):
    assert "CWE-79" not in cwes(_LODASH_APP.replace("BODY", body))


@pytest.mark.parametrize("body", [
    " res.send(_.template('<b><%= n %></b>')({ n: req.query.n })); ",                 # <%= is raw
    " res.send(_.template('<% print(n) %>')({ n: req.query.n })); ",                  # code prints raw
    " res.send(_.template('<b>${n}</b>')({ n: req.query.n })); ",                     # lodash interpolates ${}
    " let t = _.template('<b><%- n %></b>'); res.send(t({ n: req.query.n })); ",      # a let can be rebound
    " res.send(_.template('<%- n %>', { escape: /{{(.+?)}}/g })({ n: req.query.n })); ",   # options
])
def test_a_template_that_can_print_raw_is_still_xss(body):
    assert "CWE-79" in cwes(_LODASH_APP.replace("BODY", body))


def test_templatesettings_in_the_file_disables_it():
    code = _LODASH_APP.replace("const app", "_.templateSettings.escape = /{{(.+?)}}/g;\nconst app").replace(
        "BODY", " res.send(_.template('<b><%- n %></b>')({ n: req.query.n })); ")
    assert "CWE-79" in cwes(code)


def test_html_escaping_is_not_sql_escaping():
    body = " conn.query('SELECT ' + _.template('<%- n %>')({ n: req.query.n })); "
    assert "CWE-89" in cwes(_LODASH_APP.replace("BODY", body))


def test_another_functions_t_is_not_the_escaping_template():
    body = (" const t = _.template('<b><%- n %></b>'); res.send(t({ n: req.query.n })); });\n"
            "app.get('/u', (req, res) => { const t = (x) => x; res.send(t(req.query.n)); ")
    code = _LODASH_APP.replace("BODY", body)
    r = FrameScanner(language="javascript").scan(code, "t")
    assert {v.line for v in r.vulnerabilities if v.cwe_id == "CWE-79"} == {7}
