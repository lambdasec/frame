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
    code = ("const {spawn}=require('child_process');\n"
            "app.get('/x',(req,res)=>{ spawn('sh',['-c',req.query.cmd]); res.end(); });")
    assert "CWE-78" in cwes(code)


def test_spawn_constant_args_are_clean():
    code = ("const {spawn}=require('child_process');\n"
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
            "  res.json({ out });\n}\nmodule.exports = handler;")
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
