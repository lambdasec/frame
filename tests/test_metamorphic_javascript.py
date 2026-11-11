"""Metamorphic tests for JavaScript/TypeScript: a vulnerability rewritten without changing its
meaning is still found (the JS counterpart of tests/test_metamorphic.py).

An adversarial review found JS syntax the frontend lowered as a variable named by its source
text (a chained assignment, a sequence, a spread, a destructuring assignment, a receiver that is
a value rather than a path), statements it dropped (`do`, labels, bare blocks, `finally`) and
control flow it flattened (`catch` lowered as straight-line code after the `try` body, `switch`
cases run one after another). Each seed flow (request data reaching a sink in an Express
handler) is rewritten by every transform and the finding must survive; the same transform
applied to a constant must stay clean, and a transform that overwrites request data with a
constant must clear it.

A transform Frame does not handle yet is listed in KNOWN_GAPS with the reason, as a strict
xfail: fixing it makes the test pass and CI asks for the entry to be removed.
"""

import re

import pytest

from frame.sil.scanner import FrameScanner

JS_HEAD = """const express = require('express');
const cp = require('child_process');
const fs = require('fs');
const mysql = require('mysql');
const app = express();
const db = mysql.createConnection({});
function ident(s) { return s; }
function getDb() { return mysql.createConnection({}); }
class Box {
  constructor(val) { this.val = val; }
  get() { return this.val; }
}
class U {
  static run(s) { cp.exec('ping ' + s); }
}
"""
JS_HANDLER = """
app.get('/x', async (req, res) => {{
  const q = req.query.q;
{body}
  res.send('ok');
}});
"""
JS_SINKS = {
    "CWE-78": "cp.exec('ping ' + {v});",
    "CWE-89": "db.query(\"SELECT * FROM t WHERE n = '\" + {v} + \"'\");",
    "CWE-22": "fs.readFileSync('/srv/files/' + {v});",
}
# Each transform: statements that leave q's value in v (declared at the handler's top level).
JS_TRANSFORMS = {
    "plain": ["const v = q;"],
    "reassigned": ["let v;", "v = q;"],
    "chained-assignment": ["let v, w;", "v = w = q;"],
    "chained-inner-target": ["let v, w;", "w = v = q;"],
    "chained-in-declaration": ["let w;", "const v = w = q;"],
    "assignment-as-argument": ["let v;", "ident(v = q);"],
    "destructuring-declaration": ["const { v } = { v: q };"],
    "destructuring-assignment": ["let v;", "({ v } = { v: q });"],
    "array-destructuring-assignment": ["let v, n;", "[v, n] = [q, 1];"],
    "array-destructuring-declaration": ["const [v] = [q];"],
    "sequence": ["const v = (0, q);"],
    "sequence-effects": ["const v = (ident(1), q);"],
    "template": ["const v = `${q}`;"],
    "concat": ["const v = '' + q;"],
    "method": ["const v = q.trim();"],
    "paren-receiver": ["const v = ('' + q).trim();"],
    "template-receiver": ["const v = `${q}`.trim();"],
    "array-receiver": ["const v = [q].join('');"],
    "split-index": ["const v = q.split(',')[0];"],
    "split-index-method": ["const v = q.split(',')[0].trim();"],
    "await-receiver": ["const v = (await Promise.resolve(q)).trim();"],
    "ternary": ["const v = q ? q : q;"],
    "or-default": ["const v = q || 'x';"],
    "nullish": ["const v = q ?? 'x';"],
    "helper": ["const v = ident(q);"],
    "arrow-iife": ["const v = (s => s)(q);"],
    "object-field": ["const o = { k: q };", "const v = o.k;"],
    "object-attribute": ["const b = new Box(q);", "const v = b.val;"],
    "object-getter": ["const b = new Box(q);", "const v = b.get();"],
    "for-of": ["let v;", "for (v of [q]) {}"],
    "for-of-pattern": ["let v;", "for ([v] of [[q]]) {}"],
    "for-of-object-pattern": ["let v;", "for ({ v } of [{ v: q }]) {}"],
    "try-body": ["let v = '';", "try {", "  v = q;", "} catch (e) {", "  v = '';", "}"],
    "try-finally": ["let v;", "try {", "  v = 'x';", "} finally {", "  v = q;", "}"],
    "do-while": ["let v;", "do {", "  v = q;", "} while (false);"],
    "labeled-block": ["let v;", "L: {", "  v = q;", "}"],
    "bare-block": ["let v;", "{", "  v = q;", "}"],
    "switch-case": ["let v = '';", "switch (q.length) {", "  case 1: v = 'x'; break;", "  default: v = q;", "}"],
    "switch-case-block": ["let v = '';", "switch (q.length) {", "  case 1: { v = q; break; }", "}"],
    "switch-fallthrough": ["let v = '';", "switch (q.length) {", "  case 1: v = 'x';", "  case 2: v = q;", "}"],
    "while": ["let v = '';", "while (!v) {", "  v = q;", "}"],
    "string-call": ["const v = String(q);"],
    "json-roundtrip": ["const v = JSON.parse(JSON.stringify(q));"],
    "case-and-slice": ["const v = q.toLowerCase().slice(0, 100);"],
    "array-index": ["const v = [q][0];"],
}
# Sink arguments written inline (the value never passes through a variable).
JS_INLINE = {
    "spread-literal": ("cp.exec(...['ping ' + q]);", "CWE-78"),
    "spread-name": ("const args = ['ping ' + q];\n  cp.exec(...args);", "CWE-78"),
    "paren-receiver-inline": ("cp.exec(('ping ' + q).trim());", "CWE-78"),
    "sequence-callee": ("(0, cp.exec)('ping ' + q);", "CWE-78"),
    "returned-connection": ("getDb().query(\"SELECT * FROM t WHERE n = '\" + q + \"'\");", "CWE-89"),
    "nested-split-receiver": ("cp.exec('ping ' + q.split(',')[0].trim());", "CWE-78"),
    "new-function-callee": ("(new Function('return ' + q))();", "CWE-94"),
    "spread-returned-array": ("const build = () => [\"SELECT * FROM t WHERE n = '\" + q + \"'\"];\n"
                              "  db.query(...build());", "CWE-89"),
}

KNOWN_GAPS: dict = {}


def _scan(code, name="app.js", language="javascript"):
    r = FrameScanner(language=language).scan(code, name)
    assert not r.errors, r.errors
    return {v.cwe_id for v in r.vulnerabilities}


def _js(lines):
    return JS_HEAD + JS_HANDLER.format(body="\n".join("  " + ln for ln in lines))


def _gap(name):
    reason = KNOWN_GAPS.get(name)
    return [pytest.mark.xfail(reason=reason, strict=True)] if reason else []


@pytest.mark.parametrize("transform,cwe", [
    pytest.param(t, c, id=f"{t}-{c}", marks=_gap(t)) for t in JS_TRANSFORMS for c in JS_SINKS])
def test_js_flow_survives_the_rewrite(transform, cwe):
    sink = JS_SINKS[cwe].format(v="v")
    assert cwe in _scan(_js(JS_TRANSFORMS[transform] + [sink]))


@pytest.mark.parametrize("transform", [pytest.param(t, id=t, marks=_gap(t)) for t in JS_INLINE])
def test_js_inline_flow_survives_the_rewrite(transform):
    code, cwe = JS_INLINE[transform]
    assert cwe in _scan(_js([code]))


def _constant(lines):
    """The transform applied to a constant instead of the request value."""
    return [re.sub(r"\bq\b", "'localhost'", ln) for ln in lines]


@pytest.mark.parametrize("transform", list(JS_TRANSFORMS))
def test_js_rewrite_of_a_constant_stays_clean(transform):
    sink = JS_SINKS["CWE-78"].format(v="v")
    assert "CWE-78" not in _scan(_js(_constant(JS_TRANSFORMS[transform]) + [sink]))


@pytest.mark.parametrize("transform", list(JS_INLINE))
def test_js_inline_rewrite_of_a_constant_stays_clean(transform):
    code, cwe = JS_INLINE[transform]
    assert cwe not in _scan(_js(_constant([code])))


# The request value in v is overwritten with a constant by each of these: the finding must go.
JS_OVERWRITES = {
    "chained-assignment": ["let w, v = q;", "v = w = 'localhost';"],
    "chained-outer": ["let w, v = q;", "w = v = 'localhost';"],
    "destructuring-assignment": ["let v = q;", "({ v } = { v: 'localhost' });"],
    "array-destructuring-assignment": ["let v = q;", "[v] = ['localhost'];"],
    "try-body": ["let v = q;", "try {", "  v = 'localhost';", "} finally {", "}"],
    "finally": ["let v = q;", "try {", "  JSON.parse('{}');", "} finally {", "  v = 'localhost';", "}"],
    "do-while": ["let v = q;", "do {", "  v = 'localhost';", "} while (false);"],
    "labeled-block": ["let v = q;", "L: {", "  v = 'localhost';", "}"],
    "bare-block": ["let v = q;", "{", "  v = 'localhost';", "}"],
    "switch-every-case": ["let v = q;", "switch (q.length) {", "  case 1: v = 'a'; break;",
                          "  default: v = 'b';", "}"],
}


@pytest.mark.parametrize("case", list(JS_OVERWRITES))
def test_js_overwrite_with_a_constant_clears_the_flow(case):
    sink = JS_SINKS["CWE-78"].format(v="v")
    assert "CWE-78" not in _scan(_js(JS_OVERWRITES[case] + [sink]))


# try / catch / finally and switch as control flow: the handler used to run as straight-line
# code after the body (a `return` in it ended every path), `finally` was dropped, and switch
# cases ran one after another.
JS_CONTROL = {
    "sink-in-catch": (["try {", "  JSON.parse(q);", "} catch (e) {", "  cp.exec('ping ' + q);", "}"], "CWE-78"),
    "sink-in-finally": (["try {", "  JSON.parse('{}');", "} finally {", "  cp.exec('ping ' + q);", "}"], "CWE-78"),
    "sink-after-catch-returns": (["try {", "  JSON.parse(q);", "} catch (e) {", "  return res.status(400).send('bad');",
                                  "}", "cp.exec('ping ' + q);"], "CWE-78"),
    "source-bound-in-catch": (["let v = 'x';", "try {", "  JSON.parse(q);", "} catch (e) {", "  v = q;", "}",
                               "cp.exec('ping ' + v);"], "CWE-78"),
    "sink-after-finally-of-returning-try": (["try {", "  JSON.parse(q);", "} catch (e) {", "  return res.send('bad');",
                                             "} finally {", "  res.set('X', '1');", "}",
                                             "cp.exec('ping ' + q);"], "CWE-78"),
    "for-of-entries-pattern": (["for (const [k, h] of Object.entries(req.query)) {", "  cp.exec('ping ' + h);", "}"],
                               "CWE-78"),
    "for-of-entries-of-constants": (["for (const [k, h] of Object.entries({ a: 'localhost' })) {",
                                     "  cp.exec('ping ' + h);", "}"], None),
    "for-of-object-pattern-body": (["for (const { host } of req.body.items) {", "  cp.exec('ping ' + host);", "}"],
                                   "CWE-78"),
    "throw-carries-state-to-catch": (["let v = '';", "try {", "  v = q;", "  throw new Error('x');", "} catch (e) {",
                                     "  cp.exec('ping ' + v);", "}"], "CWE-78"),
    "throw-of-constant-state-to-catch": (["let v = '';", "try {", "  v = 'localhost';", "  throw new Error('x');",
                                         "} catch (e) {", "  cp.exec('ping ' + v);", "}"], None),
    "throw-guard-catch-returns": (["try {", "  if (!/^[a-z]+$/.test(q)) throw new Error('bad');", "} catch (e) {",
                                   "  return res.send('bad');", "}", "cp.exec('ping ' + q);"], None),
    "switch-return-in-earlier-case": (["switch (q.length) {", "  case 0: return res.send('none');",
                                       "  default: cp.exec('ping ' + q);", "}"], "CWE-78"),
    "switch-return-before-later-code": (["switch (q.length) {", "  case 0: return res.send('none');",
                                         "  case 1: break;", "}", "cp.exec('ping ' + q);"], "CWE-78"),
    "do-while-guarded-exit": (["do {", "  cp.exec('ping ' + q);", "} while (ident(q));"], "CWE-78"),
}


@pytest.mark.parametrize("case", list(JS_CONTROL))
def test_js_try_and_switch_are_control_flow(case):
    lines, cwe = JS_CONTROL[case]
    found = _scan(_js(lines))
    assert (cwe in found) if cwe else ("CWE-78" not in found)


# Ways of obtaining the database connection: the sink must be recognised whichever is used.
JS_CONNECTIONS = {
    "module-level": "const conn = db;",
    "local": "const conn = mysql.createConnection({});",
    "returned-by-helper": "const conn = getDb();",
    "awaited-helper": "const conn = await getDb();",
    "chained": "let c1;\n  const conn = c1 = mysql.createConnection({});",
    "assigned-in-try": "let conn;\n  try {\n    conn = mysql.createConnection({});\n  } catch (e) {\n    return;\n  }",
}


@pytest.mark.parametrize("how", list(JS_CONNECTIONS))
def test_js_connection_obtained_any_way_is_a_sink(how):
    body = [JS_CONNECTIONS[how], "conn.query(\"SELECT * FROM t WHERE n = '\" + q + \"'\");"]
    assert "CWE-89" in _scan(_js(body))


@pytest.mark.parametrize("how", list(JS_CONNECTIONS))
def test_js_connection_obtained_any_way_with_a_parameterized_query_is_clean(how):
    body = [JS_CONNECTIONS[how], "conn.query('SELECT * FROM t WHERE n = ?', [q]);"]
    assert "CWE-89" not in _scan(_js(body))


# A spread passes the elements of what it spreads, one per position: the parameterized query
# `[sql, params]` keeps the request data out of the SQL text.
@pytest.mark.parametrize("spread", [
    "db.query(...['SELECT * FROM t WHERE n = ?', [q]]);",
    "const args = ['SELECT * FROM t WHERE n = ?', [q]];\n  db.query(...args);",
    "const build = () => ['SELECT * FROM t WHERE n = ?', [q]];\n  db.query(...build());",
])
def test_js_spread_of_a_parameterized_query_is_clean(spread):
    assert "CWE-89" not in _scan(_js([spread]))


def test_js_tagged_template_values_are_the_tags():
    # sql`...${q}` binds q as a parameter (postgres.js, slonik, sql-template-strings): the tag's
    # values are not passed as data to an unmodelled tag, and the literal text is not a variable
    assert "CWE-89" not in _scan(_js(["const sql = (s, ...v) => ({ text: s.join('?'), values: v });",
                                      "db.query(sql`SELECT * FROM t WHERE n = ${q}`);"]))


# A source read written inline in an argument of a call with no spec reaches the call's result.
CLI_HEAD = "const cp = require('child_process');\nfunction wrap(s) { return 'x' + s; }\n"
CLI_FLOWS = {
    "unknown-call": "const y = unknownLib(process.argv[2]);\ncp.exec(y);",
    "returned-unknown-call": "function g() { return unknownLib(process.argv[2]); }\ncp.exec(g());",
    "returned-helper": "function g() { return wrap(process.argv[2]); }\nconst z = g();\ncp.exec(z);",
}


@pytest.mark.parametrize("flow", list(CLI_FLOWS))
def test_js_inline_source_in_a_call_argument(flow):
    assert "CWE-78" in _scan(CLI_HEAD + CLI_FLOWS[flow], "cli.js")
    assert "CWE-78" not in _scan(CLI_HEAD + CLI_FLOWS[flow].replace("process.argv[2]", "'x'"), "cli.js")


# Instance field initializers run in the constructor (an explicit one, or the implicit one).
TS_REPO = """import express from 'express';
import mysql from 'mysql';
const app = express();
class Repo {
  private db = mysql.createConnection({});
{ctor}  find(id: string) {
    return this.db.query({query});
  }
}
const repo = new Repo();
app.get('/x', (req, res) => {
  repo.find(req.query.id as string);
  res.send('ok');
});
"""


@pytest.mark.parametrize("ctor", ["", "  constructor() {}\n"], ids=["implicit-constructor", "explicit-constructor"])
def test_ts_class_field_initializer_gives_the_field_its_value(ctor):
    unsafe = TS_REPO.replace("{ctor}", ctor).replace("{query}", '"SELECT * FROM t WHERE id = " + id')
    safe = TS_REPO.replace("{ctor}", ctor).replace("{query}", '"SELECT * FROM t WHERE id = ?", [id]')
    assert "CWE-89" in _scan(unsafe, "app.ts", "typescript")
    assert "CWE-89" not in _scan(safe, "app.ts", "typescript")


# TypeScript forms around a value do not change it.
TS_HEAD = """import express from 'express';
import { exec } from 'child_process';
const app = express();
"""
TS_FORMS = {
    "angle-assertion": "<string>q",
    "as": "q as string",
    "non-null": "q!",
    "satisfies": "q satisfies string",
    "as-receiver": "(q as string).trim()",
}


def _ts(form, source):
    return TS_HEAD + (f"app.get('/x', (req, res) => {{\n  const q = {source};\n"
                      f"  const v = {TS_FORMS[form]};\n  exec('ping ' + v);\n  res.send('ok');\n}});\n")


@pytest.mark.parametrize("form", list(TS_FORMS))
def test_ts_type_forms_are_transparent(form):
    assert "CWE-78" in _scan(_ts(form, "req.query.q as string"), "app.ts", "typescript")
    assert "CWE-78" not in _scan(_ts(form, "'localhost'"), "app.ts", "typescript")


# Callbacks a builtin method calls with what its receiver holds (javascript-types.toml
# [callback_values]): an element, a promise's resolved value. Each flow is paired with the same
# code over a constant.
JS_CALLBACKS = {
    "for-of-callback": ["[q].forEach(s => cp.exec('ping ' + s));"],
    "promise-then": ["Promise.resolve(q).then(s => cp.exec('ping ' + s));"],
    "array-map-callback": ["[q].map(s => cp.exec('ping ' + s));"],
    "filter-then-some": ["const xs = [q];", "xs.filter(s => s).some(s => cp.exec('ping ' + s));"],
    "find-callback": ["q.split(',').find(s => cp.exec('ping ' + s));"],
    "flat-map-callback": ["q.split(',').flatMap(s => [cp.exec('ping ' + s)]);"],
    "every-function-expression": ["q.split(',').every(function (s) { cp.exec('ping ' + s); return true; });"],
    "reduce-element": ["q.split(',').reduce((acc, s) => { cp.exec('ping ' + s); return acc; }, 0);"],
    "named-callback": ["function run(s) { cp.exec('ping ' + s); }", "[q].forEach(run);"],
    "optional-chain": ["q.split(',')?.forEach(s => cp.exec('ping ' + s));"],
    "then-after-await-chain": ["ident(1);", "Promise.resolve(q).then(s => s.trim()).then(s => cp.exec('ping ' + s));"],
}


@pytest.mark.parametrize("case", list(JS_CALLBACKS))
def test_js_callback_parameter_receives_the_receivers_values(case):
    assert "CWE-78" in _scan(_js(JS_CALLBACKS[case]))
    assert "CWE-78" not in _scan(_js(_constant(JS_CALLBACKS[case])))


def test_js_reduce_accumulator_is_not_the_element():
    # reduce hands the element to its second parameter; the first is the accumulator
    assert "CWE-78" not in _scan(_js(["q.split(',').reduce((acc, s) => { cp.exec('ping ' + acc); return acc; },"
                                      " 'localhost');"]))


def test_js_then_hands_its_callback_the_resolved_connection():
    # the resolved value has the origin of what the receiver is (as `await` gives it)
    unsafe = "mysql.createConnection({}).then(conn => conn.query(\"SELECT * FROM t WHERE n = '\" + q + \"'\"));"
    safe = "mysql.createConnection({}).then(conn => conn.query('SELECT * FROM t WHERE n = ?', [q]));"
    assert "CWE-89" in _scan(_js([unsafe]))
    assert "CWE-89" not in _scan(_js([safe]))


def test_js_callback_of_an_unknown_function_is_not_called():
    # only a function of the file is called with the receiver's values: a library global handed
    # as the callback (`xs.forEach(eval)`) is not made a sink by the table
    code = JS_HEAD + "app.get('/x', (req, res) => {\n  req.query.q.split(',').forEach(unknownLib);\n  res.send('ok');\n});\n"
    assert not _scan(code)


# A function value bound to a name the file never rebinds: calling it is calling the function.
JS_ALIASES = {
    "in-handler": (["const run = cp.exec;", "run('ping ' + q);"], "CWE-78"),
    "of-destructured-import": (["const run = execAlias;", "run('ping ' + q);"], "CWE-78"),
}


@pytest.mark.parametrize("case", list(JS_ALIASES))
def test_js_function_alias_is_the_function(case):
    lines, cwe = JS_ALIASES[case]
    head = "const { exec: execAlias } = require('child_process');\n"
    assert cwe in _scan(head + _js(lines))
    assert cwe not in _scan(head + _js(_constant(lines)))


def test_js_function_alias_at_module_level():
    code = ("const express = require('express');\nconst cp = require('child_process');\nconst app = express();\n"
            "const run = cp.exec;\napp.get('/x', (req, res) => { run('ping ' + req.query.q); res.send('ok'); });\n")
    assert "CWE-78" in _scan(code)
    assert "CWE-78" not in _scan(code.replace("req.query.q", "'localhost'"))


def test_js_rebound_function_alias_is_not_followed():
    # a name the file binds again could hold anything at the call
    code = ("const express = require('express');\nconst cp = require('child_process');\nconst app = express();\n"
            "let run = cp.exec;\nrun = console.log;\n"
            "app.get('/x', (req, res) => { run('ping ' + req.query.q); res.send('ok'); });\n")
    assert "CWE-78" not in _scan(code)


# Methods of a same-file object literal and static methods of a same-file class, as callees.
JS_MEMBERS = {
    "object-literal-method": ["const h = { run(s) { cp.exec('ping ' + s); } };", "h.run(q);"],
    "object-literal-arrow": ["const h = { run: s => cp.exec('ping ' + s) };", "h.run(q);"],
    "nested-object-method": ["const h = { inner: { run(s) { cp.exec('ping ' + s); } } };", "h.inner.run(q);"],
    "static-method": ["U.run(q);"],
}


@pytest.mark.parametrize("case", list(JS_MEMBERS))
def test_js_same_file_member_is_a_callee(case):
    assert "CWE-78" in _scan(_js(JS_MEMBERS[case]))
    assert "CWE-78" not in _scan(_js(_constant(JS_MEMBERS[case])))


def test_js_static_arrow_field_is_a_static_method():
    code = ("const express = require('express');\nconst cp = require('child_process');\nconst app = express();\n"
            "class S { static run = (h) => { cp.exec('ping ' + h); } }\n"
            "app.get('/x', (req, res) => { S.run(req.query.q); res.send('ok'); });\n")
    assert "CWE-78" in _scan(code)
    assert "CWE-78" not in _scan(code.replace("req.query.q", "'localhost'"))


def test_ts_arrow_function_fields_are_methods():
    code = ("import express from 'express';\nimport { exec } from 'child_process';\nconst app = express();\n"
            "class Ctl {\n  private run = async (h: string) => { exec('ping ' + h); };\n"
            "  handle = (q: string) => { this.run(q); };\n}\nconst c = new Ctl();\n"
            "app.get('/x', (req, res) => { c.handle(req.query.q as string); res.send('ok'); });\n")
    assert "CWE-78" in _scan(code, "app.ts", "typescript")
    assert "CWE-78" not in _scan(code.replace("this.run(q)", "this.run('localhost')"), "app.ts", "typescript")


# A method of an object literal registered as a handler, in the same file and through an export.
CTL_HANDLER = ("const express = require('express');\nconst cp = require('child_process');\nconst app = express();\n"
               "const ctl = {ctl};\napp.get('/x', ctl.ping);\n")


@pytest.mark.parametrize("ctl", ["{ ping(req, res) { cp.exec('ping ' + req.query.q); res.send('ok'); } }",
                                 "{ ping: (req, res) => { cp.exec('ping ' + req.query.q); res.send('ok'); } }"],
                         ids=["method", "arrow"])
def test_js_object_literal_method_registered_as_handler(ctl):
    assert "CWE-78" in _scan(CTL_HANDLER.replace("{ctl}", ctl))
    assert "CWE-78" not in _scan(CTL_HANDLER.replace("{ctl}", ctl.replace("req.query.q", "'localhost'")))


@pytest.mark.parametrize("export", ["module.exports = controller;", "export default controller;"],
                         ids=["commonjs", "es-default"])
def test_js_exported_object_literal_methods_are_handlers_elsewhere(tmp_path, export):
    def run(value):
        ext = ".js" if export.startswith("module") else ".mjs"
        (tmp_path / f"ctl{ext}").write_text(
            ("import cp from 'child_process';\n" if ext == ".mjs" else "const cp = require('child_process');\n")
            + "const controller = { ping(req, res) { cp.exec('ping ' + " + value + "); res.send('ok'); } };\n"
            + export + "\n")
        (tmp_path / f"app{ext}").write_text(
            ("import express from 'express';\nimport ctl from './ctl.mjs';\n" if ext == ".mjs" else
             "const express = require('express');\nconst ctl = require('./ctl');\n")
            + "const app = express();\napp.get('/x', ctl.ping);\n")
        results = FrameScanner(verify=False).scan_directory(str(tmp_path), None, project_root=str(tmp_path))
        return {v.cwe_id for r in results for v in r.vulnerabilities}
    assert "CWE-78" in run("req.query.q")
    assert "CWE-78" not in run("'localhost'")


# A handler handed to the registration through a wrapper: a pack's ([[wrapper]],
# express-async-handler) or one of the file's that passes its parameters through.
JS_WRAPPERS = {
    "local-arrow": "const asyncHandler = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);\n"
                   "app.get('/x', asyncHandler(async (req, res) => {\n  cp.exec('ping ' + req.query.q);\n"
                   "  res.send('ok');\n}));\n",
    "local-function-of-named-handler": "const catchAsync = fn => (req, res, next) => fn(req, res, next).catch(next);\n"
                                       "async function ping(req, res) { cp.exec('ping ' + req.query.q); }\n"
                                       "app.get('/x', catchAsync(ping));\n",
    "local-function-declaration": "function wrap(fn) { return function (req, res, next) { fn(req, res, next); }; }\n"
                                  "app.post('/x', wrap(async (req, res) => { cp.exec('ping ' + req.query.q); }));\n",
    "express-async-handler": "const asyncHandler = require('express-async-handler');\n"
                             "app.get('/x', asyncHandler(async (req, res) => { cp.exec('ping ' + req.query.q); }));\n",
}


@pytest.mark.parametrize("case", list(JS_WRAPPERS))
def test_js_handler_wrapped_in_an_async_helper(case):
    code = JS_HEAD + JS_WRAPPERS[case]
    assert "CWE-78" in _scan(code)
    assert "CWE-78" not in _scan(code.replace("req.query.q", "'localhost'"))


def test_js_wrapper_that_does_not_pass_the_request_is_not_the_handler():
    # the wrapped function never runs with the request: it is not the registered handler
    code = JS_HEAD + ("const later = fn => (req, res, next) => { res.send('x'); };\n"
                      "app.get('/x', later(async (req, res) => { cp.exec('ping ' + req.query.q); }));\n")
    assert "CWE-78" not in _scan(code)


def test_js_unknown_wrapper_library_is_not_a_wrapper():
    # without a pack, a library call's argument is not a handler: the call could do anything
    code = JS_HEAD + ("const wrap = require('some-wrapper');\n"
                      "app.get('/x', wrap(async (req, res) => { cp.exec('ping ' + req.query.q); }));\n")
    assert "CWE-78" not in _scan(code)


# Number- and boolean-valued operators: the result carries no text of the operands (as Number(x)).
JS_NUMERIC = {
    "unary-plus": "+q", "comparison": "q === 'yes'", "negation": "-q", "double-tilde": "~~q",
    "bit-or": "q | 0", "times-one": "q * 1", "typeof": "typeof q", "not": "!q", "length": "q.length",
    "page-arithmetic": "(q - 1) * 10", "inline-length": "req.query.name.length", "less-than": "q < 'm'",
}


@pytest.mark.parametrize("case", list(JS_NUMERIC))
def test_js_numeric_and_boolean_values_are_clean(case):
    assert "CWE-78" not in _scan(_js([f"const v = {JS_NUMERIC[case]};", "cp.exec('ping ' + v);"]))
    assert "CWE-78" not in _scan(_js([f"cp.exec('ping ' + ({JS_NUMERIC[case]}));"]))


@pytest.mark.parametrize("value", ["q + 1", "q || 'x'", "q && q.trim()", "q ?? 'x'", "q.slice(0, q.length)",
                                   "q?.substring(2, q.length - 1)",
                                   "q.length > 3 ? q : 'x'"])
def test_js_text_valued_operators_keep_the_data(value):
    # `+` concatenates, the logical operators return an operand, and a numeric value used as an
    # argument or a condition does not clear the text it is computed from
    assert "CWE-78" in _scan(_js([f"const v = {value};", "cp.exec('ping ' + v);"]))


@pytest.mark.parametrize("lines", [
    ["const n = Number(q);", "const v = 'ping ' + q + n;", "cp.exec(v);"],
    ["const n = q.length;", "let v = 'x';", "v += 'ping ' + q + n;", "cp.exec(v);"],
    ["const off = (q - 1) * 10;", "db.query(\"SELECT * FROM t WHERE n = '\" + q + \"' LIMIT \" + off);"],
])
def test_js_a_numeric_part_does_not_sanitize_the_text_beside_it(lines):
    # a value built from a number and raw request text keeps the text's taint (the number's
    # sanitization used to be unioned into the result)
    assert ({"CWE-78", "CWE-89"} & _scan(_js(lines)))


def test_js_compound_numeric_assignment_is_clean():
    assert "CWE-78" not in _scan(_js(["let v = q;", "v *= 2;", "cp.exec('ping ' + v);"]))
    assert "CWE-78" in _scan(_js(["let v = 'x';", "v += q;", "cp.exec('ping ' + v);"]))


def test_js_comparison_in_a_condition_is_still_a_guard():
    # an equality with a literal is read as a guard in a branch condition (not as a number)
    assert "CWE-78" not in _scan(_js(["if (q !== 'localhost') return res.send('no');", "cp.exec('ping ' + q);"]))
    assert "CWE-78" in _scan(_js(["if (q === 'localhost') return res.send('no');", "cp.exec('ping ' + q);"]))


# Class members that run when the class is defined, and a derived class's field initializers.
CLASS_FIELDS = {
    "static-field": "class Repo {\n  static pool = mysql.createPool({});\n"
                    "  static find(n) { return Repo.pool.query({query}); }\n}\n",
    "static-block": "class Repo {\n  static { this.pool = mysql.createPool({}); }\n"
                    "  static find(n) { return Repo.pool.query({query}); }\n}\n",
    "derived-fields": "class Base {}\nclass Repo extends Base {\n  db = mysql.createConnection({});\n"
                      "  find(n) { return this.db.query({query}); }\n}\nconst repo = new Repo();\n",
}


@pytest.mark.parametrize("case", list(CLASS_FIELDS))
def test_js_class_member_initializers_give_their_values(case):
    call = "repo.find(req.query.q)" if case == "derived-fields" else "Repo.find(req.query.q)"
    code = ("const express = require('express');\nconst mysql = require('mysql');\nconst app = express();\n"
            + CLASS_FIELDS[case] + "app.get('/x', (req, res) => { " + call + "; res.send('ok'); });\n")
    assert "CWE-89" in _scan(code.replace("{query}", "\"SELECT * FROM t WHERE n = '\" + n + \"'\""))
    assert "CWE-89" not in _scan(code.replace("{query}", "'SELECT * FROM t WHERE n = ?', [n]"))


# An Array method that stores its arguments in the receiver.
@pytest.mark.parametrize("how", ["parts.push(q);", "parts.unshift(q);", "parts.splice(1, 0, q);"])
def test_js_push_stores_its_argument_in_the_array(how):
    lines = ["const parts = ['ping'];", how, "cp.exec(parts.join(' '));"]
    assert "CWE-78" in _scan(_js(lines))
    assert "CWE-78" not in _scan(_js(_constant(lines)))


# A guard on a request path written inline clears later reads of the same path.
@pytest.mark.parametrize("guard", ["if (!/^[a-z]+$/.test(req.query.h)) return res.send('bad');",
                                   "if (req.query.h !== 'localhost') return res.send('bad');"])
def test_js_guard_on_an_inline_request_path(guard):
    assert "CWE-78" not in _scan(_js([guard, "cp.exec('ping ' + req.query.h);"]))
    assert "CWE-78" in _scan(_js([guard.replace("req.query.h", "req.query.other"), "cp.exec('ping ' + req.query.h);"]))


# A connection exported by another module: the importing file must know what it is.
CROSS_FILE_DB = {
    "module-exports-value": ("db.js", "const mysql = require('mysql');\nmodule.exports = mysql.createPool({});\n",
                             "const pool = require('./db');"),
    "export-const-origin": ("db.mjs", "import mysql from 'mysql';\nexport const pool = mysql.createPool({});\n",
                            "import { pool } from './db.mjs';"),
    "export-default-origin": ("db.mjs", "import mysql from 'mysql';\nconst pool = mysql.createPool({});\n"
                                        "export default pool;\n", "import pool from './db.mjs';"),
    "module-exports-object-origin": ("db.js", "const mysql = require('mysql');\nconst pool = mysql.createPool({});\n"
                                              "module.exports = { pool };\n", "const { pool } = require('./db');"),
}


@pytest.mark.parametrize("case", list(CROSS_FILE_DB))
def test_js_connection_exported_by_another_module(tmp_path, case):
    db_name, db_code, import_line = CROSS_FILE_DB[case]
    app_name = "app.mjs" if db_name.endswith(".mjs") else "app.js"
    (tmp_path / db_name).write_text(db_code)
    (tmp_path / app_name).write_text(
        "import express from 'express';\n" + import_line + "\nconst app = express();\n"
        "app.get('/x', (req, res) => {\n  pool.query(\"SELECT * FROM t WHERE n = '\" + req.query.q + \"'\");\n"
        "  res.send('ok');\n});\n" if app_name.endswith(".mjs") else
        "const express = require('express');\n" + import_line + "\nconst app = express();\n"
        "app.get('/x', (req, res) => {\n  pool.query(\"SELECT * FROM t WHERE n = '\" + req.query.q + \"'\");\n"
        "  res.send('ok');\n});\n")
    results = FrameScanner(verify=False).scan_directory(str(tmp_path), None, project_root=str(tmp_path))
    assert "CWE-89" in {v.cwe_id for r in results for v in r.vulnerabilities}


# `module.exports = { ... }` keeps each field's own value (it used to collapse into the first).
def test_js_module_exports_object_keeps_each_field(tmp_path):
    (tmp_path / "db.js").write_text("const mysql = require('mysql');\nconst cp = require('child_process');\n"
                                    "module.exports = { runner: cp, pool: mysql.createPool({}) };\n")
    (tmp_path / "app.js").write_text(
        "const express = require('express');\nconst db = require('./db');\nconst app = express();\n"
        "app.get('/x', (req, res) => {\n  db.pool.query({query});\n  res.send('ok');\n});\n")
    def run(query):
        text = (tmp_path / "app.js").read_text()
        (tmp_path / "app.js").write_text(text.replace("{query}", query))
        results = FrameScanner(verify=False).scan_directory(str(tmp_path), None, project_root=str(tmp_path))
        (tmp_path / "app.js").write_text(text)
        return {v.cwe_id for r in results for v in r.vulnerabilities}
    assert "CWE-89" in run("\"SELECT * FROM t WHERE n = '\" + req.query.q + \"'\"")
    assert "CWE-89" not in run("'SELECT * FROM t WHERE n = ?', [req.query.q]")



def test_js_named_export_of_an_object_literal_holds_handlers(tmp_path):
    def run(value):
        (tmp_path / "ctl.mjs").write_text(
            "import cp from 'child_process';\nexport const controller = { ping(req, res) { cp.exec('ping ' + "
            + value + "); res.send('ok'); } };\n")
        (tmp_path / "app.mjs").write_text(
            "import express from 'express';\nimport { controller } from './ctl.mjs';\nconst app = express();\n"
            "app.get('/x', controller.ping);\n")
        results = FrameScanner(verify=False).scan_directory(str(tmp_path), None, project_root=str(tmp_path))
        return {v.cwe_id for r in results for v in r.vulnerabilities}
    assert "CWE-78" in run("req.query.q")
    assert "CWE-78" not in run("'localhost'")


def test_js_member_of_a_required_module_bound_to_a_name():
    # `var request = require('teeny-request').teenyRequest`: calls are named after the module's member
    code = ("const express = require('express');\nvar request = require('teeny-request').teenyRequest;\n"
            "const app = express();\napp.get('/x', (req, res) => { request({ uri: req.query.u }, () => {}); "
            "res.send('ok'); });\n")
    assert "CWE-918" in _scan(code)
    assert "CWE-918" not in _scan(code.replace("req.query.u", "'https://example.com'"))
