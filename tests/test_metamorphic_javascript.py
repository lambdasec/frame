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

KNOWN_GAPS = {
    "for-of-callback": "a callback a library calls (`forEach`, `map`, `then`) is not resolved: its parameter "
                       "never receives the elements",
    "promise-then": "a callback a library calls (`forEach`, `map`, `then`) is not resolved: its parameter "
                    "never receives the elements",
    "function-alias": "a function value bound to a name (`const run = cp.exec`) is not followed to the "
                      "function it names",
    "object-literal-method": "a method of a same-file object literal is not resolved as a callee",
    "array-map-callback": "a callback a library calls (`forEach`, `map`, `then`) is not resolved: its parameter "
                          "never receives the elements",
    "static-method": "a static method of a same-file class is not resolved as a callee",
    "export-const-origin": "an ES `export const` / `export default` binding gives the importing file no value "
                           "origin (value_origins)",
    "export-default-origin": "an ES `export const` / `export default` binding gives the importing file no value "
                             "origin (value_origins)",
    "module-exports-object-origin": "`module.exports = { pool }` gives the importing file no value origin for "
                                    "the destructured name (value_origins)",
    "async-wrapper": "a handler wrapped in a helper (`asyncHandler(fn)`) is not seen as registered",
    "unary-plus": "a numeric conversion by an operator (`+q`) does not clear the value",
    "comparison": "a comparison (`q === 'yes'`) still carries the request data",
}


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


# Out of scope for the frontend (value origins, callee resolution, numeric facts): strict
# xfails, each with its reason in KNOWN_GAPS.
JS_OUT_OF_SCOPE = {
    "for-of-callback": (["[q].forEach(s => cp.exec('ping ' + s));"], "CWE-78"),
    "promise-then": (["Promise.resolve(q).then(s => cp.exec('ping ' + s));"], "CWE-78"),
    "function-alias": (["const run = cp.exec;", "run('ping ' + q);"], "CWE-78"),
    "object-literal-method": (["const h = { run(s) { cp.exec('ping ' + s); } };", "h.run(q);"], "CWE-78"),
    "array-map-callback": (["[q].map(s => cp.exec('ping ' + s));"], "CWE-78"),
    "static-method": (["U.run(q);"], "CWE-78"),
}


@pytest.mark.parametrize("case", [pytest.param(c, id=c, marks=_gap(c)) for c in JS_OUT_OF_SCOPE])
def test_js_out_of_scope_flows(case):
    lines, cwe = JS_OUT_OF_SCOPE[case]
    assert cwe in _scan(_js(lines))


@pytest.mark.xfail(reason=KNOWN_GAPS["async-wrapper"], strict=True)
def test_js_handler_wrapped_in_an_async_helper():
    code = JS_HEAD + ("const asyncHandler = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);\n"
                      "app.get('/x', asyncHandler(async (req, res) => {\n"
                      "  cp.exec('ping ' + req.query.q);\n  res.send('ok');\n}));\n")
    assert "CWE-78" in _scan(code)


@pytest.mark.parametrize("case", [
    pytest.param("unary-plus", id="unary-plus", marks=_gap("unary-plus")),
    pytest.param("comparison", id="comparison", marks=_gap("comparison")),
])
def test_js_numeric_and_boolean_values_are_clean(case):
    value = {"unary-plus": "+q", "comparison": "q === 'yes'"}[case]
    assert "CWE-78" not in _scan(_js([f"const v = {value};", "cp.exec('ping ' + v);"]))


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


@pytest.mark.parametrize("case", [pytest.param(c, id=c, marks=_gap(c)) for c in CROSS_FILE_DB])
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
