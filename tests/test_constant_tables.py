"""Constant tables: a lookup in a name bound once to a literal-only collection and never
written into yields one of its constants, so the key's taint does not reach the result. Each
positive is paired with the nearest table that does not qualify, which must keep its finding."""

import pytest

from frame.sil.scanner import FrameScanner
from frame.sil.source_facts import constant_tables

JS_TABLES = """const TEMPLATES = { greeting: 'Hello <%= user %>!', farewell: `Bye` };
const LEVELS = ['low', 'high'];
let mutable = { a: 'x' };
mutable.b = req.body;
const pushed = ['a'];
pushed.push(x);
const withVar = { a: someVar };
const spread = { ...other };
const passed = { a: 'x' };
helper(passed);
const assigned = { a: 'x' };
Object.assign(assigned, req.body);
const templated = { a: `${x}` };
function f() { const local = { k: 'v' }; return JSON.stringify(local); }
const shadow = { a: '1' };
function g(shadow) { return shadow[x]; }
"""

PY_TABLES = """ALLOWED = {'a': 'x', 'b': ('y', 1), 'c': None}
SAFE = ['a', 'b']
fmt = {'a': f'{x}'}
upd = {'a': 'x'}
upd['b'] = request.args['b']
grown = {'a': 'x'}
grown.update(other)
passed = {'a': 'x'}
helper(passed)
counted = {'a': 'x'}
n = len(counted)
def h():
    local = {'k': 'v'}
    return local
def i(shadow): pass
shadow = {'a': 'b'}
twice = {'a': 'x'}
twice = {'a': 'y'}
named = {'a': 'x'}
for named in range(3): pass
"""


def test_constant_tables_are_read_conservatively():
    assert constant_tables(JS_TABLES, "javascript") == {"TEMPLATES", "LEVELS", "local"}
    assert constant_tables(PY_TABLES, "python") == {"ALLOWED", "SAFE", "counted", "local"}


def scan(lang, src):
    name = "a.py" if lang == "python" else "a.js"
    return [(v.type.value, v.line) for v in FrameScanner(language=lang).scan(src, name).vulnerabilities]


JS_HANDLER = """const express = require('express');
const _ = require('lodash');
const app = express();
app.get('/greet', (req, res) => {{
  const templates = {table};
  const render = _.template(templates[req.query.tpl]);
  res.send(render({{ user: 'guest' }}));
}});
"""


def test_js_lookup_in_a_constant_table_is_not_attacker_data():
    assert scan("javascript", JS_HANDLER.format(table="{ greeting: 'Hello <%= user %>!', bye: 'Bye' }")) == []


def test_js_table_with_attacker_data_in_it_keeps_its_finding():
    assert ("template_injection", 6) in scan("javascript", JS_HANDLER.format(table="{ greeting: req.body.t }"))


def test_js_template_from_the_request_is_still_reported():
    src = JS_HANDLER.format(table="{ a: 'x' }").replace("templates[req.query.tpl]", "req.query.tpl")
    assert ("template_injection", 6) in scan("javascript", src)


PY_HANDLER = """import os
from flask import Flask, request
app = Flask(__name__)
{table_line}

@app.route('/run')
def run():
    c = request.args.get('c')
    os.system({expr})
    return 'ok'
"""


@pytest.mark.parametrize("table_line,expr,flagged", [
    ("CMDS = {'up': 'uptime', 'disk': 'df -h'}", "CMDS[c]", False),
    ("CMDS = {'up': 'uptime'}", "CMDS.get(c, 'uptime')", False),
    ("CMDS = {'up': 'uptime'}", "c", True),
])
def test_python_lookups(table_line, expr, flagged):
    # (Python lowers a dict literal to an opaque value, so a key never tainted a lookup in
    # one; the constant table makes that a rule rather than an accident of lowering.)
    found = scan("python", PY_HANDLER.format(table_line=table_line, expr=expr))
    assert (("command_injection", 9) in found) is flagged, found
