"""Dicts per key: literal keys are constants, values keep their own taint.

The `UPDATE ... SET {', '.join(f'{k} = ?' for k in updates)}` idiom (constant column names,
parameterised values) was reported as SQL injection once comprehensions carried what they
iterate: request data in the dict's values tainted its keys. A dict literal also carried nothing
(`{"k": q}["k"]` was missed), and a dict comprehension over request data lost both its keys and
its values, so request-chosen column names reaching SQL (mass assignment) were missed too. Each
positive is paired with the nearest safe shape.
"""

import pytest

from frame.sil.scanner import FrameScanner

HEAD = """import sqlite3
from flask import Flask, request
app = Flask(__name__)
conn = sqlite3.connect('x.db')
"""


def cwes(body, module=""):
    code = HEAD + module + "@app.route('/x', methods=['POST'])\ndef x():\n" + "".join(
        "    " + ln + "\n" for ln in body.splitlines()) + "    return 'ok'\n"
    r = FrameScanner(language="python").scan(code, "app.py")
    assert not r.errors, r.errors
    return {v.cwe_id for v in r.vulnerabilities}


FILL = "u = {}\nu['title'] = request.json['t']\nu['body'] = request.json['b']\n"

SAFE = {
    "join over the dict": FILL + "s = ', '.join(f'{k} = ?' for k in u)\nconn.execute(f'UPDATE t SET {s}', list(u.values()))",
    "join over keys()": FILL + "s = ', '.join(k + ' = ?' for k in u.keys())\nconn.execute('UPDATE t SET ' + s, list(u.values()))",
    "join the dict itself": FILL + "conn.execute('SELECT ' + ', '.join(u) + ' FROM t')",
    "sorted keys": FILL + "cols = sorted(u)\nconn.execute('SELECT ' + ', '.join(cols) + ' FROM t')",
    "for loop over the dict": FILL + "s = ''\nfor k in u:\n    s += k + ' = ?, '\nconn.execute('UPDATE t SET ' + s)",
    "keys of items()": FILL + "s = ', '.join(k + ' = ?' for k, v in u.items())\nconn.execute('UPDATE t SET ' + s)",
    "a truth test does not add keys": FILL + "if u:\n    s = ', '.join(f'{k} = ?' for k in u)\n    conn.execute('UPDATE t SET ' + s, list(u.values()))",
    "literal dict, other key": "d = {'a': request.args['q'], 'b': 'name'}\nconn.execute('SELECT ' + d['b'] + ' FROM t')",
    "literal dict, other key by get": "d = {'a': request.args['q'], 'b': 'name'}\nv = d.get('b')\nconn.execute('SELECT ' + v + ' FROM t')",
    "inline literal, other key": "conn.execute('SELECT ' + {'a': request.args['q'], 'b': 'n'}['b'])",
}

VULNERABLE = {
    "values joined": FILL + "conn.execute('UPDATE t SET ' + ', '.join(v for v in u.values()))",
    "values of items()": FILL + "s = ', '.join(f'{k}={v}' for k, v in u.items())\nconn.execute('UPDATE t SET ' + s)",
    "a value by key": FILL + "conn.execute('UPDATE t SET x=' + u['title'])",
    "a request-chosen key": "u = {}\nu[request.json['k']] = 1\nconn.execute('UPDATE t SET ' + ', '.join(k for k in u))",
    "a key added by update()": "u = {}\nu.update(request.json)\nconn.execute('UPDATE t SET ' + ', '.join(k for k in u))",
    "mass assignment": "u = {k: v for k, v in request.json.items()}\ns = ', '.join(f'{k} = ?' for k in u)\nconn.execute('UPDATE t SET ' + s, list(u.values()))",
    "literal dict, the key": "d = {'a': request.args['q'], 'b': 'name'}\nconn.execute('SELECT ' + d['a'])",
    "literal dict by get": "d = {'a': request.args['q']}\nv = d.get('a')\nconn.execute('SELECT ' + v)",
    "literal dict passed whole": "d = {'a': request.args['q']}\nconn.execute('SELECT ' + str(d))",
    "inline literal, the key": "conn.execute('SELECT ' + {'a': request.args['q']}['a'])",
}


def test_a_dict_passed_to_a_function_may_get_request_chosen_keys():
    fill = "def fill(d):\n    d[request.args['c']] = 1\n"
    body = FILL + "fill(u)\nconn.execute('UPDATE t SET ' + ', '.join(k for k in u))"
    assert "CWE-89" in cwes(body, module=fill)


@pytest.mark.parametrize("body", SAFE.values(), ids=SAFE.keys())
def test_constant_keys_and_other_keys_are_not_sql(body):
    assert "CWE-89" not in cwes(body)


@pytest.mark.parametrize("body", VULNERABLE.values(), ids=VULNERABLE.keys())
def test_values_and_request_chosen_keys_reach_sql(body):
    assert "CWE-89" in cwes(body)
