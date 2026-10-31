"""JavaScript request objects are what a framework hands a handler, never a parameter's name.

A pack's entry point marks a handler's request parameter as a request object (`TaintKind.REQUEST`,
carrying the pack's `[[request_type]]`): reading a client property or calling a client method of it
is attacker data, its server state is not, and the object itself is never reported. Handlers are
found by how the framework registers them: by the value origin of the receiver (`app.get` with
`app = express()` is `express.get`), across files (a routes module handed `app`, a handler defined
in another file, a plugin), by a documented file-system convention (Next.js pages/api, Sails
controllers), or by a TypeScript type. See frame/sil/registrations.py, packs/apply.py,
translator `_request_path`."""

import pytest

from frame.sil.frontends.javascript_frontend import JavaScriptFrontend
from frame.sil.instructions import RequestType
from frame.sil.packs.schema import PackError, parse_pack
from frame.sil.scanner import FrameScanner

APP = ("const express = require('express');\nconst mysql = require('mysql');\n"
       "const db = mysql.createConnection({});\nconst app = express();\n")


def _cwe(code, cwe="CWE-89", name="a.js", lang="javascript"):
    return [v.line for v in FrameScanner(language=lang, verify=False).scan(code, name).vulnerabilities
            if v.cwe_id == cwe]


def _dir(tmp_path, files, cwe):
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    res = FrameScanner(verify=False).scan_directory(str(tmp_path), None)
    return sorted((r.filename.rsplit("/", 1)[-1], v.line) for r in res for v in r.vulnerabilities if v.cwe_id == cwe)


# ---- what a request object holds -------------------------------------------------------------

@pytest.mark.parametrize("body,reported", [
    ("db.query('S ' + req.query.id);", True),
    ("db.query('S ' + req.get('X-Id'));", True),
    ("const n = req.query.n.trim(); db.query('S ' + n);", True),
    ("const { body } = req; db.query('S ' + body.x);", True),
    ("const r = req; db.query('S ' + r.params.id);", True),
    ("db.query('S ' + req.session.uid);", False),          # server state (express-session)
    ("db.query('S ' + req.user.id);", False),              # passport's user
    ("db.query('S ' + req.isAuthenticated());", False),    # not a client method
    ("const { session } = req; db.query('S ' + session.x);", False),
    ("res.send(req);", False),                              # the object itself is not data
])
def test_express_request_fields_methods_and_server_state(body, reported):
    code = APP + f"app.get('/x', (req, res) => {{\n  {body}\n  res.end();\n}});\n"
    found = _cwe(code, "CWE-89") + _cwe(code, "CWE-79")
    assert bool(found) == reported


def test_a_request_passed_to_a_helper_keeps_what_it_holds():
    code = APP + ("function find(r) { db.query('S ' + r.body.q); }\nfunction audit(r) { db.query('S ' + r.session.q); }\n"
                  "app.post('/x', (req, res) => { find(req); audit(req); res.end(); });\n")
    assert _cwe(code) == [5]


def test_a_helper_returning_a_request_field_returns_client_data():
    code = APP + ("function dir(r) { return r.query.dir; }\nfunction who(r) { return r.session.user; }\n"
                  "app.get('/x', (req, res) => { db.query('S ' + dir(req)); db.query('T ' + who(req)); res.end(); });\n")
    assert _cwe(code) == [7]


def test_a_request_type_with_nested_fields_makes_sub_objects():
    t = RequestType("koa", fields=(("query",), ("request", "body")), methods=(("cookies", "get"),))
    assert t.is_client_field(("request", "body", "a")) and not t.is_client_field(("request", "user"))
    assert t.within(("request",)).is_client_field(("body",)) and t.within(("state",)) is None
    assert t.is_client_method(("cookies", "get")) and not t.is_client_method(("throw",))


# ---- how handlers are found -------------------------------------------------------------------

@pytest.mark.parametrize("registration", [
    "app.get('/x', h);",
    "app.post('/x', [function auth(q, s, n) { n(); }, h]);",
    "app.route('/x').get(h);",
    "express.Router().get('/x', h);",
    "require('express')().use(h);",
])
def test_registrations_by_the_receivers_origin(registration):
    code = APP + "function h(req, res) { db.query('S ' + req.query.id); }\n" + registration + "\n"
    assert _cwe(code) == [5]


@pytest.mark.parametrize("code", [
    "function h(req, res) { db.query('S ' + req.query.id); }\n",                 # nothing registers it
    "const cache = new Map();\ncache.get('/x', (req, res) => { db.query('S ' + req.query.id); });\n",
    "function setup(a) { a.get('/x', (req, res) => { db.query('S ' + req.query.id); }); }\n",  # `a` unknown
])
def test_no_registration_no_request(code):
    assert _cwe(APP + code) == []


def test_error_middleware_and_param_callbacks():
    code = APP + ("app.use((err, req, res, next) => { db.query('A ' + req.query.a); });\n"
                  "app.param('id', (req, res, next, id) => { db.query('B ' + id); next(); });\n")
    assert sorted(_cwe(code)) == [5, 6]


def test_destructured_parameters_are_positional():
    program = JavaScriptFrontend().translate("function f({ a, b: { c } }, d) { g(a, c, d); }\n", "a.js")
    proc = program.procedures["f"]
    assert [p.name for p, _ in proc.params] == ["$arg0", "d"]
    assert proc.param_patterns == {"$arg0": "{ a, b: { c } }"}
    code = APP + "app.post('/x', ({ body, session }, res) => {\n  db.query('S ' + body.a);\n  db.query('T ' + session.b);\n});\n"
    assert _cwe(code) == [6]


def test_a_typescript_parameter_of_type_express_request():
    sink = "require('child_process').exec('ls ' + req.query.dir);"
    assert _cwe(f"import {{ Request }} from 'express';\nexport function h(req: Request) {{ {sink} }}", "CWE-78",
                "c.ts", "typescript")
    assert not _cwe(f"export function h(req: any) {{ {sink} }}", "CWE-78", "c.ts", "typescript")


# ---- across a project -------------------------------------------------------------------------

def test_routes_module_handed_the_app_and_a_handler_defined_elsewhere(tmp_path):
    files = {
        "server.js": "const express = require('express');\nconst routes = require('./routes');\n"
                     "const app = express();\nroutes(app);\n",
        "routes.js": "const Handler = require('./handler');\nmodule.exports = (app) => {\n"
                     "  const h = new Handler();\n  app.get('/x', h.show);\n};\n",
        "handler.js": "const { exec } = require('child_process');\nfunction Handler() {\n"
                      "  this.show = (req, res) => { exec('ls ' + req.query.dir); };\n}\nmodule.exports = Handler;\n",
    }
    assert _dir(tmp_path, files, "CWE-78") == [("handler.js", 3)]


def test_a_parameter_callers_disagree_on_has_no_origin(tmp_path):
    files = {
        "server.js": "const express = require('express');\nconst routes = require('./routes');\n"
                     "routes(express());\nroutes(new Map());\n",
        "routes.js": "const { exec } = require('child_process');\nmodule.exports = (app) => {\n"
                     "  app.get('/x', (req, res) => { exec('ls ' + req.query.dir); });\n};\n",
    }
    assert _dir(tmp_path, files, "CWE-78") == []


def test_framework_callbacks_hand_in_framework_values(tmp_path):
    files = {
        "app.js": "const fastify = require('fastify')();\nconst { exec } = require('child_process');\n"
                  "fastify.register(require('./routes'));\n"
                  "fastify.register(async (instance) => { instance.get('/b', async (request) => { exec('ls ' + request.query.b); }); });\n"
                  "fastify.get('/c', async (request) => { exec('ls ' + request.id); });\n",
        "routes.js": "const { exec } = require('child_process');\nmodule.exports = async function (fastify) {\n"
                     "  fastify.get('/a', async (request, reply) => { exec('ls ' + request.query.a); });\n};\n",
    }
    assert _dir(tmp_path, files, "CWE-78") == [("app.js", 4), ("routes.js", 3)]


def test_socket_servers(tmp_path):
    files = {"ws.js": (
        "const { WebSocketServer } = require('ws');\nconst { exec } = require('child_process');\n"
        "const wss = new WebSocketServer({ port: 8080 });\nwss.on('connection', (ws, req) => {\n"
        "  exec('echo ' + req.headers['x-name']);\n  ws.on('message', (data) => { exec('ls ' + data); });\n});\n"
        "wss.on('error', (err) => { exec('ls ' + err.message); });\n"
        "const { Server } = require('socket.io');\nconst io = new Server(3000);\n"
        "io.on('connection', (socket) => {\n  exec('ls ' + socket.id);\n  exec('ls ' + socket.handshake.query.t);\n"
        "  socket.on('x', (m) => exec('ls ' + m));\n});\n")}
    assert _dir(tmp_path, files, "CWE-78") == [("ws.js", 5), ("ws.js", 6), ("ws.js", 13), ("ws.js", 14)]


def test_file_system_conventions_need_the_framework(tmp_path):
    handler = "export default function handler(req, res) { require('child_process').exec('ls ' + req.query.d); }\n"
    files = {"package.json": '{"dependencies": {"next": "14.2.0"}}', "pages/api/a.js": handler,
             "lib/a.js": handler}
    assert _dir(tmp_path / "next", files, "CWE-78") == [("a.js", 1)]
    found = _dir(tmp_path / "next2", files, "CWE-78")
    assert all("lib" not in f for f, _ in found)
    plain = {"pages/api/a.js": handler}                        # no Next.js in the manifest
    assert _dir(tmp_path / "plain", plain, "CWE-78") == []


def test_server_actions_by_directive():
    code = ("'use server';\nimport { revalidatePath } from 'next/cache';\nimport { exec } from 'child_process';\n"
            "export async function act(formData) { exec('r ' + formData.get('m')); }\n"
            "async function helper(x) { exec('r ' + x); }\n")
    assert _cwe(code, "CWE-78") == [4]                     # an export of a 'use server' module, not its helper
    inline = ("import { cookies } from 'next/headers';\nimport { exec } from 'child_process';\n"
              "async function act(v) { 'use server'; exec('r ' + v); }\nasync function other(v) { exec('r ' + v); }\n")
    assert _cwe(inline, "CWE-78") == [3]


# ---- the pack format --------------------------------------------------------------------------

def _pack(body, language="javascript"):
    try:
        import tomllib
    except ModuleNotFoundError:                                        # pragma: no cover - 3.10
        import tomli as tomllib
    return parse_pack(tomllib.loads(f'[pack]\nname = "x"\nlanguage = "{language}"\n' + body), "x.toml")


@pytest.mark.parametrize("body,error", [
    ('[[request_type]]\nid = "r"\n', "fields"),
    ('[[request_type]]\nid = "r"\nfields = ["*", "a"]\n', "server_state goes with"),
    ('[[request_type]]\nid = "r"\nfields = ["a"]\nserver_state = ["b"]\n', "server_state goes with"),
    ('[[request_type]]\nid = "r"\nfields = ["*"]\nmethods = ["get"]\n', "no methods"),
    ('[[request_type]]\nid = "r"\nfields = ["a b"]\n', "not a property path"),
    ('[[request_type]]\nid = "r"\nfields = ["a"]\nkinds = { b = "file" }\n', "not one of its fields"),
    ('[[entrypoint]]\nmethod = ["*"]\nparams = "all"\nrequest_type = "nope"\n', "names no"),
    ('[[request_type]]\nid = "r"\nfields = ["a"]\n[[entrypoint]]\nmethod = ["*"]\nparams = "all"\nrequest_type = "r"\nkind = "user"\n',
     "no kind"),
    ('[[entrypoint]]\nmethod = ["*"]\nparams = "all"\narity = [-1]\n', "parameter counts"),
    ('[[entrypoint]]\nmodule_path = ["**/a/**"]\nparams = "all"\nmethod = ["*"]\n', "goes with exports"),
    ('[[callback_param]]\nregistered_via = ["a.on"]\nposition = 0\n', "needs the value"),
    ('[[callback_param]]\nregistered_via = ["a.on"]\nposition = -1\norigin = "a.S"\n', "parameter position"),
])
def test_malformed_entries_are_errors(body, error):
    with pytest.raises(PackError, match=error):
        _pack(body)


def test_package_json_detection_is_for_javascript_packs():
    with pytest.raises(PackError, match="package.json"):
        parse_pack({"pack": {"name": "x", "language": "python", "detect": {"dependencies": ["django"]}}}, "x.toml")


# ---- the response side: a handler's response is a value of its framework's response origin ----

HANDLER = "const app = require('express')();\napp.get('/x', (req, res) => {\n  %s\n});\n"


@pytest.mark.parametrize("body,cwe,reported", [
    ("res.send(req.query.a);", "CWE-79", True),
    ("res.send({ a: req.query.a });", "CWE-79", False),            # an object is sent as JSON
    ("res.status(200).send(req.query.a);", "CWE-79", True),        # a chain of setters
    ("res.type('json').send(req.query.a);", "CWE-79", False),      # not an HTML response
    ("res.redirect(req.query.u);", "CWE-601", True),
    ("res.setHeader('X', req.query.u);", "CWE-113", True),
    ("ok && res.send(req.query.a);", "CWE-79", True),              # an effect behind &&
    ("ok ? res.send(req.query.a) : res.end();", "CWE-79", True),
    ("foo(res.send(req.query.a));", "CWE-79", True),               # a call inside another
    ("const out = { send: (x) => x };\n  out.send(req.query.a);", "CWE-79", False),   # not a response
])
def test_express_response_sinks(body, cwe, reported):
    assert bool(_cwe(HANDLER % body, cwe)) == reported


def test_a_helper_handed_the_response():
    code = HANDLER % "after(res, req.query.u);"
    code = "function after(r, u) { r.redirect(u); }\n" + code
    assert _cwe(code, "CWE-601") == [1]


def test_a_variable_named_res_is_not_a_response():
    assert not _cwe("function f(req, res) { res.send(req.query.a); }\nf(x, y);\n", "CWE-79")


def test_koa_context_body_is_a_property_sink():
    code = ("const Koa = require('koa');\nconst app = new Koa();\n"
            "app.use(async (ctx) => {\n  ctx.body = ctx.query.a;\n  ctx.body = { a: ctx.query.a };\n});\n")
    assert _cwe(code, "CWE-79") == [4]


def test_node_http_servers():
    code = ("const http = require('http');\nhttp.createServer((req, res) => {\n"
            "  res.end('<p>' + req.url + '</p>');\n  res.end(req.socket.remoteAddress);\n}).listen(80);\n")
    assert _cwe(code, "CWE-79") == [3]


def test_pack_property_sinks_are_named_by_call_id():
    with pytest.raises(PackError, match="property sink"):
        _pack('[[sink]]\nname = ["ctx.body"]\nproperty = true\nkind = "html"\n')
    with pytest.raises(PackError, match="no kind|origin entry point"):
        _pack('[[entrypoint]]\nmethod = ["*"]\nparams = "all"\norigin = "a.B"\nkind = "user"\n')
