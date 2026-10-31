"""A web request is a value, never a name (frame/sil/packs, `[[request_type]]`): what each framework's
request holds is its pack's request type (client fields and methods, the rest server state), and
where a handler gets one is the pack's entry points (routing, decorators, base classes, types) or a
module-level proxy (`flask.request`). A parameter called `request` that nothing hands a request is
an ordinary parameter."""

import pytest

from frame.sil.packs.schema import PackError, parse_pack
from frame.sil.scanner import FrameScanner


def _cwes(code, lang="python", name="a.py"):
    return {v.cwe_id for v in FrameScanner(language=lang, verify=False).scan(code, name).vulnerabilities}


def _lines(code, cwe, name="a.py"):
    return sorted(v.line for v in FrameScanner(language="python", verify=False).scan(code, name).vulnerabilities
                  if v.cwe_id == cwe)


# ---- JavaScript ---------------------------------------------------------------------------------

def test_javascript_request_objects_are_pack_data():
    from frame.sil.packs.loader import PackSet
    express = next(p for p in PackSet.build(builtin=True).packs if p.name == "express")
    request = express.request_types["request"]
    assert request.is_client_field(("body",)) and not request.is_client_field(("session",))
    assert request.is_client_method(("get",)) and not request.is_client_method(("isAuthenticated",))


_HANDLER = """const mysql = require('mysql');
const db = mysql.createConnection({});
require('express')().use(({ %s }, res, next) => {
  db.query("SELECT * FROM t WHERE n = '" + %s + "'");
  res.end();
});
"""


@pytest.mark.parametrize("prop, sqli", [("query", True), ("body", True), ("session", False)])
def test_destructured_request_properties(prop, sqli):
    assert ("CWE-89" in _cwes(_HANDLER % (prop, prop), "javascript", "h.js")) == sqli


# ---- Python: module-level proxies ---------------------------------------------------------------

_FLASK = "from flask import Flask, request\nimport os, sqlite3\napp = Flask(__name__)\n"


@pytest.mark.parametrize("read, found", [
    ("request.args.get('q')", True),
    ("request.args['q']", True),
    ("request.form.getlist('q')[0]", True),
    ("request.get_json()['q']", True),
    ("request.json['q']", True),
    ("request.headers.get('X-Name')", True),
    ("request.method", False),                       # not one of the request's client fields
    ("request.endpoint", False),
])
def test_flask_request_reads(read, found):
    code = _FLASK + f"@app.route('/x')\ndef x():\n    os.system({read})\n    return ''\n"
    assert ("CWE-78" in _cwes(code)) == found


def test_the_proxy_is_the_request_in_every_function_and_helper():
    code = _FLASK + ("def find(r):\n    sqlite3.connect('x').execute(\"SELECT %s\" % r.args.get('n'))\n\n"
                     "def lookup():\n    os.system(request.args.get('cmd'))\n\n"
                     "@app.route('/f')\ndef f():\n    find(request)\n    lookup()\n    return ''\n")
    assert _cwes(code) >= {"CWE-89", "CWE-78"}


def test_a_name_that_is_not_the_proxy_is_not_a_request():
    shadowed = _FLASK + ("def h(request):\n    os.system(request.args.get('q'))\n\n"
                         "def g():\n    request = make_request()\n    os.system(request.args.get('q'))\n")
    assert "CWE-78" not in _cwes(shadowed)
    unrelated = "import os\n\ndef h(request):\n    os.system(request.args.get('q'))\n"
    assert "CWE-78" not in _cwes(unrelated)          # no framework hands `h` a request


def test_the_proxy_through_its_module():
    code = ("import flask, os\napp = flask.Flask(__name__)\n\n@app.route('/x')\ndef x():\n"
            "    os.system(flask.request.args.get('q'))\n    return ''\n")
    assert "CWE-78" in _cwes(code)


def test_cherrypy_and_bottle_proxies():
    cherry = ("import cherrypy, os\n\nclass Root:\n    @cherrypy.expose\n    def run(self):\n"
              "        os.system(cherrypy.request.params['cmd'])\n        return ''\n")
    assert "CWE-78" in _cwes(cherry)
    bottle = ("from bottle import route, request\nimport os\n\n@route('/x')\ndef x():\n"
              "    os.system(request.query.cmd)\n    return ''\n")
    assert "CWE-78" in _cwes(bottle)


def test_a_credential_header_is_the_callers_own_identity():
    base = _FLASK + "from models import Order\n\n@app.route('/o')\ndef o():\n    return str(Order.query.get({}))\n"
    assert "CWE-639" in _cwes(base.format("request.args.get('id')"))
    assert "CWE-639" in _cwes(base.format("request.headers.get('X-Order')"))
    assert "CWE-639" not in _cwes(base.format("request.headers.get('Authorization')"))
    assert "CWE-639" not in _cwes(base.format("request.headers['authorization']"))
    assert "CWE-639" not in _cwes(base.format("request.cookies.get('sid')"))


# ---- Python: Django and DRF ---------------------------------------------------------------------

_DJANGO = """from django.db import connection
from django.urls import path

def view(request):
    connection.cursor().execute("SELECT * FROM t WHERE n = '%%s'" %% request.%s)

urlpatterns = [path("v/", view)]
"""


@pytest.mark.parametrize("attr, sqli", [("GET['n']", True), ("path", True), ("COOKIES['n']", True),
                                        ("user.username", False), ("session['n']", False),
                                        ("session.get('n')", False),
                                        ("resolver_match.url_name", False), ("site.domain", False)])
def test_django_request_server_state(attr, sqli):
    assert ("CWE-89" in _cwes(_DJANGO % attr, name="views.py")) == sqli


def test_django_views_are_what_the_urlconf_routes():
    view = ("import os\nfrom django.contrib.auth.decorators import login_required\nfrom django.urls import path\n\n"
            "def run(request):\n    os.system(request.GET['cmd'])\n\n"
            "def helper(request):\n    os.system(request.GET['cmd'])\n")
    assert _lines(view, "CWE-78") == []                                    # nothing routes to them
    assert _lines(view + "urlpatterns = [path('r/', run)]\n", "CWE-78") == [6]
    assert _lines(view + "urlpatterns = [path('r/', login_required(run))]\n", "CWE-78") == [6]


def test_a_view_another_file_routes(tmp_path):
    (tmp_path / "shop").mkdir()
    (tmp_path / "shop" / "__init__.py").write_text("")
    (tmp_path / "shop" / "views.py").write_text("import os\n\ndef run(request, name):\n"
                                                "    os.system(request.GET['cmd'] + name)\n")
    (tmp_path / "shop" / "urls.py").write_text("from django.urls import path\nfrom shop import views\n\n"
                                               "urlpatterns = [path('r/<name>/', views.run)]\n")
    results = FrameScanner(verify=False).scan_directory(str(tmp_path), None)
    assert ("views.py", "CWE-78") in {(r.filename.rsplit("/", 1)[-1], v.cwe_id) for r in results
                                      for v in r.vulnerabilities}


def test_django_session_writes_cross_a_trust_boundary():
    code = _DJANGO.replace('connection.cursor().execute("SELECT * FROM t WHERE n = \'%%s\'" %% request.%s)',
                           "request.session['name'] = request.GET['name']")
    assert "CWE-501" in _cwes(code, name="views.py")
    assert "CWE-501" not in _cwes(code.replace("request.GET['name']", "'guest'"), name="views.py")


def test_class_based_views_keep_the_request_on_the_instance():
    code = ("import os\nfrom django.views.generic import TemplateView\n\n"
            "class V(TemplateView):\n"
            "    def get_context_data(this, **kwargs):\n"            # the receiver is structural
            "        os.system(this.request.GET['cmd'])\n"
            "        os.system(this.kwargs['slug'])\n"
            "        os.system(this.request.user.username)\n"
            "        return {}\n\n"
            "    def get(self, request, slug):\n"
            "        os.system(request.POST['x'] + slug)\n")
    assert _lines(code, "CWE-78") == [6, 7, 12]


def test_drf_views_and_requests():
    code = ("import os\nfrom rest_framework.views import APIView\nfrom rest_framework.decorators import api_view\n\n"
            "class V(APIView):\n    def get(self, request, pk):\n"
            "        os.system(request.query_params['q'])\n        os.system(str(request.auth))\n"
            "        os.system(self.request.data['x'])\n        os.system(pk)\n\n"
            "@api_view(['POST'])\ndef f(request):\n    os.system(request.data['c'])\n")
    assert _lines(code, "CWE-78") == [7, 9, 10, 14]


# ---- Python: other frameworks -------------------------------------------------------------------

def test_aiohttp_handlers_by_registration_decorator_type_and_view():
    code = ("import os\nfrom aiohttp import web\nroutes = web.RouteTableDef()\n\n"
            "async def h(request):\n    os.system(request.query['a'])\n\n"
            "@routes.get('/b')\nasync def b(request):\n    os.system(await request.text())\n\n"
            "async def typed(request: web.Request):\n    os.system(request.match_info['c'])\n\n"
            "class V(web.View):\n    async def get(self):\n        os.system(self.request.query['d'])\n\n"
            "async def unrouted(request):\n    os.system(request.query['e'])\n\n"
            "def make():\n    app = web.Application()\n    app.router.add_get('/a', h)\n    return app\n")
    assert _lines(code, "CWE-78") == [6, 10, 13, 17]


def test_starlette_and_fastapi_requests():
    star = ("import os\nfrom starlette.routing import Route\n\n"
            "async def e(request):\n    os.system(request.query_params['q'])\n    os.system(str(request.state.x))\n\n"
            "routes = [Route('/e', e)]\n")
    assert _lines(star, "CWE-78") == [5]
    fast = ("import os\nfrom fastapi import Depends, FastAPI, Request\napp = FastAPI()\n\n"
            "def current(request: Request):\n    os.system(request.headers['x-q'])\n\n"
            "@app.get('/f')\ndef f(q: str, dep=Depends(current)):\n    os.system(q)\n")
    assert _lines(fast, "CWE-78") == [6, 10]


def test_pyramid_class_view_keeps_the_request_its_constructor_got():
    code = ("import os\nfrom pyramid.view import view_config, view_defaults\n\n"
            "@view_defaults(route_name='docs')\nclass Docs:\n    def __init__(self, request):\n"
            "        self.req = request\n\n    @view_config(request_method='GET')\n    def get(self):\n"
            "        os.system(self.req.params['doc'])\n        return {}\n\n"
            "@view_config(route_name='two')\ndef two(context, request):\n    os.system(request.GET['x'])\n")
    assert _lines(code, "CWE-78") == [11, 16]


def test_tornado_handler_accessors():
    code = ("import os\nimport tornado.web\n\nclass H(tornado.web.RequestHandler):\n    def get(self, slug):\n"
            "        os.system(self.get_argument('a'))\n        os.system(self.request.body)\n"
            "        os.system(slug)\n        os.system(self.settings['x'])\n")
    assert _lines(code, "CWE-78") == [6, 7, 8]


def test_a_benchmark_helper_is_not_engine_knowledge():
    from frame.sil.specs.python_specs import PYTHON_SPECS
    assert "request_wrapper" not in PYTHON_SPECS            # the OWASP harness's, in benchmarks/packs
    assert not any(n.startswith("request.") for n in PYTHON_SPECS)


# ---- the format ---------------------------------------------------------------------------------

@pytest.mark.parametrize("text, message", [
    ('[[request_type]]\nid = "r"\nfields = ["a"]\nproxies = ["x.request"]\n', "Python packs"),
    ('[[request_type]]\nid = "r"\nobjects = { a = "nope" }\n', "names no"),
    ('[[request_type]]\nid = "r"\nfields = ["*"]\nsessions = ["a"]\n', "client data"),
    ('[[request_type]]\nid = "r"\nfields = ["*"]\nserver_state = ["s"]\nkinds = { s = "file" }\n',
     "not one of its client fields"),
    ('[[request_type]]\nid = "r"\nobjects = { a = "s" }\n[[request_type]]\nid = "s"\nobjects = { b = "r" }\n',
     "hold each other"),
    ('[[request_type]]\nid = "r"\n', "holds nothing"),
])
def test_malformed_request_types(text, message):
    import tomllib
    data = tomllib.loads('[pack]\nname = "x"\nlanguage = "javascript"\n' + text)
    with pytest.raises(PackError, match=message):
        parse_pack(data, "x.toml")


def test_receiver_entries_are_python_and_take_no_positions():
    import tomllib
    head = '[pack]\nname = "x"\nlanguage = "%s"\n[[request_type]]\nid = "r"\nfields = ["a"]\n'
    with pytest.raises(PackError, match="Python packs"):
        parse_pack(tomllib.loads(head % "javascript" + '[[entrypoint]]\nmethod = ["get"]\nreceiver = true\n'
                                 'request_type = "r"\n'), "x.toml")
    with pytest.raises(PackError, match="no positions"):
        parse_pack(tomllib.loads(head % "python" + '[[entrypoint]]\nmethod = ["get"]\nreceiver = true\n'
                                 'param_positions = [0]\nrequest_type = "r"\n'), "x.toml")
    pack = parse_pack(tomllib.loads(head % "python" + '[[entrypoint]]\nmethod = ["get"]\nreceiver = true\n'
                                    'request_type = "r"\n'), "x.toml")
    assert pack.entrypoints[0].receiver
