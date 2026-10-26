"""Realistic multi-file Python projects: each case is a vulnerable tree and its safe twin.

Marked lines (`# frame-expect: CWE-n`) are where the report must point; the safe twin
differs only by the fix. Cases cover how real code is split across files: layered
web apps, class-based repositories, helpers that return request data, sanitising
helpers (and ones that only pretend to), re-exports, aliases and deep chains.
"""

CASES = {}


def case(name, vulnerable, safe):
    CASES[name] = (vulnerable, safe)


# --------------------------------------------------------------------------------------
case("flask_blueprint_service_repository", {
    "shop/__init__.py": '''from flask import Flask
from shop.routes import bp


def create_app():
    app = Flask(__name__)
    app.register_blueprint(bp)
    return app
''',
    "shop/routes.py": '''from flask import Blueprint, request, jsonify
from shop.services import orders

bp = Blueprint("orders", __name__)


@bp.route("/orders")
def list_orders():
    customer = request.args.get("customer", "")
    return jsonify(orders.for_customer(customer))
''',
    "shop/services/__init__.py": "",
    "shop/services/orders.py": '''from shop import db


def for_customer(name):
    rows = db.find_orders(name.strip())
    return [dict(r) for r in rows]
''',
    "shop/db.py": '''import sqlite3


def connect():
    return sqlite3.connect("shop.db")


def find_orders(customer):
    cur = connect().cursor()
    cur.execute("SELECT * FROM orders WHERE customer = '" + customer + "'")  # frame-expect: CWE-89
    return cur.fetchall()
''',
}, {
    "shop/__init__.py": '''from flask import Flask
from shop.routes import bp


def create_app():
    app = Flask(__name__)
    app.register_blueprint(bp)
    return app
''',
    "shop/routes.py": '''from flask import Blueprint, request, jsonify
from shop.services import orders

bp = Blueprint("orders", __name__)


@bp.route("/orders")
def list_orders():
    customer = request.args.get("customer", "")
    return jsonify(orders.for_customer(customer))
''',
    "shop/services/__init__.py": "",
    "shop/services/orders.py": '''from shop import db


def for_customer(name):
    rows = db.find_orders(name.strip())
    return [dict(r) for r in rows]
''',
    "shop/db.py": '''import sqlite3


def connect():
    return sqlite3.connect("shop.db")


def find_orders(customer):
    cur = connect().cursor()
    cur.execute("SELECT * FROM orders WHERE customer = ?", (customer,))
    return cur.fetchall()
''',
})

# --------------------------------------------------------------------------------------
case("django_view_to_search_module", {
    "catalog/views.py": '''from django.http import JsonResponse
from catalog.search import run_search


def search(request):
    term = request.GET.get("q", "")
    return JsonResponse({"results": run_search(term)})
''',
    "catalog/search.py": '''from django.db import connection


def run_search(term):
    with connection.cursor() as cur:
        cur.execute("SELECT id, title FROM books WHERE title LIKE '%%" + term + "%%'")  # frame-expect: CWE-89
        return cur.fetchall()
''',
}, {
    "catalog/views.py": '''from django.http import JsonResponse
from catalog.search import run_search


def search(request):
    term = request.GET.get("q", "")
    return JsonResponse({"results": run_search(term)})
''',
    "catalog/search.py": '''from django.db import connection


def run_search(term):
    with connection.cursor() as cur:
        cur.execute("SELECT id, title FROM books WHERE title LIKE %s", ["%" + term + "%"])
        return cur.fetchall()
''',
})

# --------------------------------------------------------------------------------------
case("fastapi_upload_path_traversal", {
    "api/main.py": '''from fastapi import FastAPI
from api.routers import files

app = FastAPI()
app.include_router(files.router)
''',
    "api/routers/__init__.py": "",
    "api/routers/files.py": '''from fastapi import APIRouter
from api.storage import read_document

router = APIRouter()


@router.get("/documents/{name}")
def get_document(name: str):
    return {"content": read_document(name)}
''',
    "api/storage.py": '''import os

BASE = "/srv/documents"


def read_document(name):
    path = os.path.join(BASE, name)
    with open(path) as fh:  # frame-expect: CWE-22
        return fh.read()
''',
}, {
    "api/main.py": '''from fastapi import FastAPI
from api.routers import files

app = FastAPI()
app.include_router(files.router)
''',
    "api/routers/__init__.py": "",
    "api/routers/files.py": '''from fastapi import APIRouter
from api.storage import read_document

router = APIRouter()


@router.get("/documents/{name}")
def get_document(name: str):
    return {"content": read_document(name)}
''',
    "api/storage.py": '''import os

BASE = "/srv/documents"


def read_document(name):
    path = os.path.join(BASE, os.path.basename(name))
    with open(path) as fh:
        return fh.read()
''',
})

# --------------------------------------------------------------------------------------
case("helper_returns_request_data", {
    "app/params.py": '''from flask import request


def current_user_id():
    return request.args.get("uid")
''',
    "app/views.py": '''import subprocess
from flask import Flask
from app.params import current_user_id

app = Flask(__name__)


@app.route("/export")
def export():
    uid = current_user_id()
    subprocess.call("tar czf /tmp/" + uid + ".tgz /data/" + uid, shell=True)  # frame-expect: CWE-78
    return "done"
''',
}, {
    "app/params.py": '''from flask import request


def current_user_id():
    return int(request.args.get("uid"))
''',
    "app/views.py": '''import subprocess
from flask import Flask
from app.params import current_user_id

app = Flask(__name__)


@app.route("/export")
def export():
    uid = current_user_id()
    subprocess.call("tar czf /tmp/" + str(uid) + ".tgz /data/" + str(uid), shell=True)
    return "done"
''',
})

# --------------------------------------------------------------------------------------
case("class_repository_via_constructor", {
    "app/repo.py": '''class UserRepository:
    def __init__(self, conn):
        self.conn = conn

    def find_by_name(self, name):
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM users WHERE name = '" + name + "'")  # frame-expect: CWE-89
        return cur.fetchone()
''',
    "app/handlers.py": '''import sqlite3
from flask import Flask, request
from app.repo import UserRepository

app = Flask(__name__)
repo = UserRepository(sqlite3.connect("users.db"))


@app.route("/user")
def user():
    return str(repo.find_by_name(request.args["name"]))
''',
}, {
    "app/repo.py": '''class UserRepository:
    def __init__(self, conn):
        self.conn = conn

    def find_by_name(self, name):
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM users WHERE name = ?", (name,))
        return cur.fetchone()
''',
    "app/handlers.py": '''import sqlite3
from flask import Flask, request
from app.repo import UserRepository

app = Flask(__name__)
repo = UserRepository(sqlite3.connect("users.db"))


@app.route("/user")
def user():
    return str(repo.find_by_name(request.args["name"]))
''',
})

# --------------------------------------------------------------------------------------
case("sanitiser_that_only_pretends", {
    "tools/validate.py": '''def clean_host(host):
    # looks like validation, is not
    return host.strip().lower()
''',
    "tools/net.py": '''import os
from tools.validate import clean_host


def ping(host):
    os.system("ping -c 1 " + clean_host(host))  # frame-expect: CWE-78
''',
    "tools/web.py": '''from flask import Flask, request
from tools.net import ping

app = Flask(__name__)


@app.route("/ping")
def do_ping():
    ping(request.form["host"])
    return "sent"
''',
}, {
    "tools/validate.py": '''import re
import shlex

_HOST = re.compile(r"[A-Za-z0-9.-]{1,253}")


def clean_host(host):
    if not _HOST.fullmatch(host):
        raise ValueError("bad host")
    return shlex.quote(host)
''',
    "tools/net.py": '''import os
from tools.validate import clean_host


def ping(host):
    os.system("ping -c 1 " + clean_host(host))
''',
    "tools/web.py": '''from flask import Flask, request
from tools.net import ping

app = Flask(__name__)


@app.route("/ping")
def do_ping():
    ping(request.form["host"])
    return "sent"
''',
})

# --------------------------------------------------------------------------------------
case("reexport_alias_and_star_imports", {
    "svc/__init__.py": "from svc.runner import run_report\n",
    "svc/runner.py": '''import subprocess


def run_report(name):
    subprocess.run("report --name " + name, shell=True)  # frame-expect: CWE-78
''',
    "svc/helpers.py": '''def shout(text):
    return text.upper()
''',
    "web.py": '''from flask import Flask, request
import svc as reporting
from svc.helpers import *

app = Flask(__name__)


@app.route("/report")
def report():
    reporting.run_report(shout(request.args.get("name", "")))
    return "ok"
''',
}, {
    "svc/__init__.py": "from svc.runner import run_report\n",
    "svc/runner.py": '''import subprocess


def run_report(name):
    subprocess.run(["report", "--name", name])
''',
    "svc/helpers.py": '''def shout(text):
    return text.upper()
''',
    "web.py": '''from flask import Flask, request
import svc as reporting
from svc.helpers import *

app = Flask(__name__)


@app.route("/report")
def report():
    reporting.run_report(shout(request.args.get("name", "")))
    return "ok"
''',
})

# --------------------------------------------------------------------------------------
case("five_hops_across_five_files", {
    "chain/a.py": '''from flask import Flask, request
from chain.b import step_b

app = Flask(__name__)


@app.route("/x")
def entry():
    return step_b(request.args.get("v", ""))
''',
    "chain/b.py": '''from chain.c import step_c


def step_b(v):
    return step_c(v + "!")
''',
    "chain/c.py": '''from chain.d import step_d


def step_c(v):
    return step_d(v)
''',
    "chain/d.py": '''from chain.e import step_e


def step_d(v):
    return step_e(v)
''',
    "chain/e.py": '''import os


def step_e(v):
    return os.popen("echo " + v).read()  # frame-expect: CWE-78
''',
}, {
    "chain/a.py": '''from flask import Flask, request
from chain.b import step_b

app = Flask(__name__)


@app.route("/x")
def entry():
    return step_b(request.args.get("v", ""))
''',
    "chain/b.py": '''from chain.c import step_c


def step_b(v):
    return step_c(v + "!")
''',
    "chain/c.py": '''from chain.d import step_d


def step_c(v):
    return step_d(v)
''',
    "chain/d.py": '''from chain.e import step_e


def step_d(v):
    return step_e(v)
''',
    "chain/e.py": '''import subprocess


def step_e(v):
    return subprocess.run(["echo", v], capture_output=True, text=True).stdout
''',
})

# --------------------------------------------------------------------------------------
case("ssrf_through_http_client_module", {
    "integrations/client.py": '''import requests


def fetch(url):
    return requests.get(url, timeout=5).text  # frame-expect: CWE-918
''',
    "integrations/webhooks.py": '''from flask import Flask, request
from integrations.client import fetch

app = Flask(__name__)


@app.route("/preview")
def preview():
    return fetch(request.args.get("url"))
''',
}, {
    "integrations/client.py": '''import requests
from urllib.parse import urlparse

ALLOWED_HOSTS = {"api.partner.example", "cdn.partner.example"}


def fetch(url):
    if urlparse(url).hostname not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")
    return requests.get(url, timeout=5).text
''',
    "integrations/webhooks.py": '''from flask import Flask, request
from integrations.client import fetch

app = Flask(__name__)


@app.route("/preview")
def preview():
    return fetch(request.args.get("url"))
''',
})


# ---- input validation idioms: what really protects, and what only looks like it does ----
def _handler(body, imports=""):
    return (f"import os\nimport re\nimport subprocess\nfrom flask import Flask, request, abort\n{imports}\n"
            f"app = Flask(__name__)\n\n\n@app.route('/run')\ndef run():\n{body}")


case("validation_numeric_conversion", {
    "app.py": _handler('''    n = request.args.get("n", "1")
    os.system("seq " + n)  # frame-expect: CWE-78
    return "ok"
'''),
}, {
    "app.py": _handler('''    n = int(request.args.get("n", "1"))
    os.system("seq " + str(n))
    return "ok"
'''),
})

case("validation_isdigit_guard", {
    "app.py": _handler('''    uid = request.args.get("uid", "")
    if uid.isdigit():
        pass                                   # checked, then ignored
    subprocess.call("id " + uid, shell=True)  # frame-expect: CWE-78
    return "ok"
'''),
}, {
    "app.py": _handler('''    uid = request.args.get("uid", "")
    if not uid.isdigit():
        abort(400)
    subprocess.call("id " + uid, shell=True)
    return "ok"
'''),
})

case("validation_regex_fullmatch", {
    "app.py": _handler('''    name = request.args.get("name", "")
    if not re.fullmatch(r".+", name):         # matches anything
        abort(400)
    os.system("greet " + name)  # frame-expect: CWE-78
    return "ok"
'''),
}, {
    "app.py": _handler('''    name = request.args.get("name", "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", name):
        abort(400)
    os.system("greet " + name)
    return "ok"
'''),
})

case("validation_regex_match_needs_end_anchor", {
    "app.py": _handler('''    name = request.args.get("name", "")
    if not re.match(r"[a-z]+", name):         # only the prefix is checked
        abort(400)
    os.system("greet " + name)  # frame-expect: CWE-78
    return "ok"
'''),
}, {
    "app.py": _handler('''    name = request.args.get("name", "")
    if not re.match(r"^[a-z]+$", name):
        abort(400)
    os.system("greet " + name)
    return "ok"
'''),
})

case("validation_guard_covers_a_different_variable", {
    "app.py": _handler('''    a = request.args.get("a", "")
    b = request.args.get("b", "")
    if not a.isdigit():
        abort(400)
    os.system("calc " + a + " " + b)  # frame-expect: CWE-78
    return "ok"
'''),
}, {
    "app.py": _handler('''    a = request.args.get("a", "")
    b = request.args.get("b", "")
    if not (a.isdigit() and b.isdigit()):
        abort(400)
    os.system("calc " + a + " " + b)
    return "ok"
'''),
})
