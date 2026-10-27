"""More realistic Python projects: inheritance, decorators, DI, async, packages, ORMs.

Each case is written once with `<<vulnerable|safe>>` choices; the safe twin differs only
by the fix a developer would make. Lines marked `# frame-expect: CWE-n` must be reported.
"""

import re

CASES = {}
_CHOICE = re.compile(r"<<(.*?)\|\|(.*?)>>", re.S)


def case(name, files):
    vulnerable = {p: _CHOICE.sub(lambda m: m.group(1), t) for p, t in files.items()}
    safe = {p: _CHOICE.sub(lambda m: m.group(2), t) for p, t in files.items()}
    CASES[name] = (vulnerable, safe)


# --------------------------------------------------------------------------------------


case("abstract_base_concrete_repo", {
    "dao/base.py": '''from abc import ABC, abstractmethod


class Dao(ABC):
    @abstractmethod
    def find(self, key):
        ...
''',
    "dao/sql.py": '''from dao.base import Dao


class SqlDao(Dao):
    def __init__(self, conn):
        self.conn = conn

    def find(self, key):
        cur = self.conn.cursor()
        cur.execute(<<"SELECT * FROM t WHERE k = '%s'" % key||"SELECT * FROM t WHERE k = %s", (key,)>>)  # frame-expect: CWE-89
        return cur.fetchone()
''',
    "dao/api.py": '''from flask import Flask, request
from dao.sql import SqlDao
import sqlite3

app = Flask(__name__)
dao = SqlDao(sqlite3.connect("t.db"))


@app.route("/k")
def k():
    return str(dao.find(request.args.get("k")))
''',
})

case("staticmethod_classmethod_chain", {
    "util/shell.py": '''import shlex
import subprocess


class Shell:
    prefix = "echo"

    @staticmethod
    def raw(cmd):
        return subprocess.check_output(cmd, shell=True)  # frame-expect: CWE-78

    @classmethod
    def say(cls, text):
        return cls.raw(<<cls.prefix + " " + text||cls.prefix + " " + shlex.quote(text)>>)
''',
    "util/web.py": '''from flask import Flask, request
from util.shell import Shell

app = Flask(__name__)


@app.route("/say")
def say():
    return Shell.say(request.args.get("t", ""))
''',
})


case("decorator_wrapped_handler", {
    "web/deco.py": '''import functools
from flask import session


def login_required(fn):
    @functools.wraps(fn)
    def inner(*a, **kw):
        if not session.get("uid"):
            return "denied", 401
        return fn(*a, **kw)
    return inner
''',
    "web/views.py": '''import sqlite3
from flask import Flask, request
from web.deco import login_required

app = Flask(__name__)


@app.route("/search")
@login_required
def search():
    q = request.args.get("q", "")
    cur = sqlite3.connect("a.db").cursor()
    cur.execute(<<"SELECT * FROM docs WHERE title LIKE '%" + q + "%'"||"SELECT * FROM docs WHERE title LIKE ?", ("%" + q + "%",)>>)  # frame-expect: CWE-89
    return str(cur.fetchall())
''',
})

case("context_manager_cursor", {
    "store/db.py": '''import sqlite3
from contextlib import closing


def open_db():
    return sqlite3.connect("s.db")


def lookup(email):
    with closing(open_db()) as conn:
        with conn:
            cur = conn.cursor()
            cur.execute(<<f"SELECT id FROM users WHERE email = '{email}'"||"SELECT id FROM users WHERE email = ?", (email,)>>)  # frame-expect: CWE-89
            return cur.fetchone()
''',
    "store/web.py": '''from flask import Flask, request
from store.db import lookup

app = Flask(__name__)


@app.route("/who")
def who():
    return str(lookup(request.form["email"]))
''',
})

case("async_fastapi_across_files", {
    "api/repo.py": '''import aiosqlite


async def find_item(name):
    async with aiosqlite.connect("i.db") as db:
        cur = await db.execute(<<"SELECT * FROM items WHERE name = '" + name + "'"||"SELECT * FROM items WHERE name = ?", (name,)>>)  # frame-expect: CWE-89
        return await cur.fetchall()
''',
    "api/main.py": '''from fastapi import FastAPI
from api.repo import find_item

app = FastAPI()


@app.get("/items")
async def items(name: str):
    return await find_item(name)
''',
})

case("generator_yields_request_data", {
    "feed/lines.py": '''from flask import request


def requested_hosts():
    for h in request.args.get("hosts", "").split(","):
        yield h.strip()
''',
    "feed/web.py": '''import subprocess
from flask import Flask
from feed.lines import requested_hosts

app = Flask(__name__)


@app.route("/ping")
def ping():
    for host in requested_hosts():
        subprocess.run(<<"ping -c1 " + host||["ping", "-c1", host]>>, shell=<<True||False>>)  # frame-expect: CWE-78
    return "done"
''',
})

case("pydantic_model_carries_input", {
    "svc/models.py": '''from pydantic import BaseModel


class Lookup(BaseModel):
    table: str
    key: str
''',
    "svc/main.py": '''import sqlite3
from fastapi import FastAPI
from svc.models import Lookup

app = FastAPI()


@app.post("/lookup")
def lookup(body: Lookup):
    cur = sqlite3.connect("d.db").cursor()
    cur.execute(<<"SELECT * FROM data WHERE k = '" + body.key + "'"||"SELECT * FROM data WHERE k = ?", (body.key,)>>)  # frame-expect: CWE-89
    return cur.fetchall()
''',
})

case("fastapi_depends_service", {
    "app/deps.py": '''import os
import shlex


class Archiver:
    def pack(self, folder):
        os.system(<<"tar czf out.tgz " + folder||"tar czf out.tgz " + shlex.quote(folder)>>)  # frame-expect: CWE-78


def get_archiver():
    return Archiver()
''',
    "app/main.py": '''from fastapi import Depends, FastAPI
from app.deps import Archiver, get_archiver

app = FastAPI()


@app.get("/pack")
def pack(folder: str, svc: Archiver = Depends(get_archiver)):
    svc.pack(folder)
    return {"ok": True}
''',
})


case("settings_module_and_relative_imports", {
    "proj/__init__.py": "",
    "proj/settings.py": '''REPORT_DIR = "/srv/reports"
''',
    "proj/files.py": '''import os
from . import settings


def read_report(name):
    path = os.path.join(settings.REPORT_DIR, <<name||os.path.basename(name)>>)
    with open(path) as fh:  # frame-expect: CWE-22
        return fh.read()
''',
    "proj/views.py": '''from flask import Flask, request
from .files import read_report

app = Flask(__name__)


@app.route("/report")
def report():
    return read_report(request.args.get("name", ""))
''',
})

case("parent_package_relative_import", {
    "pkg/__init__.py": "",
    "pkg/core/__init__.py": "",
    "pkg/core/exec.py": '''import os


def launch(cmd):
    os.system(cmd)  # frame-expect: CWE-78
''',
    "pkg/web/__init__.py": "",
    "pkg/web/handlers.py": '''from flask import request
from ..core import exec as core_exec


def handle():
    name = request.args.get("job", "")
    core_exec.launch(<<"run-job " + name||"run-job " + str(int(name))>>)
''',
})

case("package_init_reexport_chain", {
    "lib/__init__.py": '''from .db import run_query
''',
    "lib/db.py": '''import sqlite3


def run_query(sql):
    return sqlite3.connect("l.db").execute(sql).fetchall()  # frame-expect: CWE-89
''',
    "lib/consumer.py": '''from flask import Flask, request
from lib import run_query

app = Flask(__name__)


@app.route("/q")
def q():
    name = request.args.get("n", "")
    return str(run_query(<<"SELECT * FROM t WHERE n = '" + name + "'"||"SELECT * FROM t WHERE n = " + str(int(name))>>))
''',
})

case("conditional_import_fallback", {
    "net/fetch.py": '''try:
    import requests
except ImportError:
    requests = None


def get(url):
    return requests.get(url, timeout=5).text  # frame-expect: CWE-918
''',
    "net/web.py": '''from urllib.parse import urlparse
from flask import Flask, request
from net.fetch import get

app = Flask(__name__)
ALLOWED = {"api.example.com"}


@app.route("/proxy")
def proxy():
    url = request.args.get("url", "")
<<    pass||    if urlparse(url).hostname not in ALLOWED:
        return "blocked", 403>>
    return get(url)
''',
})


case("format_and_percent_query_builders", {
    "q/build.py": '''def by_status(status):
    return <<"SELECT * FROM jobs WHERE status = '{}'".format(status)||"SELECT * FROM jobs WHERE status = {}".format(int(status))>>


def by_owner(owner):
    return <<"SELECT * FROM jobs WHERE owner = '%s'" % owner||"SELECT * FROM jobs WHERE owner = %d" % int(owner)>>
''',
    "q/web.py": '''import sqlite3
from flask import Flask, request
from q.build import by_status, by_owner

app = Flask(__name__)
conn = sqlite3.connect("j.db")


@app.route("/s")
def s():
    return str(conn.execute(by_status(request.args["s"])).fetchall())  # frame-expect: CWE-89


@app.route("/o")
def o():
    return str(conn.execute(by_owner(request.args["o"])).fetchall())  # frame-expect: CWE-89
''',
})

case("pickle_loads_via_helper", {
    "sess/codec.py": '''import base64
import json
import pickle


def decode(blob):
    return <<pickle||json>>.loads(base64.b64decode(blob))  # frame-expect: CWE-502
''',
    "sess/web.py": '''import json
from flask import Flask, request
from sess import codec

app = Flask(__name__)


@app.route("/restore", methods=["POST"])
def restore():
    return str(codec.decode(request.form["state"]))
''',
})

case("yaml_load_vs_safe_load", {
    "cfg/loader.py": '''import yaml


def parse(text):
    return yaml.<<load(text, Loader=yaml.Loader)||safe_load(text)>>  # frame-expect: CWE-502
''',
    "cfg/web.py": '''from flask import Flask, request
from cfg.loader import parse

app = Flask(__name__)


@app.route("/cfg", methods=["POST"])
def cfg():
    return str(parse(request.get_data(as_text=True)))
''',
})

case("eval_of_request_via_helper", {
    "calc/engine.py": '''import ast


def compute(expr):
    return <<eval(expr)||ast.literal_eval(expr)>>  # frame-expect: CWE-94
''',
    "calc/web.py": '''from flask import Flask, request
from calc.engine import compute

app = Flask(__name__)


@app.route("/calc")
def calc():
    return str(compute(request.args.get("e", "1")))
''',
})


case("django_extra_where", {
    "inv/views.py": '''from django.http import JsonResponse
from inv.models import Item


def stock(request):
    sku = request.GET.get("sku", "")
    qs = Item.objects.extra(where=[<<"sku = '%s'" % sku||"sku = %s">>]<<||, params=[sku]>>)  # frame-expect: CWE-89
    return JsonResponse({"n": qs.count()})
''',
    "inv/models.py": '''from django.db import models


class Item(models.Model):
    sku = models.CharField(max_length=20)
''',
})

case("flask_app_factory_blueprints", {
    "svc/__init__.py": '''from flask import Flask


def create_app():
    app = Flask(__name__)
    from svc.files import bp as files_bp
    app.register_blueprint(files_bp, url_prefix="/files")
    return app
''',
    "svc/files.py": '''import os
from flask import Blueprint, request, send_file

bp = Blueprint("files", __name__)
ROOT = "/data/files"


@bp.route("/get")
def get():
    name = request.args.get("name", "")
    path = os.path.join(ROOT, <<name||os.path.basename(name)>>)
    return send_file(path)  # frame-expect: CWE-22
''',
})

case("celery_task_receives_args", {
    "jobs/tasks.py": '''import subprocess
from celery import shared_task


@shared_task
def convert(path, fmt):
    subprocess.call(<<"convert %s out.%s" % (path, fmt)||["convert", path, "out." + fmt]>>, shell=<<True||False>>)  # frame-expect: CWE-78
''',
    "jobs/web.py": '''from flask import Flask, request
from jobs.tasks import convert

app = Flask(__name__)


@app.route("/convert", methods=["POST"])
def start():
    convert.delay(request.form["path"], request.form["fmt"])
    return "queued"
''',
})

case("try_except_around_sink", {
    "rep/store.py": '''import logging
import sqlite3

log = logging.getLogger(__name__)


def totals(region):
    try:
        cur = sqlite3.connect("r.db").cursor()
        cur.execute(<<"SELECT SUM(v) FROM sales WHERE region = '" + region + "'"||"SELECT SUM(v) FROM sales WHERE region = ?", (region,)>>)  # frame-expect: CWE-89
        return cur.fetchone()
    except sqlite3.Error as exc:
        log.warning("failed: %s", exc)
        return None
''',
    "rep/web.py": '''from flask import Flask, request
from rep.store import totals

app = Flask(__name__)


@app.route("/t")
def t():
    return str(totals(request.args.get("region", "")))
''',
})

case("urllib_ssrf_helper", {
    "hooks/client.py": '''import urllib.request


def post_json(url, body):
    req = urllib.request.Request(url, data=body)
    return urllib.request.urlopen(req)  # frame-expect: CWE-918
''',
    "hooks/web.py": '''from flask import Flask, request
from hooks.client import post_json

app = Flask(__name__)
HOOKS = {"slack": "https://hooks.example.com/slack"}


@app.route("/notify", methods=["POST"])
def notify():
    target = <<request.form["callback"]||HOOKS.get(request.form["channel"], HOOKS["slack"])>>
    post_json(target, b"{}")
    return "sent"
''',
})

case("class_attr_service_injected", {
    "mail/sender.py": '''import os
import shlex


class Sender:
    def send(self, to, subject):
        os.system(<<"mail -s '" + subject + "' " + to||"mail -s '" + subject.replace("'", "") + "' " + shlex.quote(to)>>)  # frame-expect: CWE-78
''',
    "mail/controller.py": '''from flask import Flask, request
from mail.sender import Sender

app = Flask(__name__)


class Controller:
    def __init__(self, sender: Sender):
        self.sender = sender

    def handle(self):
        self.sender.send(request.form["to"], "hello")


ctrl = Controller(Sender())


@app.route("/mail", methods=["POST"])
def mail():
    ctrl.handle()
    return "ok"
''',
})


case("dataclass_carries_request_data", {
    "jobs/model.py": '''from dataclasses import dataclass


@dataclass
class Job:
    name: str
    args: str
''',
    "jobs/web.py": '''import os
import shlex
from flask import Flask, request
from jobs.model import Job

app = Flask(__name__)


def parse():
    return Job(request.form["name"], request.form["args"])


@app.route("/job", methods=["POST"])
def job():
    j = parse()
    os.system(<<"run " + j.name + " " + j.args||"run " + shlex.quote(j.name) + " " + shlex.quote(j.args)>>)  # frame-expect: CWE-78
    return "ok"
''',
})

case("django_custom_manager_in_view_module", {
    "blog/managers.py": '''from django.db import models


class PostManager(models.Manager):
    def search(self, term):
        return self.raw(<<"SELECT * FROM blog_post WHERE title = '%s'" % term||"SELECT * FROM blog_post WHERE title = %s", [term]>>)  # frame-expect: CWE-89
''',
    "blog/views.py": '''from django.http import HttpResponse
from blog.managers import PostManager


def search(request):
    rows = PostManager().search(request.GET.get("q", ""))
    return HttpResponse(",".join(p.title for p in rows))
''',
})

case("enumerate_over_request_list", {
    "batch/run.py": '''import subprocess


def ping_all(hosts):
    for i, host in enumerate(hosts):
        subprocess.run(<<"ping -c1 " + host||["ping", "-c1", host]>>, shell=<<True||False>>)  # frame-expect: CWE-78
''',
    "batch/web.py": '''from flask import Flask, request
from batch.run import ping_all

app = Flask(__name__)


@app.route("/ping", methods=["POST"])
def ping():
    ping_all(request.form.getlist("host"))
    return "done"
''',
})

case("constant_table_lookup_is_not_ssrf", {
    "fetch/client.py": '''import urllib.request


def fetch(endpoint):
    return urllib.request.urlopen(endpoint).read()  # frame-expect: CWE-918
''',
    "fetch/web.py": '''from flask import Flask, request
from fetch.client import fetch

app = Flask(__name__)
SOURCES = {"news": "https://news.example.com/feed", "wx": "https://wx.example.com/now"}


@app.route("/feed")
def feed():
    name = request.args.get("src", "news")
    return fetch(<<name||SOURCES.get(name, SOURCES["news"])>>)
''',
})

case("numeric_cast_inline_in_command", {
    "ops/cmd.py": '''import os


def reboot_in(minutes):
    os.system("shutdown -r +" + minutes)  # frame-expect: CWE-78
''',
    "ops/web.py": '''from flask import Flask, request
from ops.cmd import reboot_in

app = Flask(__name__)


@app.route("/reboot", methods=["POST"])
def reboot():
    reboot_in(<<request.form["m"]||str(int(request.form["m"]))>>)
    return "scheduled"
''',
})


case("inherited_helper_via_subclass", {
    "app/base.py": '''class BaseRepo:
    def __init__(self, conn):
        self.conn = conn

    def run(self, sql):
        cur = self.conn.cursor()
        cur.execute(sql)  # frame-expect: CWE-89
        return cur.fetchall()
''',
    "app/users.py": '''from app.base import BaseRepo


class UserRepo(BaseRepo):
    def by_name(self, name):
        return self.run(<<"SELECT * FROM users WHERE name = '" + name + "'"||"SELECT * FROM users WHERE name = '" + str(int(name)) + "'">>)
''',
    "app/web.py": '''from flask import Flask, request
from app.users import UserRepo
import sqlite3

app = Flask(__name__)
repo = UserRepo(sqlite3.connect("x.db"))


@app.route("/u")
def u():
    return str(repo.by_name(request.args.get("name", "")))
''',
})


case("super_call_passes_taint", {
    "svc/base.py": '''import os


class Runner:
    def execute(self, arg):
        os.system("tool " + arg)  # frame-expect: CWE-78
''',
    "svc/child.py": '''from svc.base import Runner


class AuditedRunner(Runner):
    def execute(self, arg):
        print("running")
        super().execute(<<arg||shlex_quote(arg)>>)


def shlex_quote(s):
    import shlex
    return shlex.quote(s)
''',
    "svc/web.py": '''from flask import Flask, request
from svc.child import AuditedRunner

app = Flask(__name__)


@app.route("/run")
def run():
    AuditedRunner().execute(request.args["target"])
    return "ok"
''',
})
