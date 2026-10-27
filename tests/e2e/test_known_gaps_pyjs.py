"""Realistic Python / JavaScript flows Frame does not follow yet, pinned so they cannot go unnoticed.

Each entry is a normal project case (vulnerable tree + safe twin, same markers and rules as
`test_cross_file_e2e.py`). It is a strict xfail: the day the analysis learns the idiom the test
XPASSes and fails the run until the case is moved into `projects_python_more.py` /
`projects_js_more.py`. The comment above each case names the missing piece.
"""

import re

import pytest

from e2e_helpers import expectations, scan, write_tree

_CHOICE = re.compile(r"<<(.*?)\|\|(.*?)>>", re.S)
KNOWN_GAPS = {}


def case(name, files):
    KNOWN_GAPS[name] = (
        {p: _CHOICE.sub(lambda m: m.group(1), t) for p, t in files.items()},
        {p: _CHOICE.sub(lambda m: m.group(2), t) for p, t in files.items()},
    )




# a @property that returns request data is read as an attribute (`ctx.target`): no call is made, so no return summary applies.
case("property_returns_request_data", {
    "ctx/req.py": '''from flask import request


class Ctx:
    @property
    def target(self):
        return request.args.get("target", "")
''',
    "ctx/web.py": '''import os
from flask import Flask
from ctx.req import Ctx

app = Flask(__name__)


@app.route("/t")
def t():
    ctx = Ctx()
    os.system(<<"ping -c1 " + ctx.target||"ping -c1 localhost">>)  # frame-expect: CWE-78
    return "ok"
''',
})

# project.py: `repo = Repo()` at module level of another file is not known as a receiver type after `from shop.repo import repo`.
case("module_singleton_repo", {
    "shop/repo.py": '''import sqlite3


class Repo:
    def __init__(self):
        self.conn = sqlite3.connect("shop.db")

    def by_sku(self, sku):
        cur = self.conn.cursor()
        cur.execute(<<"SELECT * FROM p WHERE sku = '" + sku + "'"||"SELECT * FROM p WHERE sku = ?", (sku,)>>)  # frame-expect: CWE-89
        return cur.fetchall()


repo = Repo()
''',
    "shop/views.py": '''from flask import Flask, request
from shop.repo import repo

app = Flask(__name__)


@app.route("/p")
def p():
    return str(repo.by_sku(request.args.get("sku", "")))
''',
})

# `run = functools.partial(shell, 'echo')`: a partial application is not followed to the wrapped function.
case("functools_partial_dispatch", {
    "tasks/run.py": '''import functools
import os


def shell(prefix, arg):
    os.system(prefix + " " + arg)  # frame-expect: CWE-78


run_echo = functools.partial(shell, "echo")
''',
    "tasks/web.py": '''from flask import Flask, request
from tasks.run import run_echo

app = Flask(__name__)


@app.route("/echo")
def echo():
    text = request.args.get("t", "")
    run_echo(<<text||str(int(text))>>)
    return "ok"
''',
})

# project.py: `Post.objects.search(q)` -- the manager is a class attribute (`objects = PostManager()`), so the receiver's class is unknown.
case("django_manager_raw", {
    "blog/models.py": '''from django.db import models


class PostManager(models.Manager):
    def search(self, term):
        return self.raw(<<"SELECT * FROM blog_post WHERE title = '%s'" % term||"SELECT * FROM blog_post WHERE title = %s", [term]>>)  # frame-expect: CWE-89


class Post(models.Model):
    title = models.CharField(max_length=100)
    objects = PostManager()
''',
    "blog/views.py": '''from django.http import HttpResponse
from blog.models import Post


def search(request):
    rows = Post.objects.search(request.GET.get("q", ""))
    return HttpResponse(",".join(p.title for p in rows))
''',
})



# project.py: `module.exports = new Mailer()` -- the exported instance's class is not known to the importer.
case("module_exports_singleton_instance", {
    "src/mailer.js": '''const { exec } = require("child_process");

class Mailer {
  send(to, subject) {
    exec(<<`mail -s "${subject}" ${to}`||`mail -s "${subject}" ` + require("shell-quote").quote([to])>>); // frame-expect: CWE-78
  }
}

module.exports = new Mailer();
''',
    "src/app.js": '''const express = require("express");
const mailer = require("./mailer");

const app = express();

app.post("/mail", (req, res) => {
  mailer.send(req.body.to, "hello");
  res.send("sent");
});
''',
})

# translator: `req.filter = req.query.filter` (middleware) -- a later read of `req.filter` is not tainted; even within one handler.
case("middleware_chain_sets_req_field", {
    "src/middleware.js": '''function parseFilter(req, res, next) {
  req.filter = req.query.filter;
  next();
}

module.exports = { parseFilter };
''',
    "src/app.js": '''const express = require("express");
const mysql = require("mysql");
const { parseFilter } = require("./middleware");

const app = express();
const db = mysql.createConnection({ host: "localhost" });

app.use(parseFilter);

app.get("/items", (req, res) => {
  db.query(<<"SELECT * FROM items WHERE tag = '" + req.filter + "'"||"SELECT * FROM items WHERE tag = ?", [req.filter]>>, (err, rows) => { // frame-expect: CWE-89
    res.json(rows);
  });
});
''',
})

# translator guards: `path.resolve(BASE, x)` followed by `if (!full.startsWith(BASE + path.sep)) throw/return` is not recognised as containment.
case("path_startswith_guard", {
    "src/static.js": '''const fs = require("fs");
const path = require("path");

const BASE = path.resolve("/srv/assets");

function readAsset(name) {
  const full = path.resolve(BASE, name);
<<  // no containment check||  if (!full.startsWith(BASE + path.sep)) {
    throw new Error("outside base");
  }>>
  return fs.readFileSync(full); // frame-expect: CWE-22
}

module.exports = { readAsset };
''',
    "src/app.js": '''const express = require("express");
const { readAsset } = require("./static");

const app = express();

app.get("/asset", (req, res) => {
  res.send(readAsset(req.query.name));
});
''',
})

# project.py: `container.reporter.render(...)` -- an instance held in an exported object literal is not a known receiver type.
case("inversify_style_di_container", {
    "src/container.ts": '''import { Reporter } from "./reporter";

export const container = {
  reporter: new Reporter(),
};
''',
    "src/reporter.ts": '''import { execSync } from "child_process";

export class Reporter {
  render(title: string): string {
    return execSync(<<`report --title ${title}`||["report", "--title", title].map((p) => JSON.stringify(p)).join(" ")>>).toString(); // frame-expect: CWE-78
  }
}
''',
    "src/app.ts": '''import express from "express";
import { container } from "./container";

const app = express();

app.get("/report", (req, res) => {
  res.send(container.reporter.render(req.query.title as string));
});
''',
})

# project.py: `module.exports = { ...require('./query') }` (and `module.exports = require('./query')`) is not a re-export.
case("cjs_spread_require_barrel", {
    "src/db/query.js": '''function findUser(db, name) {
  return db.query(<<"SELECT * FROM users WHERE name = '" + name + "'"||"SELECT * FROM users WHERE name = ?", [name]>>); // frame-expect: CWE-89
}

module.exports = { findUser };
''',
    "src/db/index.js": '''module.exports = { ...require("./query") };
''',
    "src/app.js": '''const express = require("express");
const mysql = require("mysql");
const { findUser } = require("./db");

const app = express();
const conn = mysql.createConnection({ host: "localhost" });

app.get("/user", (req, res) => {
  findUser(conn, req.query.name);
  res.send("ok");
});
''',
})


@pytest.mark.xfail(strict=True, reason="known limitation (see the comment above the case)")
@pytest.mark.parametrize("name", sorted(KNOWN_GAPS))
def test_known_gap(name, tmp_path):
    vulnerable, safe = KNOWN_GAPS[name]
    vdir = write_tree(tmp_path / "vulnerable", vulnerable)
    sdir = write_tree(tmp_path / "safe", safe)
    expected = expectations(vdir)
    wanted = set().union(*expected.values())
    got = scan(vdir)
    missed = [(p, n) for (p, n), c in expected.items() if not c <= got.at(p, n)]
    leaked = [f for f in scan(sdir).findings if f["cwe_id"] in wanted]
    assert not missed and not leaked, f"missed {missed}; safe twin flagged {[(f['path'], f['line']) for f in leaked]}"
