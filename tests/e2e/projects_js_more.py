"""More realistic JavaScript / TypeScript projects: classes, modules, DI, ORMs, middleware.

Each case is written once with `<<vulnerable||safe>>` choices; the safe twin differs only by the
fix a developer would make. Lines marked `// frame-expect: CWE-n` must be reported.
"""

import re

CASES = {}
_CHOICE = re.compile(r"<<(.*?)\|\|(.*?)>>", re.S)


def case(name, files):
    vulnerable = {p: _CHOICE.sub(lambda m: m.group(1), t) for p, t in files.items()}
    safe = {p: _CHOICE.sub(lambda m: m.group(2), t) for p, t in files.items()}
    CASES[name] = (vulnerable, safe)


# --------------------------------------------------------------------------------------


case("esm_export_star_barrel", {
    "src/db/query.js": '''export function findUser(db, name) {
  return db.query(<<"SELECT * FROM users WHERE name = '" + name + "'"||"SELECT * FROM users WHERE name = ?", [name]>>); // frame-expect: CWE-89
}
''',
    "src/db/index.js": '''export * from "./query.js";
''',
    "src/app.js": '''import express from "express";
import mysql from "mysql";
import { findUser } from "./db/index.js";

const app = express();
const conn = mysql.createConnection({ host: "localhost" });

app.get("/user", (req, res) => {
  findUser(conn, req.query.name);
  res.send("ok");
});
''',
})

case("esm_named_and_default_exports", {
    "src/shell.mjs": '''import { execSync, execFileSync } from "node:child_process";

export function archive(dir) {
  return <<execSync("tar czf out.tgz " + dir)||execFileSync("tar", ["czf", "out.tgz", dir])>>; // frame-expect: CWE-78
}

export default archive;
''',
    "src/server.mjs": '''import express from "express";
import archive from "./shell.mjs";

const app = express();

app.post("/archive", (req, res) => {
  archive(req.body.dir);
  res.send("done");
});
''',
})

case("promise_chain_across_files", {
    "src/store.js": '''const sqlite3 = require("sqlite3");
const db = new sqlite3.Database("app.db");

function findNote(id) {
  return new Promise((resolve, reject) => {
    db.all(<<"SELECT * FROM notes WHERE id = " + id||"SELECT * FROM notes WHERE id = ?", [id]>>, (err, rows) => { // frame-expect: CWE-89
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

module.exports = { findNote };
''',
    "src/app.js": '''const express = require("express");
const { findNote } = require("./store");

const app = express();

app.get("/note", (req, res) => {
  findNote(req.query.id)
    .then((rows) => res.json(rows))
    .catch((e) => res.status(500).send(e.message));
});
''',
})

case("async_await_service", {
    "src/service.js": '''const { Pool } = require("pg");
const pool = new Pool();

async function ordersFor(customer) {
  const res = await pool.query(<<`SELECT * FROM orders WHERE customer = '${customer}'`||"SELECT * FROM orders WHERE customer = $1", [customer]>>); // frame-expect: CWE-89
  return res.rows;
}

module.exports = { ordersFor };
''',
    "src/app.js": '''const express = require("express");
const { ordersFor } = require("./service");

const app = express();

app.get("/orders", async (req, res) => {
  const rows = await ordersFor(req.query.customer);
  res.json(rows);
});
''',
})


case("express_router_mounted_from_index", {
    "src/routes/files.js": '''const express = require("express");
const fs = require("fs");
const path = require("path");

const router = express.Router();
const ROOT = path.join(__dirname, "..", "..", "public");

router.get("/read", (req, res) => {
  const target = path.join(ROOT, <<req.query.name||path.basename(req.query.name)>>);
  res.send(fs.readFileSync(target, "utf8")); // frame-expect: CWE-22
});

module.exports = router;
''',
    "src/routes/index.js": '''const express = require("express");
const files = require("./files");

const router = express.Router();
router.use("/files", files);

module.exports = router;
''',
    "src/app.js": '''const express = require("express");
const routes = require("./routes");

const app = express();
app.use("/api", routes);
app.listen(3000);
''',
})


case("callback_through_helper", {
    "src/util.js": '''function withParam(req, name, cb) {
  cb(req.query[name]);
}

module.exports = { withParam };
''',
    "src/app.js": '''const express = require("express");
const { exec } = require("child_process");
const { withParam } = require("./util");

const app = express();

app.get("/echo", (req, res) => {
  const v = req.query.msg;
  exec(<<"echo " + v||"echo " + Number(v)>>); // frame-expect: CWE-78
  res.send("ok");
});
''',
})

case("tagged_template_vs_concat", {
    "src/db.js": '''const sql = require("sql-template-strings");
const { Pool } = require("pg");
const pool = new Pool();

function byEmail(email) {
  return pool.query(<<`SELECT * FROM users WHERE email = '${email}'`||sql`SELECT * FROM users WHERE email = ${email}`>>); // frame-expect: CWE-89
}

module.exports = { byEmail };
''',
    "src/app.js": '''const express = require("express");
const { byEmail } = require("./db");

const app = express();

app.get("/u", async (req, res) => {
  res.json((await byEmail(req.query.email)).rows);
});
''',
})

case("knex_raw_helper", {
    "src/repo.js": '''const knex = require("knex")({ client: "pg" });

function search(term) {
  return knex.raw(<<`SELECT * FROM products WHERE name ILIKE '%${term}%'`||"SELECT * FROM products WHERE name ILIKE ?", [`%${term}%`]>>); // frame-expect: CWE-89
}

module.exports = { search };
''',
    "src/app.js": '''const express = require("express");
const { search } = require("./repo");

const app = express();

app.get("/search", async (req, res) => {
  res.json(await search(req.query.q));
});
''',
})

case("sequelize_query_replacements", {
    "src/models.js": '''const { Sequelize } = require("sequelize");
const sequelize = new Sequelize("sqlite::memory:");

async function totalFor(region) {
  return sequelize.query(<<"SELECT SUM(v) FROM sales WHERE region = '" + region + "'"||"SELECT SUM(v) FROM sales WHERE region = :region", { replacements: { region } }>>); // frame-expect: CWE-89
}

module.exports = { totalFor };
''',
    "src/app.js": '''const express = require("express");
const { totalFor } = require("./models");

const app = express();

app.get("/total", async (req, res) => {
  res.json(await totalFor(req.query.region));
});
''',
})

case("typeorm_query_in_repository", {
    "src/user.repository.ts": '''import { DataSource } from "typeorm";

export class UserRepository {
  constructor(private readonly ds: DataSource) {}

  findByRole(role: string) {
    return this.ds.query(<<`SELECT * FROM users WHERE role = '${role}'`||"SELECT * FROM users WHERE role = $1", [role]>>); // frame-expect: CWE-89
  }
}
''',
    "src/user.controller.ts": '''import { Controller, Get, Query } from "@nestjs/common";
import { UserRepository } from "./user.repository";

@Controller("users")
export class UserController {
  constructor(private readonly repo: UserRepository) {}

  @Get()
  list(@Query("role") role: string) {
    return this.repo.findByRole(role);
  }
}
''',
})

case("execfile_vs_exec", {
    "src/convert.js": '''const cp = require("child_process");

function toPdf(file) {
  <<cp.exec("libreoffice --convert-to pdf " + file)||cp.execFile("libreoffice", ["--convert-to", "pdf", file])>>; // frame-expect: CWE-78
}

module.exports = { toPdf };
''',
    "src/app.js": '''const express = require("express");
const { toPdf } = require("./convert");

const app = express();

app.post("/pdf", (req, res) => {
  toPdf(req.body.file);
  res.send("queued");
});
''',
})


case("axios_ssrf_helper", {
    "src/http.js": '''const axios = require("axios");

async function getJson(url) {
  const res = await axios.get(url); // frame-expect: CWE-918
  return res.data;
}

module.exports = { getJson };
''',
    "src/app.js": '''const express = require("express");
const { getJson } = require("./http");

const app = express();
const FEEDS = { news: "https://news.example.com/feed", wx: "https://wx.example.com/now" };

app.get("/feed", async (req, res) => {
  res.json(await getJson(<<req.query.url||FEEDS[req.query.name] || FEEDS.news>>));
});
''',
})

case("fetch_ssrf_ts_service", {
    "src/preview.service.ts": '''export class PreviewService {
  async title(url: string): Promise<string> {
    const res = await fetch(url); // frame-expect: CWE-918
    const html = await res.text();
    return html.slice(0, 100);
  }
}
''',
    "src/preview.controller.ts": '''import { Controller, Get, Query } from "@nestjs/common";
import { PreviewService } from "./preview.service";

const ALLOWED = new Set(["https://example.com/", "https://example.org/"]);

@Controller("preview")
export class PreviewController {
  constructor(private readonly svc: PreviewService) {}

  @Get()
  async preview(@Query("url") url: string) {
<<    return this.svc.title(url);||    if (!ALLOWED.has(url)) {
      throw new Error("blocked");
    }
    return this.svc.title(url);>>
  }
}
''',
})

case("nosql_spread_body_into_filter", {
    "src/users.js": '''const User = require("./model");

function find(filter) {
  return User.find(filter); // frame-expect: CWE-943
}

module.exports = { find };
''',
    "src/model.js": '''const mongoose = require("mongoose");

module.exports = mongoose.model("User", new mongoose.Schema({ name: String, pass: String }));
''',
    "src/app.js": '''const express = require("express");
const { find } = require("./users");

const app = express();
app.use(express.json());

app.post("/login", async (req, res) => {
  const user = await find(<<{ ...req.body }||{ name: String(req.body.name), pass: String(req.body.pass) }>>);
  res.json(user);
});
''',
})

case("lodash_merge_prototype_pollution", {
    "src/settings.js": '''const _ = require("lodash");

const defaults = { theme: "light", admin: false };

function build(overrides) {
  return <<_.merge({}, defaults, overrides)||Object.assign({}, defaults, { theme: String(overrides.theme) })>>; // frame-expect: CWE-1321
}

module.exports = { build };
''',
    "src/app.js": '''const express = require("express");
const { build } = require("./settings");

const app = express();
app.use(express.json());

app.post("/settings", (req, res) => {
  res.json(build(req.body));
});
''',
})

case("json_parse_into_function_constructor", {
    "src/rules.js": '''function compile(ruleJson) {
  const rule = JSON.parse(ruleJson);
  return <<new Function("ctx", "return " + rule.expr)||(ctx) => ctx.score > Number(rule.threshold)>>; // frame-expect: CWE-94
}

module.exports = { compile };
''',
    "src/app.js": '''const express = require("express");
const { compile } = require("./rules");

const app = express();

app.post("/eval", (req, res) => {
  const fn = compile(req.body.rule);
  res.json({ ok: fn({ score: 3 }) });
});
''',
})

case("dynamic_import_of_request_path", {
    "src/plugins.js": '''const FORMATS = { csv: "./plugins/csv.js", json: "./plugins/json.js" };

async function load(name) {
  const mod = await import(<<"./plugins/" + name + ".js"||FORMATS[name]>>); // frame-expect: CWE-94
  return mod.default;
}

module.exports = { load };
''',
    "src/app.js": '''const express = require("express");
const { load } = require("./plugins");

const app = express();

app.get("/export", async (req, res) => {
  const plugin = await load(req.query.format);
  res.send(plugin());
});
''',
})

case("tsconfig_path_alias_service", {
    "tsconfig.json": '''{
  "compilerOptions": {
    "baseUrl": ".",
    "paths": { "@app/*": ["src/*"] }
  }
}
''',
    "src/shell/runner.ts": '''import { exec, execFile } from "child_process";

export function convert(file: string): void {
  <<exec("convert " + file + " out.png")||execFile("convert", [file, "out.png"])>>; // frame-expect: CWE-78
}
''',
    "src/server.ts": '''import express from "express";
import { convert } from "@app/shell/runner";

const app = express();

app.post("/convert", (req, res) => {
  convert(req.body.file);
  res.send("ok");
});
''',
})


case("xss_innerhtml_vs_textcontent_server_render", {
    "src/render.js": '''const escapeHtml = require("escape-html");

function page(name) {
  return <<`<h1>Hello ${name}</h1>`||`<h1>Hello ${escapeHtml(name)}</h1>`>>;
}

module.exports = { page };
''',
    "src/app.js": '''const express = require("express");
const { page } = require("./render");

const app = express();

app.get("/hello", (req, res) => {
  res.send(page(req.query.name)); // frame-expect: CWE-79
});
''',
})

case("open_redirect_via_helper", {
    "src/nav.js": '''function after(res, target) {
  res.redirect(target); // frame-expect: CWE-601
}

module.exports = { after };
''',
    "src/app.js": '''const express = require("express");
const { after } = require("./nav");

const app = express();
const PAGES = { home: "/", account: "/account" };

app.get("/go", (req, res) => {
  after(res, <<req.query.next||PAGES[req.query.page] || "/">>);
});
''',
})

case("path_join_inline_request_value", {
    "src/files.js": '''const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..", "public");

function readPublic(req) {
  const target = path.join(ROOT, <<req.query.name||path.basename(req.query.name)>>);
  return fs.readFileSync(target, "utf8"); // frame-expect: CWE-22
}

module.exports = { readPublic };
''',
    "src/app.js": '''const express = require("express");
const { readPublic } = require("./files");

const app = express();

app.get("/public", (req, res) => {
  res.type("text/plain").send(readPublic(req));
});
''',
})

case("set_has_allowlist_guard", {
    "src/proxy.js": '''const axios = require("axios");

const ALLOWED = new Set(["https://api.example.com/v1", "https://api.example.org/v1"]);

async function relay(req, res) {
  const target = req.query.target;
<<  // forward whatever was asked for||  if (!ALLOWED.has(target)) {
    return res.status(403).send("blocked");
  }>>
  const upstream = await axios.get(target); // frame-expect: CWE-918
  res.json(upstream.data);
}

module.exports = { relay };
''',
    "src/app.js": '''const express = require("express");
const { relay } = require("./proxy");

const app = express();
app.get("/relay", relay);
''',
})

case("prisma_raw_unsafe_vs_tagged", {
    "src/repo.ts": '''import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

export async function byEmail(email: string) {
  return <<prisma.$queryRawUnsafe(`SELECT * FROM "User" WHERE email = '${email}'`)||prisma.$queryRaw`SELECT * FROM "User" WHERE email = ${email}`>>; // frame-expect: CWE-89
}
''',
    "src/server.ts": '''import express from "express";
import { byEmail } from "./repo";

const app = express();

app.get("/user", async (req, res) => {
  res.json(await byEmail(String(req.query.email)));
});
''',
})

case("spawn_shell_option", {
    "src/git.js": '''const { spawn } = require("child_process");

function log(branch) {
  return spawn(<<"git log " + branch||"git", ["log", branch]>>, <<{ shell: true }||{ shell: false }>>); // frame-expect: CWE-78
}

module.exports = { log };
''',
    "src/app.js": '''const express = require("express");
const { log } = require("./git");

const app = express();

app.get("/log", (req, res) => {
  const child = log(req.query.branch);
  child.stdout.pipe(res);
});
''',
})

case("promisified_exec_async", {
    "src/sh.js": '''const util = require("util");
const cp = require("child_process");
const execAsync = util.promisify(cp.exec);

async function whois(domain) {
  const { stdout } = await <<execAsync("whois " + domain)||util.promisify(cp.execFile)("whois", [domain])>>; // frame-expect: CWE-78
  return stdout;
}

module.exports = { whois };
''',
    "src/app.js": '''const express = require("express");
const { whois } = require("./sh");

const app = express();

app.get("/whois", async (req, res) => {
  res.send(await whois(req.query.domain));
});
''',
})

case("mongoose_where_string", {
    "src/orders.js": '''const mongoose = require("mongoose");
const Order = mongoose.model("Order", new mongoose.Schema({ owner: String, total: Number }));

function ownedBy(owner) {
  return Order.find(<<{ $where: "this.owner == '" + owner + "'" }||{ owner: String(owner) }>>); // frame-expect: CWE-943
}

module.exports = { ownedBy };
''',
    "src/app.js": '''const express = require("express");
const { ownedBy } = require("./orders");

const app = express();

app.get("/orders", async (req, res) => {
  res.json(await ownedBy(req.query.owner));
});
''',
})


case("class_inheritance_super_call", {
    "src/base.js": '''const { exec } = require("child_process");

class BaseRunner {
  run(cmd) {
    exec(cmd); // frame-expect: CWE-78
  }
}

module.exports = BaseRunner;
''',
    "src/runner.js": '''const BaseRunner = require("./base");

class PingRunner extends BaseRunner {
  ping(host) {
    this.run(<<"ping -c1 " + host||"ping -c1 " + String(parseInt(host, 10))>>);
  }
}

module.exports = PingRunner;
''',
    "src/app.js": '''const express = require("express");
const PingRunner = require("./runner");

const app = express();
const runner = new PingRunner();

app.get("/ping", (req, res) => {
  runner.ping(req.query.host);
  res.send("ok");
});
''',
})

# Containment: `path.resolve(BASE, x)` then `if (!full.startsWith(BASE + path.sep)) throw` (a normalised path under a constant base).
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

# A constructor function's prototype method (`Exporter.prototype.run = function`) resolves like a class method.
case("prototype_constructor_method_in_file", {
    "app.js": '''const express = require("express");
const { execSync } = require("child_process");
const app = express();

function Exporter() {}
Exporter.prototype.run = function (name) {
  return execSync("export --name " + name).toString(); // frame-expect: CWE-78
};

app.get("/e", (req, res) => {
  const e = new Exporter();
  res.send(e.run(<<req.query.name||String(parseInt(req.query.name, 10))>>));
});
''',
})
