"""Realistic multi-file JavaScript / TypeScript projects (vulnerable tree + safe twin)."""

CASES = {}


def case(name, vulnerable, safe):
    CASES[name] = (vulnerable, safe)


# --------------------------------------------------------------------------------------
# The applications that register the handlers the cases below define in other files.
_SEARCH_APP = '''const express = require("express");
const search = require("./routes/search");

const app = express();
app.get("/search", search);
module.exports = app;
'''
_USERS_APP = '''const express = require("express");
const users = require("./controllers/users");

const app = express();
app.get("/users/:id", users.show);
module.exports = app;
'''
_LOGIN_APP = '''const express = require("express");
const login = require("./controllers/login");

const app = express();
app.post("/login", express.json(), login.login);
module.exports = app;
'''

_APP = '''const express = require("express");
const users = require("./routes/users");

const app = express();
app.use(express.json());
app.use("/users", users);
module.exports = app;
'''
_ROUTES = '''const express = require("express");
const service = require("../services/userService");

const router = express.Router();

router.get("/", async (req, res) => {
  const rows = await service.search(req.query.name);
  res.json(rows);
});

module.exports = router;
'''
_SERVICE = '''const repo = require("../db/userRepo");

exports.search = (name) => repo.findByName(name.trim());
'''
case("express_routes_service_repo_mysql", {
    "app.js": _APP, "routes/users.js": _ROUTES, "services/userService.js": _SERVICE,
    "db/userRepo.js": '''const mysql = require("mysql");
const conn = mysql.createConnection({ host: "db", user: "app", database: "shop" });

exports.findByName = (name) =>
  new Promise((resolve, reject) => {
    conn.query("SELECT * FROM users WHERE name = '" + name + "'", (err, rows) => {  // frame-expect: CWE-89
      if (err) reject(err);
      else resolve(rows);
    });
  });
''',
}, {
    "app.js": _APP, "routes/users.js": _ROUTES, "services/userService.js": _SERVICE,
    "db/userRepo.js": '''const mysql = require("mysql");
const conn = mysql.createConnection({ host: "db", user: "app", database: "shop" });

exports.findByName = (name) =>
  new Promise((resolve, reject) => {
    conn.query("SELECT * FROM users WHERE name = ?", [name], (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
''',
})

# --------------------------------------------------------------------------------------
_ESM_SERVER = '''import express from "express";
import { runReport } from "./reports/index.js";

const app = express();

app.get("/report", (req, res) => {
  const out = runReport(req.query.name);
  res.send(out);
});

export default app;
'''
case("esm_barrel_reexport_command", {
    "server.js": _ESM_SERVER,
    "reports/index.js": 'export { runReport } from "./runner.js";\n',
    "reports/runner.js": '''import { execSync } from "node:child_process";

export function runReport(name) {
  return execSync(`generate-report --name ${name}`).toString();  // frame-expect: CWE-78
}
''',
}, {
    "server.js": _ESM_SERVER,
    "reports/index.js": 'export { runReport } from "./runner.js";\n',
    "reports/runner.js": '''import { execFileSync } from "node:child_process";

export function runReport(name) {
  return execFileSync("generate-report", ["--name", name]).toString();
}
''',
})

# --------------------------------------------------------------------------------------
_CTRL = '''const UserService = require("../services/userService");
const db = require("../db");

const service = new UserService(db);

exports.show = (req, res) => {
  service.find(req.params.id).then((u) => res.json(u));
};
'''
case("class_service_constructed_with_db", {
    "app.js": _USERS_APP,
    "controllers/users.js": _CTRL,
    "db.js": '''const mysql = require("mysql");
module.exports = mysql.createPool({ host: "db", database: "shop" });
''',
    "services/userService.js": '''class UserService {
  constructor(db) {
    this.db = db;
  }

  find(id) {
    return new Promise((resolve, reject) => {
      this.db.query(`SELECT * FROM users WHERE id = ${id}`, (e, rows) => (e ? reject(e) : resolve(rows[0])));  // frame-expect: CWE-89
    });
  }
}

module.exports = UserService;
''',
}, {
    "app.js": _USERS_APP,
    "controllers/users.js": _CTRL,
    "db.js": '''const mysql = require("mysql");
module.exports = mysql.createPool({ host: "db", database: "shop" });
''',
    "services/userService.js": '''class UserService {
  constructor(db) {
    this.db = db;
  }

  find(id) {
    return new Promise((resolve, reject) => {
      this.db.query("SELECT * FROM users WHERE id = ?", [id], (e, rows) => (e ? reject(e) : resolve(rows[0])));
    });
  }
}

module.exports = UserService;
''',
})

# --------------------------------------------------------------------------------------
_LOGIN = '''const auth = require("../auth");

exports.login = async (req, res) => {
  const user = await auth.authenticate(req.body);
  if (!user) return res.status(401).end();
  res.json({ ok: true });
};
'''
case("nosql_operator_injection_through_helper", {
    "app.js": _LOGIN_APP,
    "controllers/login.js": _LOGIN,
    "auth.js": '''const { MongoClient } = require("mongodb");
const client = new MongoClient(process.env.MONGO_URL);

exports.authenticate = async (creds) => {
  const users = client.db("app").collection("users");
  return users.findOne({ username: creds.username, password: creds.password });  // frame-expect: CWE-943
};
''',
}, {
    "app.js": _LOGIN_APP,
    "controllers/login.js": _LOGIN,
    "auth.js": '''const { MongoClient } = require("mongodb");
const client = new MongoClient(process.env.MONGO_URL);

exports.authenticate = async (creds) => {
  const users = client.db("app").collection("users");
  return users.findOne({ username: String(creds.username), password: String(creds.password) });
};
''',
})

# --------------------------------------------------------------------------------------
_NEST_CTRL = '''import { Controller, Get, Query } from "@nestjs/common";
import { UsersService } from "./users.service";

@Controller("users")
export class UsersController {
  constructor(private readonly users: UsersService) {}

  @Get()
  find(@Query("name") name: string) {
    return this.users.findByName(name);
  }
}
'''
_NEST_SVC = '''import { Injectable } from "@nestjs/common";
import { UsersRepository } from "./users.repository";

@Injectable()
export class UsersService {
  constructor(private readonly repo: UsersRepository) {}

  findByName(name: string) {
    return this.repo.findByName(name);
  }
}
'''
case("nestjs_controller_service_repository", {
    "src/users/users.controller.ts": _NEST_CTRL,
    "src/users/users.service.ts": _NEST_SVC,
    "src/users/users.repository.ts": '''import { Injectable } from "@nestjs/common";
import { DataSource } from "typeorm";

@Injectable()
export class UsersRepository {
  constructor(private readonly dataSource: DataSource) {}

  findByName(name: string) {
    return this.dataSource.query(`SELECT * FROM users WHERE name = '${name}'`);  // frame-expect: CWE-89
  }
}
''',
}, {
    "src/users/users.controller.ts": _NEST_CTRL,
    "src/users/users.service.ts": _NEST_SVC,
    "src/users/users.repository.ts": '''import { Injectable } from "@nestjs/common";
import { DataSource } from "typeorm";

@Injectable()
export class UsersRepository {
  constructor(private readonly dataSource: DataSource) {}

  findByName(name: string) {
    return this.dataSource.query("SELECT * FROM users WHERE name = $1", [name]);
  }
}
''',
})

# --------------------------------------------------------------------------------------
case("closure_builds_query_from_outer_variable", {
    "app.js": _SEARCH_APP,
    "routes/search.js": '''const db = require("../db");

module.exports = function search(req, res) {
  const term = req.query.q;
  const buildQuery = () => "SELECT * FROM products WHERE title LIKE '%" + term + "%'";
  db.query(buildQuery(), (err, rows) => res.json(rows));  // frame-expect: CWE-89
};
''',
    "db.js": '''const mysql = require("mysql");
module.exports = mysql.createPool({ host: "db", database: "shop" });
''',
}, {
    "app.js": _SEARCH_APP,
    "routes/search.js": '''const db = require("../db");

module.exports = function search(req, res) {
  const term = req.query.q;
  const buildQuery = () => ["SELECT * FROM products WHERE title LIKE ?", ["%" + term + "%"]];
  db.query(...buildQuery(), (err, rows) => res.json(rows));
};
''',
    "db.js": '''const mysql = require("mysql");
module.exports = mysql.createPool({ host: "db", database: "shop" });
''',
})

# --------------------------------------------------------------------------------------
_PROFILE = '''const express = require("express");
const router = express.Router();

router.post("/profile", (req, res) => {
  res.render("profile", { bio: req.body.bio });  // MARK
});

module.exports = router;
'''
case("ejs_template_raw_versus_escaped", {
    "routes/profile.js": _PROFILE.replace("// MARK", "// frame-expect: CWE-79"),
    "views/profile.ejs": "<h1>Profile</h1>\n<div class=\"bio\"><%- bio %></div>\n",
}, {
    "routes/profile.js": _PROFILE.replace("  // MARK", ""),
    "views/profile.ejs": "<h1>Profile</h1>\n<div class=\"bio\"><%= bio %></div>\n",
})

# --------------------------------------------------------------------------------------
_DL_ROUTE = '''const express = require("express");
const files = require("../files");

const router = express.Router();

router.get("/download/:name", (req, res) => {
  res.sendFile(files.resolve(req.params.name));  // MARK
});

module.exports = router;
'''
case("path_traversal_through_resolver", {
    "routes/download.js": _DL_ROUTE.replace("// MARK", "// frame-expect: CWE-22"),
    "files.js": '''const path = require("path");
const BASE = "/srv/uploads";

exports.resolve = (name) => path.join(BASE, name);
''',
}, {
    "routes/download.js": _DL_ROUTE.replace("  // MARK", ""),
    "files.js": '''const path = require("path");
const BASE = "/srv/uploads";

exports.resolve = (name) => path.join(BASE, path.basename(name));
''',
})

# --------------------------------------------------------------------------------------
case("open_redirect_same_origin_guard", {
    "routes/login.js": '''const express = require("express");
const router = express.Router();

router.post("/login", (req, res) => {
  const next = req.body.next || "/";
  if (next.startsWith("/")) {
    return res.redirect(next);  // frame-expect: CWE-601
  }
  res.redirect("/");
});

module.exports = router;
''',
}, {
    "routes/login.js": '''const express = require("express");
const router = express.Router();

router.post("/login", (req, res) => {
  const next = req.body.next || "/";
  if (next.startsWith("/") && !next.startsWith("//")) {
    return res.redirect(next);
  }
  res.redirect("/");
});

module.exports = router;
''',
})

# --------------------------------------------------------------------------------------
case("ssrf_host_allowlist", {
    "routes/proxy.js": '''const axios = require("axios");
const express = require("express");
const router = express.Router();

router.get("/fetch", async (req, res) => {
  const r = await axios.get(req.query.url);  // frame-expect: CWE-918
  res.send(r.data);
});

module.exports = router;
''',
}, {
    "routes/proxy.js": '''const axios = require("axios");
const express = require("express");
const router = express.Router();

const ALLOWED_HOSTS = ["api.partner.example", "cdn.partner.example"];

router.get("/fetch", async (req, res) => {
  const target = req.query.url;
  if (!ALLOWED_HOSTS.includes(new URL(target).hostname)) {
    return res.status(400).end();
  }
  const r = await axios.get(target);
  res.send(r.data);
});

module.exports = router;
''',
})
