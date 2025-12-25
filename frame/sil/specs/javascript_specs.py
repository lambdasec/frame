"""
Library specifications for JavaScript/TypeScript frameworks.

This module defines ProcSpec for common JS/TS APIs including:
- Express (web framework)
- Node.js standard library
- MongoDB/Mongoose (database)
- DOM APIs (browser)
- React (frontend framework)
"""

from typing import Dict
from frame.sil.procedure import ProcSpec


def _source(kind: str, desc: str = "") -> ProcSpec:
    """Create a taint source spec"""
    return ProcSpec(is_source=kind, description=desc)


def _sink(kind: str, args: list = None, desc: str = "") -> ProcSpec:
    """Create a taint sink spec"""
    return ProcSpec(is_sink=kind, sink_args=args or [0], description=desc)


def _sanitizer(kinds: list, desc: str = "") -> ProcSpec:
    """Create a sanitizer spec"""
    return ProcSpec(is_sanitizer=kinds, description=desc)


def _propagator(args: list, desc: str = "") -> ProcSpec:
    """Create a taint propagator spec"""
    return ProcSpec(taint_propagates=args, description=desc)


# =============================================================================
# Express.js Framework
# =============================================================================

EXPRESS_SPECS = {
    # Request data (taint sources)
    "req.body": _source("user", "Express request body"),
    "req.query": _source("user", "Express query parameters"),
    "req.params": _source("user", "Express route parameters"),
    "req.cookies": _source("user", "Express cookies"),
    "req.headers": _source("user", "Express request headers"),
    "req.get": _source("user", "Express header getter"),
    "req.header": _source("user", "Express header getter"),
    "req.param": _source("user", "Express parameter getter"),
    "req.files": _source("file", "Express file uploads"),
    "req.file": _source("file", "Express single file upload"),

    # Response sinks (XSS)
    "res.send": _sink("html", [0], "Express response (XSS)"),
    "res.write": _sink("html", [0], "Express response write (XSS)"),
    "res.end": _sink("html", [0], "Express response end (XSS)"),
    "res.render": _sink("html", [1], "Express template render"),
    "res.json": _propagator([0], "Express JSON response"),

    # Redirects
    "res.redirect": _sink("redirect", [0], "Express redirect (open redirect)"),

    # Headers
    "res.setHeader": _sink("header", [1], "Express header injection"),
    "res.set": _sink("header", [1], "Express header injection"),
}

# =============================================================================
# Node.js Standard Library
# =============================================================================

NODE_SPECS = {
    # File System (path traversal sinks)
    "fs.readFile": _sink("path", [0], "Node.js file read (path traversal)"),
    "fs.readFileSync": _sink("path", [0], "Node.js file read sync (path traversal)"),
    "fs.writeFile": _sink("path", [0], "Node.js file write (path traversal)"),
    "fs.writeFileSync": _sink("path", [0], "Node.js file write sync (path traversal)"),
    "fs.unlink": _sink("path", [0], "Node.js file delete (path traversal)"),
    "fs.unlinkSync": _sink("path", [0], "Node.js file delete sync (path traversal)"),
    "fs.readdir": _sink("path", [0], "Node.js directory read (path traversal)"),
    "fs.readdirSync": _sink("path", [0], "Node.js directory read sync (path traversal)"),
    "fs.stat": _sink("path", [0], "Node.js file stat (path traversal)"),
    "fs.statSync": _sink("path", [0], "Node.js file stat sync (path traversal)"),
    "fs.access": _sink("path", [0], "Node.js file access (path traversal)"),
    "fs.accessSync": _sink("path", [0], "Node.js file access sync (path traversal)"),
    "fs.createReadStream": _sink("path", [0], "Node.js read stream (path traversal)"),
    "fs.createWriteStream": _sink("path", [0], "Node.js write stream (path traversal)"),

    # Path module
    "path.join": _propagator([0, 1], "Path join (propagates taint)"),
    "path.resolve": _propagator([0], "Path resolve (propagates taint)"),
    "path.normalize": _propagator([0], "Path normalize (propagates taint)"),

    # Child Process (command injection sinks)
    "child_process.exec": _sink("command", [0], "Node.js exec (command injection)"),
    "child_process.execSync": _sink("command", [0], "Node.js execSync (command injection)"),
    "child_process.spawn": _sink("command", [0, 1], "Node.js spawn (command injection)"),
    "child_process.spawnSync": _sink("command", [0, 1], "Node.js spawnSync (command injection)"),
    "child_process.execFile": _sink("command", [0, 1], "Node.js execFile (command injection)"),
    "child_process.execFileSync": _sink("command", [0, 1], "Node.js execFileSync (command injection)"),
    "child_process.fork": _sink("command", [0], "Node.js fork (command injection)"),
    "exec": _sink("command", [0], "exec (command injection)"),
    "execSync": _sink("command", [0], "execSync (command injection)"),
    "spawn": _sink("command", [0, 1], "spawn (command injection)"),

    # Process
    "process.env": _source("env", "Environment variables"),
    "process.argv": _source("user", "Command line arguments"),

    # HTTP (SSRF sinks)
    "http.get": _sink("ssrf", [0], "Node.js HTTP GET (SSRF)"),
    "http.request": _sink("ssrf", [0], "Node.js HTTP request (SSRF)"),
    "https.get": _sink("ssrf", [0], "Node.js HTTPS GET (SSRF)"),
    "https.request": _sink("ssrf", [0], "Node.js HTTPS request (SSRF)"),

    # URL
    "url.parse": _propagator([0], "URL parse (propagates taint)"),
    "new URL": _propagator([0], "URL constructor (propagates taint)"),

    # Crypto (weak crypto detection)
    "crypto.createHash": _propagator([0], "Hash creation"),

    # Eval (code injection)
    "eval": _sink("code", [0], "eval (code injection)"),
    "Function": _sink("code", [0], "Function constructor (code injection)"),
    "setTimeout": _sink("code", [0], "setTimeout with string (code injection)"),
    "setInterval": _sink("code", [0], "setInterval with string (code injection)"),
    "vm.runInThisContext": _sink("code", [0], "vm.runInThisContext (code injection)"),
    "vm.runInNewContext": _sink("code", [0], "vm.runInNewContext (code injection)"),
}

# =============================================================================
# MongoDB / Mongoose
# =============================================================================

MONGODB_SPECS = {
    # Query methods (NoSQL injection sinks)
    "find": _sink("nosql", [0], "MongoDB find (NoSQL injection)"),
    "findOne": _sink("nosql", [0], "MongoDB findOne (NoSQL injection)"),
    "findById": _sink("nosql", [0], "MongoDB findById (NoSQL injection)"),
    "findOneAndUpdate": _sink("nosql", [0, 1], "MongoDB findOneAndUpdate (NoSQL injection)"),
    "findOneAndDelete": _sink("nosql", [0], "MongoDB findOneAndDelete (NoSQL injection)"),
    "findOneAndRemove": _sink("nosql", [0], "MongoDB findOneAndRemove (NoSQL injection)"),
    "findByIdAndUpdate": _sink("nosql", [0, 1], "MongoDB findByIdAndUpdate (NoSQL injection)"),
    "findByIdAndDelete": _sink("nosql", [0], "MongoDB findByIdAndDelete (NoSQL injection)"),
    "updateOne": _sink("nosql", [0, 1], "MongoDB updateOne (NoSQL injection)"),
    "updateMany": _sink("nosql", [0, 1], "MongoDB updateMany (NoSQL injection)"),
    "deleteOne": _sink("nosql", [0], "MongoDB deleteOne (NoSQL injection)"),
    "deleteMany": _sink("nosql", [0], "MongoDB deleteMany (NoSQL injection)"),
    "aggregate": _sink("nosql", [0], "MongoDB aggregate (NoSQL injection)"),
    "where": _sink("nosql", [0], "MongoDB where (NoSQL injection)"),
    "$where": _sink("nosql", [0], "MongoDB $where (code injection)"),

    # Collection methods
    "collection.find": _sink("nosql", [0], "MongoDB collection.find (NoSQL injection)"),
    "collection.findOne": _sink("nosql", [0], "MongoDB collection.findOne (NoSQL injection)"),
    "collection.insertOne": _sink("nosql", [0], "MongoDB insertOne"),
    "collection.insertMany": _sink("nosql", [0], "MongoDB insertMany"),
}

# =============================================================================
# SQL Databases (mysql, pg, sequelize)
# =============================================================================

SQL_SPECS = {
    # mysql/mysql2
    "connection.query": _sink("sql", [0], "MySQL query (SQL injection)"),
    "connection.execute": _sink("sql", [0], "MySQL execute (SQL injection)"),
    "pool.query": _sink("sql", [0], "MySQL pool query (SQL injection)"),
    "pool.execute": _sink("sql", [0], "MySQL pool execute (SQL injection)"),

    # pg (PostgreSQL)
    "client.query": _sink("sql", [0], "PostgreSQL query (SQL injection)"),
    "pool.query": _sink("sql", [0], "PostgreSQL pool query (SQL injection)"),

    # Sequelize
    "sequelize.query": _sink("sql", [0], "Sequelize raw query (SQL injection)"),
    "Model.findAll": _sink("sql", [0], "Sequelize findAll (potential SQL injection)"),
    "Model.findOne": _sink("sql", [0], "Sequelize findOne (potential SQL injection)"),
    "sequelize.literal": _sink("sql", [0], "Sequelize literal (SQL injection)"),

    # Knex
    "knex.raw": _sink("sql", [0], "Knex raw query (SQL injection)"),
    "whereRaw": _sink("sql", [0], "Knex whereRaw (SQL injection)"),
    "havingRaw": _sink("sql", [0], "Knex havingRaw (SQL injection)"),
    "orderByRaw": _sink("sql", [0], "Knex orderByRaw (SQL injection)"),
}

# =============================================================================
# DOM APIs (Browser)
# =============================================================================

DOM_SPECS = {
    # XSS sinks
    "innerHTML": _sink("html", [0], "innerHTML (XSS)"),
    "outerHTML": _sink("html", [0], "outerHTML (XSS)"),
    "document.write": _sink("html", [0], "document.write (XSS)"),
    "document.writeln": _sink("html", [0], "document.writeln (XSS)"),
    "insertAdjacentHTML": _sink("html", [1], "insertAdjacentHTML (XSS)"),
    "element.innerHTML": _sink("html", [0], "element.innerHTML (XSS)"),
    "element.outerHTML": _sink("html", [0], "element.outerHTML (XSS)"),

    # Script injection
    "script.src": _sink("code", [0], "script.src (script injection)"),
    "script.text": _sink("code", [0], "script.text (script injection)"),

    # URL sinks
    "location.href": _sink("redirect", [0], "location.href (open redirect)"),
    "location.assign": _sink("redirect", [0], "location.assign (open redirect)"),
    "location.replace": _sink("redirect", [0], "location.replace (open redirect)"),
    "window.open": _sink("redirect", [0], "window.open (open redirect)"),

    # Taint sources (browser)
    "location.search": _source("user", "URL query string"),
    "location.hash": _source("user", "URL hash"),
    "location.pathname": _source("user", "URL pathname"),
    "document.URL": _source("user", "Document URL"),
    "document.documentURI": _source("user", "Document URI"),
    "document.referrer": _source("user", "Document referrer"),
    "document.cookie": _source("user", "Document cookies"),
    "window.name": _source("user", "Window name"),

    # postMessage
    "event.data": _source("user", "postMessage data"),
    "message.data": _source("user", "Message event data"),
}

# =============================================================================
# React / Frontend Frameworks
# =============================================================================

REACT_SPECS = {
    # XSS sink
    "dangerouslySetInnerHTML": _sink("html", [0], "React dangerouslySetInnerHTML (XSS)"),

    # Safe by default (but track taint)
    "setState": _propagator([0], "React setState"),
    "useState": _propagator([0], "React useState"),
}

# =============================================================================
# HTTP Clients (SSRF sources)
# =============================================================================

HTTP_CLIENT_SPECS = {
    # axios
    "axios": _sink("ssrf", [0], "axios (SSRF)"),
    "axios.get": _sink("ssrf", [0], "axios.get (SSRF)"),
    "axios.post": _sink("ssrf", [0], "axios.post (SSRF)"),
    "axios.put": _sink("ssrf", [0], "axios.put (SSRF)"),
    "axios.delete": _sink("ssrf", [0], "axios.delete (SSRF)"),
    "axios.request": _sink("ssrf", [0], "axios.request (SSRF)"),

    # fetch
    "fetch": _sink("ssrf", [0], "fetch (SSRF)"),

    # request (deprecated but still used)
    "request": _sink("ssrf", [0], "request (SSRF)"),
    "request.get": _sink("ssrf", [0], "request.get (SSRF)"),
    "request.post": _sink("ssrf", [0], "request.post (SSRF)"),

    # got
    "got": _sink("ssrf", [0], "got (SSRF)"),
    "got.get": _sink("ssrf", [0], "got.get (SSRF)"),
    "got.post": _sink("ssrf", [0], "got.post (SSRF)"),

    # node-fetch
    "node-fetch": _sink("ssrf", [0], "node-fetch (SSRF)"),
}

# =============================================================================
# Serialization
# =============================================================================

SERIALIZATION_SPECS = {
    # JSON (generally safe but track)
    "JSON.parse": _propagator([0], "JSON.parse (propagates taint)"),
    "JSON.stringify": _propagator([0], "JSON.stringify (propagates taint)"),

    # Unsafe deserialization
    "serialize": _propagator([0], "serialize"),
    "unserialize": _sink("deserialize", [0], "unserialize (unsafe deserialization)"),
    "node-serialize.unserialize": _sink("deserialize", [0], "node-serialize.unserialize (RCE)"),
    "js-yaml.load": _sink("deserialize", [0], "js-yaml.load (unsafe by default)"),
    "yaml.load": _sink("deserialize", [0], "yaml.load (unsafe deserialization)"),
}

# =============================================================================
# Sanitizers
# =============================================================================

SANITIZER_SPECS = {
    # HTML sanitizers
    "escape": _sanitizer(["html"], "HTML escape"),
    "encodeURIComponent": _sanitizer(["url"], "URL encode"),
    "encodeURI": _sanitizer(["url"], "URI encode"),
    "DOMPurify.sanitize": _sanitizer(["html"], "DOMPurify sanitize"),
    "sanitize-html": _sanitizer(["html"], "sanitize-html"),
    "xss": _sanitizer(["html"], "xss filter"),
    "validator.escape": _sanitizer(["html"], "validator.escape"),

    # SQL sanitizers
    "escape": _sanitizer(["sql"], "SQL escape"),
    "mysql.escape": _sanitizer(["sql"], "MySQL escape"),
    "pg.escapeLiteral": _sanitizer(["sql"], "PostgreSQL escape literal"),
    "pg.escapeIdentifier": _sanitizer(["sql"], "PostgreSQL escape identifier"),

    # Path sanitizers
    "path.basename": _sanitizer(["path"], "Path basename (partial sanitizer)"),
}

# =============================================================================
# Combined JavaScript Specs
# =============================================================================

JAVASCRIPT_SPECS: Dict[str, ProcSpec] = {}
JAVASCRIPT_SPECS.update(EXPRESS_SPECS)
JAVASCRIPT_SPECS.update(NODE_SPECS)
JAVASCRIPT_SPECS.update(MONGODB_SPECS)
JAVASCRIPT_SPECS.update(SQL_SPECS)
JAVASCRIPT_SPECS.update(DOM_SPECS)
JAVASCRIPT_SPECS.update(REACT_SPECS)
JAVASCRIPT_SPECS.update(HTTP_CLIENT_SPECS)
JAVASCRIPT_SPECS.update(SERIALIZATION_SPECS)
JAVASCRIPT_SPECS.update(SANITIZER_SPECS)

# Alias for TypeScript (same specs)
TYPESCRIPT_SPECS = JAVASCRIPT_SPECS
