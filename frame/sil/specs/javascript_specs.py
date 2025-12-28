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
# A01: Broken Access Control (OWASP 2025)
# =============================================================================

ACCESS_CONTROL_SPECS = {
    # JWT handling (potential vulnerabilities)
    "jwt.verify": _sink("auth", [0], "JWT verify - check algorithm (CWE-347)"),
    "jwt.decode": _sink("auth", [0], "JWT decode without verify (CWE-347)"),
    "jwt.sign": _propagator([0], "JWT sign"),
    "jsonwebtoken.verify": _sink("auth", [0], "JWT verify (CWE-347)"),
    "jsonwebtoken.decode": _sink("auth", [0], "JWT decode (CWE-347)"),

    # Session handling
    "req.session": _source("user", "Express session data"),
    "session.userId": _source("user", "Session user ID"),
    "session.user": _source("user", "Session user object"),

    # CORS (misconfiguration detection)
    "cors": _sink("cors", [0], "CORS middleware configuration (CWE-942)"),
    "Access-Control-Allow-Origin": _sink("cors", [0], "CORS header (CWE-942)"),
    "origin: '*'": _sink("cors", [0], "CORS allow all origins (CWE-942)"),
    "origin: true": _sink("cors", [0], "CORS reflect origin (CWE-942)"),

    # Authorization middleware
    "isAuthenticated": _propagator([0], "Authentication check"),
    "isAuthorized": _propagator([0], "Authorization check"),
    "requiresAuth": _propagator([0], "Auth required middleware"),
    "passport.authenticate": _propagator([0], "Passport authentication"),
}

# =============================================================================
# A02: Security Misconfiguration (OWASP 2025)
# =============================================================================

MISCONFIGURATION_SPECS = {
    # Debug/Development mode
    "NODE_ENV": _propagator([0], "Node environment"),
    "development": _sink("config", [0], "Development mode"),
    "app.set('env', 'development')": _sink("config", [0], "Express dev mode"),

    # Secret keys (hardcoded)
    "secret": _sink("hardcoded_secret", [0], "Hardcoded secret (CWE-798)"),
    "SECRET_KEY": _sink("hardcoded_secret", [0], "Hardcoded secret key (CWE-798)"),
    "JWT_SECRET": _sink("hardcoded_secret", [0], "Hardcoded JWT secret (CWE-798)"),
    "API_KEY": _sink("hardcoded_secret", [0], "Hardcoded API key (CWE-798)"),
    "privateKey": _sink("hardcoded_secret", [0], "Hardcoded private key (CWE-798)"),

    # SSL/TLS verification disabled
    "rejectUnauthorized: false": _sink("ssl", [0], "TLS verification disabled (CWE-295)"),
    "NODE_TLS_REJECT_UNAUTHORIZED": _sink("ssl", [0], "TLS verification disabled (CWE-295)"),
    "strictSSL: false": _sink("ssl", [0], "Strict SSL disabled (CWE-295)"),

    # Verbose errors
    "stack": _sink("info_disclosure", [0], "Stack trace exposure (CWE-209)"),
    "console.error": _sink("info_disclosure", [0], "Console error (may leak info CWE-209)"),

    # Binding to all interfaces
    "0.0.0.0": _sink("config", [0], "Binding to all interfaces (CWE-668)"),
}

# =============================================================================
# A04: Cryptographic Failures (OWASP 2025)
# =============================================================================

CRYPTO_SPECS = {
    # Weak hash functions
    "crypto.createHash('md5')": _sink("weak_hash", [0], "MD5 hash (CWE-328)"),
    "crypto.createHash('sha1')": _sink("weak_hash", [0], "SHA1 hash (CWE-328)"),
    "md5": _sink("weak_hash", [0], "MD5 hash (CWE-328)"),
    "sha1": _sink("weak_hash", [0], "SHA1 hash (CWE-328)"),

    # Weak encryption
    "createCipheriv('des": _sink("weak_crypto", [0], "DES encryption (CWE-327)"),
    "createCipheriv('des3": _sink("weak_crypto", [0], "3DES encryption (CWE-327)"),
    "createCipheriv('rc4": _sink("weak_crypto", [0], "RC4 encryption (CWE-327)"),
    "aes-128-ecb": _sink("weak_crypto", [0], "AES ECB mode (CWE-327)"),
    "aes-256-ecb": _sink("weak_crypto", [0], "AES ECB mode (CWE-327)"),

    # Insecure random
    "Math.random": _sink("insecure_random", [0], "Math.random not cryptographic (CWE-330)"),

    # Secure alternatives
    "crypto.randomBytes": _sanitizer(["random"], "Cryptographically secure random"),
    "crypto.randomUUID": _sanitizer(["random"], "Cryptographically secure UUID"),
    "crypto.getRandomValues": _sanitizer(["random"], "Crypto getRandomValues (secure)"),

    # Weak key sizes
    "modulusLength: 1024": _sink("weak_crypto", [0], "Weak RSA key size (CWE-326)"),
    "modulusLength: 512": _sink("weak_crypto", [0], "Weak RSA key size (CWE-326)"),
}

# =============================================================================
# A07: Identification and Authentication Failures (OWASP 2025)
# =============================================================================

AUTH_SPECS = {
    # Hardcoded credentials
    "password": _sink("hardcoded_cred", [0], "Potential hardcoded password (CWE-798)"),
    "passwd": _sink("hardcoded_cred", [0], "Potential hardcoded password (CWE-798)"),
    "apiKey": _sink("hardcoded_cred", [0], "Potential hardcoded API key (CWE-798)"),
    "api_key": _sink("hardcoded_cred", [0], "Potential hardcoded API key (CWE-798)"),
    "token": _sink("hardcoded_cred", [0], "Potential hardcoded token (CWE-798)"),

    # Password hashing
    "bcrypt.hash": _sanitizer(["password"], "bcrypt password hashing (safe)"),
    "bcrypt.compare": _propagator([0, 1], "bcrypt password compare"),
    "argon2.hash": _sanitizer(["password"], "Argon2 password hashing (safe)"),
    "scrypt": _sanitizer(["password"], "scrypt password hashing (safe)"),
    "pbkdf2": _sanitizer(["password"], "PBKDF2 password hashing"),

    # Session management
    "maxAge": _sink("session", [0], "Session max age config"),
    "cookie.secure": _propagator([0], "Secure cookie flag"),
    "cookie.httpOnly": _propagator([0], "HttpOnly cookie flag"),
    "cookie.sameSite": _propagator([0], "SameSite cookie flag"),

    # Rate limiting
    "express-rate-limit": _propagator([0], "Rate limiting middleware"),
    "rateLimit": _propagator([0], "Rate limiting"),
}

# =============================================================================
# A10: Mishandling of Exceptional Conditions (OWASP 2025 - NEW)
# =============================================================================

EXCEPTION_SPECS = {
    # Empty catch blocks
    "catch (e) {}": _sink("exception", [0], "Empty catch block (CWE-390)"),
    "catch {}": _sink("exception", [0], "Empty catch block (CWE-390)"),

    # Generic error handling
    ".catch(() =>": _sink("exception", [0], "Swallowed promise rejection (CWE-390)"),

    # Unhandled rejections
    "unhandledRejection": _propagator([0], "Unhandled rejection handler"),
    "uncaughtException": _propagator([0], "Uncaught exception handler"),

    # Process exit
    "process.exit": _sink("exception", [0], "Process exit (CWE-705)"),

    # Error disclosure
    "err.stack": _sink("info_disclosure", [0], "Error stack disclosure (CWE-209)"),
    "error.message": _propagator([0], "Error message (may leak info)"),
}

# =============================================================================
# Sensitive Data Exposure (A01/A09)
# =============================================================================

SENSITIVE_DATA_SPECS = {
    # Logging sensitive data
    "console.log": _sink("sensitive_log", [0], "Console log (may contain sensitive data CWE-532)"),
    "console.debug": _sink("sensitive_log", [0], "Console debug (may contain sensitive data CWE-532)"),
    "winston.info": _sink("sensitive_log", [0], "Winston info log (CWE-532)"),
    "winston.debug": _sink("sensitive_log", [0], "Winston debug log (CWE-532)"),
    "bunyan.info": _sink("sensitive_log", [0], "Bunyan info log (CWE-532)"),
    "pino.info": _sink("sensitive_log", [0], "Pino info log (CWE-532)"),

    # Response data (note: res.send is defined as HTML sink in EXPRESS_SPECS)
    "res.json": _propagator([0], "JSON response (check for sensitive data)"),
}

# =============================================================================
# HTTP Header Security (A02/A05)
# =============================================================================

HEADER_SPECS = {
    # Security headers middleware
    "helmet": _sanitizer(["header"], "Helmet security headers"),

    # Individual headers
    "X-Frame-Options": _propagator([0], "X-Frame-Options header"),
    "X-Content-Type-Options": _propagator([0], "X-Content-Type-Options header"),
    "X-XSS-Protection": _propagator([0], "X-XSS-Protection header"),
    "Content-Security-Policy": _propagator([0], "CSP header"),
    "Strict-Transport-Security": _propagator([0], "HSTS header"),

    # Header injection
    "res.setHeader": _sink("header_injection", [1], "Set header (CWE-113)"),
    "res.header": _sink("header_injection", [1], "Set header (CWE-113)"),
}

# =============================================================================
# SSRF Enhanced (A01)
# =============================================================================

SSRF_ENHANCED_SPECS = {
    # Cloud metadata endpoints
    "169.254.169.254": _sink("ssrf", [0], "Cloud metadata endpoint (SSRF)"),
    "metadata.google.internal": _sink("ssrf", [0], "GCP metadata (SSRF)"),

    # Internal network access
    "localhost": _sink("ssrf", [0], "Localhost access (SSRF)"),
    "127.0.0.1": _sink("ssrf", [0], "Loopback access (SSRF)"),
    "0.0.0.0": _sink("ssrf", [0], "All interfaces (SSRF)"),

    # URL parsing
    "new URL": _propagator([0], "URL parsing"),
    "url.parse": _propagator([0], "URL parsing"),
}

# =============================================================================
# Prototype Pollution (JavaScript-specific)
# =============================================================================

PROTOTYPE_POLLUTION_SPECS = {
    # Object manipulation
    "__proto__": _sink("prototype_pollution", [0], "Prototype access (CWE-1321)"),
    "constructor.prototype": _sink("prototype_pollution", [0], "Constructor prototype (CWE-1321)"),
    "Object.assign": _sink("prototype_pollution", [1], "Object.assign (potential pollution)"),
    "_.merge": _sink("prototype_pollution", [0, 1], "Lodash merge (prototype pollution)"),
    "_.defaultsDeep": _sink("prototype_pollution", [0, 1], "Lodash defaultsDeep (prototype pollution)"),
    "$.extend": _sink("prototype_pollution", [0, 1], "jQuery extend (prototype pollution)"),
    "merge": _sink("prototype_pollution", [0, 1], "Deep merge (potential pollution)"),
    "deepmerge": _sink("prototype_pollution", [0, 1], "Deep merge (potential pollution)"),
}

# =============================================================================
# Regular Expression DoS (A05)
# =============================================================================

REDOS_SPECS = {
    # Regex operations with user input
    "new RegExp": _sink("redos", [0], "Dynamic regex (potential ReDoS CWE-1333)"),
    "RegExp": _sink("redos", [0], "Dynamic regex (potential ReDoS CWE-1333)"),
    ".match": _sink("redos", [0], "Regex match (potential ReDoS)"),
    ".replace": _sink("redos", [0], "Regex replace (potential ReDoS)"),
    ".split": _sink("redos", [0], "Regex split (potential ReDoS)"),
    ".search": _sink("redos", [0], "Regex search (potential ReDoS)"),
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
# OWASP 2025 enhanced coverage
JAVASCRIPT_SPECS.update(ACCESS_CONTROL_SPECS)
JAVASCRIPT_SPECS.update(MISCONFIGURATION_SPECS)
JAVASCRIPT_SPECS.update(CRYPTO_SPECS)
JAVASCRIPT_SPECS.update(AUTH_SPECS)
JAVASCRIPT_SPECS.update(EXCEPTION_SPECS)
JAVASCRIPT_SPECS.update(SENSITIVE_DATA_SPECS)
JAVASCRIPT_SPECS.update(HEADER_SPECS)
JAVASCRIPT_SPECS.update(SSRF_ENHANCED_SPECS)
JAVASCRIPT_SPECS.update(PROTOTYPE_POLLUTION_SPECS)
JAVASCRIPT_SPECS.update(REDOS_SPECS)

# Alias for TypeScript (same specs)
TYPESCRIPT_SPECS = JAVASCRIPT_SPECS
