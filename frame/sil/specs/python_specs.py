"""
Library specifications for Python frameworks and standard library.

This module defines ProcSpec for common Python APIs including:
- Flask (web framework)
- Django (web framework)
- SQLAlchemy (ORM/database)
- subprocess (shell commands)
- os (operating system)
- Standard library (open, input, etc.)
"""

from typing import Dict
from frame.sil.procedure import ProcSpec


def _source(kind: str, desc: str = "") -> ProcSpec:
    """Create a taint source spec"""
    return ProcSpec(is_source=kind, description=desc)


def _sink(kind: str, args: list = None, desc: str = "") -> ProcSpec:
    """Create a taint sink spec"""
    # Use [0] as default if args is None, but allow empty list for usage-based sinks
    sink_args = args if args is not None else [0]
    return ProcSpec(is_sink=kind, sink_args=sink_args, description=desc)


def _sanitizer(kinds: list, desc: str = "") -> ProcSpec:
    """Create a sanitizer spec"""
    return ProcSpec(is_sanitizer=kinds, description=desc)


def _propagator(args: list, desc: str = "", from_receiver: bool = False) -> ProcSpec:
    """Create a taint propagator spec"""
    return ProcSpec(taint_propagates=args, taint_from_receiver=from_receiver, description=desc)


# =============================================================================
# Flask Framework
# =============================================================================

FLASK_SPECS = {
    # Request data (taint sources)
    "request.args.get": _source("user", "Flask query parameter"),
    "request.args.getlist": _source("user", "Flask query parameter list"),
    "request.args.__getitem__": _source("user", "Flask query parameter"),
    "request.form.get": _source("user", "Flask form data"),
    "request.form.getlist": _source("user", "Flask form data list"),
    "request.form.__getitem__": _source("user", "Flask form data"),
    "request.json": _source("user", "Flask JSON body"),
    "request.json.get": _source("user", "Flask JSON field"),
    "request.data": _source("user", "Flask raw request data"),
    "request.values.get": _source("user", "Flask combined args/form"),
    "request.cookies.get": _source("user", "Flask cookie"),
    "request.headers.get": _source("user", "Flask request header"),
    "request.headers.getlist": _source("user", "Flask request header list"),
    "request.headers.__getitem__": _source("user", "Flask request header"),
    "request.files.get": _source("file", "Flask file upload"),
    "request.get_data": _source("user", "Flask raw data"),
    "request.get_json": _source("user", "Flask JSON data"),

    # Template rendering (potential XSS sinks)
    "render_template_string": _sink("html", [0], "Flask template string (XSS)"),
    "Markup": _sink("html", [0], "Flask Markup (XSS if unsanitized)"),

    # Redirects (open redirect sink)
    "redirect": _sink("redirect", [0], "Flask redirect (open redirect)"),

    # Response headers
    "make_response": _propagator([0], "Flask response"),
}

# =============================================================================
# Django Framework
# =============================================================================

DJANGO_SPECS = {
    # Request data (taint sources)
    "request.GET.get": _source("user", "Django GET parameter"),
    "request.GET.getlist": _source("user", "Django GET parameter list"),
    "request.GET.__getitem__": _source("user", "Django GET parameter"),
    "request.POST.get": _source("user", "Django POST parameter"),
    "request.POST.getlist": _source("user", "Django POST parameter list"),
    "request.POST.__getitem__": _source("user", "Django POST parameter"),
    "request.body": _source("user", "Django raw body"),
    "request.COOKIES.get": _source("user", "Django cookie"),
    "request.META.get": _source("user", "Django request meta"),
    "request.FILES.get": _source("file", "Django file upload"),

    # Database (SQL sinks)
    "cursor.execute": _sink("sql", [0], "Django raw SQL"),
    "connection.cursor().execute": _sink("sql", [0], "Django raw SQL"),
    "RawSQL": _sink("sql", [0], "Django RawSQL"),
    "raw": _sink("sql", [0], "Django Manager.raw()"),

    # Template rendering (XSS)
    "mark_safe": _sink("html", [0], "Django mark_safe (XSS)"),
    "SafeString": _sink("html", [0], "Django SafeString (XSS)"),

    # Redirects
    "HttpResponseRedirect": _sink("redirect", [0], "Django redirect"),
    "redirect": _sink("redirect", [0], "Django redirect shortcut"),

    # Sanitizers
    "escape": _sanitizer(["html"], "Django HTML escape"),
    "conditional_escape": _sanitizer(["html"], "Django conditional escape"),
    "strip_tags": _sanitizer(["html"], "Django strip tags"),
}

# =============================================================================
# SQLAlchemy / Database
# =============================================================================

SQLALCHEMY_SPECS = {
    # Raw SQL execution (SQL injection sinks)
    "session.execute": _sink("sql", [0], "SQLAlchemy session execute"),
    "engine.execute": _sink("sql", [0], "SQLAlchemy engine execute"),
    "connection.execute": _sink("sql", [0], "SQLAlchemy connection execute"),
    "db.execute": _sink("sql", [0], "Database execute"),
    "db.session.execute": _sink("sql", [0], "Flask-SQLAlchemy execute"),

    # Text SQL (dangerous)
    "text": _sink("sql", [0], "SQLAlchemy text() - raw SQL"),
    "literal_column": _sink("sql", [0], "SQLAlchemy literal_column"),

    # Database sources
    "fetchone": _source("database", "Database query result"),
    "fetchall": _source("database", "Database query results"),
    "fetchmany": _source("database", "Database query results"),
    "scalar": _source("database", "Database scalar result"),
    "first": _source("database", "Database first result"),
    "one": _source("database", "Database single result"),
}

# =============================================================================
# Subprocess / Shell
# =============================================================================

SUBPROCESS_SPECS = {
    # Command execution (command injection sinks)
    "subprocess.run": _sink("shell", [0], "subprocess.run"),
    "subprocess.call": _sink("shell", [0], "subprocess.call"),
    "subprocess.check_call": _sink("shell", [0], "subprocess.check_call"),
    "subprocess.check_output": _sink("shell", [0], "subprocess.check_output"),
    "subprocess.Popen": _sink("shell", [0], "subprocess.Popen"),
    "subprocess.getoutput": _sink("shell", [0], "subprocess.getoutput"),
    "subprocess.getstatusoutput": _sink("shell", [0], "subprocess.getstatusoutput"),

    # os module
    "os.system": _sink("shell", [0], "os.system"),
    "os.popen": _sink("shell", [0], "os.popen"),
    "os.popen2": _sink("shell", [0], "os.popen2"),
    "os.popen3": _sink("shell", [0], "os.popen3"),
    "os.popen4": _sink("shell", [0], "os.popen4"),
    "os.spawnl": _sink("shell", [1], "os.spawnl"),
    "os.spawnle": _sink("shell", [1], "os.spawnle"),
    "os.spawnlp": _sink("shell", [1], "os.spawnlp"),
    "os.spawnlpe": _sink("shell", [1], "os.spawnlpe"),
    "os.spawnv": _sink("shell", [1], "os.spawnv"),
    "os.spawnve": _sink("shell", [1], "os.spawnve"),
    "os.spawnvp": _sink("shell", [1], "os.spawnvp"),
    "os.spawnvpe": _sink("shell", [1], "os.spawnvpe"),
    "os.execl": _sink("shell", [0], "os.execl"),
    "os.execle": _sink("shell", [0], "os.execle"),
    "os.execlp": _sink("shell", [0], "os.execlp"),
    "os.execlpe": _sink("shell", [0], "os.execlpe"),
    "os.execv": _sink("shell", [0], "os.execv"),
    "os.execve": _sink("shell", [0], "os.execve"),
    "os.execvp": _sink("shell", [0], "os.execvp"),
    "os.execvpe": _sink("shell", [0], "os.execvpe"),

    # Sanitizers
    "shlex.quote": _sanitizer(["shell"], "Shell argument quoting"),
    "shlex.join": _sanitizer(["shell"], "Shell argument joining"),
}

# =============================================================================
# File System
# =============================================================================

FILESYSTEM_SPECS = {
    # File operations (path traversal sinks)
    "open": _sink("filesystem", [0], "File open"),
    "builtins.open": _sink("filesystem", [0], "File open"),
    "io.open": _sink("filesystem", [0], "File open"),
    "codecs.open": _sink("filesystem", [0], "codecs.open (path traversal CWE-22)"),

    # Path operations
    "os.path.join": _propagator([0, 1], "Path join"),
    "pathlib.Path": _sink("filesystem", [0], "Pathlib Path"),
    "Path": _sink("filesystem", [0], "Pathlib Path"),
    "Path.read_text": _sink("filesystem", [], "Path read"),
    "Path.read_bytes": _sink("filesystem", [], "Path read"),
    "Path.write_text": _sink("filesystem", [0], "Path write"),
    "Path.write_bytes": _sink("filesystem", [0], "Path write"),
    "Path.open": _sink("filesystem", [], "Path open"),
    "Path.unlink": _sink("filesystem", [], "Path delete"),
    "Path.rmdir": _sink("filesystem", [], "Path rmdir"),
    "Path.mkdir": _sink("filesystem", [], "Path mkdir"),

    # os file operations
    "os.remove": _sink("filesystem", [0], "os.remove"),
    "os.unlink": _sink("filesystem", [0], "os.unlink"),
    "os.rmdir": _sink("filesystem", [0], "os.rmdir"),
    "os.mkdir": _sink("filesystem", [0], "os.mkdir"),
    "os.makedirs": _sink("filesystem", [0], "os.makedirs"),
    "os.rename": _sink("filesystem", [0, 1], "os.rename"),
    "os.replace": _sink("filesystem", [0, 1], "os.replace"),
    "os.link": _sink("filesystem", [0, 1], "os.link"),
    "os.symlink": _sink("filesystem", [0, 1], "os.symlink"),
    "os.readlink": _sink("filesystem", [0], "os.readlink"),
    "os.listdir": _sink("filesystem", [0], "os.listdir"),
    "os.scandir": _sink("filesystem", [0], "os.scandir"),
    "os.walk": _sink("filesystem", [0], "os.walk"),
    "os.chdir": _sink("filesystem", [0], "os.chdir"),
    "os.chmod": _sink("filesystem", [0], "os.chmod"),
    "os.chown": _sink("filesystem", [0], "os.chown"),

    # shutil operations
    "shutil.copy": _sink("filesystem", [0, 1], "shutil.copy"),
    "shutil.copy2": _sink("filesystem", [0, 1], "shutil.copy2"),
    "shutil.copytree": _sink("filesystem", [0, 1], "shutil.copytree"),
    "shutil.move": _sink("filesystem", [0, 1], "shutil.move"),
    "shutil.rmtree": _sink("filesystem", [0], "shutil.rmtree"),

    # File sources
    "read": _source("file", "File read"),
    "readline": _source("file", "File readline"),
    "readlines": _source("file", "File readlines"),

    # Sanitizers
    "os.path.basename": _sanitizer(["filesystem"], "Path basename (partial sanitizer)"),
    "os.path.normpath": _sanitizer(["filesystem"], "Path normalization"),
    "os.path.realpath": _sanitizer(["filesystem"], "Path realpath"),
}

# =============================================================================
# Code Execution / Eval
# =============================================================================

EVAL_SPECS = {
    # Code execution (code injection sinks)
    "eval": _sink("eval", [0], "eval() - code injection"),
    "exec": _sink("eval", [0], "exec() - code injection"),
    "compile": _sink("eval", [0], "compile() - code injection"),
    "__import__": _sink("eval", [0], "__import__() - code injection"),
    "importlib.import_module": _sink("eval", [0], "Dynamic import"),

    # Pickle (deserialization sinks) - require tainted data reaching pickle
    "pickle.loads": _sink("deserialize", [0], "Pickle deserialization (CWE-502)"),
    "pickle.load": _sink("deserialize", [0], "Pickle deserialization (CWE-502)"),
    "cPickle.loads": _sink("deserialize", [0], "cPickle deserialization"),
    "cPickle.load": _sink("deserialize", [0], "cPickle deserialization"),
    "marshal.loads": _sink("deserialize", [0], "Marshal deserialization"),
    "marshal.load": _sink("deserialize", [0], "Marshal deserialization"),
    "yaml.load": _sink("deserialize", [0], "YAML deserialization (unsafe)"),
    "yaml.unsafe_load": _sink("deserialize", [0], "YAML unsafe deserialization"),

    # Safe deserializers
    "json.loads": _source("user", "JSON deserialization (safe but tainted)"),
    "json.load": _source("user", "JSON deserialization (safe but tainted)"),
    "yaml.safe_load": _source("user", "YAML safe deserialization (tainted)"),
}

# =============================================================================
# Network / HTTP
# =============================================================================

NETWORK_SPECS = {
    # HTTP client (SSRF sinks)
    "requests.get": _sink("ssrf", [0], "requests.get (SSRF)"),
    "requests.post": _sink("ssrf", [0], "requests.post (SSRF)"),
    "requests.put": _sink("ssrf", [0], "requests.put (SSRF)"),
    "requests.delete": _sink("ssrf", [0], "requests.delete (SSRF)"),
    "requests.patch": _sink("ssrf", [0], "requests.patch (SSRF)"),
    "requests.head": _sink("ssrf", [0], "requests.head (SSRF)"),
    "requests.options": _sink("ssrf", [0], "requests.options (SSRF)"),
    "requests.request": _sink("ssrf", [1], "requests.request (SSRF)"),

    "urllib.request.urlopen": _sink("ssrf", [0], "urllib.urlopen (SSRF)"),
    "urllib.request.urlretrieve": _sink("ssrf", [0], "urllib.urlretrieve (SSRF)"),
    "urllib2.urlopen": _sink("ssrf", [0], "urllib2.urlopen (SSRF)"),
    "httplib.HTTPConnection": _sink("ssrf", [0], "HTTPConnection (SSRF)"),
    "httplib.HTTPSConnection": _sink("ssrf", [0], "HTTPSConnection (SSRF)"),
    "http.client.HTTPConnection": _sink("ssrf", [0], "HTTPConnection (SSRF)"),
    "http.client.HTTPSConnection": _sink("ssrf", [0], "HTTPSConnection (SSRF)"),

    "aiohttp.ClientSession.get": _sink("ssrf", [0], "aiohttp get (SSRF)"),
    "aiohttp.ClientSession.post": _sink("ssrf", [0], "aiohttp post (SSRF)"),
    "httpx.get": _sink("ssrf", [0], "httpx get (SSRF)"),
    "httpx.post": _sink("ssrf", [0], "httpx post (SSRF)"),

    # Socket operations
    "socket.socket.connect": _sink("ssrf", [0], "Socket connect (SSRF)"),
}

# =============================================================================
# HTML / XSS
# =============================================================================

HTML_SPECS = {
    # HTML sinks
    "innerHTML": _sink("html", [0], "innerHTML (XSS)"),

    # Jinja2
    "jinja2.Template": _sink("html", [0], "Jinja2 template (XSS if unescaped)"),
    "jinja2.Environment.from_string": _sink("html", [0], "Jinja2 from_string"),

    # HTML sanitizers
    "html.escape": _sanitizer(["html"], "HTML escape"),
    "cgi.escape": _sanitizer(["html"], "CGI escape (deprecated)"),
    "markupsafe.escape": _sanitizer(["html"], "MarkupSafe escape"),
    "bleach.clean": _sanitizer(["html"], "Bleach HTML sanitizer"),
}

# =============================================================================
# Logging
# =============================================================================

LOGGING_SPECS = {
    # Logging (log injection sinks - lower severity)
    "logging.debug": _sink("log", [0], "Log injection"),
    "logging.info": _sink("log", [0], "Log injection"),
    "logging.warning": _sink("log", [0], "Log injection"),
    "logging.error": _sink("log", [0], "Log injection"),
    "logging.critical": _sink("log", [0], "Log injection"),
    "logging.exception": _sink("log", [0], "Log injection"),
    "logging.log": _sink("log", [1], "Log injection"),
    "logger.debug": _sink("log", [0], "Log injection"),
    "logger.info": _sink("log", [0], "Log injection"),
    "logger.warning": _sink("log", [0], "Log injection"),
    "logger.error": _sink("log", [0], "Log injection"),
    "logger.critical": _sink("log", [0], "Log injection"),
}

# =============================================================================
# Standard Library Sources
# =============================================================================

STDLIB_SOURCES = {
    # User input
    "input": _source("user", "Console input"),
    "raw_input": _source("user", "Console input (Python 2)"),

    # Environment
    "os.environ.get": _source("env", "Environment variable"),
    "os.environ.__getitem__": _source("env", "Environment variable"),
    "os.getenv": _source("env", "Environment variable"),

    # Command line
    "sys.argv": _source("user", "Command line arguments"),
}

# =============================================================================
# String Operations (Propagators)
# =============================================================================

STRING_SPECS = {
    # String operations that propagate taint
    "str.format": _propagator([0], "String format"),
    "str.__mod__": _propagator([0, 1], "String % formatting"),
    "str.__add__": _propagator([0, 1], "String concatenation"),
    "str.join": _propagator([0, 1], "String join"),
    "str.replace": _propagator([0], "String replace"),
    "str.lower": _propagator([0], "String lower"),
    "str.upper": _propagator([0], "String upper"),
    "str.strip": _propagator([0], "String strip"),
    "str.lstrip": _propagator([0], "String lstrip"),
    "str.rstrip": _propagator([0], "String rstrip"),
    "str.split": _propagator([0], "String split"),
    "str.encode": _propagator([0], "String encode"),
    "bytes.decode": _propagator([0], "Bytes decode"),

    # f-strings are handled specially in the frontend
}

# =============================================================================
# List/Collection Operations (Taint Propagation)
# =============================================================================

LIST_SPECS = {
    # List operations that propagate taint
    "list.append": _propagator([0], "List append (taints the list)"),
    "list.extend": _propagator([0], "List extend (taints the list)"),
    "list.insert": _propagator([1], "List insert (taints the list)"),
    "list.__setitem__": _propagator([1], "List item assignment"),
    "list.__getitem__": _propagator([0], "List item access"),
    "list.pop": _propagator([0], "List pop"),
    "append": _propagator([0], "List append"),
    "extend": _propagator([0], "List extend"),
    "insert": _propagator([1], "List insert"),

    # Dict operations
    "dict.__setitem__": _propagator([1], "Dict item assignment"),
    "dict.__getitem__": _propagator([0], "Dict item access"),
    "dict.get": _propagator([0], "Dict get"),
    "dict.update": _propagator([0], "Dict update"),
}

# =============================================================================
# URL/Encoding Operations (taint propagation)
# =============================================================================

URL_ENCODING_SPECS = {
    # urllib.parse - URL encoding/decoding (propagates taint)
    "urllib.parse.unquote": _propagator([0], "URL unquote"),
    "urllib.parse.unquote_plus": _propagator([0], "URL unquote_plus"),
    "urllib.parse.quote": _propagator([0], "URL quote"),
    "urllib.parse.quote_plus": _propagator([0], "URL quote_plus"),
    "urllib.parse.urlencode": _propagator([0], "URL encode"),
    "urllib.parse.parse_qs": _propagator([0], "Parse query string"),
    "urllib.parse.parse_qsl": _propagator([0], "Parse query string list"),
    "urllib.parse.urlparse": _propagator([0], "URL parse"),
    "urllib.parse.urlsplit": _propagator([0], "URL split"),
    "urllib.parse.urljoin": _propagator([0, 1], "URL join"),

    # html escaping
    "html.escape": _sanitizer(["html"], "HTML escape (sanitizer)"),
    "html.unescape": _propagator([0], "HTML unescape"),
    "cgi.escape": _sanitizer(["html"], "CGI HTML escape (deprecated)"),

    # base64 (propagates taint)
    "base64.b64encode": _propagator([0], "Base64 encode"),
    "base64.b64decode": _propagator([0], "Base64 decode"),
    "base64.urlsafe_b64encode": _propagator([0], "URL-safe base64 encode"),
    "base64.urlsafe_b64decode": _propagator([0], "URL-safe base64 decode"),

    # json (propagates taint)
    "json.loads": _propagator([0], "JSON loads"),
    "json.dumps": _propagator([0], "JSON dumps"),
}

# =============================================================================
# A04: Cryptographic Failures (OWASP 2025)
# =============================================================================

CRYPTO_SPECS = {
    # Weak cryptography sinks - hashlib (usage-based - calling these is the vulnerability)
    "hashlib.md5": _sink("weak_hash", [], "MD5 hash (CWE-328)"),
    "hashlib.sha1": _sink("weak_hash", [], "SHA1 hash (CWE-328)"),
    "hashlib.new": _sink("weak_hash", [], "hashlib.new - usage-based (CWE-328)"),
    "Crypto.Hash.MD5.new": _sink("weak_hash", [], "PyCrypto MD5 (CWE-328)"),
    "Crypto.Hash.SHA.new": _sink("weak_hash", [], "PyCrypto SHA1 (CWE-328)"),
    # Additional weak hash constructors
    "md5": _sink("weak_hash", [], "MD5 hash (CWE-328)"),
    "sha1": _sink("weak_hash", [], "SHA1 hash (CWE-328)"),

    # Insecure random sinks - random module (not cryptographically secure)
    "random.random": _sink("insecure_random", [], "Non-cryptographic random (CWE-330)"),
    "random.randint": _sink("insecure_random", [], "Non-cryptographic random (CWE-330)"),
    "random.choice": _sink("insecure_random", [], "Non-cryptographic random (CWE-330)"),
    "random.randrange": _sink("insecure_random", [], "Non-cryptographic random (CWE-330)"),
    "random.uniform": _sink("insecure_random", [], "Non-cryptographic random (CWE-330)"),
    "random.triangular": _sink("insecure_random", [], "Non-cryptographic random (CWE-330)"),
    "random.gauss": _sink("insecure_random", [], "Non-cryptographic random (CWE-330)"),
    "random.normalvariate": _sink("insecure_random", [], "Non-cryptographic random (CWE-330)"),
    "random.lognormvariate": _sink("insecure_random", [], "Non-cryptographic random (CWE-330)"),
    "random.expovariate": _sink("insecure_random", [], "Non-cryptographic random (CWE-330)"),
    "random.betavariate": _sink("insecure_random", [], "Non-cryptographic random (CWE-330)"),
    "random.gammavariate": _sink("insecure_random", [], "Non-cryptographic random (CWE-330)"),
    "random.paretovariate": _sink("insecure_random", [], "Non-cryptographic random (CWE-330)"),
    "random.weibullvariate": _sink("insecure_random", [], "Non-cryptographic random (CWE-330)"),
    "random.sample": _sink("insecure_random", [], "Non-cryptographic random (CWE-330)"),
    "random.shuffle": _sink("insecure_random", [], "Non-cryptographic random (CWE-330)"),
    "random.getrandbits": _sink("insecure_random", [], "Non-cryptographic random (CWE-330)"),
    "random.randbytes": _sink("insecure_random", [], "Non-cryptographic random (CWE-330)"),
    "random.choices": _sink("insecure_random", [], "Non-cryptographic random (CWE-330)"),

    # Weak encryption modes
    "Crypto.Cipher.AES.new": _sink("weak_crypto", [0], "Check AES mode (CWE-327)"),
    "Crypto.Cipher.DES.new": _sink("weak_crypto", [0], "DES is deprecated (CWE-327)"),
    "Crypto.Cipher.DES3.new": _sink("weak_crypto", [0], "3DES is deprecated (CWE-327)"),
    "cryptography.hazmat.primitives.ciphers.algorithms.TripleDES": _sink("weak_crypto", [], "3DES deprecated"),

    # Hardcoded secrets (detected via pattern, not just API call)
    # These are handled specially by the scanner for pattern matching
}

# =============================================================================
# A08: Software/Data Integrity - Additional Deserialization
# =============================================================================

DESERIALIZATION_SPECS = {
    # Dangerous deserialization
    "jsonpickle.decode": _sink("deserialize", [0], "jsonpickle deserialization (CWE-502)"),
    "dill.loads": _sink("deserialize", [0], "dill deserialization (CWE-502)"),
    "shelve.open": _sink("deserialize", [0], "shelve deserialization (CWE-502)"),

    # XML parsing (XXE)
    "xml.etree.ElementTree.parse": _sink("xml", [0], "XML parse (potential XXE CWE-611)"),
    "xml.etree.ElementTree.fromstring": _sink("xml", [0], "XML parse (potential XXE)"),
    "lxml.etree.parse": _sink("xml", [0], "lxml parse (potential XXE)"),
    "lxml.etree.fromstring": _sink("xml", [0], "lxml parse (potential XXE)"),
    "xml.dom.minidom.parse": _sink("xml", [0], "minidom parse (XXE)"),
    "xml.dom.minidom.parseString": _sink("xml", [0], "minidom parseString (XXE)"),
    "xml.sax.parse": _sink("xml", [0], "SAX parse (XXE)"),

    # Safe XML parsers (sanitizers)
    "defusedxml.parse": _sanitizer(["xml"], "defusedxml safe parser"),
    "defusedxml.fromstring": _sanitizer(["xml"], "defusedxml safe parser"),
}

# =============================================================================
# NoSQL Databases (A05: Injection)
# =============================================================================

NOSQL_SPECS = {
    # MongoDB (NoSQL injection)
    "pymongo.collection.Collection.find": _sink("nosql", [0], "MongoDB find (NoSQL injection)"),
    "pymongo.collection.Collection.find_one": _sink("nosql", [0], "MongoDB find_one"),
    "pymongo.collection.Collection.aggregate": _sink("nosql", [0], "MongoDB aggregate"),
    "pymongo.collection.Collection.update": _sink("nosql", [0, 1], "MongoDB update"),
    "pymongo.collection.Collection.delete_many": _sink("nosql", [0], "MongoDB delete"),

    # Redis
    "redis.Redis.execute_command": _sink("nosql", [0], "Redis command injection"),
    "redis.Redis.eval": _sink("eval", [0], "Redis Lua eval"),
}

# =============================================================================
# Regex (A05: ReDoS)
# =============================================================================

REGEX_SPECS = {
    # Regex DoS sinks
    "re.match": _sink("regex", [0], "Regex match (potential ReDoS CWE-1333)"),
    "re.search": _sink("regex", [0], "Regex search (potential ReDoS)"),
    "re.findall": _sink("regex", [0], "Regex findall (potential ReDoS)"),
    "re.sub": _sink("regex", [0], "Regex sub (potential ReDoS)"),
    "re.compile": _sink("regex", [0], "Regex compile (potential ReDoS)"),
}

# =============================================================================
# Template Engines (A05: Template Injection)
# =============================================================================

TEMPLATE_SPECS = {
    # Jinja2
    "jinja2.Environment.from_string": _sink("template", [0], "Jinja2 template injection (CWE-1336)"),
    "jinja2.Template": _sink("template", [0], "Jinja2 template injection"),

    # Mako
    "mako.template.Template": _sink("template", [0], "Mako template injection"),

    # String formatting as template
    "string.Template": _sink("template", [0], "String template injection"),
}

# =============================================================================
# LDAP (A05: LDAP Injection)
# =============================================================================

LDAP_SPECS = {
    # python-ldap
    "ldap.initialize": _sink("ldap", [0], "LDAP connection"),
    "ldap.open": _sink("ldap", [0], "LDAP connection"),
    "ldap.LDAPObject.search_s": _sink("ldap", [0, 2], "LDAP search (injection CWE-90)"),
    "ldap.LDAPObject.search": _sink("ldap", [0, 2], "LDAP search"),
    "ldap.filter.filter_format": _sanitizer(["ldap"], "LDAP filter escaping"),

    # ldap3 library (commonly used in OWASP benchmarks)
    "conn.search": _sink("ldap", [1], "ldap3 search (filter is arg 1, CWE-90)"),
    "connection.search": _sink("ldap", [1], "ldap3 search (CWE-90)"),
    "Connection.search": _sink("ldap", [1], "ldap3 Connection.search (CWE-90)"),
    "ldap3.Connection.search": _sink("ldap", [1], "ldap3 search (CWE-90)"),
    "search": _sink("ldap", [1], "LDAP search (CWE-90)"),
}

# =============================================================================
# XPath Injection (CWE-643)
# =============================================================================

XPATH_SPECS = {
    # lxml XPath
    "lxml.etree.XPath": _sink("xpath", [0], "XPath query (CWE-643)"),
    "lxml.etree.ETXPath": _sink("xpath", [0], "XPath query (CWE-643)"),

    # elementpath library
    "elementpath.select": _sink("xpath", [1], "elementpath XPath select (CWE-643)"),
    "elementpath.iter_select": _sink("xpath", [1], "elementpath XPath iter_select (CWE-643)"),
    "elementpath.Selector": _sink("xpath", [0], "elementpath Selector (CWE-643)"),

    # xml.etree XPath
    "xml.etree.ElementTree.Element.find": _sink("xpath", [0], "ElementTree find (CWE-643)"),
    "xml.etree.ElementTree.Element.findall": _sink("xpath", [0], "ElementTree findall (CWE-643)"),
    "xml.etree.ElementTree.Element.iterfind": _sink("xpath", [0], "ElementTree iterfind (CWE-643)"),

    # Direct xpath method calls
    "xpath": _sink("xpath", [0], "XPath query (CWE-643)"),
    "find": _sink("xpath", [0], "XML find (potential XPath CWE-643)"),
    "findall": _sink("xpath", [0], "XML findall (potential XPath CWE-643)"),
}

# =============================================================================
# Trust Boundary Violation (CWE-501)
# =============================================================================

TRUST_BOUNDARY_SPECS = {
    # Session storage with untrusted data
    "flask.session.__setitem__": _sink("trust_boundary", [1], "Session storage (CWE-501)"),
    "session.__setitem__": _sink("trust_boundary", [1], "Session storage (CWE-501)"),

    # Django session
    "request.session.__setitem__": _sink("trust_boundary", [1], "Django session storage (CWE-501)"),

    # Storing in application context
    "g.__setattr__": _sink("trust_boundary", [1], "Flask g storage (CWE-501)"),

    # Additional session patterns (for OWASP benchmark)
    # When session['key'] = value, the frontend translates this to session.__setitem__
    # But we also need to catch direct session attribute assignment
    "session": _sink("trust_boundary", [0], "Session storage (CWE-501)"),
    "flask.session": _sink("trust_boundary", [0], "Flask session storage (CWE-501)"),
}

# =============================================================================
# Insecure Cookie (CWE-614)
# =============================================================================

COOKIE_SPECS = {
    # Flask/Werkzeug cookies - the vulnerability is when secure=False
    # Use empty sink_args for usage-based detection with special handling in translator
    "response.set_cookie": _sink("insecure_cookie", [], "Cookie setting (check secure flag CWE-614)"),
    "Response.set_cookie": _sink("insecure_cookie", [], "Cookie setting (CWE-614)"),
    "make_response().set_cookie": _sink("insecure_cookie", [], "Cookie setting (CWE-614)"),
    "set_cookie": _sink("insecure_cookie", [], "Cookie setting (CWE-614)"),
    "RESPONSE.set_cookie": _sink("insecure_cookie", [], "Cookie setting (CWE-614)"),

    # Django cookies
    "HttpResponse.set_cookie": _sink("insecure_cookie", [], "Django cookie (CWE-614)"),
}

# =============================================================================
# Open Redirect (CWE-601)
# =============================================================================

REDIRECT_SPECS = {
    # Flask redirects
    "flask.redirect": _sink("redirect", [0], "Flask redirect (open redirect CWE-601)"),
    "redirect": _sink("redirect", [0], "Redirect (open redirect CWE-601)"),

    # Django redirects
    "django.shortcuts.redirect": _sink("redirect", [0], "Django redirect (CWE-601)"),
    "HttpResponseRedirect": _sink("redirect", [0], "Django HttpResponseRedirect (CWE-601)"),
    "HttpResponsePermanentRedirect": _sink("redirect", [0], "Django permanent redirect (CWE-601)"),

    # URL for with external URL
    "url_for": _propagator([0], "URL generation"),
}

# =============================================================================
# SQL Injection Enhanced (CWE-89)
# =============================================================================

SQL_ENHANCED_SPECS = {
    # cursor.execute variations
    "cursor.execute": _sink("sql", [0], "SQL execute (CWE-89)"),
    "cur.execute": _sink("sql", [0], "SQL execute (CWE-89)"),
    "conn.execute": _sink("sql", [0], "SQL execute (CWE-89)"),

    # sqlite3
    "sqlite3.Connection.execute": _sink("sql", [0], "SQLite execute (CWE-89)"),
    "sqlite3.Cursor.execute": _sink("sql", [0], "SQLite cursor execute (CWE-89)"),
    "sqlite3.Cursor.executemany": _sink("sql", [0], "SQLite executemany (CWE-89)"),
    "sqlite3.Cursor.executescript": _sink("sql", [0], "SQLite executescript (CWE-89)"),

    # psycopg2 (PostgreSQL)
    "psycopg2.cursor.execute": _sink("sql", [0], "PostgreSQL execute (CWE-89)"),
    "psycopg2.cursor.executemany": _sink("sql", [0], "PostgreSQL executemany (CWE-89)"),

    # mysql-connector
    "mysql.connector.cursor.execute": _sink("sql", [0], "MySQL execute (CWE-89)"),

    # Parameterized query helpers (safe)
    "cursor.mogrify": _propagator([0], "SQL mogrify (use params)"),
}

# =============================================================================
# Command Injection Enhanced (CWE-78)
# =============================================================================

COMMAND_INJECTION_SPECS = {
    # Shell=True is particularly dangerous
    "subprocess.run": _sink("command", [0], "subprocess.run (CWE-78)"),
    "subprocess.call": _sink("command", [0], "subprocess.call (CWE-78)"),
    "subprocess.Popen": _sink("command", [0], "subprocess.Popen (CWE-78)"),
    "subprocess.check_output": _sink("command", [0], "subprocess.check_output (CWE-78)"),
    "subprocess.check_call": _sink("command", [0], "subprocess.check_call (CWE-78)"),

    # os module commands
    "os.system": _sink("command", [0], "os.system (CWE-78)"),
    "os.popen": _sink("command", [0], "os.popen (CWE-78)"),

    # commands module (Python 2)
    "commands.getoutput": _sink("command", [0], "commands.getoutput (CWE-78)"),
    "commands.getstatusoutput": _sink("command", [0], "commands.getstatusoutput (CWE-78)"),
}

# =============================================================================
# XSS / Reflected Output (CWE-79)
# =============================================================================

XSS_SPECS = {
    # Direct response output
    "Response": _sink("xss", [0], "Response body (potential XSS CWE-79)"),

    # Template rendering without escaping
    "render_template_string": _sink("xss", [0], "Template string (XSS CWE-79)"),
    "Markup": _sink("xss", [0], "Markup (XSS if not escaped CWE-79)"),

    # Django
    "mark_safe": _sink("xss", [0], "Django mark_safe (XSS CWE-79)"),
    "SafeString": _sink("xss", [0], "Django SafeString (XSS CWE-79)"),

    # Jinja2 without autoescape
    "jinja2.Environment": _sink("xss", [0], "Jinja2 Environment (check autoescape CWE-79)"),

    # Sanitizers
    "escape": _sanitizer(["xss", "html"], "HTML escape"),
    "html.escape": _sanitizer(["xss", "html"], "HTML escape"),
    "markupsafe.escape": _sanitizer(["xss", "html"], "MarkupSafe escape"),
    "bleach.clean": _sanitizer(["xss", "html"], "Bleach HTML cleaner"),
    "cgi.escape": _sanitizer(["xss", "html"], "CGI escape (deprecated)"),
    "helpers.utils.escape_for_html": _sanitizer(["xss", "html"], "Custom HTML escape"),
    "escape_for_html": _sanitizer(["xss", "html"], "Custom HTML escape"),
}

# =============================================================================
# A09: Logging - Sensitive Data Exposure
# =============================================================================

SENSITIVE_LOGGING_SPECS = {
    # Patterns that might log sensitive data
    # Note: These require context analysis, flagged as potential issues
    "print": _sink("sensitive_log", [0], "Print (may expose sensitive data CWE-532)"),
}

# =============================================================================
# A01: Broken Access Control (OWASP 2025)
# =============================================================================

ACCESS_CONTROL_SPECS = {
    # JWT handling (potential vulnerabilities)
    "jwt.decode": _sink("auth", [0], "JWT decode - verify signature (CWE-347)"),
    "jwt.encode": _propagator([0], "JWT encode"),
    "jose.jwt.decode": _sink("auth", [0], "python-jose JWT decode"),
    "authlib.jose.jwt.decode": _sink("auth", [0], "Authlib JWT decode"),

    # Session handling
    "session": _propagator([0], "Session data (check authorization)"),
    "flask.session": _propagator([0], "Flask session"),
    "request.session": _propagator([0], "Django session"),

    # CORS (misconfiguration detection)
    "CORS": _sink("cors", [0], "CORS configuration (CWE-942)"),
    "Access-Control-Allow-Origin": _sink("cors", [0], "CORS header"),

    # Authorization decorators (track usage)
    "login_required": _propagator([0], "Login required decorator"),
    "permission_required": _propagator([0], "Permission required decorator"),
    "requires_auth": _propagator([0], "Auth required decorator"),
}

# =============================================================================
# A02: Security Misconfiguration (OWASP 2025)
# =============================================================================

MISCONFIGURATION_SPECS = {
    # Debug mode
    "app.debug": _sink("config", [0], "Debug mode enabled (CWE-489)"),
    "DEBUG": _sink("config", [0], "Debug flag (CWE-489)"),
    "app.run": _sink("config", [0], "Flask app.run - check debug param"),

    # Secret keys (hardcoded)
    "SECRET_KEY": _sink("hardcoded_secret", [0], "Hardcoded secret key (CWE-798)"),
    "app.secret_key": _sink("hardcoded_secret", [0], "Flask secret key (CWE-798)"),
    "JWT_SECRET_KEY": _sink("hardcoded_secret", [0], "JWT secret key (CWE-798)"),

    # SSL/TLS verification disabled
    "verify=False": _sink("ssl", [0], "SSL verification disabled (CWE-295)"),
    "CERT_NONE": _sink("ssl", [0], "Certificate verification disabled (CWE-295)"),
    "ssl._create_unverified_context": _sink("ssl", [0], "Unverified SSL context (CWE-295)"),

    # Binding to all interfaces
    "0.0.0.0": _sink("config", [0], "Binding to all interfaces (CWE-668)"),

    # Verbose errors
    "PROPAGATE_EXCEPTIONS": _sink("config", [0], "Exception propagation enabled"),
    "traceback.print_exc": _sink("info_disclosure", [0], "Traceback disclosure (CWE-209)"),
    "traceback.format_exc": _sink("info_disclosure", [0], "Traceback formatting (CWE-209)"),
}

# =============================================================================
# A07: Identification and Authentication Failures (OWASP 2025)
# =============================================================================

AUTH_SPECS = {
    # Hardcoded credentials
    "password": _sink("hardcoded_cred", [0], "Potential hardcoded password (CWE-798)"),
    "passwd": _sink("hardcoded_cred", [0], "Potential hardcoded password (CWE-798)"),
    "api_key": _sink("hardcoded_cred", [0], "Potential hardcoded API key (CWE-798)"),
    "apikey": _sink("hardcoded_cred", [0], "Potential hardcoded API key (CWE-798)"),
    "secret": _sink("hardcoded_cred", [0], "Potential hardcoded secret (CWE-798)"),
    "token": _sink("hardcoded_cred", [0], "Potential hardcoded token (CWE-798)"),
    "private_key": _sink("hardcoded_cred", [0], "Potential hardcoded private key (CWE-798)"),

    # Weak password hashing - NOTE: hashlib.md5/sha1 are already defined in CRYPTO_SPECS
    # as usage-based sinks (CWE-328). Don't redefine here.

    # Password storage
    "bcrypt.hashpw": _sanitizer(["password"], "bcrypt password hashing (safe)"),
    "argon2.hash": _sanitizer(["password"], "Argon2 password hashing (safe)"),
    "pbkdf2_hmac": _sanitizer(["password"], "PBKDF2 password hashing (safe)"),
    "werkzeug.security.generate_password_hash": _sanitizer(["password"], "Werkzeug password hash"),
    "django.contrib.auth.hashers.make_password": _sanitizer(["password"], "Django password hash"),

    # Session management
    "session.permanent": _sink("session", [0], "Permanent session (check timeout)"),
    "PERMANENT_SESSION_LIFETIME": _sink("session", [0], "Session lifetime config"),

    # Rate limiting (absence is a vulnerability)
    "ratelimit": _propagator([0], "Rate limiting decorator"),
    "Limiter": _propagator([0], "Flask-Limiter"),
}

# =============================================================================
# A10: Mishandling of Exceptional Conditions (OWASP 2025 - NEW)
# =============================================================================

EXCEPTION_SPECS = {
    # Bare except (catches everything including SystemExit)
    "except:": _sink("exception", [0], "Bare except clause (CWE-396)"),
    "except Exception:": _sink("exception", [0], "Generic exception catch (CWE-396)"),
    "except BaseException:": _sink("exception", [0], "BaseException catch (CWE-396)"),

    # Exception swallowing
    "pass": _sink("exception", [0], "Potential exception swallowing (CWE-390)"),

    # Assertions in production (can be disabled with -O)
    "assert": _sink("assertion", [0], "Assert statement (disabled with -O) (CWE-617)"),

    # Resource management
    # Note: "open" is already defined in FILESYSTEM_SPECS for path traversal (CWE-22)
    # which is the more critical security concern

    # Error disclosure
    "str(e)": _propagator([0], "Exception to string (may leak info)"),
    "repr(e)": _propagator([0], "Exception repr (may leak info)"),
}

# =============================================================================
# A04: Additional Cryptographic Failures (OWASP 2025)
# =============================================================================

CRYPTO_ENHANCED_SPECS = {
    # ECB mode (insecure)
    "MODE_ECB": _sink("weak_crypto", [0], "ECB mode is insecure (CWE-327)"),
    "AES.MODE_ECB": _sink("weak_crypto", [0], "AES ECB mode (CWE-327)"),

    # Weak key sizes
    "key_size=1024": _sink("weak_crypto", [0], "Weak RSA key size (CWE-326)"),
    "key_size=512": _sink("weak_crypto", [0], "Weak RSA key size (CWE-326)"),

    # Predictable IV/nonce
    "iv=": _sink("weak_crypto", [0], "Check for random IV (CWE-329)"),
    "nonce=": _sink("weak_crypto", [0], "Check for random nonce (CWE-329)"),

    # Insecure TLS versions
    "SSLv2": _sink("weak_crypto", [0], "SSLv2 is insecure (CWE-327)"),
    "SSLv3": _sink("weak_crypto", [0], "SSLv3 is insecure (CWE-327)"),
    "TLSv1": _sink("weak_crypto", [0], "TLSv1.0 is deprecated (CWE-327)"),
    "TLSv1_1": _sink("weak_crypto", [0], "TLSv1.1 is deprecated (CWE-327)"),
    "PROTOCOL_SSLv2": _sink("weak_crypto", [0], "SSLv2 protocol (CWE-327)"),
    "PROTOCOL_SSLv3": _sink("weak_crypto", [0], "SSLv3 protocol (CWE-327)"),
    "PROTOCOL_TLSv1": _sink("weak_crypto", [0], "TLSv1.0 protocol (CWE-327)"),

    # Secure alternatives
    "secrets.token_bytes": _sanitizer(["random"], "Cryptographically secure random"),
    "secrets.token_hex": _sanitizer(["random"], "Cryptographically secure random"),
    "secrets.token_urlsafe": _sanitizer(["random"], "Cryptographically secure random"),
    "os.urandom": _sanitizer(["random"], "Cryptographically secure random"),
}

# =============================================================================
# Sensitive Data Exposure (A01/A09)
# =============================================================================

SENSITIVE_DATA_SPECS = {
    # Logging sensitive data
    "logging.debug": _sink("sensitive_log", [0], "Debug log (may contain sensitive data CWE-532)"),
    "logging.info": _sink("sensitive_log", [0], "Info log (may contain sensitive data CWE-532)"),

    # Sensitive data patterns in responses
    "password": _sink("sensitive_exposure", [0], "Password in response (CWE-200)"),
    "credit_card": _sink("sensitive_exposure", [0], "Credit card in response (CWE-200)"),
    "ssn": _sink("sensitive_exposure", [0], "SSN in response (CWE-200)"),
    "social_security": _sink("sensitive_exposure", [0], "SSN in response (CWE-200)"),

    # PII exposure
    "email": _propagator([0], "Email data (PII)"),
    "phone": _propagator([0], "Phone data (PII)"),
    "address": _propagator([0], "Address data (PII)"),
}

# =============================================================================
# HTTP Header Security (A02/A05)
# =============================================================================

HEADER_SPECS = {
    # Missing security headers
    "X-Frame-Options": _propagator([0], "X-Frame-Options header"),
    "X-Content-Type-Options": _propagator([0], "X-Content-Type-Options header"),
    "X-XSS-Protection": _propagator([0], "X-XSS-Protection header"),
    "Content-Security-Policy": _propagator([0], "CSP header"),
    "Strict-Transport-Security": _propagator([0], "HSTS header"),

    # Header injection
    "response.headers": _sink("header_injection", [0], "Response header manipulation (CWE-113)"),
    "make_response().headers": _sink("header_injection", [0], "Response header (CWE-113)"),
}

# =============================================================================
# Server-Side Request Forgery Enhanced (A01)
# =============================================================================

SSRF_ENHANCED_SPECS = {
    # Cloud metadata endpoints
    "169.254.169.254": _sink("ssrf", [0], "Cloud metadata endpoint (SSRF)"),
    "metadata.google.internal": _sink("ssrf", [0], "GCP metadata (SSRF)"),

    # Internal network access
    "localhost": _sink("ssrf", [0], "Localhost access (SSRF)"),
    "127.0.0.1": _sink("ssrf", [0], "Loopback access (SSRF)"),
    "0.0.0.0": _sink("ssrf", [0], "All interfaces (SSRF)"),
    "10.": _sink("ssrf", [0], "Private network (SSRF)"),
    "172.16.": _sink("ssrf", [0], "Private network (SSRF)"),
    "192.168.": _sink("ssrf", [0], "Private network (SSRF)"),

    # URL parsing (potential bypass)
    "urllib.parse.urlparse": _propagator([0], "URL parsing"),
    "urlparse": _propagator([0], "URL parsing"),
}

# =============================================================================
# Combined Specifications
# =============================================================================

PYTHON_SPECS: Dict[str, ProcSpec] = {}
PYTHON_SPECS.update(FLASK_SPECS)
PYTHON_SPECS.update(DJANGO_SPECS)
PYTHON_SPECS.update(SQLALCHEMY_SPECS)
PYTHON_SPECS.update(SUBPROCESS_SPECS)
PYTHON_SPECS.update(FILESYSTEM_SPECS)
PYTHON_SPECS.update(EVAL_SPECS)
PYTHON_SPECS.update(NETWORK_SPECS)
PYTHON_SPECS.update(HTML_SPECS)
PYTHON_SPECS.update(LOGGING_SPECS)
PYTHON_SPECS.update(STDLIB_SOURCES)
PYTHON_SPECS.update(STRING_SPECS)
PYTHON_SPECS.update(LIST_SPECS)
PYTHON_SPECS.update(URL_ENCODING_SPECS)
# OWASP 2025 additions
PYTHON_SPECS.update(CRYPTO_SPECS)
PYTHON_SPECS.update(DESERIALIZATION_SPECS)
PYTHON_SPECS.update(NOSQL_SPECS)
PYTHON_SPECS.update(REGEX_SPECS)
PYTHON_SPECS.update(TEMPLATE_SPECS)
PYTHON_SPECS.update(LDAP_SPECS)
PYTHON_SPECS.update(SENSITIVE_LOGGING_SPECS)
# OWASP 2025 enhanced coverage
PYTHON_SPECS.update(ACCESS_CONTROL_SPECS)
PYTHON_SPECS.update(MISCONFIGURATION_SPECS)
PYTHON_SPECS.update(AUTH_SPECS)
PYTHON_SPECS.update(EXCEPTION_SPECS)
PYTHON_SPECS.update(CRYPTO_ENHANCED_SPECS)
PYTHON_SPECS.update(SENSITIVE_DATA_SPECS)
PYTHON_SPECS.update(HEADER_SPECS)
PYTHON_SPECS.update(SSRF_ENHANCED_SPECS)
# Additional OWASP benchmark coverage
PYTHON_SPECS.update(XPATH_SPECS)
PYTHON_SPECS.update(TRUST_BOUNDARY_SPECS)
PYTHON_SPECS.update(COOKIE_SPECS)
PYTHON_SPECS.update(REDIRECT_SPECS)
PYTHON_SPECS.update(SQL_ENHANCED_SPECS)
PYTHON_SPECS.update(COMMAND_INJECTION_SPECS)
PYTHON_SPECS.update(XSS_SPECS)

# =============================================================================
# OWASP Benchmark Helper Patterns
# =============================================================================

OWASP_HELPERS_SPECS = {
    # Request wrapper patterns (used in OWASP benchmark)
    "wrapped.get_form_parameter": _source("user", "Wrapped form parameter"),
    "get_form_parameter": _source("user", "Form parameter getter"),
    "request_wrapper": _propagator([0], "Request wrapper"),
    "helpers.separate_request.request_wrapper": _propagator([0], "OWASP request wrapper"),

    # ConfigParser (taint propagation)
    # set() propagates from value (arg 2) to the receiver object (handled by translator)
    "configparser.ConfigParser.set": _propagator([2], "ConfigParser set (taints config)"),
    "ConfigParser.set": _propagator([2], "ConfigParser set"),
    # get() propagates from receiver (the ConfigParser object) to return value
    "configparser.ConfigParser.get": _propagator([], "ConfigParser get (from config)", from_receiver=True),
    "ConfigParser.get": _propagator([], "ConfigParser get", from_receiver=True),

    # More Flask request patterns
    "request.form.keys": _source("user", "Flask form keys"),
    "request.form.values": _source("user", "Flask form values"),
    "request.form.items": _source("user", "Flask form items"),
    "request.args.keys": _source("user", "Flask query keys"),
    "request.args.values": _source("user", "Flask query values"),

    # ThingFactory patterns (OWASP helper)
    "thing.doSomething": _propagator([0], "OWASP helper doSomething"),
    "doSomething": _propagator([0], "OWASP doSomething"),
    "helpers.ThingFactory.createThing": _propagator([0], "OWASP ThingFactory"),
    "createThing": _propagator([0], "OWASP createThing"),

    # OWASP SimpleClass patterns
    "SimpleClass": _propagator([0], "OWASP SimpleClass"),
    "simple.doSomething": _propagator([0], "OWASP simple helper"),

    # Base64 encoding/decoding (taint propagation)
    "base64.b64encode": _propagator([0], "Base64 encode"),
    "base64.b64decode": _propagator([0], "Base64 decode"),
    "base64.urlsafe_b64encode": _propagator([0], "Base64 URL-safe encode"),
    "base64.urlsafe_b64decode": _propagator([0], "Base64 URL-safe decode"),
    "base64.b32encode": _propagator([0], "Base32 encode"),
    "base64.b32decode": _propagator([0], "Base32 decode"),
    "base64.b16encode": _propagator([0], "Base16 encode"),
    "base64.b16decode": _propagator([0], "Base16 decode"),

    # String encode/decode methods (taint propagation)
    "str.encode": _propagator([0], "String encode"),
    "bytes.decode": _propagator([0], "Bytes decode"),
    # Receiver-based propagation for method calls
    "encode": _propagator([0], "String encode method"),
    "decode": _propagator([0], "Bytes decode method"),
}

PYTHON_SPECS.update(OWASP_HELPERS_SPECS)


def get_python_specs() -> Dict[str, ProcSpec]:
    """Get all Python library specifications"""
    return PYTHON_SPECS.copy()


def get_flask_specs() -> Dict[str, ProcSpec]:
    """Get Flask-specific specifications"""
    return FLASK_SPECS.copy()


def get_django_specs() -> Dict[str, ProcSpec]:
    """Get Django-specific specifications"""
    return DJANGO_SPECS.copy()
