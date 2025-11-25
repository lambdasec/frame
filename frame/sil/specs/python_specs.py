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
    return ProcSpec(is_sink=kind, sink_args=args or [0], description=desc)


def _sanitizer(kinds: list, desc: str = "") -> ProcSpec:
    """Create a sanitizer spec"""
    return ProcSpec(is_sanitizer=kinds, description=desc)


def _propagator(args: list, desc: str = "") -> ProcSpec:
    """Create a taint propagator spec"""
    return ProcSpec(taint_propagates=args, description=desc)


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

    # Pickle (deserialization sinks)
    "pickle.loads": _sink("deserialize", [0], "Pickle deserialization"),
    "pickle.load": _sink("deserialize", [0], "Pickle deserialization"),
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


def get_python_specs() -> Dict[str, ProcSpec]:
    """Get all Python library specifications"""
    return PYTHON_SPECS.copy()


def get_flask_specs() -> Dict[str, ProcSpec]:
    """Get Flask-specific specifications"""
    return FLASK_SPECS.copy()


def get_django_specs() -> Dict[str, ProcSpec]:
    """Get Django-specific specifications"""
    return DJANGO_SPECS.copy()
