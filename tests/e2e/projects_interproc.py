"""Interprocedural taint inside one file (helper sinks, returned data, sanitising helpers,
recursion, callbacks, methods), each with a safe twin."""

CASES = {}


def case(name, vulnerable, safe):
    CASES[name] = (vulnerable, safe)


_PY_HEAD = "import os\nimport shlex\nimport subprocess\nfrom flask import Flask, request\n\napp = Flask(__name__)\n\n\n"

case("py_argument_reaches_helper_sink", {
    "app.py": _PY_HEAD + '''def archive(name):
    os.system("tar czf out.tgz " + name)  # frame-expect: CWE-78


@app.route("/a")
def a():
    archive(request.args.get("name", ""))
    return "ok"
''',
}, {
    "app.py": _PY_HEAD + '''def archive(name):
    os.system("tar czf out.tgz " + shlex.quote(name))


@app.route("/a")
def a():
    archive(request.args.get("name", ""))
    return "ok"
''',
})

case("py_helper_returns_request_data", {
    "app.py": _PY_HEAD + '''def current_name():
    return request.args.get("name", "")


@app.route("/a")
def a():
    os.system("echo " + current_name())  # frame-expect: CWE-78
    return "ok"
''',
}, {
    "app.py": _PY_HEAD + '''def current_name():
    return request.args.get("name", "")


@app.route("/a")
def a():
    os.system("echo " + shlex.quote(current_name()))
    return "ok"
''',
})

case("py_taint_through_four_helpers", {
    "app.py": _PY_HEAD + '''def d(x):
    subprocess.call("echo " + x, shell=True)  # frame-expect: CWE-78


def c(x):
    d(x + "!")


def b(x):
    c(x)


def a_(x):
    b(x)


@app.route("/a")
def a():
    a_(request.args.get("q", ""))
    return "ok"
''',
}, {
    "app.py": _PY_HEAD + '''def d(x):
    subprocess.call(["echo", x])


def c(x):
    d(x + "!")


def b(x):
    c(x)


def a_(x):
    b(x)


@app.route("/a")
def a():
    a_(request.args.get("q", ""))
    return "ok"
''',
})

case("py_mutual_recursion_terminates_and_finds", {
    "app.py": _PY_HEAD + '''def ping(x, n):
    if n <= 0:
        os.system("echo " + x)  # frame-expect: CWE-78
        return
    pong(x, n - 1)


def pong(x, n):
    ping(x, n)


@app.route("/a")
def a():
    ping(request.args.get("q", ""), 3)
    return "ok"
''',
}, {
    "app.py": _PY_HEAD + '''def ping(x, n):
    if n <= 0:
        os.system("echo " + shlex.quote(x))
        return
    pong(x, n - 1)


def pong(x, n):
    ping(x, n)


@app.route("/a")
def a():
    ping(request.args.get("q", ""), 3)
    return "ok"
''',
})

case("py_method_on_self", {
    "app.py": _PY_HEAD + '''class Reports:
    def render(self, title):
        os.system("report --title " + title)  # frame-expect: CWE-78

    def handle(self, title):
        self.render(title.strip())


@app.route("/r")
def r():
    Reports().handle(request.args.get("title", ""))
    return "ok"
''',
}, {
    "app.py": _PY_HEAD + '''class Reports:
    def render(self, title):
        os.system("report --title " + shlex.quote(title))

    def handle(self, title):
        self.render(title.strip())


@app.route("/r")
def r():
    Reports().handle(request.args.get("title", ""))
    return "ok"
''',
})

case("py_helper_only_sanitises_one_of_two_parameters", {
    "app.py": _PY_HEAD + '''def run(safe, raw):
    os.system("tool " + shlex.quote(safe) + " " + raw)  # frame-expect: CWE-78


@app.route("/a")
def a():
    run(request.args.get("a", ""), request.args.get("b", ""))
    return "ok"
''',
}, {
    "app.py": _PY_HEAD + '''def run(safe, raw):
    os.system("tool " + shlex.quote(safe) + " " + shlex.quote(raw))


@app.route("/a")
def a():
    run(request.args.get("a", ""), request.args.get("b", ""))
    return "ok"
''',
})

_JS_HEAD = 'const express = require("express");\nconst { execSync } = require("child_process");\nconst app = express();\n\n'
case("js_argument_reaches_helper_sink", {
    "app.js": _JS_HEAD + '''function archive(name) {
  execSync("tar czf out.tgz " + name);  // frame-expect: CWE-78
}

app.get("/a", (req, res) => {
  archive(req.query.name);
  res.send("ok");
});
''',
}, {
    "app.js": _JS_HEAD.replace("execSync }", "execFileSync }") + '''function archive(name) {
  execFileSync("tar", ["czf", "out.tgz", name]);
}

app.get("/a", (req, res) => {
  archive(req.query.name);
  res.send("ok");
});
''',
})

case("js_returned_value_and_numeric_sanitiser", {
    "app.js": _JS_HEAD + '''const readName = (req) => req.query.name;

app.get("/a", (req, res) => {
  execSync("echo " + readName(req));  // frame-expect: CWE-78
  res.send("ok");
});
''',
}, {
    "app.js": _JS_HEAD + '''const readCount = (req) => parseInt(req.query.count, 10);

app.get("/a", (req, res) => {
  execSync("seq " + readCount(req));
  res.send("ok");
});
''',
})

case("js_class_method_chain", {
    "app.js": _JS_HEAD + '''class Exporter {
  run(name) {
    return execSync("export --name " + name).toString();  // frame-expect: CWE-78
  }

  handle(req) {
    return this.run(req.query.name);
  }
}

app.get("/e", (req, res) => {
  res.send(new Exporter().handle(req));
});
''',
}, {
    "app.js": _JS_HEAD.replace("execSync }", "execFileSync }") + '''class Exporter {
  run(name) {
    return execFileSync("export", ["--name", name]).toString();
  }

  handle(req) {
    return this.run(req.query.name);
  }
}

app.get("/e", (req, res) => {
  res.send(new Exporter().handle(req));
});
''',
})


# ---- the request object and callbacks travel through helpers -------------------------------
case("py_request_object_passed_to_helper", {
    "app.py": _PY_HEAD + '''def run_report(req):
    os.system("report --title " + req.args.get("title", ""))  # frame-expect: CWE-78


@app.route("/r")
def r():
    run_report(request)
    return "ok"
''',
}, {
    "app.py": _PY_HEAD + '''def run_report(req):
    os.system("report --title " + shlex.quote(req.args.get("title", "")))


@app.route("/r")
def r():
    run_report(request)
    return "ok"
''',
})

case("js_callback_parameter_receives_request_data", {
    "app.js": _JS_HEAD + '''function withName(req, cb) {
  cb(req.query.name);
}

app.get("/a", (req, res) => {
  withName(req, (name) => {
    execSync("echo " + name);  // frame-expect: CWE-78
    res.send("ok");
  });
});
''',
}, {
    "app.js": _JS_HEAD.replace("execSync }", "execFileSync }") + '''function withName(req, cb) {
  cb(req.query.name);
}

app.get("/a", (req, res) => {
  withName(req, (name) => {
    execFileSync("echo", [name]);
    res.send("ok");
  });
});
''',
})

case("js_named_callback_passed_to_helper", {
    "app.js": _JS_HEAD + '''function forEachParam(req, visit) {
  Object.keys(req.query).forEach((k) => visit(req.query[k]));
}

function run(value) {
  execSync("echo " + value);  // frame-expect: CWE-78
}

app.get("/a", (req, res) => {
  forEachParam(req, run);
  res.send("ok");
});
''',
}, {
    "app.js": _JS_HEAD.replace("execSync }", "execFileSync }") + '''function forEachParam(req, visit) {
  Object.keys(req.query).forEach((k) => visit(req.query[k]));
}

function run(value) {
  execFileSync("echo", [value]);
}

app.get("/a", (req, res) => {
  forEachParam(req, run);
  res.send("ok");
});
''',
})
