"""Hardening findings: an explicit off switch for a protection (debug mode, cookie flags).

Reported in their own category and never for a merely missing option. Each positive is paired
with the nearest correct form.
"""

import pytest

try:
    import tomllib
except ModuleNotFoundError:                 # Python < 3.11
    import tomli as tomllib                 # type: ignore[no-redef]

from frame.sil.scanner import FrameScanner


def hardening(code, language="python", name="a.py"):
    r = FrameScanner(language=language).scan(code, name)
    return sorted((v.cwe_id, v.line) for v in r.vulnerabilities if v.category == "hardening")


FLASK = "from flask import Flask\napp = Flask(__name__)\n"


@pytest.mark.parametrize("body,expected", [
    ("app.run(debug=True, port=5000)\n", [("CWE-215", 3)]),
    ("app.run(host='0.0.0.0')\n", []),
    ("app.run(debug=False)\n", []),
    ("app.debug = True\n", [("CWE-215", 3)]),
    ("app.config['DEBUG'] = True\n", [("CWE-215", 3)]),
    ("app.config['DEBUG'] = False\n", []),
    ("app.config['SESSION_COOKIE_SECURE'] = False\n", [("CWE-614", 3)]),
    ("app.config['SESSION_COOKIE_SECURE'] = True\n", []),
    ("app.config.update(SESSION_COOKIE_HTTPONLY=False)\n", [("CWE-1004", 3)]),
    ("app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SECURE=True)\n", []),
    ("app.config['SESSION_COOKIE_NAME'] = 'x'\n", []),
])
def test_flask_configuration(body, expected):
    assert hardening(FLASK + body) == expected


def test_run_debug_true_outside_a_web_framework_is_not_reported():
    assert hardening("import uvicorn\nuvicorn.run('app:app', debug=True)\n") == []
    assert hardening("class Job:\n    pass\nJob().run(debug=True)\n") == []


@pytest.mark.parametrize("code,name,expected", [
    ("DEBUG = True\nALLOWED_HOSTS = []\n", "settings.py", [("CWE-215", 1)]),
    ("DEBUG = True\n", "prod_settings.py", []),                       # not a settings module name or marker
    ("DEBUG = False\nALLOWED_HOSTS = []\n", "settings.py", []),
    ("DEBUG = True\n", "util.py", []),                                # a flag in ordinary code
    ("SESSION_COOKIE_SECURE = False\n", "settings.py", [("CWE-614", 1)]),
    ("SESSION_COOKIE_HTTPONLY = False\nCSRF_COOKIE_SECURE = False\n", "settings.py",
     [("CWE-1004", 1), ("CWE-614", 2)]),
    ("SESSION_COOKIE_SECURE = not DEBUG\n", "settings.py", []),
])
def test_django_settings(code, name, expected):
    assert hardening(code, name=name) == expected


@pytest.mark.parametrize("code,expected", [
    ("app.use(session({ secret: 'k', cookie: { secure: false } }));", [("CWE-614", 1)]),
    ("app.use(session({ secret: 'k', cookie: { httpOnly: false } }));", [("CWE-1004", 1)]),
    ("app.use(session({ secret: 'k', cookie: { secure: true, httpOnly: true } }));", []),
    ("app.use(session({ secret: 'k' }));", []),                                   # missing is not reported
    ("res.cookie('a', 'b', { httpOnly: false, secure: false });", [("CWE-1004", 1), ("CWE-614", 1)]),
    ("const options = { secure: false };", []),                                   # not a cookie call
    ("https.createServer({ secure: false });", []),
])
def test_express_cookie_options(code, expected):
    assert hardening(code, "javascript", "a.js") == expected


def test_hardening_is_its_own_category_in_the_json():
    r = FrameScanner(language="python").scan(FLASK + "app.run(debug=True)\n", "a.py")
    d = [v.to_dict() for v in r.vulnerabilities]
    assert d and all(x["category"] == "hardening" for x in d)


def test_inline_ignore_marker_silences_it():
    code = FLASK + "app.run(debug=True)  # frame: ignore\n"
    r = FrameScanner(language="python").scan(code, "a.py")
    assert not [v for v in r.vulnerabilities if v.category]


def test_a_project_pack_adds_a_setting(tmp_path):
    pack = tmp_path / "acme.toml"
    pack.write_text('''[pack]
name = "acme-settings"
language = "python"
detect = { imports = ["acme"] }

[[setting]]
kind = "debug"
at = "kwarg"
call = ["acme.serve"]
keys = ["trace"]
value = true
description = "Tracing server enabled"
''')
    code = "import acme\nacme.serve(trace=True)\nacme.serve(trace=False)\n"
    r = FrameScanner(language="python", packs=[str(pack)]).scan(code, "a.py")
    found = [(v.cwe_id, v.line, v.description) for v in r.vulnerabilities if v.category == "hardening"]
    assert found == [("CWE-215", 2, "Tracing server enabled: acme.serve(trace=True)")]
    assert hardening(code) == []                                     # without the pack: nothing


@pytest.mark.parametrize("entry,message", [
    ('kind = "verbose"\nat = "kwarg"\ncall = ["x"]\nkeys = ["a"]\nvalue = true', "kind"),
    ('kind = "debug"\nat = "env"\nkeys = ["a"]\nvalue = true', "at"),
    ('kind = "debug"\nat = "kwarg"\nkeys = ["a"]\nvalue = true', "needs call"),
    ('kind = "debug"\nat = "subscript"\nkeys = ["a"]\nvalue = true', "needs receiver"),
    ('kind = "debug"\nat = "assignment"\nkeys = ["a"]\nvalue = "yes"', "value"),
])
def test_malformed_settings_are_rejected(entry, message):
    from frame.sil.packs.schema import PackError, parse_pack
    doc = tomllib.loads(f'[pack]\nname = "p"\nlanguage = "python"\n\n[[setting]]\n{entry}\n')
    with pytest.raises(PackError, match=message):
        parse_pack(doc, "t.toml")
