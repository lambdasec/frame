"""Framework packs, used the way a team would: teach Frame an in-house library or framework
with a TOML file -- from `--pack`, from the project's `.frame/packs`, or from `.frame.toml` --
and scan real code with it. Also: what a broken pack looks like, and the packs CLI.
"""

import json
import subprocess
import sys

import pytest

from e2e_helpers import scan, scan_subprocess, write_tree

# An in-house stack Frame knows nothing about: `acme.web` (routing + request access),
# `acme.store` (raw SQL), `acme.proc` (process execution), `acme.text` (cleaning).
APP = {
    "service/handlers.py": '''import acme.web as web
import acme.store as store
import acme.proc as proc
import acme.text as text


@web.route("/users")
def users(name, limit):
    return store.query_sql("SELECT * FROM users WHERE name = '" + name + "'")


@web.route("/safe-users")
def safe_users(name):
    return store.query_sql("SELECT * FROM users WHERE name = '" + text.sql_clean(name) + "'")


def handler():
    tag = web.param("tag")
    proc.launch("git tag " + tag, shell=True)
    proc.launch("git tag " + tag, shell=False)
''',
}

PACK = '''[pack]
name = "acme"
language = "python"
description = "Acme in-house web stack"
detect = { imports = ["acme"] }

[[entrypoint]]
id = "acme-route"
decorator = ["acme.web.route", "web.route"]
params = "all"

[[source]]
call = ["acme.web.param"]
kind = "user_input"

[[sink]]
call = ["acme.store.query_sql"]
kind = "sql"
description = "acme.store.query_sql executes its argument as SQL"

[[sink]]
call = ["acme.proc.launch"]
kind = "command"
when_kwarg = { name = "shell", value = "True" }

[[sanitizer]]
call = ["acme.text.sql_clean"]
kinds = ["sql"]
'''


def findings_by_line(result):
    return {(f["line"], f["cwe_id"]) for f in result.findings}


@pytest.fixture
def project(tmp_path):
    write_tree(tmp_path, APP)
    return tmp_path


def test_without_a_pack_the_in_house_stack_is_invisible(project):
    assert scan(project).findings == []


def test_pack_flag_teaches_sources_sinks_sanitizers_entry_points_and_conditions(project):
    pack = project / "acme.toml"
    pack.write_text(PACK)
    result = scan(project, "--pack", str(pack))
    got = findings_by_line(result)
    assert (9, "CWE-89") in got                      # handler parameter of an @web.route function -> raw SQL
    assert not any(line == 14 for line, _ in got)    # the same query behind acme.text.sql_clean
    assert (19, "CWE-78") in got                     # shell=True with request data
    assert not any(line == 20 for line, _ in got)    # shell=False: the condition does not hold
    assert "python/acme" in result.packs_applied


def test_project_packs_directory_is_found_without_any_flag(project):
    write_tree(project, {".frame/packs/acme.toml": PACK})
    result = scan(project)
    assert (9, "CWE-89") in findings_by_line(result)
    assert "python/acme" in result.doc["packs"]


def test_pack_from_the_config_file(project):
    write_tree(project, {"security/acme.toml": PACK, ".frame.toml": 'packs = ["security/acme.toml"]\n'})
    assert (9, "CWE-89") in findings_by_line(scan(project))


def test_a_pack_only_applies_to_files_that_show_the_framework(tmp_path):
    write_tree(tmp_path, {
        "acme_clone.py": 'from other import web, db\n\n\n@web.route("/x")\ndef x(name):\n    return store.query_sql("SELECT " + name)\n',
        ".frame/packs/acme.toml": PACK,
    })
    assert scan(tmp_path).findings == []             # imports nothing from acme


def test_a_pack_refines_a_builtin_spec_instead_of_replacing_it(tmp_path):
    # os.system stays a command sink; the pack only adds an in-house sanitizer for it.
    write_tree(tmp_path, {
        "app.py": ('import os\nimport acme.text as text\nfrom flask import Flask, request\n'
                   'app = Flask(__name__)\n\n\n@app.route("/a")\ndef a():\n'
                   '    os.system("echo " + request.args["x"])\n    return ""\n\n\n@app.route("/b")\ndef b():\n'
                   '    os.system("echo " + text.shell_clean(request.args["x"]))\n    return ""\n'),
        ".frame/packs/acme.toml": '[pack]\nname="acme"\nlanguage="python"\n[[sanitizer]]\ncall=["acme.text.shell_clean"]\nkinds=["command","shell"]\n',
    })
    got = findings_by_line(scan(tmp_path))
    assert (9, "CWE-78") in got and not any(line == 15 for line, _ in got)


def test_builtin_packs_can_be_switched_off(tmp_path):
    write_tree(tmp_path, {"app.py": (
        "import tornado.web\n\n\nclass Hello(tornado.web.RequestHandler):\n"
        "    def get(self):\n        self.write('<b>' + self.get_argument('name') + '</b>')\n")})
    assert {f["cwe_id"] for f in scan(tmp_path).findings} == {"CWE-79"}     # the tornado pack
    assert scan(tmp_path, "--no-packs").findings == []


def test_packs_apply_in_a_single_file_scan_too(project):
    pack = project / "acme.toml"
    pack.write_text(PACK)
    result = scan(project / "service" / "handlers.py", "--pack", str(pack))
    assert (9, "CWE-89") in findings_by_line(result)


# ---- a broken pack is an error with a location, never a silent no-op ----------------------

@pytest.mark.parametrize("body, needle", [
    ('[pack]\nname = "x"\nlanguage = "cobol"\n', "language"),
    ('[pack]\nname = "x"\nlanguage = "python"\n[[sink]]\ncall = ["a.b"]\nkind = "no-such-kind"\n', "sink kind"),
    ('[pack]\nname = "x"\nlanguage = "python"\n[[sink]]\nkind = "sql"\n', "needs `call`"),
    ('[pack]\nname = "x"\nlanguage = "python"\n[[source]]\ncall = ["a.b"]\nbogus = 1\n', "unknown key"),
    ('[pack]\nname = "x"\nlanguage = "python"\n[[entrypoint]]\ndecorator = ["a"]\n', "taints nothing"),
    ('[pack\nname = ', "invalid TOML"),
])
def test_broken_pack_exits_2_and_names_the_problem(project, body, needle):
    bad = project / "bad.toml"
    bad.write_text(body)
    done = scan_subprocess(project, "--pack", str(bad), "-f", "json")
    assert done.returncode == 2
    assert "bad.toml" in done.stderr and needle in done.stderr


def test_missing_pack_path_is_an_error(project):
    done = scan_subprocess(project, "--pack", str(project / "nope.toml"))
    assert done.returncode == 2 and "nope.toml" in done.stderr


def test_packs_check_validates_files(tmp_path):
    good, bad = tmp_path / "good.toml", tmp_path / "bad.toml"
    good.write_text(PACK)
    bad.write_text('[pack]\nname = "x"\nlanguage = "python"\n[[sink]]\ncall = ["a"]\nkind = "nope"\n')
    ok = subprocess.run([sys.executable, "-m", "frame.cli", "packs", "check", str(good)], capture_output=True, text=True)
    assert ok.returncode == 0 and "python/acme" in ok.stdout
    fail = subprocess.run([sys.executable, "-m", "frame.cli", "packs", "check", str(good), str(bad)],
                          capture_output=True, text=True)
    assert fail.returncode == 1 and "bad.toml" in fail.stderr


def test_packs_list_shows_builtin_and_project_packs(project):
    write_tree(project, {".frame/packs/acme.toml": PACK})
    done = subprocess.run([sys.executable, "-m", "frame.cli", "packs", "list", "--language", "python",
                           "--project", str(project)], capture_output=True, text=True)
    assert done.returncode == 0
    assert "tornado" in done.stdout and "acme" in done.stdout
