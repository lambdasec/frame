"""Standard-library API facts the engine reads are data, not code branches: algorithm-by-name
calls (`algorithm_name_arg`), keywords that switch a usage sink off (`safe_kwargs`), scanf
formats (`scanf_format_arg`) in the spec tables, and the calls branch guards understand
(`specs/data/guards.toml`)."""

import pytest

from frame.sil.scanner import FrameScanner
from frame.sil.specs import guards
from frame.sil.specs.tables import SpecTableError, parse_table
from frame.sil.specs.weak_algorithms import weak_algorithm


def _found(code, lang, name):
    return sorted({(v.cwe_id, v.line) for v in FrameScanner(language=lang, verify=False).scan(code, name).vulnerabilities})


@pytest.mark.parametrize("kind,name,why", [
    ("weak_hash", "md5", "hash"), ("weak_hash", "SHA-1", "hash"), ("weak_hash", "SHA-256", None),
    ("weak_crypto", "DES/CBC/PKCS5Padding", "cipher"), ("weak_crypto", "DESede", "cipher"),
    ("weak_crypto", "PBEWithMD5AndDES", "cipher"), ("weak_crypto", "AES/ECB/PKCS5Padding", "mode"),
    ("weak_crypto", "AES/GCM/NoPadding", None), ("weak_crypto", "AES/CBC/NoPadding", None),
    ("weak_crypto", "AES", None), ("sql", "md5", None),
])
def test_weak_algorithm_names(kind, name, why):
    assert weak_algorithm(kind, name) == why


def test_algorithm_named_by_a_literal():
    code = ("import javax.crypto.Cipher; import java.security.MessageDigest;\nclass A { void f(String alg) throws Exception {\n"
            ' Cipher a = Cipher.getInstance("DES/CBC/PKCS5Padding");\n'
            ' Cipher b = Cipher.getInstance("AES/GCM/NoPadding");\n'
            ' MessageDigest c = MessageDigest.getInstance(alg);\n'
            ' MessageDigest d = MessageDigest.getInstance("SHA-256");\n'
            ' MessageDigest e = MessageDigest.getInstance("MD5");\n}}\n')
    assert _found(code, "java", "A.java") == [("CWE-327", 3), ("CWE-328", 7)]
    py = 'import hashlib\n\ndef f(alg):\n    a = hashlib.new(alg)\n    b = hashlib.new("sha256")\n'
    assert _found(py, "python", "a.py") == []
    assert _found('import hashlib\nh = hashlib.new("md5")\n', "python", "a.py") == [("CWE-328", 2)]


@pytest.mark.parametrize("call,reported", [
    ('hashlib.md5(b"x")', True),
    ('hashlib.md5(b"x", usedforsecurity=False)', False),
    ('hashlib.md5(b"x", usedforsecurity=True)', True),
    ('hashlib.new("md5", usedforsecurity=False)', False),
])
def test_usedforsecurity_false_is_a_documented_non_security_hash(call, reported):
    assert bool(_found(f"import hashlib\nh = {call}\n", "python", "a.py")) == reported


@pytest.mark.parametrize("lang", ["c", "cpp"])
def test_scanf_is_a_sink_only_with_an_unbounded_conversion(lang):
    code = ("#include <stdio.h>\nint main(void)\n{\n    char b[10];\n    int n;\n    scanf(\"%d\", &n);\n"
            "    scanf(\"%s\", b);\n    sscanf(b, \"%9s\", b);\n    sscanf(b, \"%s\", b);\n    return 0;\n}\n")
    assert [line for cwe, line in _found(code, lang, "a." + lang) if cwe == "CWE-120"] == [7, 9]


@pytest.mark.parametrize("entry,error", [
    ({"name": "f", "algorithm_name_arg": -1}, "algorithm_name_arg must be an argument position"),
    ({"name": "f", "scanf_format_arg": "0"}, "scanf_format_arg must be an argument position"),
    ({"name": "f", "safe_kwargs": {"usedforsecurity": False}}, "safe_kwargs maps"),
])
def test_malformed_fields_are_errors(entry, error):
    with pytest.raises(SpecTableError, match=error):
        parse_table({"spec": [entry]}, "t.toml")


# --- guards.toml -------------------------------------------------------------------------------

def test_the_shipped_guards_load():
    g = guards.load()
    assert "isdigit" in g.charset_methods and "urlparse" in g.url_parsers and "hostname" in g.host_fields
    assert g.regex_function("re.fullmatch").how == "full"
    ismatch = g.regex_function("Regex.IsMatch")
    assert (ismatch.pattern_arg, ismatch.subject_arg) == (1, 0)


@pytest.mark.parametrize("edit,error", [
    (('how = "full"', 'how = "all"', 1), "how in"),
    (("subject_arg = 1", "subject_arg = 0", 1), "distinct"),
    (('matcher = "matcher"', 'matcher = "a.b"', 1), "matcher must be"),
    (("test = \"search\" }", "test = \"anywhere\" }", 1), "maps method names"),
])
def test_malformed_guards_are_errors(tmp_path, edit, error):
    bad = tmp_path / "guards.toml"
    bad.write_text(guards.PATH.read_text().replace(*edit))
    with pytest.raises(ValueError, match=error):
        guards.load(bad)


def test_an_unknown_key_is_an_error(tmp_path):
    bad = tmp_path / "guards.toml"
    bad.write_text("extra = []\n" + guards.PATH.read_text())
    with pytest.raises(ValueError, match="needs exactly"):
        guards.load(bad)


@pytest.mark.parametrize("guard,safe", [
    ("if not re.fullmatch(r'[a-z0-9]+', name):\n        return", True),
    ("if not re.match(r'[a-z0-9]+$', name):\n        return", True),
    ("if not re.search(r'[a-z0-9]+', name):\n        return", False),       # unanchored
    ("if not name.isalnum():\n        return", True),
])
def test_guards_read_through_the_data(guard, safe):
    code = ("import os\nimport re\nfrom flask import Flask, request\napp = Flask(__name__)\n\n"
            "@app.route('/r')\ndef r():\n    name = request.args.get('n')\n    " + guard + "\n"
            "    os.system('ls ' + name)\n")
    assert (not [c for c, _ in _found(code, "python", "a.py") if c == "CWE-78"]) == safe


# --- c-library.toml: libc facts beside the spec tables ------------------------------------------

from frame.sil import c_facts                                          # noqa: E402


def test_the_c_library_facts_load():
    lib = c_facts.library()
    assert lib.element_writes["strcpy"] == [(0, None)] and lib.element_reads["memcmp"] == [(0, 2), (1, 2)]
    assert lib.bounded_writes["read"] == (1, 2) and lib.literal_copies["strcpy"] == 1
    assert "strtok" not in lib.non_retaining and "va_start" in lib.bare_out_params
    assert lib.bounded_copies["snprintf"] == 1 and "gets" in lib.unbounded_copies


@pytest.mark.parametrize("name,position", [
    ("printf", 0), ("fprintf", 1), ("sprintf", 1), ("snprintf", 2), ("swprintf", 2), ("vswprintf", 2),
    ("_snprintf", 2), ("_snwprintf", 2), ("syslog", 1), ("vsyslog", 1),
])
def test_format_argument_positions_follow_the_signatures(name, position):
    # C11 7.21.6 / 7.29.2 (swprintf takes a count before the format), POSIX syslog, the MS CRT
    assert c_facts.library().format_functions[name] == position


def test_format_positions_agree_with_the_spec_table():
    from frame.sil.specs.tables import load_table
    c = load_table("c")
    for name, position in c_facts.library().format_functions.items():
        spec = c.get(name)
        if spec is not None and spec.sink_args:
            assert spec.sink_args == [position], name


@pytest.mark.parametrize("edit,error", [
    (("[[buffer]]\nname = \"read\"\n", "[[buffer]]\nname = \"read\"\nextra = 1\n"), "needs a name"),
    (("swprintf = 2", "swprintf = -2"), "argument positions"),
    (("bounded_write = [1, 2]", "bounded_write = [1, -1]"), "argument positions"),
])
def test_malformed_c_library_facts_are_errors(tmp_path, edit, error):
    bad = tmp_path / "c-library.toml"
    text = c_facts.LIBRARY_PATH.read_text()
    assert edit[0] in text
    bad.write_text(text.replace(*edit, 1))
    with pytest.raises(ValueError, match=error):
        c_facts.library(bad)


def test_a_c_function_listed_twice_is_an_error(tmp_path):
    bad = tmp_path / "c-library.toml"
    bad.write_text(c_facts.LIBRARY_PATH.read_text() + '\n[[buffer]]\nname = "read"\nliteral_copy = 1\n')
    with pytest.raises(ValueError, match="listed twice"):
        c_facts.library(bad)


# --- java-types.toml: java.lang, name-only receivers, project packages ---------------------------

def test_java_type_facts():
    from frame.sil.metadata import _java_lang
    from frame.sil.specs import java_specs as j
    assert {"String", "Error", "Void"} <= j.JAVA_LANG_TYPES and _java_lang() == j.JAVA_LANG_TYPES
    assert "*Statement" in j.NAME_ONLY_RECEIVERS["execute"] and "RowSet" in j.NAME_ONLY_NOT_RECEIVERS
    assert "org" in j.UMBRELLA_PACKAGE_ROOTS


@pytest.mark.parametrize("receiver,sink", [("Statement", True), ("JdbcTemplate", True), ("Executor", False),
                                           ("PreparedQuery", False)])
def test_execute_is_sql_only_on_statement_like_receivers(receiver, sink):
    code = ("import java.sql.*;\nimport java.util.concurrent.*;\nimport javax.servlet.http.*;\n"
            "class A {\n  void f(HttpServletRequest req, %s s) throws Exception {\n"
            '    s.execute("SELECT * FROM t WHERE n = \'" + req.getParameter("n") + "\'");\n  }\n}\n') % receiver
    assert ("CWE-89" in {c for c, _ in _found(code, "java", "A.java")}) == sink


def test_deserialization_methods_are_data():
    from frame.sil.specs.parser_hardening import load
    h = load()
    assert "fromXML" in h.xstream_methods and "readValue" in h.jackson_methods and "load" in h.yaml_methods


# --- the same-origin redirect guard reads the expression tree -------------------------------------

_REDIRECT = """const express = require('express');
const app = express();
app.get('/r', (req, res) => {
  const next = req.query.next;
  const other = req.query.other;
  %s
});
"""


@pytest.mark.parametrize("body,safe", [
    ("if (next.startsWith('/') && !next.startsWith('//')) { res.redirect(next); }", True),
    ("if (!next.startsWith('/') || next.startsWith('//')) { return res.redirect('/'); }\n  res.redirect(next);", True),
    ("if (next.startsWith('/')) { res.redirect(next); }", False),                    # //evil.example passes
    ("if (next.startsWith('/') && !other.startsWith('//')) { res.redirect(next); }", False),   # another value
    ("if (next.startsWith('/') || !next.startsWith('//')) { res.redirect(next); }", False),
])
def test_same_origin_redirect_guard(body, safe):
    found = {c for c, _ in _found(_REDIRECT % body, "javascript", "r.js")}
    assert ("CWE-601" not in found) == safe


def test_same_origin_redirect_guard_in_python():
    code = ("from flask import Flask, request, redirect\napp = Flask(__name__)\n\n@app.route('/r')\ndef r():\n"
            "    nxt = request.args.get('next')\n    if not nxt.startswith('/') or nxt.startswith('//'):\n"
            "        return redirect('/')\n    return redirect(nxt)\n")
    assert "CWE-601" not in {c for c, _ in _found(code, "python", "r.py")}
    assert "CWE-601" in {c for c, _ in _found(code.replace(" or nxt.startswith('//')", ""), "python", "r.py")}


# --- receiver-guesses.toml: a name heuristic, per language, as data ----------------------------

def test_receiver_guesses_are_per_language_and_name_rows_of_that_table():
    from frame.sil.specs import receiver_guesses
    from frame.sil.specs.tables import load_table
    data = receiver_guesses.load()
    table = {"python": "python", "java": "java", "javascript": "javascript", "csharp": "csharp"}
    for lang, names in data.items():
        rows = load_table(table[lang])
        for n in names:                       # every guess names a receiver with a propagation row
            assert any(k.startswith(n + ".") and not (s.is_sink or s.is_source or s.is_sanitizer)
                       for k, s in rows.items()), (lang, n)
    assert receiver_guesses.guesses("typescript") == receiver_guesses.guesses("javascript")
    assert receiver_guesses.guesses("c") == ()


def test_a_guess_of_another_language_does_not_apply():
    from frame.sil.procedure import Program, ProcSpec
    p = Program(library_specs={"StringBuilder.append": ProcSpec(taint_propagates=[0])}, language="python")
    assert p.get_spec("sb.append") is None               # `StringBuilder` is a Java guess, not a Python one
    p.language = "java"
    assert p.get_spec("sb.append") is not None


@pytest.mark.parametrize("spec", [{"is_sink": "ssrf"}, {"is_source": "user"}, {"is_sanitizer": ["filesystem"]}])
def test_a_guess_never_yields_a_source_sink_or_sanitizer(spec):
    from frame.sil.procedure import Program, ProcSpec
    p = Program(library_specs={"request.get": ProcSpec(**spec), "dict.get": ProcSpec(taint_propagates=[0])},
                language="python")
    assert p.get_spec("options.get") is p.library_specs["dict.get"]     # never the request client's sink
    assert p.get_spec("app.get") is None             # `app` is a type's row head (flask.Flask): by type only


def test_malformed_receiver_guesses_are_errors(tmp_path):
    from frame.sil.specs import receiver_guesses
    bad = tmp_path / "g.toml"
    bad.write_text('ruby = ["x"]\n')
    with pytest.raises(ValueError, match="unknown language"):
        receiver_guesses.load(bad)
    bad.write_text('python = ["x", "x"]\n')
    with pytest.raises(ValueError, match="distinct"):
        receiver_guesses.load(bad)
