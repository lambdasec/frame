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
