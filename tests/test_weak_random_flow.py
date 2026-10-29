"""Weak randomness by flow (Python, JS/TS, Java): a non-cryptographic PRNG's output
(`weak_random`: java.util.Random, Python's `random`, JS `Math.random`) is CWE-338 only where a
value must be unpredictable (specs/data/unpredictable.toml: a cookie's value, a key, IV, nonce or
salt), as in C/C++. A random number used for jitter, sampling or a delay is not a finding, and it
is never attacker data at an injection sink. Each positive is paired with the nearest correct idiom.
"""

import pytest

from frame.sil.scanner import FrameScanner


def cwes(code, language, name):
    r = FrameScanner(language=language).scan(code, name)
    assert not r.errors, r.errors
    return {v.cwe_id for v in r.vulnerabilities} - {"CWE-614", "CWE-1004"}   # cookie flags are separate


PY = "import random, secrets, hmac, hashlib\nfrom flask import make_response\n\ndef f(db):\n"


@pytest.mark.parametrize("body,expected", [
    ("    r = make_response('x')\n    r.set_cookie('sid', str(random.random()))\n    return r\n", {"CWE-338"}),
    ("    r = make_response('x')\n    r.set_cookie('sid', value=str(random.getrandbits(64)))\n    return r\n", {"CWE-338"}),
    ("    r = make_response('x')\n    r.set_cookie('sid', secrets.token_hex(16))\n    return r\n", set()),
    ("    hmac.new(random.randbytes(16), b'm', 'sha256')\n", {"CWE-338"}),
    ("    hmac.new(secrets.token_bytes(16), b'm', 'sha256')\n", set()),
    ("    k = random.randbytes(16)\n    hashlib.pbkdf2_hmac('sha256', b'pw', k, 1000)\n", {"CWE-338"}),
    ("    hashlib.pbkdf2_hmac('sha256', b'pw', salt=random.randbytes(16), iterations=1000)\n", {"CWE-338"}),
    ("    delay = random.uniform(0, 1)\n    items = random.sample(range(10), 3)\n    return delay, items\n", set()),
    ("    db.execute('SELECT * FROM t WHERE id = ' + str(random.randint(1, 9)))\n", set()),   # a number, not text
])
def test_python(body, expected):
    assert cwes(PY + body, "python", "a.py") == expected


JS = "const crypto = require('crypto');\nmodule.exports = function f(req, res) {\n"


@pytest.mark.parametrize("body,expected", [
    ("  const t = Math.random().toString(36);\n  res.cookie('sid', t);\n", {"CWE-338"}),
    ("  res.cookie('sid', crypto.randomBytes(16).toString('hex'));\n", set()),
    ("  const k = String(Math.random());\n  crypto.createHmac('sha256', k);\n", {"CWE-338"}),
    ("  const iv = Buffer.from(String(Math.random()));\n  crypto.createCipheriv('aes-256-gcm', key, iv);\n",
     {"CWE-338"}),
    ("  const d = Math.random() * 100;\n  setTimeout(() => res.end(), d);\n", set()),
])
def test_javascript(body, expected):
    assert cwes(JS + body + "};\n", "javascript", "a.js") == expected


JAVA = ("import javax.servlet.http.*;\nimport javax.crypto.spec.*;\n"
        "class R {\n  void f(HttpServletResponse resp) throws Exception {\n")


@pytest.mark.parametrize("body,expected", [
    # OWASP BenchmarkJava's remember-me shape
    ("    float rand = new java.util.Random().nextFloat();\n"
     "    String key = Float.toString(rand).substring(2);\n"
     "    Cookie c = new Cookie(\"rememberMe\", key);\n    resp.addCookie(c);\n", {"CWE-338"}),
    ("    String t = Long.toString(new java.util.Random().nextLong());\n"
     "    resp.addCookie(new Cookie(\"remember\", t));\n", {"CWE-338"}),            # nested in addCookie
    ("    double v = new java.security.SecureRandom().nextDouble();\n"
     "    resp.addCookie(new Cookie(\"remember\", Double.toString(v)));\n", set()),
    ("    java.util.Random r = new java.util.Random();\n    byte[] k = new byte[16];\n"
     "    r.nextBytes(k);\n    SecretKeySpec s = new SecretKeySpec(k, \"AES\");\n", {"CWE-338"}),
    ("    java.util.Random r = new java.util.Random();\n    Thread.sleep(r.nextInt(100));\n", set()),
])
def test_java(body, expected):
    assert cwes(JAVA + body + "  }\n}\n", "java", "R.java") == expected


def test_the_table_is_strict(tmp_path, monkeypatch):
    import frame.sil.specs.unpredictable as U
    bad = tmp_path / "u.toml"
    bad.write_text('[[call]]\nlanguage = "java"\nnames = ["new X"]\ndescription = "d"\n')   # no args
    monkeypatch.setattr(U, "PATH", bad)
    U.table.cache_clear()
    with pytest.raises(ValueError):
        U.table()
    U.table.cache_clear()


@pytest.mark.parametrize("body", [
    'const key = "R_" + Math.random();\n  vm.runInNewContext(key + "=" + code, {});',
    'const src = code + Math.random();\n  vm.runInNewContext(src, {});',
    'const src = "v" + Math.random() + code;\n  return eval(src);',
])
def test_attacker_data_beside_a_weak_random_number_stays_attacker_data(body):
    """A string built from a random number and attacker data is attacker data whichever comes
    first: the random number's taint never replaces it (SecBench's eval-in-vm)."""
    code = f'const vm = require("vm");\nmodule.exports = function run(code) {{\n  {body}\n}};\n'
    found = {v.cwe_id for v in FrameScanner(language="javascript", library_mode=True).scan(code, "a.js").vulnerabilities}
    assert "CWE-94" in found
