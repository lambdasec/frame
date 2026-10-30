"""Test code is recognised from the program (frame/sil/test_code.py), never from the file name:
a test framework's import, its test attributes / annotations, pytest's asserting `test_*`
functions, callbacks registered with jest / mocha globals. Findings there are tagged
`context: "test"`, never dropped; only a credential found by its variable's name drops to low.
Each positive is paired with the nearest production code that must stay untagged.
"""

import pytest

from frame.sil.scanner import FrameScanner

GITHUB = "gh" + "p_" + "Q7r8S9t0U1v2W3x4Y5z6A1b2C3d4E5f6G7h8"   # built here: never a contiguous token


def scan(language, code, filename):
    r = FrameScanner(language=language).scan(code, filename)
    assert not r.errors, r.errors
    return r.vulnerabilities


@pytest.mark.parametrize("language,code,filename", [
    ("python", "import pytest\n\ndef helper():\n    password = 'hunter2hunter2'\n    return password\n", "fixtures.py"),
    ("python", "import unittest\n\nclass T(unittest.TestCase):\n    def test_a(self):\n"
               "        password = 'hunter2hunter2'\n        self.assertTrue(password)\n", "checks.py"),
    ("python", "def test_login():\n    password = 'hunter2hunter2'\n    assert login(password)\n", "checks.py"),
    ("java", "import org.junit.jupiter.api.Test;\nclass LoginIT {\n  @Test void a() {\n"
             "    String password = \"hunter2hunter2\";\n  }\n}\n", "LoginIT.java"),
    ("java", "class LoginIT {\n  @org.testng.annotations.Test void a() {\n    String password = \"hunter2hunter2\";\n"
             "  }\n}\n", "LoginIT.java"),
    ("javascript", "describe('login', () => {\n  it('works', () => {\n    const password = 'hunter2hunter2';\n"
                   "  });\n});\n", "login.js"),
    ("javascript", "import { test } from 'vitest';\nconst password = 'hunter2hunter2';\n", "login.js"),
    ("typescript", "import { describe } from '@jest/globals';\nconst password: string = 'hunter2hunter2';\n", "login.ts"),
    ("csharp", "class LoginTests {\n  [Fact]\n  public void A() {\n    var password = \"hunter2hunter2\";\n  }\n}\n",
     "LoginTests.cs"),
    ("csharp", "class LoginTests {\n  [TestMethod]\n  public void A() {\n    var password = \"hunter2hunter2\";\n  }\n}\n",
     "LoginTests.cs"),
    ("cpp", "#include <gtest/gtest.h>\nTEST(Login, Works) {\n  const char* password = \"hunter2hunter2\";\n}\n",
     "login.cpp"),
])
def test_a_named_credential_in_test_code_is_low_and_tagged(language, code, filename):
    [v] = scan(language, code, filename)
    assert (v.type.value, v.severity.value, v.context) == ("hardcoded_secret", "low", "test")
    assert v.to_dict()["context"] == "test"


@pytest.mark.parametrize("language,code,filename", [
    # a file named like a test, defining production helpers
    ("python", "def login():\n    password = 'hunter2hunter2'\n    return password\n", "test_utils.py"),
    # a production helper called test_*: it does not assert
    ("python", "def test_connection():\n    password = 'hunter2hunter2'\n    return connect(password)\n", "db.py"),
    # unittest named in a string is not an import
    ("python", "MODE = 'unittest'\npassword = 'hunter2hunter2'\n", "settings.py"),
    # the project's own @Test annotation is not JUnit's
    ("java", "class Probe {\n  @Test void a() {\n    String password = \"hunter2hunter2\";\n  }\n}\n@interface Test {}\n",
     "Probe.java"),
    # a route callback is not a test callback
    ("javascript", "const express = require('express');\nconst app = express();\n"
                   "app.get('/x', (req, res) => {\n  const password = 'hunter2hunter2';\n  res.send('ok');\n});\n",
     "login.test.js"),
    ("csharp", "class Login {\n  [HttpPost]\n  public void A() {\n    var password = \"hunter2hunter2\";\n  }\n}\n",
     "LoginTests.cs"),
    ("cpp", "#include <stdio.h>\nint main() {\n  const char* password = \"hunter2hunter2\";\n  return 0;\n}\n",
     "test_main.cpp"),
])
def test_production_code_is_not_test_code_whatever_its_name(language, code, filename):
    [v] = scan(language, code, filename)
    assert v.context == "" and v.severity.value != "low" and "context" not in v.to_dict()


def test_a_provider_format_key_in_a_test_keeps_its_severity():
    """A live-format key in a test may be real: it is tagged, not lowered."""
    code = f"import pytest\n\ndef test_client():\n    client = Github(\"{GITHUB}\")\n    assert client\n"
    [v] = scan("python", code, "checks.py")
    assert v.context == "test" and v.severity.value == "critical" and "GitHub format" in v.description


def test_other_findings_in_test_code_are_tagged_not_lowered():
    code = ("import pytest\nimport os\nfrom flask import request\n\n"
            "def test_handler():\n    os.system('ls ' + request.args['d'])\n    assert True\n")
    vulns = scan("python", code, "checks.py")
    assert vulns and all(v.context == "test" for v in vulns)
    assert any(v.cwe_id == "CWE-78" and v.severity.value in ("critical", "high") for v in vulns)


def test_sarif_carries_the_context():
    r = FrameScanner(language="python").scan("def test_a():\n    password = 'hunter2hunter2'\n    assert 1\n",
                                             "checks.py")
    [result] = r.to_sarif()["runs"][0]["results"]
    assert result["properties"]["context"] == "test"


def test_the_catalog_is_data_and_strict(tmp_path):
    from frame.sil.specs import test_frameworks
    catalog = test_frameworks.load()
    assert "pytest" in catalog.imports["python"] and "Fact" in catalog.csharp_attributes
    text = test_frameworks.PATH.read_text()
    bad = tmp_path / "test-frameworks.toml"
    bad.write_text(text.replace('test_function_prefix = "test_"', 'prefix = "test_"'))
    with pytest.raises(ValueError, match=r"\[python\]"):
        test_frameworks.load(bad)
    bad.write_text(text + "\n[ruby]\nimports = []\n")
    with pytest.raises(ValueError, match="needs exactly"):
        test_frameworks.load(bad)
