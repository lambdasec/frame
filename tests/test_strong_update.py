"""Assigning a plain local replaces its value: the old taint does not survive unless the new
value reads it (`x = x + y`). Fields and elements keep weak updates."""

from frame.sil.scanner import FrameScanner


def cwes(code: str, language: str, filename: str) -> set:
    return {v.cwe_id for v in FrameScanner(language=language).scan(code, filename).vulnerabilities}


PY = '''import os
from flask import Flask, request
app = Flask(__name__)

@app.route("/r")
def r():
    cmd = request.args.get("c", "")
    {line}
    os.system(cmd)
    return "ok"
'''


def test_python_reassignment_to_a_constant_clears_taint():
    assert "CWE-78" not in cwes(PY.format(line='cmd = "uptime"'), "python", "a.py")


def test_python_reassignment_from_another_clean_value_clears_taint():
    assert "CWE-78" not in cwes(PY.format(line='cmd = "ls " + str(len("abc"))'), "python", "a.py")


def test_python_self_referencing_update_keeps_taint():
    assert "CWE-78" in cwes(PY.format(line='cmd = cmd + " -l"'), "python", "a.py")


JAVA = '''import java.io.IOException;
import javax.servlet.http.*;
public class S extends HttpServlet {{
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {{
        String name = req.getParameter("n");
        {line}
        Runtime.getRuntime().exec("echo " + name);
    }}
}}
'''


def test_java_reassignment_to_a_constant_clears_taint():
    assert "CWE-78" not in cwes(JAVA.format(line='name = "guest";'), "java", "S.java")


def test_java_self_referencing_update_keeps_taint():
    assert "CWE-78" in cwes(JAVA.format(line='name = name.trim();'), "java", "S.java")


def test_java_parsed_number_is_not_a_command_payload():
    # Integer.parseInt yields a number: harmless for every text-payload sink (as JS/C).
    assert "CWE-78" not in cwes(JAVA.format(line='name = String.valueOf(Integer.parseInt(name));'), "java", "S.java")
    assert "CWE-78" in cwes(JAVA.format(line='name = name.toLowerCase();'), "java", "S.java")


TERNARY = '''import os
from flask import Flask, request
app = Flask(__name__)

@app.route("/t")
def t():
    param = request.args.get("p", "")
    num = {num}
    bar = "{text}" if 7 * 18 + num > 200 else param
    os.system("echo " + bar)
    return "ok"
'''


def test_ternary_condition_is_folded_not_read_from_the_words():
    # 126 + 106 > 200: the constant branch is taken, whatever its text says.
    assert "CWE-78" not in cwes(TERNARY.format(num=106, text="This_should_never_happen"), "python", "t.py")
    # 126 + 50 <= 200: the attacker branch is taken, even if the constant says "always".
    assert "CWE-78" in cwes(TERNARY.format(num=50, text="This_should_always_happen"), "python", "t.py")


def test_ternary_with_an_unknown_condition_carries_either_branch():
    code = TERNARY.format(num='request.args.get("n", "0")', text="safe").replace(
        "7 * 18 + num > 200", "num == '1'")
    assert "CWE-78" in cwes(code, "python", "t.py")
