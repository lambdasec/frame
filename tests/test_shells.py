"""Shells as data (`frame/sil/specs/data/shells.toml`): one list for the Java frontend's shell
argument vectors and the JavaScript frontend's spawn programs, compared by the last part of a path."""

import pytest

from frame.sil.scanner import FrameScanner
from frame.sil.specs.shells import is_shell, load


def test_names_and_paths():
    assert is_shell("/usr/bin/bash") and is_shell("C:\\Windows\\System32\\cmd.exe") and is_shell("FISH")
    assert not is_shell("ping") and not is_shell("/bin/ls")
    assert {"-c", "/c"} <= load().command_flags


@pytest.mark.parametrize("program", ["/usr/bin/bash", "/bin/sh"])
def test_java_shell_vector(program):
    code = ("import javax.servlet.http.*;\nclass A extends HttpServlet {\n"
            "  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws java.io.IOException {\n"
            '    String host = req.getParameter("host");\n'
            f'    String[] cmd = {{"{program}", "-c", host}};\n'
            "    Runtime.getRuntime().exec(cmd);\n  }\n}\n")
    found = {v.cwe_id for v in FrameScanner(language="java").scan(code, "A.java").vulnerabilities}
    assert "CWE-78" in found


def test_a_malformed_file_is_an_error(tmp_path):
    p = tmp_path / "s.toml"
    p.write_text('programs = ["sh"]\n')
    with pytest.raises(ValueError, match="needs exactly"):
        load(p)
