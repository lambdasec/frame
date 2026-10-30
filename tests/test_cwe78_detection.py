"""
Test CWE-78 (OS Command Injection) detection.

Command sinks of the structural taint analysis: they need a real source and honour checks such
as strcmp against constants. system/popen, the exec family (an `execl` of a shell with a command
flag runs the argument after it: `argv_from` and shells.toml), CreateProcess, WinExec and
ShellExecute are rows of the c/cpp spec tables.
"""

import pytest
from frame.sil.scanner import FrameScanner


def scan_cwes(code: str) -> set:
    return {v.cwe_id for v in FrameScanner(language="c").scan(code, "test.c").vulnerabilities}


class TestCWE78CommandInjection:
    """Test cases for CWE-78 OS Command Injection detection."""

    def test_system_with_user_input(self):
        """system() reached by attacker data passed into a helper."""
        code = """#include <stdlib.h>
void vulnerable(char* data) {
    system(data);
}
int main(void) {
    char* q = getenv("QUERY_STRING");
    vulnerable(q);
    return 0;
}
"""
        assert "CWE-78" in scan_cwes(code)

    def test_popen_with_tainted_command(self):
        """popen() with a command read from stdin."""
        code = """#include <stdio.h>
void vulnerable(void) {
    char command[256];
    fgets(command, 256, stdin);
    FILE* fp = popen(command, "r");
}
"""
        assert "CWE-78" in scan_cwes(code)

    @pytest.mark.parametrize("call", ['execl("/bin/sh", "sh", "-c", cmd, NULL);',
                                      'execlp("bash", "bash", "-c", cmd, (char *)NULL);',
                                      'CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);',
                                      "WinExec(cmd, SW_SHOW);",
                                      'ShellExecuteA(NULL, "open", cmd, NULL, NULL, SW_SHOW);'])
    def test_process_apis_with_attacker_data(self, call):
        code = ("#include <stdlib.h>\n#include <unistd.h>\n#include <windows.h>\n\nvoid run(void)\n{\n"
                "    STARTUPINFOA si;\n    PROCESS_INFORMATION pi;\n    char *cmd = getenv(\"Q\");\n"
                f"    {call}\n}}\n")
        assert "CWE-78" in scan_cwes(code)

    def test_an_exec_argument_that_is_not_a_shell_command_is_not(self):
        code = ("#include <stdlib.h>\n#include <unistd.h>\n\nvoid run(void)\n{\n"
                "    char *name = getenv(\"Q\");\n    execl(\"/bin/ls\", \"ls\", \"-l\", name, NULL);\n}\n")
        assert "CWE-78" not in scan_cwes(code)

    def test_argv_in_system(self):
        code = "#include <stdlib.h>\n\nint main(int argc, char *argv[])\n{\n    system(argv[1]);\n    return 0;\n}\n"
        assert "CWE-78" in scan_cwes(code)

    def test_taint_tracking_from_fgets(self):
        """fgets -> sprintf -> system."""
        code = """#include <stdio.h>
#include <stdlib.h>
void vulnerable(void) {
    char buffer[256];
    char cmd[512];
    fgets(buffer, 256, stdin);
    sprintf(cmd, "ls %s", buffer);
    system(cmd);
}
"""
        assert "CWE-78" in scan_cwes(code)

    def test_taint_tracking_from_getenv(self):
        """getenv -> sprintf -> system."""
        code = """#include <stdio.h>
#include <stdlib.h>
void vulnerable(void) {
    char* path = getenv("PATH");
    char cmd[512];
    sprintf(cmd, "ls %s", path);
    system(cmd);
}
"""
        assert "CWE-78" in scan_cwes(code)

    def test_safe_constant_system_call(self):
        assert "CWE-78" not in scan_cwes("#include <stdlib.h>\n\nvoid safe(void)\n{\n    system(\"ls -la\");\n}\n")

    def test_parameter_no_caller_taints_is_not_reported(self):
        """A parameter is not attacker data by its name ('data'): with no caller passing
        attacker data, popen(data) is not a finding."""
        code = """#include <stdio.h>
void run(char* data) {
    FILE* fp = popen(data, "r");
}
"""
        assert "CWE-78" not in scan_cwes(code)

    def test_strcmp_allowlist_clears_the_command(self):
        """Only constants pass `strcmp(x, "a") == 0 || strcmp(x, "b") == 0`."""
        code = """#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    const char* level = getenv("LEVEL");
    char cmd[128];
    if (level == NULL || (strcmp(level, "error") != 0 && strcmp(level, "warn") != 0)) {
        return 1;
    }
    snprintf(cmd, sizeof(cmd), "grep -c %s app.log", level);
    return system(cmd);
}
"""
        assert "CWE-78" not in scan_cwes(code)
