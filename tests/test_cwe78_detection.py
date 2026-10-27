"""
Test CWE-78 (OS Command Injection) detection.

system() / popen() are command sinks of the structural taint analysis (they need a real
source and honour checks such as strcmp against constants); the exec family, CreateProcess
and WinExec are still matched by the line analyzer.
"""

import pytest
from frame.sil.analyzers.interprocedural_analyzer import analyze_interprocedural
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

    def test_execl_with_shell(self):
        """Test detection of execl() with /bin/sh -c pattern."""
        code = '''
        void vulnerable(char* userInput) {
            execl("/bin/sh", "sh", "-c", userInput, NULL);
        }
        '''
        vulns = analyze_interprocedural(code, "test.c")
        cwe78_vulns = [v for v in vulns if v.cwe_id == "CWE-78"]
        assert len(cwe78_vulns) >= 1

    def test_argv_in_system(self):
        """Test detection of direct argv usage in system()."""
        code = '''
        int main(int argc, char* argv[]) {
            system(argv[1]);
            return 0;
        }
        '''
        vulns = analyze_interprocedural(code, "test.c")
        cwe78_vulns = [v for v in vulns if v.cwe_id == "CWE-78"]
        assert len(cwe78_vulns) >= 1
        assert any("argv" in v.var_name or "argv" in v.description.lower() for v in cwe78_vulns)

    def test_create_process_with_variable(self):
        """Test detection of CreateProcess() with variable command line."""
        code = '''
        void vulnerable(LPSTR cmdLine) {
            STARTUPINFO si;
            PROCESS_INFORMATION pi;
            CreateProcess(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
        }
        '''
        vulns = analyze_interprocedural(code, "test.c")
        cwe78_vulns = [v for v in vulns if v.cwe_id == "CWE-78"]
        assert len(cwe78_vulns) >= 1
        assert any("createprocess" in v.description.lower() for v in cwe78_vulns)

    def test_winexec_with_variable(self):
        """Test detection of WinExec() with variable command."""
        code = '''
        void vulnerable(char* cmd) {
            WinExec(cmd, SW_SHOW);
        }
        '''
        vulns = analyze_interprocedural(code, "test.c")
        cwe78_vulns = [v for v in vulns if v.cwe_id == "CWE-78"]
        assert len(cwe78_vulns) >= 1
        assert any("winexec" in v.description.lower() for v in cwe78_vulns)

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
        """Test that constant string system() calls may have lower confidence."""
        code = '''
        void safe() {
            system("ls -la");
        }
        '''
        vulns = analyze_interprocedural(code, "test.c")
        # Constant string should not trigger high-confidence CWE-78
        cwe78_vulns = [v for v in vulns if v.cwe_id == "CWE-78"]
        # Should not report CWE-78 for constant strings
        # (our current implementation doesn't flag literal strings)
        assert len(cwe78_vulns) == 0

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
