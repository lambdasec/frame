"""
Test CWE-78 (OS Command Injection) detection in the interprocedural analyzer.
"""

import pytest
from frame.sil.analyzers.interprocedural_analyzer import analyze_interprocedural


class TestCWE78CommandInjection:
    """Test cases for CWE-78 OS Command Injection detection."""

    def test_system_with_user_input(self):
        """Test detection of system() with user-controlled input."""
        code = '''
        void vulnerable(char* data) {
            system(data);
        }
        '''
        vulns = analyze_interprocedural(code, "test.c")
        cwe78_vulns = [v for v in vulns if v.cwe_id == "CWE-78"]
        assert len(cwe78_vulns) >= 1
        assert any("system" in v.description.lower() for v in cwe78_vulns)

    def test_popen_with_tainted_command(self):
        """Test detection of popen() with tainted command."""
        code = '''
        void vulnerable() {
            char command[256];
            fgets(command, 256, stdin);
            FILE* fp = popen(command, "r");
        }
        '''
        vulns = analyze_interprocedural(code, "test.c")
        cwe78_vulns = [v for v in vulns if v.cwe_id == "CWE-78"]
        assert len(cwe78_vulns) >= 1
        assert any("popen" in v.description.lower() for v in cwe78_vulns)

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
        """Test that taint tracking works for fgets input."""
        code = '''
        void vulnerable() {
            char buffer[256];
            char cmd[512];
            fgets(buffer, 256, stdin);
            sprintf(cmd, "ls %s", buffer);
            system(cmd);
        }
        '''
        vulns = analyze_interprocedural(code, "test.c")
        cwe78_vulns = [v for v in vulns if v.cwe_id == "CWE-78"]
        assert len(cwe78_vulns) >= 1

    def test_taint_tracking_from_getenv(self):
        """Test that taint tracking works for getenv input."""
        code = '''
        void vulnerable() {
            char* path = getenv("PATH");
            char cmd[512];
            sprintf(cmd, "ls %s", path);
            system(cmd);
        }
        '''
        vulns = analyze_interprocedural(code, "test.c")
        cwe78_vulns = [v for v in vulns if v.cwe_id == "CWE-78"]
        assert len(cwe78_vulns) >= 1

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

    def test_popen_with_data_variable(self):
        """Test popen with 'data' variable (common benchmark variable)."""
        code = '''
        void vulnerable(char* data) {
            FILE* fp = _popen(data, "r");
        }
        '''
        vulns = analyze_interprocedural(code, "test.c")
        cwe78_vulns = [v for v in vulns if v.cwe_id == "CWE-78"]
        assert len(cwe78_vulns) >= 1
        # 'data' is treated as tainted, so confidence should be higher
        assert any(v.confidence >= 0.9 for v in cwe78_vulns)

    def test_exec_with_tainted_variable(self):
        """Test exec family with tainted variable in arguments."""
        code = '''
        void vulnerable() {
            char* userInput = getenv("USER_CMD");
            execv("/bin/cmd", userInput);
        }
        '''
        vulns = analyze_interprocedural(code, "test.c")
        cwe78_vulns = [v for v in vulns if v.cwe_id == "CWE-78"]
        assert len(cwe78_vulns) >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
