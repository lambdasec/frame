"""
Test CWE-134: Use of Externally-Controlled Format String detection.

Tests the enhanced format string vulnerability detection in the interprocedural analyzer.
"""

import pytest
import sys
import os

# Add the parent directory to the path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from frame.sil.analyzers.interprocedural_analyzer import _detect_semantic_cwes


class TestCWE134FormatString:
    """Test cases for CWE-134 format string vulnerability detection."""

    def test_printf_with_variable(self):
        """Test detection of printf(user_input) pattern."""
        source = '''
void vulnerable(char *data) {
    printf(data);
}
'''
        vulns = _detect_semantic_cwes(source, "test.c")
        cwe134_vulns = [v for v in vulns if v.cwe_id == "CWE-134"]
        assert len(cwe134_vulns) >= 1, "Should detect printf with variable as format"
        assert any("printf" in v.description.lower() for v in cwe134_vulns)

    def test_printf_with_literal_safe(self):
        """Test that printf with literal format string is not flagged."""
        source = '''
void safe() {
    printf("Hello, world!");
    printf("Value: %d", x);
}
'''
        vulns = _detect_semantic_cwes(source, "test.c")
        cwe134_vulns = [v for v in vulns if v.cwe_id == "CWE-134"]
        # Should not detect format string vuln with literal format
        assert len(cwe134_vulns) == 0, "Should not flag printf with literal format"

    def test_sprintf_with_variable_format(self):
        """Test detection of sprintf(buf, source) where source is tainted."""
        source = '''
void vulnerable(char *data) {
    char buf[100];
    sprintf(buf, data);
}
'''
        vulns = _detect_semantic_cwes(source, "test.c")
        cwe134_vulns = [v for v in vulns if v.cwe_id == "CWE-134"]
        assert len(cwe134_vulns) >= 1, "Should detect sprintf with variable format"

    def test_sprintf_with_literal_safe(self):
        """Test that sprintf with literal format string is not flagged for CWE-134."""
        source = '''
void func() {
    char buf[100];
    sprintf(buf, "Hello %s", name);
}
'''
        vulns = _detect_semantic_cwes(source, "test.c")
        cwe134_vulns = [v for v in vulns if v.cwe_id == "CWE-134"]
        # May still flag CWE-122 for unbounded sprintf, but not CWE-134
        assert len(cwe134_vulns) == 0, "Should not flag sprintf with literal format for CWE-134"

    def test_fprintf_with_variable_format(self):
        """Test detection of fprintf(f, tainted_var) pattern."""
        source = '''
void vulnerable(FILE *f, char *data) {
    fprintf(f, data);
}
'''
        vulns = _detect_semantic_cwes(source, "test.c")
        cwe134_vulns = [v for v in vulns if v.cwe_id == "CWE-134"]
        assert len(cwe134_vulns) >= 1, "Should detect fprintf with variable format"
        assert any("fprintf" in v.description.lower() for v in cwe134_vulns)

    def test_fprintf_stderr_with_variable(self):
        """Test detection of fprintf(stderr, userInput) pattern."""
        source = '''
void vulnerable(char *userInput) {
    fprintf(stderr, userInput);
}
'''
        vulns = _detect_semantic_cwes(source, "test.c")
        cwe134_vulns = [v for v in vulns if v.cwe_id == "CWE-134"]
        assert len(cwe134_vulns) >= 1, "Should detect fprintf to stderr with variable format"

    def test_fprintf_with_literal_safe(self):
        """Test that fprintf with literal format is safe."""
        source = '''
void safe(FILE *f) {
    fprintf(f, "Error: %s", msg);
}
'''
        vulns = _detect_semantic_cwes(source, "test.c")
        cwe134_vulns = [v for v in vulns if v.cwe_id == "CWE-134"]
        assert len(cwe134_vulns) == 0, "Should not flag fprintf with literal format"

    def test_syslog_with_variable_format(self):
        """Test detection of syslog(LOG_ERR, data) pattern."""
        source = '''
void vulnerable(char *data) {
    syslog(LOG_ERR, data);
}
'''
        vulns = _detect_semantic_cwes(source, "test.c")
        cwe134_vulns = [v for v in vulns if v.cwe_id == "CWE-134"]
        assert len(cwe134_vulns) >= 1, "Should detect syslog with variable format"
        assert any("syslog" in v.description.lower() for v in cwe134_vulns)

    def test_syslog_with_numeric_priority(self):
        """Test detection of syslog with numeric priority and variable format."""
        source = '''
void vulnerable(char *data) {
    syslog(3, data);
}
'''
        vulns = _detect_semantic_cwes(source, "test.c")
        cwe134_vulns = [v for v in vulns if v.cwe_id == "CWE-134"]
        assert len(cwe134_vulns) >= 1, "Should detect syslog with numeric priority and variable format"

    def test_syslog_with_literal_safe(self):
        """Test that syslog with literal format is safe."""
        source = '''
void safe() {
    syslog(LOG_ERR, "Error occurred: %s", error_msg);
}
'''
        vulns = _detect_semantic_cwes(source, "test.c")
        cwe134_vulns = [v for v in vulns if v.cwe_id == "CWE-134"]
        assert len(cwe134_vulns) == 0, "Should not flag syslog with literal format"

    def test_snprintf_with_variable_format(self):
        """Test detection of snprintf with tainted format string."""
        source = '''
void vulnerable(char *data) {
    char buf[100];
    snprintf(buf, sizeof(buf), data);
}
'''
        vulns = _detect_semantic_cwes(source, "test.c")
        cwe134_vulns = [v for v in vulns if v.cwe_id == "CWE-134"]
        assert len(cwe134_vulns) >= 1, "Should detect snprintf with variable format"

    def test_snprintf_with_literal_safe(self):
        """Test that snprintf with literal format is safe."""
        source = '''
void safe(int value) {
    char buf[100];
    snprintf(buf, sizeof(buf), "Value: %d", value);
}
'''
        vulns = _detect_semantic_cwes(source, "test.c")
        cwe134_vulns = [v for v in vulns if v.cwe_id == "CWE-134"]
        assert len(cwe134_vulns) == 0, "Should not flag snprintf with literal format"

    def test_wprintf_with_variable_format(self):
        """Test detection of wprintf with variable format."""
        source = '''
void vulnerable(wchar_t *data) {
    wprintf(data);
}
'''
        vulns = _detect_semantic_cwes(source, "test.c")
        cwe134_vulns = [v for v in vulns if v.cwe_id == "CWE-134"]
        assert len(cwe134_vulns) >= 1, "Should detect wprintf with variable format"

    def test_vprintf_with_tainted_format(self):
        """Test detection of vprintf with user-controlled format."""
        source = '''
void vulnerable(char *data, ...) {
    va_list args;
    va_start(args, data);
    vprintf(data, args);
    va_end(args);
}
'''
        vulns = _detect_semantic_cwes(source, "test.c")
        cwe134_vulns = [v for v in vulns if v.cwe_id == "CWE-134"]
        assert len(cwe134_vulns) >= 1, "Should detect vprintf with tainted format"

    def test_higher_confidence_for_tainted_vars(self):
        """Test that tainted variables get higher confidence scores."""
        # 'data' is in the default tainted_vars set
        source = '''
void vulnerable_tainted() {
    printf(data);
}
'''
        vulns = _detect_semantic_cwes(source, "test.c")
        cwe134_vulns = [v for v in vulns if v.cwe_id == "CWE-134"]
        assert len(cwe134_vulns) >= 1
        # Tainted variable should have high confidence
        assert any(v.confidence >= 0.85 for v in cwe134_vulns), "Tainted var should have high confidence"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
