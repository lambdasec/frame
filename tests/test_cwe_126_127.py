"""
Test cases for CWE-126 (Buffer Over-read) and CWE-127 (Buffer Under-read) detection.

These tests verify that the interprocedural analyzer correctly detects:
- CWE-126: Buffer Over-read patterns
- CWE-127: Buffer Under-read patterns

These tests use the _detect_semantic_cwes function directly for unit testing.
"""

import pytest
from frame.sil.analyzers.interprocedural_analyzer import _detect_semantic_cwes


def get_cwe_vulns(source: str, cwe_id: str) -> list:
    """Helper to extract vulns with a specific CWE-ID."""
    vulns = _detect_semantic_cwes(source, "test.c", verbose=False)
    return [v for v in vulns if v.cwe_id == cwe_id]


class TestCWE126BufferOverread:
    """Tests for CWE-126: Buffer Over-read detection."""

    def test_memcpy_with_dest_size(self):
        """Detect memcpy using destination size instead of source size."""
        source = '''
void vuln(char *data) {
    char dest[100];
    memcpy(dest, data, strlen(dest));
}
'''
        cwe_126 = get_cwe_vulns(source, "CWE-126")
        assert len(cwe_126) > 0, "Should detect CWE-126 for memcpy with dest size"

    def test_strlen_on_tainted_buffer(self):
        """Detect strlen on potentially non-null-terminated buffer."""
        source = '''
void vuln(char *data) {
    size_t len = strlen(data);
}
'''
        cwe_126 = get_cwe_vulns(source, "CWE-126")
        assert len(cwe_126) > 0, "Should detect CWE-126 for strlen on tainted buffer"

    def test_large_constant_index(self):
        """Detect read with very large constant index."""
        source = '''
void vuln() {
    char buf[10];
    char c = buf[5000];
}
'''
        cwe_126 = get_cwe_vulns(source, "CWE-126")
        assert len(cwe_126) > 0, "Should detect CWE-126 for large constant index"

    def test_memcpy_large_size(self):
        """Detect memcpy with large constant size from tainted source."""
        source = '''
void vuln(char *data) {
    char dest[100];
    memcpy(dest, data, 2048);
}
'''
        cwe_126 = get_cwe_vulns(source, "CWE-126")
        assert len(cwe_126) > 0, "Should detect CWE-126 for memcpy with large size"


class TestCWE127BufferUnderread:
    """Tests for CWE-127: Buffer Under-read detection."""

    def test_negative_array_index_read(self):
        """Detect read with negative array index."""
        source = '''
void vuln() {
    char buf[10];
    char c = buf[-1];
}
'''
        cwe_127 = get_cwe_vulns(source, "CWE-127")
        assert len(cwe_127) > 0, "Should detect CWE-127 for negative array index"

    def test_ptr_minus_constant(self):
        """Detect read from ptr - constant offset."""
        source = '''
void vuln(char *ptr) {
    char c = *(ptr - 5);
}
'''
        cwe_127 = get_cwe_vulns(source, "CWE-127")
        assert len(cwe_127) > 0, "Should detect CWE-127 for ptr - constant"

    def test_ptr_minus_variable(self):
        """Detect read from ptr - variable offset without bounds check."""
        source = '''
void vuln(char *ptr, int offset) {
    char c = *(ptr - offset);
}
'''
        cwe_127 = get_cwe_vulns(source, "CWE-127")
        assert len(cwe_127) > 0, "Should detect CWE-127 for ptr - variable"

    def test_memcpy_from_negative_offset(self):
        """Detect memcpy reading from ptr - offset."""
        source = '''
void vuln(char *data) {
    char dest[10];
    memcpy(dest, data - 5, 10);
}
'''
        cwe_127 = get_cwe_vulns(source, "CWE-127")
        assert len(cwe_127) > 0, "Should detect CWE-127 for memcpy from negative offset"

    def test_memmove_from_tainted_source(self):
        """Detect memmove from tainted data with fixed size."""
        source = '''
void vuln(char *data) {
    char dest[10];
    memmove(dest, data, 100);
}
'''
        cwe_127 = get_cwe_vulns(source, "CWE-127")
        assert len(cwe_127) > 0, "Should detect CWE-127 for memmove from data"

    def test_data_negative_index_legacy(self):
        """Detect legacy pattern: data[-n] access."""
        source = '''
void vuln(char *data) {
    char c = data[-1];
}
'''
        cwe_127 = get_cwe_vulns(source, "CWE-127")
        assert len(cwe_127) > 0, "Should detect CWE-127 for data[-n]"


class TestNegativeCases:
    """Test that false positives are avoided."""

    def test_safe_strlen(self):
        """No detection for strlen on known null-terminated string."""
        source = '''
void safe() {
    const char *msg = "hello";
    size_t len = strlen(msg);
}
'''
        cwe_126 = get_cwe_vulns(source, "CWE-126")
        # msg is not 'data' or in tainted_vars, so should not trigger
        assert len(cwe_126) == 0, "Should not detect CWE-126 for safe strlen"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
