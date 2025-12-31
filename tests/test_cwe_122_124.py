"""Test CWE-122 (Heap Buffer Overflow) and CWE-124 (Buffer Underwrite) detection."""

import pytest
from frame.sil.analyzers.interprocedural_analyzer import analyze_interprocedural


class TestCWE122HeapBufferOverflow:
    """Test detection of CWE-122: Heap-based Buffer Overflow."""

    def test_memcpy_larger_than_allocation(self):
        """Test: malloc(10) followed by memcpy(ptr, src, 100)."""
        source = '''
void vulnerable() {
    char *buf = malloc(10);
    memcpy(buf, userInput, 100);  // CWE-122: copying 100 bytes to 10-byte buffer
}
'''
        vulns = analyze_interprocedural(source, "test.c")
        cwe122_vulns = [v for v in vulns if v.cwe_id == "CWE-122"]
        assert len(cwe122_vulns) > 0, "Should detect heap buffer overflow with memcpy"

    def test_strcpy_to_heap_buffer_tainted(self):
        """Test: strcpy to heap buffer from tainted source."""
        source = '''
void vulnerable(char *data) {
    char *heapBuf = malloc(32);
    strcpy(heapBuf, data);  // CWE-122: strcpy to heap buffer with user input
}
'''
        vulns = analyze_interprocedural(source, "test.c")
        cwe122_vulns = [v for v in vulns if v.cwe_id == "CWE-122"]
        assert len(cwe122_vulns) > 0, "Should detect heap buffer overflow with strcpy"

    def test_memset_larger_than_allocation(self):
        """Test: memset with size larger than allocation."""
        source = '''
void vulnerable() {
    char *buf = malloc(16);
    memset(buf, 0, 256);  // CWE-122: memset 256 bytes to 16-byte buffer
}
'''
        vulns = analyze_interprocedural(source, "test.c")
        cwe122_vulns = [v for v in vulns if v.cwe_id == "CWE-122"]
        assert len(cwe122_vulns) > 0, "Should detect heap buffer overflow with memset"

    def test_safe_memcpy(self):
        """Test: memcpy with size within allocation should not be flagged."""
        source = '''
void safe() {
    char *buf = malloc(100);
    memcpy(buf, src, 50);  // Safe: 50 bytes to 100-byte buffer
}
'''
        vulns = analyze_interprocedural(source, "test.c")
        # This specific memcpy should not trigger CWE-122
        cwe122_memcpy_vulns = [v for v in vulns if v.cwe_id == "CWE-122" and "memcpy writes" in v.description]
        assert len(cwe122_memcpy_vulns) == 0, "Safe memcpy should not be flagged"


class TestCWE124BufferUnderwrite:
    """Test detection of CWE-124: Buffer Underwrite (Write-what-where Condition)."""

    def test_negative_array_index(self):
        """Test: ptr[-1] = x pattern."""
        source = '''
void vulnerable() {
    char buf[10];
    buf[-1] = 'x';  // CWE-124: negative array index
}
'''
        vulns = analyze_interprocedural(source, "test.c")
        cwe124_vulns = [v for v in vulns if v.cwe_id == "CWE-124"]
        assert len(cwe124_vulns) > 0, "Should detect buffer underwrite with negative index"

    def test_pointer_arithmetic_underwrite(self):
        """Test: *(ptr - N) = x pattern."""
        source = '''
void vulnerable() {
    char *ptr = buffer;
    *(ptr - 5) = 'x';  // CWE-124: pointer arithmetic underwrite
}
'''
        vulns = analyze_interprocedural(source, "test.c")
        cwe124_vulns = [v for v in vulns if v.cwe_id == "CWE-124"]
        assert len(cwe124_vulns) > 0, "Should detect buffer underwrite via pointer arithmetic"

    def test_pointer_subtraction_from_heap(self):
        """Test: ptr = heapBuf - offset pattern."""
        source = '''
void vulnerable() {
    char *heapBuf = malloc(100);
    char *ptr = heapBuf - 10;  // CWE-124: pointer before buffer start
    *ptr = 'x';
}
'''
        vulns = analyze_interprocedural(source, "test.c")
        cwe124_vulns = [v for v in vulns if v.cwe_id == "CWE-124"]
        assert len(cwe124_vulns) > 0, "Should detect pointer computed before heap buffer"

    def test_safe_array_access(self):
        """Test: positive array index should not trigger CWE-124."""
        source = '''
void safe() {
    char buf[10];
    buf[5] = 'x';  // Safe: positive index
}
'''
        vulns = analyze_interprocedural(source, "test.c")
        # Filter for CWE-124 specifically from our new patterns
        cwe124_neg_vulns = [v for v in vulns if v.cwe_id == "CWE-124" and "negative" in v.description]
        assert len(cwe124_neg_vulns) == 0, "Safe array access should not be flagged"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
