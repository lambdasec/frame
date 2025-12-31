"""
Test cases for improved CWE-476 NULL Pointer Dereference detection.

Tests the enhanced detection in interprocedural_analyzer.py:
1. No false positives on type declarations
2. Detection of pointers from NULL-returnable functions
3. Proper NULL check scope tracking
"""

import pytest
from frame.sil.analyzers.interprocedural_analyzer import analyze_interprocedural


class TestCWE476TypeDeclarations:
    """Test that type declarations don't trigger false positives."""

    def test_no_fp_basic_type_declaration(self):
        """int *ptr should not trigger CWE-476."""
        code = '''
void foo() {
    int *ptr;
    ptr = malloc(sizeof(int));
    if (ptr != NULL) {
        *ptr = 5;
    }
}
'''
        vulns = analyze_interprocedural(code, "test.c")
        cwe476_vulns = [v for v in vulns if v.cwe_id == "CWE-476"]
        # Should not report the declaration as a dereference
        assert all("type declaration" not in v.description.lower() for v in cwe476_vulns)

    def test_no_fp_struct_type_declaration(self):
        """struct Node *ptr should not trigger CWE-476."""
        code = '''
struct Node {
    int data;
    struct Node *next;
};
void foo() {
    struct Node *head;
    head = malloc(sizeof(struct Node));
    if (head) {
        head->data = 10;
    }
}
'''
        vulns = analyze_interprocedural(code, "test.c")
        cwe476_vulns = [v for v in vulns if v.cwe_id == "CWE-476"]
        # Type declarations should not be flagged
        for v in cwe476_vulns:
            assert "struct Node" not in v.description

    def test_no_fp_typedef_declaration(self):
        """TypeName *ptr should not trigger CWE-476."""
        code = '''
typedef struct { int x; } Point;
void foo() {
    Point *p = malloc(sizeof(Point));
    if (p != NULL) {
        p->x = 5;
    }
}
'''
        vulns = analyze_interprocedural(code, "test.c")
        cwe476_vulns = [v for v in vulns if v.cwe_id == "CWE-476"]
        # Should not have false positives on typedef declarations
        assert len(cwe476_vulns) == 0


class TestCWE476NullReturnableFunctions:
    """Test detection of pointers from functions that can return NULL."""

    def test_fopen_null_dereference(self):
        """fopen can return NULL, so using result without check is CWE-476."""
        code = '''
void process_file() {
    FILE *fp = fopen("test.txt", "r");
    fread(buffer, 1, 100, fp);
}
'''
        vulns = analyze_interprocedural(code, "test.c")
        cwe476_vulns = [v for v in vulns if v.cwe_id == "CWE-476"]
        # Should detect potential NULL dereference of fp
        assert any(v.var_name == "fp" for v in cwe476_vulns)

    def test_strstr_null_dereference(self):
        """strstr can return NULL if substring not found."""
        code = '''
void find_and_modify(char *haystack, char *needle) {
    char *result = strstr(haystack, needle);
    *result = 'X';
}
'''
        vulns = analyze_interprocedural(code, "test.c")
        cwe476_vulns = [v for v in vulns if v.cwe_id == "CWE-476"]
        # Should detect potential NULL dereference
        assert any(v.var_name == "result" for v in cwe476_vulns)

    def test_getenv_null_dereference(self):
        """getenv can return NULL if env var not set."""
        code = '''
void check_env() {
    char *home = getenv("HOME");
    printf("Home: %s\n", home);
    int len = strlen(home);
}
'''
        vulns = analyze_interprocedural(code, "test.c")
        cwe476_vulns = [v for v in vulns if v.cwe_id == "CWE-476"]
        # Should detect potential NULL dereference of home
        assert any(v.var_name == "home" for v in cwe476_vulns)


class TestCWE476NullCheckScope:
    """Test that NULL checks properly suppress detection."""

    def test_null_check_suppresses_detection(self):
        """if (ptr != NULL) should suppress detection inside block."""
        code = '''
void safe_use() {
    char *ptr = malloc(100);
    if (ptr != NULL) {
        *ptr = 'a';
        ptr[0] = 'b';
    }
}
'''
        vulns = analyze_interprocedural(code, "test.c")
        cwe476_vulns = [v for v in vulns if v.cwe_id == "CWE-476"]
        # NULL-checked variable should not be flagged
        assert len(cwe476_vulns) == 0

    def test_truthiness_check_suppresses(self):
        """if (ptr) should also suppress detection."""
        code = '''
void safe_use() {
    char *ptr = malloc(100);
    if (ptr) {
        *ptr = 'a';
    }
}
'''
        vulns = analyze_interprocedural(code, "test.c")
        cwe476_vulns = [v for v in vulns if v.cwe_id == "CWE-476"]
        # Truthiness check should also suppress
        assert len(cwe476_vulns) == 0

    def test_null_check_in_condition(self):
        """ptr != NULL in complex condition should suppress."""
        code = '''
void safe_use() {
    char *ptr = malloc(100);
    if (ptr != NULL && strlen(ptr) > 0) {
        *ptr = 'a';
    }
}
'''
        vulns = analyze_interprocedural(code, "test.c")
        cwe476_vulns = [v for v in vulns if v.cwe_id == "CWE-476"]
        # Condition includes NULL check, should suppress
        assert len(cwe476_vulns) == 0


class TestCWE476TruePositives:
    """Test that true vulnerabilities are detected."""

    def test_malloc_no_check(self):
        """malloc result used without NULL check is vulnerable."""
        code = '''
void vulnerable() {
    int *data = malloc(sizeof(int) * 100);
    data[0] = 42;
}
'''
        vulns = analyze_interprocedural(code, "test.c")
        cwe476_vulns = [v for v in vulns if v.cwe_id == "CWE-476"]
        # Should detect NULL dereference
        assert len(cwe476_vulns) > 0
        assert any(v.var_name == "data" for v in cwe476_vulns)

    def test_arrow_dereference_no_check(self):
        """Arrow operator on unchecked pointer is vulnerable."""
        code = '''
struct Node { int value; };
void vulnerable() {
    struct Node *node = malloc(sizeof(struct Node));
    node->value = 10;
}
'''
        vulns = analyze_interprocedural(code, "test.c")
        cwe476_vulns = [v for v in vulns if v.cwe_id == "CWE-476"]
        # Should detect arrow dereference without NULL check
        assert len(cwe476_vulns) > 0
        assert any(v.var_name == "node" for v in cwe476_vulns)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
