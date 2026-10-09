"""Recall/precision regressions for C/C++ found by probing Juliet-style patterns.

Source is written one statement per line, like real code: several analyzers are
line-based and a one-line function hides the very structure they look for.
Every positive pins a former miss; every negative pins the correct idiom nearest
to it, so a recall gain cannot quietly become noise.
"""

import pytest

from frame.sil.scanner import FrameScanner

HDR = "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n"


def cwes(*lines, language="c"):
    src = HDR + "\n".join(lines) + "\n"
    r = FrameScanner(language=language, verify=False).scan(src, "t.c")
    assert not r.errors, r.errors
    return {v.cwe_id for v in r.vulnerabilities}


def fn(*body):
    return ("void f(){", *body, "}")


# ---- CWE-476: a local that is provably NULL ---------------------------------

@pytest.mark.parametrize("body", [
    ("int *p = NULL;", "*p = 5;"),
    ("int *p = NULL;", "int y = *p;", 'printf("%d", y);'),
    ("char *p = NULL;", "p[0] = 'a';"),
    ("int *p;", "p = NULL;", "*p = 5;"),
])
def test_null_local_dereference_is_reported(body):
    assert "CWE-476" in cwes(*fn(*body))


def test_null_through_arrow_is_reported():
    assert "CWE-476" in cwes("struct S{int a;};", "int f(){", "struct S *p = NULL;", "return p->a;", "}")
    assert "CWE-476" in cwes("struct S{int a;};", "void f(){", "struct S *p = NULL;", "p->a = 1;", "}")


@pytest.mark.parametrize("body", [
    ("int *p = NULL;", "int c = rand();", "if (c) p = (int*)malloc(4);", "if (p) *p = 1;"),   # idiom
    ("int x;", "int *p = NULL;", "p = &x;", "*p = 5;"),                                         # reassigned
    ("int *p = NULL;", "if (p != NULL) *p = 5;"),                                               # checked
    ("int *p = NULL;", "init(&p);", "*p = 5;"),                                                 # address taken
])
def test_null_local_negatives_stay_clean(body):
    assert "CWE-476" not in cwes("void init(int**);", *fn(*body))


def test_null_global_reset_by_callee_is_not_reported():
    assert "CWE-476" not in cwes("int *g;", "void h();", "void f(){", "g = NULL;", "h();", "*g = 5;", "}")


# ---- pointer dereference through ->  ---------------------------------------

def test_use_after_free_through_arrow():
    body = ("struct S{int a;};", "int f(){",
            "struct S *p = (struct S*)malloc(sizeof(struct S));", "if (!p) return 0;",
            "free(p);", "return p->a;", "}")
    assert "CWE-416" in cwes(*body)


def test_matched_arrow_use_then_free_is_clean():
    body = ("struct S{int a;};", "int f(){",
            "struct S *p = (struct S*)malloc(sizeof(struct S));", "if (!p) return 0;",
            "p->a = 1;", "int r = p->a;", "free(p);", "return r;", "}")
    assert "CWE-416" not in cwes(*body)


def test_cpp_programs_are_labelled_cpp():
    from frame.sil.scanner import FrameScanner as S
    assert S(language="cpp").frontend.translate("int main(){return 0;}", "t.cpp").language == "cpp"
    assert S(language="c").frontend.translate("int main(){return 0;}", "t.c").language == "c"


# ---- CWE-401: leaks through calls that cannot retain the pointer ----------------

@pytest.mark.parametrize("use", ['strcpy(p, "hi");', 'puts(p);', 'printf("%s", p);', "p[0] = 1;"])
def test_leak_through_non_retaining_use(use):
    found = cwes(*fn("char *p = (char*)malloc(10);", "if (!p) return;", use))
    assert "CWE-401" in found
    assert "CWE-252" not in found, "a checked malloc is not an unchecked return value"


def test_unknown_callee_may_take_ownership_so_no_leak():
    assert "CWE-401" not in cwes("void helper(char*);",
                                 *fn("char *p = (char*)malloc(10);", "if (!p) return;", "helper(p);"))


def test_freed_allocation_is_clean():
    found = cwes(*fn("char *p = (char*)malloc(10);", "if (!p) return;", 'strcpy(p, "hi");', "free(p);"))
    assert not found & {"CWE-401", "CWE-252"}


@pytest.mark.parametrize("check", ["if (!p) return;", "if (p == NULL) return;", "if (NULL == p) return;"])
def test_null_check_spellings_are_equivalent(check):
    assert "CWE-252" not in cwes(*fn("char *p = (char*)malloc(10);", check, "p[0] = 1;", "free(p);"))


# ---- CWE-457: scalar passed by value ----------------------------------------------

def test_uninitialized_scalar_passed_to_printf():
    assert "CWE-457" in cwes(*fn("int x;", 'printf("%d", x);'))


# ---- CWE-787/125 and CWE-22: input functions fill their arguments ---------------

def test_fgets_atoi_index_is_a_tainted_write():
    body = fn("int a[10];", "char in[16];", "int i;", "fgets(in, 16, stdin);", "i = atoi(in);", "a[i] = 1;")
    assert "CWE-787" in cwes(*body)


def test_scanf_index_is_a_tainted_read():
    body = fn("int a[10];", "int i;", 'scanf("%d", &i);', 'printf("%d", a[i]);')
    assert "CWE-125" in cwes(*body)


def test_guarded_tainted_index_is_clean():
    body = fn("int a[10];", "int i;", 'scanf("%d", &i);', "if (i >= 0 && i < 10) { a[i] = 1; }")
    assert not cwes(*body) & {"CWE-787", "CWE-125"}


def test_tainted_fopen_path_is_path_traversal_not_sql():
    found = cwes(*fn("char b[64];", "fgets(b, 64, stdin);", 'FILE *fp = fopen(b, "r");', "if (fp) fclose(fp);"))
    assert "CWE-22" in found
    assert "CWE-89" not in found


def test_constant_fopen_path_is_clean():
    assert "CWE-22" not in cwes(*fn('FILE *fp = fopen("/etc/motd", "r");', "if (fp) fclose(fp);"))


# ---- CWE-190 ---------------------------------------------------------------------

def test_tainted_malloc_size_is_integer_overflow_not_code_injection():
    found = cwes(*fn("int n;", "char in[16];", "fgets(in, 16, stdin);", "n = atoi(in);",
                     "char *p = (char*)malloc(n * sizeof(int));", "if (p) free(p);"))
    assert "CWE-190" in found
    assert "CWE-94" not in found


def test_literal_upper_bound_makes_the_product_safe():
    guarded = fn("int d;", "char in[16];", "fgets(in, 16, stdin);", "d = atoi(in);",
                 "if (d < 1000) {", "int r = d * 2;", 'printf("%d", r);', "}")
    unguarded = fn("int d;", "char in[16];", "fgets(in, 16, stdin);", "d = atoi(in);",
                   "int r = d * 2;", 'printf("%d", r);')
    assert "CWE-190" not in cwes(*guarded)
    assert "CWE-190" in cwes(*unguarded)


def test_literal_bound_too_loose_for_the_multiplier_is_still_flagged():
    loose = fn("int d;", "char in[16];", "fgets(in, 16, stdin);", "d = atoi(in);",
               "if (d < 2000000000) {", "int r = d * 2;", 'printf("%d", r);', "}")
    assert "CWE-190" in cwes(*loose)


# ---- CWE-120/121/122: constant-size writes into constant-capacity buffers --------

@pytest.mark.parametrize("body", [
    ("char buf[10];", 'strcpy(buf, "AAAAAAAAAAAAAAAAAAAA");'),
    ("char buf[10] = \"\";", 'strcat(buf, "0123456789ABCDEF");'),
    ("char buf[8];", 'sprintf(buf, "this is far too long");'),
    ("char buf[10];", "memset(buf, 'A', 100);"),
    ("char src[100];", "char dst[50];", "memset(src, 'C', 99);", "memcpy(dst, src, 99);"),
    ("char buf[10];", "fgets(buf, 100, stdin);"),
    ("char buf[10];", "snprintf(buf, 64, \"%d\", 1);"),
    ("char *d = (char*)malloc(10);", "if (d == NULL) return;", 'strcpy(d, "AAAAAAAAAAAAAAAAAAAA");', "free(d);"),
    ("char buf[10];", "char *p = buf;", 'strcpy(p, "AAAAAAAAAAAAAAAAAAAA");'),
    ("char buf[50];", "memset(buf, 'A', 100 - 1);"),
])
def test_constant_size_overflow_is_reported(body):
    assert cwes(*fn(*body)) & {"CWE-120", "CWE-121", "CWE-122", "CWE-787"}


@pytest.mark.parametrize("body", [
    ("char buf[10];", 'strcpy(buf, "AAAA");'),
    ("char buf[8];", 'strcpy(buf, "1234567");'),                     # exactly fits with NUL
    ("char src[100];", "char dst[100];", "memset(src, 'C', 99);", "memcpy(dst, src, sizeof(dst));"),
    ("char buf[10];", "fgets(buf, sizeof(buf), stdin);"),
    ("char buf[10];", "memset(buf, 0, 10);"),
    ("char buf[10];", "memset(buf, 0, SOME_MACRO);"),                # unresolved size is never guessed
    ("int a[10];", "memset(a, 0, 40);"),                              # non-char array: bytes != elements
    ("char buf[10];", "char *p = buf;", "p = (char*)malloc(100);", "memset(p, 'A', 50);"),   # pointer re-defined
    ("char buf[64];", 'snprintf(buf, sizeof(buf), "%s", "ok");'),
])
def test_constant_size_negatives_stay_clean(body):
    assert not cwes(*fn(*body)) & {"CWE-120", "CWE-121", "CWE-122", "CWE-787"}


# ---- false positives found by scanning real C (psutil, cffi, lz4, bitarray) -------

def test_goto_on_the_null_branch_ends_that_path():
    body = ("struct S{int a;};", "int f(){",
            "struct S *p = (struct S*)malloc(sizeof(struct S));",
            "if (p == NULL) {", "goto error;", "}",
            "p->a = 1;", "free(p);", "return 0;", "error:", "return -1;", "}")
    assert "CWE-476" not in cwes(*body)


def test_write_inside_a_loop_condition_is_a_reassignment():
    body = ("struct E{int a;};", "struct E *next(void);", "void f(){",
            "struct E *e = NULL;", "while ((e = next())) {", "e->a = 1;", "}", "}")
    assert "CWE-476" not in cwes(*body)


def test_macro_sized_array_passed_by_name_is_not_an_uninitialized_scalar():
    body = ("#define SIZE 64", "void fill(char*);", "void f(){", "char errbuf[SIZE];",
            "fill(errbuf);", "}")
    assert "CWE-457" not in cwes(*body)


def test_branches_that_goto_out_do_not_leave_a_variable_uninitialized():
    body = ("void use(int, int);", "int f(int c, int d){", "int duplex;", "int speed;",
            "if (c) {", "duplex = 1;", "speed = 2;", "} else {",
            "if (d) {", "duplex = 3;", "speed = 0;", "} else {", "goto error;", "}", "}",
            "use(duplex, speed);", "return 0;", "error:", "return -1;", "}")
    assert "CWE-457" not in cwes(*body)


def test_alloca_is_stack_storage_not_a_leak():
    body = ("#include <alloca.h>", "int f(int n){", "char *x = alloca(n);",
            "memset((void*)x, 0, n);", "return 0;", "}")
    assert "CWE-401" not in cwes(*body)


def test_uninitialized_read_with_no_goto_in_the_function_is_still_reported():
    assert "CWE-457" in cwes("void use(int);", "void f(int c){", "int x;", "if (c) { x = 1; }", "use(x);", "}")


# ---- functions that do not parse cleanly --------------------------------------------

def test_function_with_unexpanded_statement_macros_is_flagged_as_unreliable():
    from frame.sil.frontends.c_frontend import CFrontend
    macro = ("void f(void *file){", "BEGIN_BLOCKING", "file = open_it();", "END_BLOCKING",
             "if (file == NULL) { return; }", "}")
    clean = ("void g(void *file){", "file = open_it();", "if (file == NULL) { return; }", "}")
    fe = CFrontend()
    assert fe.translate("\n".join(macro), "t.c").procedures["f"].has_parse_errors
    assert not fe.translate("\n".join(clean), "t.c").procedures["g"].has_parse_errors


def test_dataflow_defects_are_not_reported_in_a_function_that_failed_to_parse():
    # Same shape as a reported defect, but the unexpanded macro without a semicolon
    # makes the CFG untrustworthy, so the null-dereference check stays silent.
    body = ("struct S{int a;};", "void f(){", "BEGIN_BLOCKING", "struct S *p = NULL;",
            "END_BLOCKING", "p->a = 1;", "}")
    assert "CWE-476" not in cwes(*body)
    clean = ("struct S{int a;};", "void g(){", "struct S *p = NULL;", "p->a = 1;", "}")
    assert "CWE-476" in cwes(*clean)
