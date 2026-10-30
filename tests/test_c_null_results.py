"""CWE-690: reading through the result of a function that returns NULL as an ordinary outcome
(`returns_null = "normally"` in the c/cpp tables: getenv, fopen, strchr, readdir...), on a path
that did not exclude NULL. Decided by the solver against the path-fact fixpoint (`pc & p == nil`
satisfiable), like CWE-476; a check before the read makes it unsatisfiable. Allocators
(`returns_null = "on_exhaustion"`: NULL only when memory runs out) are not reported: an unchecked
`malloc` is the ordinary idiom."""

import pytest

from frame.sil.scanner import FrameScanner

HDR = "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <dirent.h>\n\n"


def cwe690(body, params="void", language="c"):
    src = HDR + f"void f({params})\n{{\n" + "\n".join("    " + line for line in body) + "\n}\n"
    r = FrameScanner(language=language, verify=False).scan(src, "t.c" if language == "c" else "t.cpp")
    assert not r.errors, r.errors
    lines = src.split("\n")
    return [lines[v.line - 1].strip() for v in r.vulnerabilities if v.cwe_id == "CWE-690"]


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("body, params, line", [
    (['char *home = getenv("HOME");', "size_t n = strlen(home);", 'printf("%zu", n);'], "void", "size_t n = strlen(home);"),
    (['size_t n = strlen(getenv("HOME"));', 'printf("%zu", n);'], "void", 'size_t n = strlen(getenv("HOME"));'),
    (['FILE *fp = fopen("/tmp/x", "w");', 'fputs("x", fp);'], "void", 'fputs("x", fp);'),
    (["char *eq = strchr(s, '=');", "*eq = '\\0';"], "char *s", "*eq = '\\0';"),
    (['DIR *d = opendir("/tmp");', "struct dirent *e = readdir(d);", 'printf("%s", e->d_name);'], "void",
     'printf("%s", e->d_name);'),
])
def test_an_unchecked_null_result_read_through(body, params, line, language):
    assert line in cwe690(body, params, language)


@pytest.mark.parametrize("body, params", [
    (['char *home = getenv("HOME");', "if (home == NULL)", "{", "return;", "}", "size_t n = strlen(home);",
      'printf("%zu", n);'], "void"),
    (['FILE *fp = fopen("/tmp/x", "w");', "if (!fp)", "{", "return;", "}", 'fputs("x", fp);', "fclose(fp);"], "void"),
    (["char *eq = strchr(s, '=');", "if (eq != NULL)", "{", "*eq = '\\0';", "}"], "char *s"),
    (['char *home = getenv("HOME");', 'printf("%s", home ? home : "/");'], "void"),
    (["char *p = malloc(10);", "p[0] = 'a';", "free(p);"], "void"),          # an allocator: not reported
])
def test_a_checked_result_or_an_allocation_is_not(body, params):
    assert cwe690(body, params) == []


def test_returns_null_is_validated(tmp_path):
    from frame.sil.specs.tables import SpecTableError, parse_table
    with pytest.raises(SpecTableError, match="returns_null"):
        parse_table({"spec": [{"name": "f", "returns_null": "sometimes"}]}, "t.toml")
