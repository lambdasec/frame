"""CWE-134 (externally controlled format string) in C: attacker data as the format argument of the
printf / syslog / err families (spec sinks, reached by taint). A literal format with the data as
an argument is the fix."""

import pytest

from frame.sil.scanner import FrameScanner

HDR = ("#include <stdio.h>\n#include <stdlib.h>\n#include <stdarg.h>\n#include <syslog.h>\n"
       "#include <wchar.h>\n#include <err.h>\n\n")


def cwes(body, params="va_list ap"):
    src = (HDR + f"void f({params})\n{{\n    char buf[100];\n    wchar_t wbuf[10];\n"
           "    char *s = getenv(\"Q\");\n    wchar_t w[50];\n    fgetws(w, 50, stdin);\n"
           f"    {body}\n}}\n")
    r = FrameScanner(language="c", verify=False).scan(src, "t.c")
    assert not r.errors, r.errors
    return {v.cwe_id for v in r.vulnerabilities}


@pytest.mark.parametrize("call", [
    "printf(s);", "fprintf(stderr, s);", "sprintf(buf, s);", "snprintf(buf, sizeof(buf), s);",
    "syslog(LOG_ERR, s);", "syslog(3, s);", "vprintf(s, ap);", "vfprintf(stderr, s, ap);",
    "vsprintf(buf, s, ap);", "vsnprintf(buf, 10, s, ap);", "wprintf(w);", "fwprintf(stderr, w);",
    "swprintf(wbuf, 10, w);", "err(1, s);", "warn(s);",
])
def test_attacker_format_string(call):
    assert "CWE-134" in cwes(call)


@pytest.mark.parametrize("call", [
    'printf("%s", s);', 'fprintf(stderr, "Error: %s", s);', 'syslog(LOG_ERR, "%s", s);',
    'snprintf(buf, sizeof(buf), "Value: %s", s);', 'printf("Hello, world!");',
])
def test_a_literal_format_is_not(call):
    assert "CWE-134" not in cwes(call)

