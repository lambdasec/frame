"""Rules of the C line-based fallback (`interprocedural_analyzer._detect_semantic_cwes`) replaced
by structural ones (roadmap Phase 1, step 7): each positive is paired with its nearest safe twin,
and neither depends on what a variable is called."""

import pytest

from frame.sil.scanner import FrameScanner


def findings(code, lang="c"):
    res = FrameScanner(language=lang, verify=False).scan(code, "t.c" if lang == "c" else "t.cpp")
    return {(v.cwe_id, v.line) for v in res.vulnerabilities}


_CONFIG = """#include <windows.h>
#include <stdlib.h>
#include <string.h>

void handler(void)
{
    char host[100] = "";
    char *env = getenv("ADD");
    if (env != NULL)
    {
        strncat(host, env, 99);
    }
    %s
}
"""


@pytest.mark.parametrize("lang", ["c", "cpp"])
@pytest.mark.parametrize("call", ["SetComputerNameA(host);", "SetEnvironmentVariableA(\"PATH\", host);",
                                  "RegSetValueExA(key, \"v\", 0, REG_SZ, (BYTE *)host, 100);"])
def test_attacker_data_choosing_a_system_setting_is_cwe_15(call, lang):
    assert ("CWE-15", 13) in findings(_CONFIG % call, lang)


@pytest.mark.parametrize("call", ["SetComputerNameA(\"build-host\");",
                                  "RegSetValueExA(key, \"v\", 0, REG_SZ, (BYTE *)\"x\", 2);"])
def test_a_constant_setting_is_not(call):
    assert not {f for f in findings(_CONFIG % call) if f[0] == "CWE-15"}


_LOAD = """#include <windows.h>
#include <dlfcn.h>
#include <stdio.h>

void plugin(void)
{
    char path[256] = "";
    fgets(path, 256, stdin);
    %s
}
"""


@pytest.mark.parametrize("lang", ["c", "cpp"])
@pytest.mark.parametrize("call", ["LoadLibraryA(path);", "LoadLibraryExW(path, NULL, 0);", "dlopen(path, RTLD_NOW);"])
def test_a_library_named_by_attacker_data_is_cwe_114(call, lang):
    assert ("CWE-114", 9) in findings(_LOAD % call, lang)


@pytest.mark.parametrize("call", ['LoadLibraryA("C:\\\\Windows\\\\System32\\\\winhttp.dll");',
                                  'dlopen("/usr/lib/libz.so.1", RTLD_NOW);'])
def test_a_fixed_library_is_not(call):
    assert not {f for f in findings(_LOAD % call) if f[0] == "CWE-114"}


@pytest.mark.parametrize("call", ["tmpnam(name);", "tempnam(NULL, \"x\");", "mktemp(name);", "_mktemp(name);"])
def test_temp_names_that_race_are_cwe_377(call):
    code = "#include <stdio.h>\n#include <stdlib.h>\n\nvoid f(void)\n{\n    char name[64] = \"tmpXXXXXX\";\n    %s\n}\n"
    assert ("CWE-377", 7) in findings(code % call)


def test_mkstemp_is_not():
    code = ("#include <stdlib.h>\n\nvoid f(void)\n{\n    char name[64] = \"tmpXXXXXX\";\n"
            "    int fd = mkstemp(name);\n    (void)fd;\n}\n")
    assert not {f for f in findings(code) if f[0] == "CWE-377"}


_SWITCH = """#include <stdio.h>
#include <stdlib.h>

void f(int x)
{
    switch (x)
    {
    case 1:
        printf("one");
%s
    case 2:
        printf("two");
        break;
    default:
        break;
    }
}
"""


@pytest.mark.parametrize("lang", ["c", "cpp"])
def test_a_case_running_into_the_next_is_cwe_484(lang):
    assert ("CWE-484", 11) in findings(_SWITCH % "", lang)


@pytest.mark.parametrize("end", ["        break;", "        return;", "        exit(1);", "        /* fall through */",
                                 "        // FALLTHRU", "        { printf(\"x\"); break; }"])
def test_an_ended_or_marked_case_is_not(end):
    assert not {f for f in findings(_SWITCH % end) if f[0] == "CWE-484"}


def test_cpp_fallthrough_attribute_is_a_mark():
    assert not {f for f in findings(_SWITCH % "        [[fallthrough]];", "cpp") if f[0] == "CWE-484"}


def test_shared_labels_are_not_a_fall_through():
    code = "void f(int x)\n{\n    switch (x)\n    {\n    case 1:\n    case 2:\n        g();\n        break;\n    }\n}\n"
    assert not {f for f in findings(code) if f[0] == "CWE-484"}


@pytest.mark.parametrize("stmt, flagged", [
    ("char *p = (char *)0x400000;", True),
    ("int *q; q = (int *)(0x7fff0000);", True),
    ("char *p = (char *)0;", False),
    ("char *p = NULL;", False),
    ("long a = (long)0x400000;", False),
])
def test_a_fixed_address_given_to_a_pointer_is_cwe_587(stmt, flagged):
    code = "#include <stddef.h>\n\nvoid f(void)\n{\n    %s\n}\n" % stmt
    assert bool({f for f in findings(code) if f[0] == "CWE-587"}) == flagged


@pytest.mark.parametrize("define, cwe", [('#define PASSWORD "ABCD1234!"', "CWE-259"),
                                         ('#define API_TOKEN "q8Hk2LmZp4Rt7XvN"', "CWE-798"),
                                         ('#define PASSWORD_FIELD "password"', None),
                                         ('#define GREETING "hello world"', None)])
def test_a_credential_macro_is_a_hardcoded_secret(define, cwe):
    code = define + "\n\nvoid f(void)\n{\n}\n"
    got = {c for c, _ in findings(code) if c in ("CWE-259", "CWE-798", "CWE-321")}
    assert got == ({cwe} if cwe else set())


_RACE = """#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

void f(void)
{
    char path[100] = "";
    struct stat st;
    fgets(path, 100, stdin);
    %s
    {
        return;
    }
    %s
    int fd = open(path, O_RDWR);
    (void)fd;
}
"""


@pytest.mark.parametrize("lang", ["c", "cpp"])
@pytest.mark.parametrize("check", ["if (stat(path, &st) == -1)", "if (access(path, W_OK) != 0)",
                                   "if (lstat(path, &st) != 0)"])
def test_a_checked_path_then_used_is_cwe_367(check, lang):
    assert ("CWE-367", 17) in findings(_RACE % (check, ""), lang)


@pytest.mark.parametrize("check, between", [
    ("if (stat(path, &st) == -1)", 'strcpy(path, "/var/app/data");'),    # a different path is used
    ("if (path[0] == '\\0')", ""),                                         # nothing was checked
])
def test_an_unchecked_or_rewritten_path_is_not(check, between):
    assert not {f for f in findings(_RACE % (check, between)) if f[0] == "CWE-367"}


@pytest.mark.parametrize("value, reported", [
    ('user ? user : "guest"', True),       # either branch can be the value
    ('user ? "guest" : user', True),
    ('1 ? "guest" : user', False),         # the condition folds: only the constant branch
    ('0 ? user : "guest"', False),
])
def test_a_c_ternary_is_either_branch(value, reported):
    code = ("#include <stdio.h>\n#include <stdlib.h>\n\nvoid f(void)\n{\n    char *user = getenv(\"USER\");\n"
            f"    char *who = {value};\n    system(who);\n}}\n")
    assert (("CWE-78", 8) in findings(code)) == reported
