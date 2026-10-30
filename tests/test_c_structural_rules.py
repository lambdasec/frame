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
