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
