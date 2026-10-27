"""CWE-338 follows a weak PRNG's output to where a value must be unpredictable (a cookie, a
key, an IV, a seed); rand() used for anything else is not a finding. Also pins two engine
fixes found on the way: code after a constant-bound loop is analysed, and `strlen(buf)` of a
fixed array is bounded by its capacity."""

from frame.sil.scanner import FrameScanner


def found(code: str) -> set:
    return {(v.cwe_id, v.line) for v in FrameScanner(language="c").scan(code, "t.c").vulnerabilities}


def cwes(code: str) -> set:
    return {c for c, _ in found(code)}


def test_rand_token_set_as_a_cookie():
    code = """#include <stdio.h>
#include <stdlib.h>
int main(void)
{
    char token[33];
    for (int i = 0; i < 32; i++) {
        token[i] = "0123456789abcdef"[rand() % 16];
    }
    token[32] = '\\0';
    printf("Set-Cookie: session=%s\\r\\n", token);
    return 0;
}
"""
    assert ("CWE-338", 10) in found(code)


def test_rand_used_as_an_encryption_key():
    code = """#include <stdlib.h>
int enc(void *ctx, const void *cipher)
{
    unsigned char key[32];
    for (int i = 0; i < 32; i++) key[i] = (unsigned char)rand();
    return EVP_EncryptInit_ex(ctx, cipher, NULL, key, NULL);
}
"""
    assert ("CWE-338", 6) in found(code)


def test_rand_used_as_data_is_not_a_finding():
    code = """#include <stdio.h>
#include <stdlib.h>
int main(void)
{
    int data = rand();
    printf("%d\\n", data);
    return 0;
}
"""
    assert "CWE-338" not in cwes(code)


def test_predictable_data_is_not_an_injection_payload():
    code = """#include <stdio.h>
#include <stdlib.h>
int main(void)
{
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "sleep %d", rand() % 5);
    return system(cmd);
}
"""
    assert "CWE-78" not in cwes(code)


def test_code_after_a_constant_bound_loop_is_analysed():
    code = """#include <stdlib.h>
int main(void)
{
    for (int i = 0; i < 3; i++) {
    }
    return system(getenv("X"));
}
"""
    assert "CWE-78" in cwes(code)


def test_strlen_of_a_fixed_buffer_bounds_an_index():
    code = """#include <stdio.h>
#include <string.h>
int main(void)
{
    char line[100];
    if (fgets(line, 100, stdin) == NULL) {
        return 1;
    }
    size_t n = strlen(line);
    if (n > 0) {
        line[n - 1] = '\\0';
    }
    return 0;
}
"""
    assert "CWE-787" not in cwes(code)
