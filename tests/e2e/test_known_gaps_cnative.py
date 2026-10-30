"""Realistic C/C++ flows Frame does not follow yet (or reports wrongly), pinned so they cannot go unnoticed.

Each entry is a strict xfail: a MISS asserts the CWE is reported in the file, a FALSE POSITIVE asserts
it is not. The day the analysis learns the idiom the test XPASSes and fails the run until the entry is
moved into the regular matrix (`projects_c.py`).
"""

import pytest

from e2e_helpers import scan, write_tree

HDR = "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <unistd.h>\n"

# (id, kind, cwe, source). kind: "miss" -> the CWE must be reported; "fp" -> it must not be.
GAPS = [
    # ---- C has no interprocedural taint: the request value is read in one function, used in another
    # ---- validation idioms that make a value safe for a shell are not recognised
    # ---- buffer overflows
    # a pointer moved before its buffer's start, then written or read through (only constant
    # negative indexes on the array itself are followed)
    ("pointer_arithmetic_underwrite", "miss", "CWE-124", "buf.c", HDR + """
void f(void)
{
    char buf[10];
    char *ptr = buf;
    *(ptr - 5) = 'x';
    printf("%s", buf);
}
"""),
    ("pointer_arithmetic_underread", "miss", "CWE-127", "buf.c", HDR + """
void f(void)
{
    char buf[10] = "abc";
    char *ptr = buf;
    char c = *(ptr - 5);
    printf("%c", c);
}
"""),

    # ---- heap lifecycle
    # ---- weak randomness is reported where an API needs an unpredictable value (a key, IV,
    #      salt, seed, a Set-Cookie header), not where code makes a token by its purpose alone
    ("rand_bytes_hashed_into_session_token", "miss", "CWE-338", "auth/token.c", HDR + """#include <openssl/sha.h>
#include <time.h>

void new_session_token(char out[65])
{
    unsigned char raw[16];
    unsigned char digest[SHA256_DIGEST_LENGTH];
    srand((unsigned)time(NULL));
    for (int i = 0; i < 16; i++) {
        raw[i] = (unsigned char)rand();
    }
    SHA256(raw, sizeof(raw), digest);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(out + i * 2, "%02x", digest[i]);
    }
}
"""),
]


@pytest.mark.xfail(strict=True, reason="known limitation (see test_known_gaps_cnative.py)")
@pytest.mark.parametrize("gap", GAPS, ids=[g[0] for g in GAPS])
def test_known_gap(gap, tmp_path):
    _name, kind, cwe, filename, source = gap
    write_tree(tmp_path, {filename: source})
    got = scan(tmp_path)
    reported = {f["cwe_id"] for f in got.findings}
    if kind == "miss":
        assert cwe in reported, f"{cwe} not reported; got {sorted(reported)}"
    else:
        assert cwe not in reported, f"false {cwe}: {[(f['line'], f['cwe_id']) for f in got.findings]}"
