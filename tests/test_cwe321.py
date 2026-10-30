"""CWE-321 (hard-coded cryptographic key) in C/C++: a literal reaching an argument the callee takes
as a key (`key_args` in the c/cpp spec tables: EVP_*Init*, AES_set_*_key, HMAC, DES_set_key),
directly or through a local the path shows holds one (a string, or a brace list of literals). A
key from anywhere else is not one, whatever the variable is called. Credential-named bindings
(`secret_key = "..."`, `#define AES_KEY "..."`) are the shared name rules (tests/test_secret_names.py)."""

import pytest

from frame.sil.scanner import FrameScanner

HDR = "#include <openssl/aes.h>\n#include <openssl/evp.h>\n#include <openssl/hmac.h>\n#include <openssl/des.h>\n\n"
SIG = "void f(EVP_CIPHER_CTX *ctx, const unsigned char *user_key, const unsigned char *iv, unsigned char *out)\n"


def cwe321(*body, language="c"):
    src = HDR + SIG + "{\n" + "\n".join("    " + b for b in body) + "\n}\n"
    r = FrameScanner(language=language).scan(src, "t.c" if language == "c" else "t.cpp")
    assert not r.errors, r.errors
    return sorted(v.line for v in r.vulnerabilities if v.cwe_id == "CWE-321")


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("body", [
    ('unsigned char key[16] = "hardcodedkey123";', "AES_KEY k;", "AES_set_encrypt_key(key, 128, &k);"),
    ("unsigned char key[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};", "AES_KEY k;",
     "AES_set_decrypt_key(key, 64, &k);"),
    ('EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, (const unsigned char *)"0123456789abcdef", iv);',),
    ('const char *secret = "s3cr3t-hmac";', "unsigned int n = 0;",
     "HMAC(EVP_sha256(), secret, 11, user_key, 16, out, &n);"),
    ("DES_cblock key = {1, 2, 3, 4, 5, 6, 7, 8};", "DES_key_schedule ks;", "DES_set_key(&key, &ks);"),
])
def test_a_literal_key_is_reported(body, language):
    assert cwe321(*body, language=language)


@pytest.mark.parametrize("body", [
    ("AES_KEY k;", "AES_set_encrypt_key(user_key, 128, &k);"),
    ("EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, user_key, iv);",),
    # a buffer filled at run time is not a literal, whatever it is called
    ("unsigned char key[16];", "RAND_bytes(key, sizeof(key));", "AES_KEY k;", "AES_set_encrypt_key(key, 128, &k);"),
    # a literal IV is not a key (a different weakness)
    ('EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, user_key, (const unsigned char *)"0000000000000000");',),
])
def test_a_key_from_elsewhere_is_not(body):
    assert not cwe321(*body)
