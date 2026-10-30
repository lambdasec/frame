"""Weak algorithm names as data (`frame/sil/specs/data/weak-algorithms.toml`): one list, read by the
Java frontend and the translator's by-name checks (MessageDigest, Cipher, hashlib.new)."""

import pytest

from frame.sil.scanner import FrameScanner
from frame.sil.specs.weak_algorithms import load


def test_the_lists():
    w = load()
    assert {"MD5", "SHA", "SHA-1"} <= w.hashes and "SHA256" not in w.hashes
    assert {"DES", "RC4"} <= w.ciphers and w.cipher_modes == {"ECB"}


@pytest.mark.parametrize("algo,cwe", [('"MD5"', "CWE-328"), ('"SHA"', "CWE-328"), ('"SHA-256"', None)])
def test_java_message_digest(algo, cwe):
    code = ("import java.security.MessageDigest;\nclass A {\n  byte[] h(byte[] b) throws Exception {\n"
            f"    MessageDigest md = MessageDigest.getInstance({algo});\n    return md.digest(b);\n  }}\n}}\n")
    found = {v.cwe_id for v in FrameScanner(language="java").scan(code, "A.java").vulnerabilities}
    assert (cwe in found) if cwe else not ({"CWE-328", "CWE-327"} & found)


@pytest.mark.parametrize("algo,weak", [('"DES/CBC/PKCS5Padding"', True), ('"AES/ECB/PKCS5Padding"', True),
                                       ('"AES/GCM/NoPadding"', False)])
def test_java_cipher(algo, weak):
    code = ("import javax.crypto.Cipher;\nclass A {\n  Cipher c() throws Exception {\n"
            f"    return Cipher.getInstance({algo});\n  }}\n}}\n")
    found = {v.cwe_id for v in FrameScanner(language="java").scan(code, "A.java").vulnerabilities}
    assert ("CWE-327" in found) == weak


def test_a_malformed_file_is_an_error(tmp_path):
    p = tmp_path / "w.toml"
    p.write_text('hashes = ["MD5"]\nciphers = []\ncipher_modes = ["ECB"]\n[windows_alg_ids]\nCALG_MD5 = "MD5"\n')
    with pytest.raises(ValueError, match="non-empty"):
        load(p)


def test_an_alg_id_must_name_a_listed_algorithm(tmp_path):
    p = tmp_path / "w.toml"
    p.write_text('hashes = ["MD5"]\nciphers = ["DES"]\ncipher_modes = ["ECB"]\n[windows_alg_ids]\nCALG_RC5 = "RC5"\n')
    with pytest.raises(ValueError, match="RC5"):
        load(p)


_CRYPTOAPI = """#include <windows.h>
#include <wincrypt.h>

void f(HCRYPTPROV prov, HCRYPTHASH base)
{
    HCRYPTHASH hash;
    HCRYPTKEY key;
    %s
}
"""


@pytest.mark.parametrize("call,cwe", [
    ("CryptCreateHash(prov, CALG_MD5, 0, 0, &hash);", "CWE-328"),
    ("CryptCreateHash(prov, CALG_SHA1, 0, 0, &hash);", "CWE-328"),
    ("CryptDeriveKey(prov, CALG_RC4, base, 0, &key);", "CWE-327"),
    ("CryptGenKey(prov, CALG_DES, 0, &key);", "CWE-327"),
    ("CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash);", None),
    ("CryptDeriveKey(prov, CALG_AES_256, base, 0, &key);", None),
])
@pytest.mark.parametrize("lang", ["c", "cpp"])
def test_windows_cryptoapi_algorithm_ids(call, cwe, lang):
    r = FrameScanner(language=lang).scan(_CRYPTOAPI % call, "t." + lang)
    found = {v.cwe_id for v in r.vulnerabilities} & {"CWE-327", "CWE-328"}
    assert found == ({cwe} if cwe else set())


@pytest.mark.parametrize("lang", ["c", "cpp"])
def test_a_call_inside_a_condition_is_checked_too(lang):
    """`if (!CryptCreateHash(...))` and `if (!MD5(...))`: a call that is itself a finding is its own
    Call instruction even inside an expression."""
    body = ("if (!CryptCreateHash(prov, CALG_MD5, 0, 0, &hash))\n    {\n        return;\n    }\n"
            "    if (!MD5((const unsigned char *)\"x\", 1, (unsigned char *)&key))\n    {\n        return;\n    }")
    r = FrameScanner(language=lang).scan(_CRYPTOAPI % body, "t." + lang)
    assert {(v.cwe_id, v.line) for v in r.vulnerabilities if v.cwe_id == "CWE-328"} == {("CWE-328", 8), ("CWE-328", 12)}
