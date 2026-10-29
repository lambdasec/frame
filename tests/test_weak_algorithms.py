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
    p.write_text('hashes = ["MD5"]\nciphers = []\ncipher_modes = ["ECB"]\n')
    with pytest.raises(ValueError, match="non-empty"):
        load(p)
