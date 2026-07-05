"""Weak-hash detection must honor Python's `usedforsecurity=False`.

`hashlib.md5(x, usedforsecurity=False)` (Python 3.9+) documents that the digest is
NOT used for security. Bandit's B324 treats it as safe, and so should Frame -- it is
a false positive to flag it as CWE-328. Plain `hashlib.md5(x)` must still be flagged.
"""

from frame.sil import FrameScanner


def _weak_hash_flagged(tmp_path, src: str) -> bool:
    f = tmp_path / "h.py"
    f.write_text(src)
    r = FrameScanner(language="python", verify=False).scan_file(str(f))
    return any(v.type.value == "weak_hash" for v in r.vulnerabilities)


def test_md5_plain_is_flagged(tmp_path):
    assert _weak_hash_flagged(
        tmp_path, "import hashlib\ndef f(x): return hashlib.md5(x).hexdigest()\n")


def test_md5_usedforsecurity_false_not_flagged(tmp_path):
    assert not _weak_hash_flagged(
        tmp_path,
        "import hashlib\ndef f(x): return hashlib.md5(x, usedforsecurity=False).hexdigest()\n")


def test_sha1_usedforsecurity_false_not_flagged(tmp_path):
    assert not _weak_hash_flagged(
        tmp_path,
        "import hashlib\ndef f(x): return hashlib.sha1(x, usedforsecurity=False).hexdigest()\n")


def test_md5_usedforsecurity_false_with_concat_arg_not_flagged(tmp_path):
    # The reported openevolve pattern: a concatenated first argument.
    assert not _weak_hash_flagged(
        tmp_path,
        'import hashlib\ndef f(seed): return hashlib.md5(seed + b"llm", usedforsecurity=False).hexdigest()\n')


def test_md5_usedforsecurity_true_still_flagged(tmp_path):
    # Explicitly security-relevant -> still a weak-hash finding.
    assert _weak_hash_flagged(
        tmp_path,
        "import hashlib\ndef f(x): return hashlib.md5(x, usedforsecurity=True).hexdigest()\n")
