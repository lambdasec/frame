"""Provider credential formats (specs/data/secret-formats.toml): a string literal containing one is
a hardcoded credential whatever holds it. Every sample here is built at run time by
concatenation, so this file holds no token-shaped string (GitHub push protection, and our own
scanner, would rightly object)."""

import pytest

from frame.sil.scanner import FrameScanner
from frame.sil.secret_formats import SecretFormatError, find, formats, load


def j(*parts):
    return "".join(parts)


ALNUM = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6"
SAMPLES = {
    "aws-access-key-id": j("AK", "IA", "Z7K3M9Q2W8E4R6T1"),
    "github-token": j("gh", "p_", ALNUM[:36]),
    "github-fine-grained-pat": j("github", "_pat_", (ALNUM + "_" + ALNUM)[:82]),
    "gitlab-pat": j("gl", "pat-", ALNUM[:20]),
    "slack-token": j("xo", "xb-", "12345678901", "-", "abcdefghijklmnop"),
    "slack-webhook": j("https://hooks.", "slack.com/services/", "T01ABCDEFGH/B01ABCDEFGH/", ALNUM[:24]),
    "google-api-key": j("AI", "za", ALNUM[:35]),
    "stripe-live-key": j("sk", "_live_", ALNUM[:24]),
    "openai-api-key": j("sk-", "proj-", ALNUM[:48]),
    "anthropic-api-key": j("sk-", "ant-", "api03-", (ALNUM * 2)[:90]),
    "sendgrid-api-key": j("SG", ".", ALNUM[:22], ".", (ALNUM + ALNUM)[:43]),
    "npm-token": j("np", "m_", ALNUM[:36]),
    "pypi-token": j("pypi-", "AgEIcHlwaS5vcmc", (ALNUM * 2)[:60]),
    "huggingface-token": j("h", "f_", "abcdefghijklmnopqrstuvwxyzABCDEFGH"),
    "digitalocean-token": j("do", "p_v1_", "0123456789abcdef" * 4),
    "shopify-token": j("shp", "at_", "0123456789abcdef" * 2),
    "private-key": j("-----BEGIN ", "RSA PRIVATE KEY-----\n", "MIIEowIBAAKCAQEA", ALNUM, "\n-----END RSA PRIVATE KEY-----"),
}


def test_every_format_has_a_sample_and_each_sample_is_its_own_format():
    assert {f.id for f in formats()} == set(SAMPLES)
    for fid, sample in SAMPLES.items():
        hit = find(sample)
        assert hit is not None and hit[0].id == fid, (fid, hit and hit[0].id)


@pytest.mark.parametrize("fid", sorted(set(SAMPLES) - {"private-key", "slack-webhook"}))
def test_a_token_glued_to_a_longer_identifier_is_not_one(fid):
    hit = find("x" + SAMPLES[fid])                                    # nothing on the left
    assert hit is None or hit[0].id != fid


@pytest.mark.parametrize("fid", ["aws-access-key-id", "google-api-key", "npm-token", "huggingface-token",
                                 "digitalocean-token", "shopify-token", "github-fine-grained-pat"])
def test_a_fixed_length_token_with_more_characters_is_not_one(fid):
    hit = find(SAMPLES[fid] + "Z9")                                   # nor on the right, at a fixed length
    assert hit is None or hit[0].id != fid


def test_documented_examples_and_test_keys_are_not_credentials():
    assert find(j("AKIA", "IOSFODNN7", "EXAMPLE")) is None             # AWS's own documentation example
    assert find(j("sk", "_test_", ALNUM[:24])) is None                   # Stripe test mode
    assert find("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmno") is None   # a bare JWT


def test_the_table_is_loaded_strictly(tmp_path):
    bad = tmp_path / "f.toml"
    bad.write_text('[[format]]\nid = "x"\nprovider = "p"\npattern = "("\ndescription = "d"\nreference = "r"\n')
    with pytest.raises(SecretFormatError, match="compile"):
        load(bad)
    bad.write_text('[[format]]\nid = "x"\nprovider = "p"\npattern = "a"\ndescription = "d"\nreference = "r"\nweird = 1\n')
    with pytest.raises(SecretFormatError, match="unknown"):
        load(bad)


def lines(code, language, name):
    r = FrameScanner(language=language).scan(code, name)
    return {v.line for v in r.vulnerabilities if v.cwe_id == "CWE-798"}


@pytest.mark.parametrize("language,name,code,expected", [
    ("python", "a.py", 'from github import Github\n\n\n\n\n\ng = Github("{gh}")\n', {7}),
    ("python", "b.py", 'import requests\n\n\n\n\n\nh = {{"Authorization": "Bearer {gh}"}}\n', {7}),
    ("javascript", "c.js", "const x = 1;\n\n\n\n\n\nfetch(u, {{ headers: {{ Authorization: `token {gh}` }} }});\n", {7}),
    ("java", "D.java", 'class D {{\n\n\n\n\n\n  String t = "{gh}";\n}}\n', {7}),
    ("csharp", "E.cs", 'class E {{\n\n\n\n\n\n  string t = "{gh}";\n}}\n', {7}),
    ("c", "f.c", 'int f(void) {{\n\n\n\n\n\n  return auth("{gh}");\n}}\n', {7}),
])
def test_a_token_in_any_literal_of_any_language(language, name, code, expected):
    assert lines(code.format(gh=SAMPLES["github-token"]), language, name) == expected


def test_a_comment_is_not_a_literal():
    code = f"# old token {SAMPLES['github-token']} was rotated\nx = 1\n"
    assert lines(code, "python", "g.py") == set()
