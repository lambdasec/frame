from app import host_of, quoted


def test_host():
    assert host_of("https://example.com:8443/a?b=1") == "example.com"


def test_quote():
    assert quoted("a b/c") == "a%20b/c"
