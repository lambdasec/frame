# Malicious packages and informational advisories

Real OSV records (`https://api.osv.dev/v1/vulns/<id>`, fetched 2026-11-18), for
`tests/test_sca_malicious.py`:

- `MAL-2026-20101`: OpenSSF, the agent-framework 1.26.1 / 1.26.2 releases (PyPI), versions listed, no range
- `MAL-2026-3204`: OpenSSF, intercom-client 7.0.4 (npm)
- `GHSA-54pg-9963-v8vg`: GitHub, the same compromised intercom-client release, CWE-506, not aliased to the MAL record
- `GHSA-vv52-3mrp-455m`: GitHub, m-backdoor (npm), CWE-506, every version (`introduced: 0.0.0`, never closed)
- `RUSTSEC-2025-0056`: RustSec, adler is unmaintained (`informational: unmaintained`)
- `PYSEC-2026-151`: an ordinary flaw (wasmtime), which must carry no kind
