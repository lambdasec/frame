# Reproduction exemplars

Each directory is a small project that reaches a known vulnerability shape through
its own code, with a `case.json` giving the finding Frame reported and a driver
Frame confirmed. They are real, runnable reproductions: Frame drove the project to
the vulnerable call and a spy observed attacker-marked data arrive there.

| Case | Language | Class | Sink | Library |
|------|----------|-------|------|---------|
| `python-sca-pickle` | Python | insecure deserialization (CWE-502) | `pickle.loads` | real (stdlib) |
| `python-sca-yaml-load` | Python | deserialization (CWE-502) | `yaml.load` | real (PyYAML) |
| `python-taint-cmdi` | Python | command injection (CWE-78) | `os.system` | real (stdlib) |
| `python-taint-subprocess` | Python | command injection (CWE-78) | `subprocess.call(shell=True)` | real (stdlib) |
| `python-taint-sqli` | Python | SQL injection (CWE-89) | a DB cursor's `execute` | stand-in |
| `python-taint-pathtraversal` | Python | path traversal (CWE-22) | `open` | real (stdlib) |
| `python-taint-ssrf` | Python | SSRF (CWE-918) | `urllib.request.urlopen` | real (stdlib) |
| `js-taint-cmdi` | JavaScript | command injection (CWE-78) | `child_process.exec` | real (node core) |
| `js-taint-pathtraversal` | JavaScript | path traversal (CWE-22) | `fs.readFileSync` | real (node core) |
| `java-sca-deserialization` | Java | deserialization (CWE-502) | a library `parse` | real (JDK, Mockito) |

Most cases drive a genuine library sink (`pickle.loads`, real PyYAML `yaml.load`,
`os.system`, `subprocess.call`, `child_process.exec`); the stand-in cases use a small
local module that mirrors a real sink's shape (a DB cursor's `execute`; the Java case's
vulnerable library), so they stay self-contained. A case that needs a real library
declares it in `requires`, and the test skips when it is absent. The Java case needs a
JDK + Maven (Mockito construction-mocks the sink, a non-bootstrap library class); its
test skips where the toolchain is absent. A JDK bootstrap sink (`Runtime`/`ProcessBuilder`)
is not portably mockable this way and is left for the agent-based runner.

`case.json` fields: `language`, `cwe`, `advisory`, `vuln_function` (the sink's
canonical id), `call_site` (`file:line` where the project calls it), `source_var`
(the tainted variable), `driver` (the confirmed reproduction), and an optional `requires` (real libraries the case needs; the test skips if absent).

`tests/test_reproduction_exemplars.py` runs each case's driver through the spy
runner and asserts the marker reaches the sink *through the project* (a direct call
to the sink does not count). The runner is deterministic and needs no model; the
agent (`frame exploit --deps`) finds the driver in practice.

