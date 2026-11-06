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
| `python-taint-xss` | Python | reflected XSS (CWE-79) | an HTML-marking sink (`mark_safe`) | stand-in |
| `js-taint-cmdi` | JavaScript | command injection (CWE-78) | `child_process.exec` | real (node core) |
| `js-taint-pathtraversal` | JavaScript | path traversal (CWE-22) | `fs.readFileSync` | real (node core) |
| `js-sca-yaml-load` | JavaScript | deserialization (CWE-502) | `js-yaml.load` | vendored dep |
| `java-sca-deserialization` | Java | deserialization (CWE-502) | an injected store interface | real (JDK) |
| `csharp-taint-cmdi` | C# | command injection (CWE-78) | an injected shell interface | real (.NET SDK) |

Most cases drive a genuine library sink (`pickle.loads`, real PyYAML `yaml.load`,
`os.system`, `subprocess.call`, `child_process.exec`); the stand-in cases use a small
local module that mirrors a real sink's shape (a DB cursor's `execute`; the Java and C# cases'
injected sink interface), so they stay self-contained. A case that needs a real library
declares it in `requires`, and the test skips when it is absent. The Java case needs a JDK
(a `java.lang.reflect.Proxy` spies the injected sink interface, no Maven or Mockito); the
C# case needs the .NET SDK (xUnit + Moq spy the interface); each test skips where its
toolchain is absent. A non-interface or JDK-bootstrap sink is left for the agent-based runner.

`case.json` fields: `language`, `cwe`, `advisory`, `vuln_function` (the sink's
canonical id), `call_site` (`file:line` where the project calls it), `source_var`
(the tainted variable), `driver` (the confirmed reproduction), and an optional `requires` (real libraries the case needs; the test skips if absent).

The `js-sca-yaml-load` case vendors a minimal `node_modules/js-yaml` so the
dependency sink is reached by a bare specifier (as a real install would), with no
`npm install` step; the `python-taint-xss` sink is a small local HTML-marking module
mirroring `mark_safe`/`Markup`.

A case with a `fixed/` subdirectory also carries a repaired copy of its own sources.
The **fix-loop** test (`test_fix_stops_the_reproduction`) runs the SAME confirmed
driver against the vulnerable tree and the `fixed/` tree, and requires the
reproduction to trigger against the former and NOT the latter: the proof of the
vulnerability has become a proof of the fix. Only a fix that removes the flow to the
sink flips a reachability reproduction (input validation that rejects the attacker
value, a safe-API swap, a dropped call); a sanitize-in-place or a dependency upgrade
that keeps the call is certified by a re-scan, not by this test. The same check is
available from the CLI as `frame exploit --deps --check-fixed DIR`.

`tests/test_reproduction_exemplars.py` runs each case's driver through the spy
runner and asserts the marker reaches the sink *through the project* (a direct call
to the sink does not count). The runner is deterministic and needs no model; the
agent (`frame exploit --deps`) finds the driver in practice.

