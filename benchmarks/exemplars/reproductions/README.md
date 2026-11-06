# Reproduction exemplars

Each directory is a small project that reaches a known vulnerability shape through
its own code, with a `case.json` giving the finding Frame reported and a driver
Frame confirmed. They are real, runnable reproductions: Frame drove the project to
the vulnerable call and a spy observed attacker-marked data arrive there.

| Case | Language | Class | Sink |
|------|----------|-------|------|
| `python-sca-yaml-load` | Python | SCA deserialization (CWE-502) | `yaml.load` |
| `python-taint-cmdi` | Python | command injection (CWE-78) | `os.system` |
| `python-taint-sqli` | Python | SQL injection (CWE-89) | a DB cursor's `execute` |
| `js-taint-cmdi` | JavaScript | command injection (CWE-78) | `child_process.exec` |

`case.json` fields: `language`, `cwe`, `advisory`, `vuln_function` (the sink's
canonical id), `call_site` (`file:line` where the project calls it), `source_var`
(the tainted variable), and `driver` (the confirmed reproduction).

`tests/test_reproduction_exemplars.py` runs each case's driver through the spy
runner and asserts the marker reaches the sink *through the project* (a direct call
to the sink does not count). The runner is deterministic and needs no model; the
agent (`frame exploit --deps`) finds the driver in practice.

The libraries here are small stand-ins that mirror the real sinks (PyYAML's
`yaml.load`, `os.system`, `child_process.exec`, a DB cursor), so the cases are
self-contained and need nothing installed.
