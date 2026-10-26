# Framework fixtures

Small, realistic applications -- one vulnerable, one done correctly -- for each
framework Frame has a pack for. `tests/e2e/test_framework_packs.py` scans every
one through the real `frame` CLI and checks the result, so this directory is both
the regression suite for `frame/sil/packs/data` and the proof of what each pack
covers.

```
<language>/<framework>/
    framework.toml          language, packs that must apply, requires_pack
    vulnerable/...          the app; every vulnerable sink line carries a marker
    safe/...                the same app with the flaw fixed (parameterised query,
                            argument list, allow-list, escaping, ...)
```

A marker is a comment on the sink line the scanner reports:

```python
conn.execute("SELECT * FROM u WHERE id = '" + uid + "'")   # frame-expect: CWE-89
```
(`//` in Java/JS/C#/C). Several CWEs on one line: `frame-expect: CWE-89, CWE-79`.

What the test enforces:

* every marker is reported with that CWE;
* no finding of those CWEs appears in the vulnerable app without a marker;
* the safe twin has none of them;
* the packs named in `framework.toml` (`packs = ["python/tornado"]`) applied;
* with `requires_pack = true` (the default) a scan with `--no-packs` misses at least
  one marker -- the pack must earn its place. Set `requires_pack = false` for a
  fixture that only guards coverage the built-in specs already had.

Write the app as a user would: routes, a helper module, a model/repository layer.
Put the flaw where real code puts it, and make the safe twin differ only in the fix.
