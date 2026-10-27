# Quickstart

A three-file Flask app with two cross-file flaws, used in the main README. Run it:

```bash
frame scan benchmarks/exemplars/quickstart --root benchmarks/exemplars/quickstart
```

| Finding | Where it is reported | Where the data came from |
|---|---|---|
| SQL injection (CWE-89) | `shop/services/orders.py:8` | `request.args["customer"]` in `shop/app.py:11` |
| Command injection (CWE-78) | `shop/services/orders.py:13` | `request.args["format"]` in `shop/app.py:17` |

Fix them and re-scan: a placeholder (`cur.execute("... WHERE customer = ?", (name,))`) and an argument
list (`subprocess.run(["export-orders", "--format", fmt])`) clear both. `tests/e2e/test_quickstart_e2e.py`
runs this scan, applies those two fixes to a copy, and checks that the findings disappear.
