# An upgrade that breaks the code: Werkzeug 2 to 3

`app.py` uses `werkzeug.urls.url_parse` and `url_quote`, and `test_app.py` tests it. Werkzeug 2.2.3 has eight advisories, and the lowest version clear of all of them is 3.1.9, a major upgrade. Werkzeug 3 removed both functions. The output below is from real runs: the upgrade, the rollback and the adaptation (the adaptation with DeepSeek through mlx-optiq cloud).

```bash
cd examples/adapt-werkzeug
frame kb pull --advisories --source offline-advisories
python -m venv .venv && .venv/bin/pip install -q -r requirements.txt
```

## The plan

```console
$ frame deps --vulns --plan
8 known vulnerabilities:
...
Upgrade plan (1 package):
  werkzeug 2.2.3 -> 3.1.9 [major]: raise the project's requirement  [requirements.txt; fixes 8]

Edits (dry run; --apply writes them):
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,2 +1,2 @@
-werkzeug==2.2.3
+werkzeug==3.1.9
 pytest
```

## Applying it, with the tests as the judge

```console
$ frame deps --vulns --plan --apply --verify ".venv/bin/pip install -q -r requirements.txt && .venv/bin/python -m pytest -q"
After applying: 0 fixed, 8 remaining
Verify: the command passed before and fails after the upgrade; every edit was rolled back:
ImportError while importing test module '.../test_app.py'.
```

The tests passed on 2.2.3 and fail on 3.1.9, so `requirements.txt` is back to `werkzeug==2.2.3`.

## Letting a model adapt the code

```bash
export FRAME_LLM_BASE_URL=https://cloud.mlx-optiq.com/api/v1 FRAME_LLM_MODEL=deepseek-v4.1-flash FRAME_LLM_API_KEY=...
```

```console
$ frame deps --vulns --plan --apply --verify ".venv/bin/pip install -q -r requirements.txt && .venv/bin/python -m pytest -q" --adapt
After applying: 8 fixed, 0 remaining
Adapted: the code was changed for the new versions in 1 round(s) (Werkzeug 3 removed url_parse and url_quote from werkzeug.urls; use the standard urllib.parse equivalents.); the command passes and a re-scan of the edited files finds nothing new:
--- a/app.py
+++ b/app.py
-from werkzeug.urls import url_parse, url_quote
+from urllib.parse import quote, urlsplit
 
 
 def host_of(url):
-    return url_parse(url).host
+    return urlsplit(url).hostname
 
 
 def quoted(path):
-    return url_quote(path)
+    return quote(path)
```

The model saw the failing output, the file that imports Werkzeug, and Werkzeug's changelog between 2.2.3 and 3.1.9 (including 2.3.0's "Deprecate the `werkzeug.urls` module"). Another model, or another run, may write different code. What is kept is decided by your command passing and by a Frame re-scan of every edited file finding nothing new; anything else is rolled back, upgrade included. It never edits `requirements.txt` or another manifest.

See [docs/dependencies.md](../../docs/dependencies.md#when-an-upgrade-breaks-your-code---adapt).
