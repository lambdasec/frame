# Hardcoded credentials by provider format

`make_demo.py` writes a small Python and JavaScript app into `demo/` with credentials in the places people commit them by mistake: passed straight to a client, inside a request header, as a keyword argument, plus a test file. The tokens are assembled when the script runs, so this repository never contains one, and none is real.

```console
$ python make_demo.py && frame scan demo
...
   Location: demo/billing.js:3:22
   Description: Hardcoded Stripe live secret or restricted key (Stripe format: stripe-live-key)
   Location: demo/checks.py:9:4  (test code)
   Description: Hardcoded password: 'admin_password' is assigned a literal value
   Location: demo/deploy.py:6:12
   Description: Hardcoded GitHub token (personal access, OAuth, user-to-server, server-to-server or refresh) (GitHub format: github-token)
   Location: demo/deploy.py:11:44
   Description: Hardcoded OpenAI API key (OpenAI format: openai-api-key)
   Location: demo/deploy.py:14:42
   Description: Hardcoded AWS access key ID (AWS format: aws-access-key-id)
Scanned 3 files: 5 findings (4 critical, 1 low)
```

None of these is in a variable whose name says "secret": `Github("...")`, a header dict, `aws_access_key_id=`, `Stripe("...")`. They are found by their format, in any string literal of any language Frame reads.

`demo/checks.py` is test code, and Frame knows it from the program, not the file name (it is not called `test_*`): it imports pytest and its `test_` function asserts. A test framework's import (pytest, unittest, JUnit, TestNG, Mockito, jest, vitest, mocha, gtest, Catch2...), a C# `[Fact]` / `[Test]` / `[TestMethod]`, a JUnit `@Test`, or callbacks passed to `describe` / `it` / `test` say the same in other languages. Findings there carry `context: "test"` (JSON and SARIF) and `(test code)` in the text. They are never dropped: a credential found by its variable's name, like this fixture password, drops to low, but a provider-format key in a test keeps its severity, since it may be real.

What is not reported, and why:

- `"AKIA" "IOSFODNN7EXAMPLE"` (`deploy.py:17`) is the example key from AWS's own documentation. Each format lists its provider's published examples (`ignore`).
- The rotated token in the comment on `deploy.py:19`. Literals come from the syntax tree, and a comment is not a literal.
- Stripe test keys (`sk_test_...`) and bare JWTs, which are mostly fixtures. Only formats with a fixed provider prefix and length are in the table.

## In the git history

A key "fixed" by deleting it is still in every clone. `--history` makes `demo/` a git repository: the files are committed, then `billing.js` is changed to read the Stripe key from the environment and committed again.

```console
$ python make_demo.py --history && frame history demo
4 credential(s) in the history (rotate each one: removing it from the code does not remove it from clones):
  Stripe Stripe live secret or restricted key: sk_l... (32 characters) added in 4996bdfefbcd billing.js:3 (not in the current tree, still in the history)
  GitHub GitHub token (personal access, OAuth, user-to-server, server-to-server or refresh): ghp_... (40 characters) added in 4996bdfefbcd deploy.py:6 (still in the current tree)
  OpenAI OpenAI API key: sk-p... (56 characters) added in 4996bdfefbcd deploy.py:11 (still in the current tree)
  AWS AWS access key ID: AKIA... (20 characters) added in 4996bdfefbcd deploy.py:14 (still in the current tree)
```

`frame scan` no longer reports the Stripe key, since the code does not have it; the history still does, so it must be rotated. The values are never printed: the first four characters, the length, and in `-f json` a SHA-256 fingerprint. The rotated GitHub token in the comment is the same credential as on line 6, so it is reported once. In history, comments count: a real key in a comment is as leaked as one in a string. `--range origin/main..HEAD` reads only what a branch adds, for a pre-merge check.

The formats are data, each with its provider's documentation: [`frame/sil/specs/data/secret-formats.toml`](../../frame/sil/specs/data/secret-formats.toml). It covers AWS, GitHub, GitLab, Slack, Google, Stripe, OpenAI, Anthropic, SendGrid, npm, PyPI, Hugging Face, DigitalOcean, Shopify and PEM private keys. Credential-named variables (`password = "..."`, `API_KEY = "..."`) are reported separately, by name, whatever the value's format. See [docs/coverage.md](../../docs/coverage.md#what-it-detects).
