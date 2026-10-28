# Hardcoded credentials by provider format

`make_demo.py` writes a small Python and JavaScript app into `demo/` with credentials in the places people commit them by mistake: passed straight to a client, inside a request header, as a keyword argument. The tokens are assembled when the script runs, so this repository never contains one, and none is real.

```console
$ python make_demo.py && frame scan demo
...
   Location: demo/billing.js:3:22
   Description: Hardcoded Stripe live secret or restricted key (Stripe format: stripe-live-key)
   Location: demo/deploy.py:6:12
   Description: Hardcoded GitHub token (personal access, OAuth, user-to-server, server-to-server or refresh) (GitHub format: github-token)
   Location: demo/deploy.py:11:44
   Description: Hardcoded OpenAI API key (OpenAI format: openai-api-key)
   Location: demo/deploy.py:14:42
   Description: Hardcoded AWS access key ID (AWS format: aws-access-key-id)
Scanned 2 files: 4 findings (4 critical)
```

None of these is in a variable whose name says "secret": `Github("...")`, a header dict, `aws_access_key_id=`, `Stripe("...")`. They are found by their format, in any string literal of any language Frame reads.

What is not reported, and why:

- `"AKIA" "IOSFODNN7EXAMPLE"` (`deploy.py:17`) is the example key from AWS's own documentation. Each format lists its provider's published examples (`ignore`).
- The rotated token in the comment on `deploy.py:19`. Literals come from the syntax tree, and a comment is not a literal.
- Stripe test keys (`sk_test_...`) and bare JWTs, which are mostly fixtures. Only formats with a fixed provider prefix and length are in the table.

The formats are data, each with its provider's documentation: [`frame/sil/specs/data/secret-formats.toml`](../../frame/sil/specs/data/secret-formats.toml). It covers AWS, GitHub, GitLab, Slack, Google, Stripe, OpenAI, Anthropic, SendGrid, npm, PyPI, Hugging Face, DigitalOcean, Shopify and PEM private keys. Credential-named variables (`password = "..."`, `API_KEY = "..."`) are reported separately, by name, whatever the value's format. See [docs/coverage.md](../../docs/coverage.md#what-it-detects).
