# Secrets: hardcoded credentials and git history

Frame finds credentials in source, in any of the five languages, and in a repository's whole git history, and can check a found credential against its provider to tell a real leak from a test fixture.

## In the code

Hardcoded secrets are found two ways.

- **By name**: a credential-named variable (`password`, `API_KEY`, `client_secret`) bound to a literal, reported unless the value is plainly not a secret (a field name, a filename, a placeholder). The name rules and value shapes are data (`frame/sil/specs/data/secret-names.toml`).
- **By format**: any string literal containing a provider's credential format, whatever holds it (an argument, a dict value, a header). That covers AWS, GitHub, GitLab, Slack, Google, Stripe (live keys), OpenAI, Anthropic, SendGrid, npm, PyPI, Hugging Face, DigitalOcean, Shopify and PEM private keys. The formats are data (`frame/sil/specs/data/secret-formats.toml`), each with the provider's documentation.

Literals come from the syntax tree, so a token in a comment is not reported, and the providers' own published example keys are ignored. A C or C++ string macro (`#define PASSWORD "..."`) is a binding like an assignment.

Test code is told apart by its program, not its file name (`frame/sil/test_code.py`): a test framework's import, a `@Test` or C# test attribute, an asserting pytest `test_*`, or a `describe` / `it` / `test` callback. A credential found only by its variable's name drops to low there (a test's password is a fixture); one in a provider's format keeps its severity, since it may be real.

## In the git history

A credential removed from the code is still in every clone's history. `frame history [repo]` reads every line the git history ever added, in any file, comments included, and reports each credential once at the commit that added it, saying whether the current tree still has it (rotate it either way). Values are never printed: the output carries the first four characters, the length, and a SHA-256 fingerprint. On a test repository it finds every credential gitleaks finds, at the same commit, file and line, and also Hugging Face and Anthropic keys gitleaks 8.21 has no rule for.

`--range REV` scans one branch or range (`origin/main..HEAD`). Exit 1 when any credential is found, 2 when the directory is not a git repository.

## Verifying with the provider

A found credential may be live, revoked, or never real. `frame scan --verify-secrets` and `frame history --verify` ask each one's provider, the way Semgrep Secrets' validators and Endor Labs' secret validation do. It is off by default: it sends each found credential to its provider, which the provider sees as a use of that credential.

```console
$ frame scan demo --verify-secrets
1. [LOW] 🔵 hardcoded_secret
   Location: demo/deploy.py:6:12
   Description: Hardcoded GitHub token (...) (GitHub format: github-token)
   Verified: rejected by api.github.com (revoked or expired)
```

What is sent, and where: one read-only request per distinct credential, to the provider's own API, with the credential in the header the provider documents. Nothing else leaves the machine (no file name, no code, nothing to Frame's authors), and the run makes no other network request. The checks are data, each with the provider's documentation (`[format.verify]` in [`frame/sil/specs/data/secret-formats.toml`](../frame/sil/specs/data/secret-formats.toml)); the loader refuses a check whose URL is not a fixed `https://` address, so a credential can only go to that provider's host.

| Format | Request | Valid | Invalid |
|---|---|---|---|
| GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`) | `GET https://api.github.com/user` | 200 | 401 |
| Slack tokens (`xox?-`) | `POST https://slack.com/api/auth.test` | `"ok": true` | `invalid_auth`, `not_authed`, `account_inactive`, `token_revoked`, `token_expired` |
| Stripe live keys | `GET https://api.stripe.com/v1/balance` | 200 | 401 |
| OpenAI | `GET https://api.openai.com/v1/models` | 200 | 401 |
| Anthropic | `GET https://api.anthropic.com/v1/models` | 200 | 401 |
| SendGrid | `GET https://api.sendgrid.com/v3/scopes` | 200 | 401 |
| Hugging Face | `GET https://huggingface.co/api/whoami-v2` | 200 | 401 |
| DigitalOcean | `GET https://api.digitalocean.com/v2/account` | 200 | 401 |
| npm | `GET https://registry.npmjs.org/-/whoami` | 200 | 401 |

Not checked, and why: an AWS access key ID (the check needs its secret key, which is rarely beside it), a GitLab token (it may belong to a self-managed instance, so gitlab.com rejecting it says nothing), a Slack webhook (the only check is posting to it), and Google API keys, PyPI and Shopify tokens and private keys (no side-effect-free check).

Each finding gets `validity` (JSON, SARIF properties, a `Verified:` line in the text; in `frame history`, after the location):

- `valid`: the provider accepted it, so anyone with the code can use it now. Severity becomes critical. Rotate it first, then remove it.
- `invalid`: the provider rejected it (revoked, expired, or a fixture). Severity becomes low: it is still in the code and the history.
- `unverified`: no check for the format, or no clear answer (a timeout, a rate limit, a 403 from a key that exists but may not read that endpoint). Severity is unchanged.

Each credential is asked about once per run, however many places hold it. Behind a proxy, the standard `HTTPS_PROXY` variable applies.

### Trying it, and how it is tested

To see both answers on your own machine with a credential you control:

```bash
mkdir -p /tmp/verify-demo
printf 'GITHUB_TOKEN = "%s"\n' "$(gh auth token)" > /tmp/verify-demo/config.py   # or a new fine-grained PAT with no permissions
frame scan /tmp/verify-demo --verify-secrets      # Verified: verified valid at api.github.com: it works now, rotate it
# revoke the token (github.com/settings/tokens), run again: Verified: rejected by api.github.com (revoked or expired)
rm -r /tmp/verify-demo
```

The secrets example's tokens are fake, so all three checked ones come back rejected ([examples/secrets](../examples/secrets/README.md#checking-them-with-the-providers)).

Frame's own tests (`tests/test_secret_verify.py`) need no credentials:

- Offline, on every run: the provider is a real HTTP server on localhost, which records what it was sent. The tests check that the credential goes in the documented header and nowhere else, that each answer means what the table says (Slack's `ratelimited` is unverified, not invalid), that each credential is asked once, and that nothing is sent without the flag.
- `FRAME_SECRETS_LIVE=1`: a well-formed but fake token of every checked format is sent to the real provider, which must reject it. This proves each endpoint, method and header against the real API. CI runs it in the `sca-real` job.
- `FRAME_VERIFY_GITHUB_TOKEN=$(gh auth token)`: a real token must come back valid (run locally; the Actions token is an installation token that may not read `/user`).

```bash
python -m pytest tests/test_secret_verify.py                                    # offline
FRAME_SECRETS_LIVE=1 python -m pytest tests/test_secret_verify.py -k live       # against the providers
FRAME_VERIFY_GITHUB_TOKEN=$(gh auth token) python -m pytest tests/test_secret_verify.py -k real
```

To add a check for a format: a `[format.verify]` table with `method`, a fixed `url`, `headers` carrying `{token}`, the `valid` and `invalid` status codes (or `valid_json` / `invalid_json` for an API that answers 200 either way, as Slack's does), and the provider's documentation as `reference`; add a fake token of the format to `FAKE` in the test, and run the live test once.

A walkthrough with real output is in [examples/secrets](../examples/secrets/README.md).
