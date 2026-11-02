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

## Verifying against the provider

`frame scan --verify-secrets` and `frame history --verify` check each found credential with a read-only request to the provider's own API: GitHub, Slack, Stripe, OpenAI, Anthropic, SendGrid, Hugging Face, DigitalOcean and npm. A live credential becomes critical, a rejected one low, and one that cannot be checked keeps its severity. A credential is only ever sent to its own provider's documented endpoint. See [verifying secrets](usage.md#verifying-secrets) for the setup and the offline test.

A walkthrough with real output is in [examples/secrets](../examples/secrets/README.md).
