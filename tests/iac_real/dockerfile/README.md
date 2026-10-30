# Ground truth for the Dockerfile parser

BuildKit's own parser (`github.com/moby/buildkit/frontend/dockerfile/parser`, pinned in `go.mod`)
on every Dockerfile in `tests/fixtures/iac/dockerfile`: one JSON line per file with each
instruction's command, arguments, flags, JSON form, lines, heredocs and ONBUILD instruction, or
the error BuildKit stops with. `tests/test_iac_dockerfile.py` compares `frame/iac/dockerfile_parser.py`
with it file by file.

```bash
(cd tests/iac_real/dockerfile && GOTOOLCHAIN=auto go build -o /tmp/dfdump .)
cd tests/fixtures/iac/dockerfile
find . -type f ! -name LICENSE ! -name '*.py' ! -name '*.md' ! -name '*.jsonl' | sed 's|^\./||' | sort \
  | xargs /tmp/dfdump > expected.jsonl
```

`generated/` holds Dockerfiles made by `generated/generate.py` (seed 99) from the parts that
trip parsers: escape directives, continuations with comments and blank lines inside, heredocs
(quoted, `<<-`, numbered, unterminated), JSON and shell forms, quoted flags, ONBUILD, a BOM,
CRLF. During development the same generator ran 16,000 files through both parsers with no
difference.
