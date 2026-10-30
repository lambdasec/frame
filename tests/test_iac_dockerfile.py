"""Dockerfiles (frame/iac/dockerfile_parser.py, dockerfile.py, packs/data/dockerfile/docker.toml).

The parser is checked against BuildKit's own: `expected.jsonl` is BuildKit's parse of every
fixture (its parser test files, real Dockerfiles, and generated ones built from the constructs
that trip parsers), recorded by tests/iac_real/dockerfile. Each must parse to the same
instructions, arguments, flags, lines and heredocs, or fail where BuildKit fails."""

import json
from pathlib import Path

import pytest

from frame.iac.dockerfile_parser import DockerfileError, parse
from frame.iac.scan import scan

FIXTURES = Path(__file__).parent / "fixtures" / "iac" / "dockerfile"
EXPECTED = [json.loads(line) for line in (FIXTURES / "expected.jsonl").read_text().splitlines()]


def _ours(path: Path):
    text = path.read_bytes().decode("utf-8", errors="surrogateescape")
    try:
        instructions, escape = parse(text)
    except DockerfileError as e:
        return {"error": str(e)}

    def node(i, top=True):
        out = {"cmd": i.cmd, "args": i.args, "flags": i.flags, "json": i.json,
               "start": i.start_line if top else 0, "end": i.end_line if top else 0,
               "heredocs": [{"name": h.name, "content": h.content, "chomp": h.chomp, "expand": h.expand, "fd": h.fd}
                            for h in i.heredocs]}
        if i.sub is not None:
            out["sub"] = node(i.sub, False)
        return out
    return {"escape": escape, "nodes": [node(i) for i in instructions]}


def test_the_fixture_set_covers_what_it_should():
    files = [e["file"] for e in EXPECTED]
    assert len(files) == 345
    assert sum(f.startswith("generated/") for f in files) == 300
    assert sum("error" in e for e in EXPECTED) == 98                # BuildKit refuses these


@pytest.mark.parametrize("expected", EXPECTED, ids=[e["file"] for e in EXPECTED])
def test_every_dockerfile_parses_as_buildkit_parses_it(expected):
    ours = _ours(FIXTURES / expected["file"])
    if "error" in expected:
        assert "error" in ours, ours
    else:
        assert ours == {"escape": expected["escape"], "nodes": expected["nodes"]}


@pytest.mark.parametrize("text, cmd, args", [
    ("FROM a\nRUN echo \\\n  # dropped\n\n  done\n", "RUN", ["echo   done"]),
    ("# escape=`\nFROM a\nRUN echo `\n  b\n", "RUN", ["echo   b"]),
    ("FROM a\nENV k v w\n", "ENV", ["k", "v w", ""]),
    ('FROM a\nENV k="v w" x=y\n', "ENV", ["k", '"v w"', "=", "x", "y", "="]),
    ('FROM a\nCMD ["a", "b"]\n', "CMD", ["a", "b"]),
    ('FROM a\nCMD ["a", b]\n', "CMD", ['["a", b]']),
    ("FROM a\nCOPY --chown='a b' x y\n", "COPY", ["x", "y"]),
])
def test_buildkit_quirks(text, cmd, args):
    ins = [i for i in parse(text)[0] if i.cmd == cmd][0]
    assert ins.args == args


def test_heredocs_and_the_nested_expansion_quirk():
    ins = parse("FROM a\nRUN <<EOF\necho hi\nEOF\nRUN x << ${X:-d}\n")[0]
    assert [h.name for h in ins[1].heredocs] == ["EOF"] and ins[1].heredocs[0].content == "echo hi\n"
    assert ins[2].heredocs == []           # BuildKit's lexer drops the `<<` before a ${X:-..}
    with pytest.raises(DockerfileError, match="unterminated heredoc"):
        parse("FROM a\nRUN <<EOF\necho\n")


# --- policies ----------------------------------------------------------------------------

def _run(tmp_path, text, name="Dockerfile"):
    (tmp_path / name).write_text(text)
    return scan(tmp_path)


def _rules(run):
    return {(f.rule, f.line) for f in run.findings}


@pytest.mark.parametrize("text, line", [
    ("FROM debian:12\nUSER root\n", 2),
    ("FROM debian:12\nUSER 0:0\n", 2),
    ("FROM debian:12 AS base\nUSER root\nFROM base\nRUN true\n", 3),     # inherited from the stage
    ("FROM golang:1.23 AS build\nUSER app\nFROM scratch\nCOPY --from=build /x /x\n", 3),
])
def test_an_image_that_runs_as_root(tmp_path, text, line):
    assert ("docker-root-user", line) in _rules(_run(tmp_path, text))


def test_an_image_with_a_user_does_not(tmp_path):
    run = _run(tmp_path, "FROM debian:12\nUSER root\nRUN apt-get update\nUSER 10001\n")
    assert not {r for r, _ in _rules(run)} & {"docker-root-user", "docker-user-not-set"}


def test_a_base_images_own_user_is_not_known(tmp_path):
    run = _run(tmp_path, "FROM python:3.13-slim\nRUN pip install x\n")
    assert ("docker-user-not-set", 1) in _rules(run)
    assert "docker-root-user" not in {r for r, _ in _rules(run)}
    assert [u["rule"] for u in run.undecided] == ["docker-root-user"]


def test_a_user_from_a_build_argument_is_not_known(tmp_path):
    run = _run(tmp_path, "FROM debian:12\nARG UID\nUSER ${UID}\n")
    assert not _rules(run) and [u["rule"] for u in run.undecided] == ["docker-root-user"]


def test_remote_downloads_need_a_checksum(tmp_path):
    text = ("FROM debian:12\nADD https://example.com/tool.tgz /opt/\n"
            "ADD --checksum=sha256:24454f830cdb571e2c4ad15481119c43b3cafd48dd869a9b2945d1036d1dc68d "
            "https://example.com/ok.tgz /opt/\nADD ./local.tgz /opt/\nADD ${URL} /opt/\nUSER 1000\n")
    run = _run(tmp_path, text)
    assert {(r, ln) for r, ln in _rules(run) if r.startswith("docker-add")} == {("docker-add-unverified-download", 2)}


@pytest.mark.parametrize("ref, floating", [
    ("ubuntu", True), ("ubuntu:latest", True), ("registry:5000/team/app", True),
    ("ubuntu:24.04", False), ("ubuntu@sha256:" + "a" * 64, False), ("registry:5000/team/app:1.2", False),
])
def test_floating_base_images(tmp_path, ref, floating):
    run = _run(tmp_path, f"FROM {ref}\nUSER 1000\n")
    assert (("docker-floating-base-image", 1) in _rules(run)) == floating


def test_stage_references_scratch_and_build_arguments_are_not_base_images(tmp_path):
    run = _run(tmp_path, "ARG BASE=ubuntu\nFROM ${BASE} AS one\nFROM one\nFROM scratch\nUSER 1000\n")
    assert "docker-floating-base-image" not in {r for r, _ in _rules(run)}
    assert [u["resource"] for u in run.undecided if u["rule"] == "docker-floating-base-image"] == [
        "Dockerfile stage one"]


def test_a_provider_credential_in_env_arg_or_label(tmp_path):
    token = "ghp_" + "Ab3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dF3hJ5"          # built here: never committed whole
    run = _run(tmp_path, f"ARG GH={token}\nFROM debian:12\nENV TOKEN={token}\nLABEL x=1\nUSER 1000\n")
    assert {ln for r, ln in _rules(run) if r == "docker-credential-in-image"} == {3}
    run = _run(tmp_path, f"ARG GH={token}\nFROM debian:12\nUSER 1000\n")
    assert {ln for r, ln in _rules(run) if r == "docker-credential-in-image"} == {1}


def test_unparsable_dockerfiles_warn_and_suppressions_apply(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "Dockerfile").write_text("FROM a\nRUN <<EOF\nnever closed\n")
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "Dockerfile").write_text("FROM debian:12\n# frame: ignore[docker-root-user] init needs root\nUSER root\n")
    run = scan(tmp_path)
    assert run.warnings == ["a/Dockerfile: not a valid Dockerfile (line 2: unterminated heredoc)"]
    assert [f.rule for f in run.suppressed] == ["docker-root-user"] and not run.findings


def test_dockerfile_names(tmp_path):
    for name in ("Dockerfile", "Containerfile", "api.Dockerfile", "Dockerfile.prod", "notes.txt"):
        (tmp_path / name).write_text("FROM ubuntu\nUSER 1000\n")
    run = scan(tmp_path)
    assert run.files["dockerfile"] == ["Containerfile", "Dockerfile", "Dockerfile.prod", "api.Dockerfile"]
