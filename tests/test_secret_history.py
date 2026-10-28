"""`frame history`: provider credentials anywhere in a repository's git history
(`frame/sil/secret_history.py`). The repository is built at run time with generated tokens of
every format; live (FRAME_SCA_REAL=1), gitleaks scans the same repository and every credential
it finds is reported by Frame at the same first commit, file and line."""

import json
import os
import random
import shutil
import string
import subprocess
import sys
from pathlib import Path

import pytest

from frame.sil.secret_history import scan_history

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
ROOT = Path(__file__).resolve().parents[1]


def make_repo(repo: Path, seed: int = 1) -> dict:
    """A repository whose history holds provider-format credentials, built at run time (never
    a contiguous token in Frame's own tree)."""
    repo.mkdir(parents=True, exist_ok=True)
    rnd = random.Random(seed)
    def s(alphabet, n): return "".join(rnd.choice(alphabet) for _ in range(n))
    A, U, D, L = string.ascii_letters + string.digits, string.ascii_uppercase + string.digits, string.digits, string.ascii_letters
    tok = {
        "aws": "AK" + "IA" + s(U, 16),
        "github": "gh" + "p_" + s(A, 36),
        "gitlab": "gl" + "pat-" + s(A, 20),
        "slack": "xo" + "xb-" + s(D, 12) + "-" + s(D, 12) + "-" + s(A, 24),
        "stripe": "sk" + "_live_" + s(A, 24),
        "sendgrid": "S" + "G." + s(A, 22) + "." + s(A, 43),
        "npm": "np" + "m_" + s(A, 36),
        "hf": "h" + "f_" + s(L, 34),
        "digitalocean": "do" + "p_v1_" + s("0123456789abcdef", 64),
        "shopify": "sh" + "pat_" + s("0123456789abcdef", 32),
        "openai": "sk" + "-" + s(A, 20) + "T3Blbk" + "FJ" + s(A, 20),
        "anthropic": "sk" + "-ant-api03-" + s(A + "_-", 93) + "AA",
        "google": "AI" + "za" + s(A + "_-", 35),
    }
    key = "-----BEGIN RSA " + "PRIVATE KEY-----\n" + "\n".join(s(A + "+/", 64) for _ in range(6)) + "\n-----END RSA " + "PRIVATE KEY-----\n"
    def git(*a): subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True,
                                env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"})
    def commit(msg, **files):
        for name, text in files.items():
            p = repo / name; p.parent.mkdir(parents=True, exist_ok=True)
            if text is None: p.unlink()
            else: p.write_text(text)
        git("add", "-A"); git("commit", "-q", "-m", msg)
    git("init", "-q", "-b", "main")
    commit("app", **{"app.py": f'import github\nclient = github.Github("{tok["github"]}")\n'})
    commit("config", **{"config.yml": f'aws:\n  key_id: {tok["aws"]}\n  example: AKIA" + "IOSFODNN7EXAMPLE\n'})
    commit("remove key", **{"config.yml": "aws:\n  key_id: ${AWS_KEY_ID}\n"})
    commit("notes", **{"deploy.sh": f'#!/bin/sh\n# old token: {tok["gitlab"]}\ncurl -H "Authorization: Bearer $TOKEN" https://x\n'})
    commit("env", **{".env": "".join(f"{k.upper()}={v}\n" for k, v in tok.items() if k in ("stripe", "sendgrid", "npm", "hf", "digitalocean"))})
    commit("more", **{"src/clients.js": "".join(f'const {k} = "{v}";\n' for k, v in tok.items() if k in ("shopify", "openai", "anthropic", "google"))})
    commit("key", **{"certs/server.key": key})
    commit("drop key", **{"certs/server.key": None})
    commit("reuse", **{"tools/sync.py": f'TOKEN = "{tok["github"]}"\n'})
    git("checkout", "-q", "-b", "experiment")
    commit("slack", **{"bot.py": f'SLACK = "{tok["slack"]}"\n'})
    git("checkout", "-q", "main")
    return tok


@pytest.fixture(scope="module")
def history(tmp_path_factory):
    repo = tmp_path_factory.mktemp("h") / "repo"
    return repo, make_repo(repo)


def test_every_credential_once_at_the_commit_that_added_it(history):
    repo, tok = history
    leaks = {x.format: x for x in scan_history(repo)}
    assert len(leaks) == 14 and set(leaks) >= {"aws-access-key-id", "github-token", "private-key", "slack-token"}
    gh = leaks["github-token"]
    assert (gh.path, gh.line, gh.commits, gh.in_head) == ("app.py", 2, 2, True)      # added twice, reported once
    aws = leaks["aws-access-key-id"]
    assert (aws.path, aws.line, aws.in_head) == ("config.yml", 2, False)            # deleted later, still leaked
    assert leaks["gitlab-pat"].path == "deploy.sh"                                   # in a comment: still a leak
    assert (leaks["private-key"].path, leaks["private-key"].line) == ("certs/server.key", 1)   # spans lines
    assert leaks["slack-token"].in_head is False                                     # only on a side branch


def test_values_are_never_printed(history, capsys):
    repo, tok = history
    out = subprocess.run([sys.executable, "-m", "frame.cli", "history", str(repo), "-f", "json"], capture_output=True,
                         text=True, env={**os.environ, "PYTHONPATH": str(ROOT)})
    assert out.returncode == 1
    data = json.loads(out.stdout)
    assert len(data["credentials"]) == 14
    for value in tok.values():
        assert value not in out.stdout and value[4:] not in out.stdout
    text = subprocess.run([sys.executable, "-m", "frame.cli", "history", str(repo)], capture_output=True, text=True,
                          env={**os.environ, "PYTHONPATH": str(ROOT)}).stdout
    assert all(v not in text for v in tok.values()) and "14 credential(s) in the history" in text


def test_a_range_reads_only_that_history(history):
    repo, _ = history
    on_main = {x.format for x in scan_history(repo, "main")}
    assert "slack-token" not in on_main and len(on_main) == 13


def test_documented_examples_and_clean_repositories(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "README.md").write_text("Set the key, e.g. AKIA" + "IOSFODNN7EXAMPLE (AWS's documented example).\n")
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "docs"], check=True, env=env)
    assert scan_history(repo) == []
    r = subprocess.run([sys.executable, "-m", "frame.cli", "history", str(tmp_path)], capture_output=True, text=True,
                       env={**os.environ, "PYTHONPATH": str(ROOT)})
    assert r.returncode == 2 and "not a git repository" in r.stderr


@pytest.mark.skipif(os.environ.get("FRAME_SCA_REAL") != "1" or not shutil.which("docker"),
                    reason="live: set FRAME_SCA_REAL=1 (gitleaks in Docker)")
def test_live_gitleaks_finds_nothing_frame_misses(history, tmp_path):
    repo, tok = history
    shutil.copytree(repo, tmp_path / "repo")
    subprocess.run(["docker", "run", "--rm", "-v", f"{tmp_path}:/w", "zricethezav/gitleaks:v8.21.2", "detect",
                    "--source", "/w/repo", "--log-opts=--all", "--report-format", "json", "--report-path",
                    "/w/gitleaks.json", "--no-banner"], capture_output=True, timeout=900)
    found = json.loads((tmp_path / "gitleaks.json").read_text())
    assert len(found) >= 12
    ours = scan_history(repo)
    first = {}
    for g in found:
        key = g["Secret"] if g["RuleID"] != "private-key" else "private-key"
        loc = (g["Commit"], g["File"], g["StartLine"])
        first.setdefault(key, set()).add(loc)
    for key, locs in first.items():
        match = [x for x in ours if (x.format == "private-key" if key == "private-key" else x.redacted == f"{key[:4]}... ({len(key)} characters)")]
        assert match and (match[0].commit, match[0].path, match[0].line) in locs, key[:6]
