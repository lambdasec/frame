"""The documentation keeps up with the code: every command-line flag, every FRAME_* environment
variable Frame reads, and every relative link in the docs. Adding a flag or a variable without
documenting it fails here."""

import argparse
import re
from pathlib import Path

import pytest

from frame.cli import create_parser

ROOT = Path(__file__).resolve().parents[1]
DOCS = [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md")), *sorted((ROOT / "examples").glob("**/README.md"))]
# the solver commands are documented in the engine guide
ENGINE_COMMANDS = {"solve", "check", "parse", "repl"}


def _walk(parser: argparse.ArgumentParser, path=()):
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, sub in action.choices.items():
                yield from _walk(sub, path + (name,))
        else:
            for opt in action.option_strings:
                if opt.startswith("--") and opt not in ("--help", "--version"):
                    yield path, opt


def _flags():
    return sorted(set(_walk(create_parser())))


@pytest.mark.parametrize("path,flag", _flags(), ids=lambda x: " ".join(x) if isinstance(x, tuple) else x)
def test_every_flag_is_documented(path, flag):
    doc = ROOT / "docs" / ("engine.md" if path and path[0] in ENGINE_COMMANDS else "usage.md")
    assert re.search(rf"(?<![\w-]){re.escape(flag)}(?![\w-])", doc.read_text()), \
        f"frame {' '.join(path)} {flag} is not documented in {doc.relative_to(ROOT)}"


def test_every_environment_variable_is_documented():
    read = set()
    for p in (ROOT / "frame").rglob("*.py"):
        read |= set(re.findall(r"""["'](FRAME_[A-Z0-9_]+)["']""", p.read_text(encoding="utf-8", errors="replace")))
    text = "\n".join(d.read_text() for d in DOCS)
    missing = sorted(v for v in read if v not in text)
    assert not missing, f"undocumented environment variables: {missing}"


def _slug(heading: str) -> str:
    h = re.sub(r"[`*_]", "", heading.strip().lower())
    h = re.sub(r"[^\w\- ]", "", h)
    return h.replace(" ", "-")


def test_relative_links_resolve():
    broken = []
    for doc in DOCS:
        text = doc.read_text()
        for target in re.findall(r"\]\(([^)\s]+)\)", text):
            if re.match(r"^[a-z]+:", target):
                continue
            file_part, _, anchor = target.partition("#")
            dest = (doc.parent / file_part).resolve() if file_part else doc
            if not dest.exists():
                broken.append(f"{doc.name}: {target}")
                continue
            if anchor and dest.suffix == ".md":
                slugs = {_slug(h) for h in re.findall(r"^#+\s+(.*)$", dest.read_text(), re.M)}
                if anchor not in slugs:
                    broken.append(f"{doc.name}: {target} (no such heading)")
    assert not broken, broken
