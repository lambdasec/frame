"""Release notes between two versions of a package, for `frame deps --adapt` (the model adapting
code to an upgrade reads what changed instead of guessing it from the error).

    1. the source repository, from the registry: npm `repository`, PyPI `project_urls` /
       `home_page`, crates.io `repository`, RubyGems `source_code_uri`; GitHub only;
    2. the project's changelog file (CHANGES.rst, CHANGELOG.md, HISTORY.md, NEWS.md, ...) at the
       target version's tag (else the default branch), sliced to the sections whose heading
       names a version after the current one and up to the target;
    3. else the GitHub release bodies for those versions.

Feature releases (x.0.0, x.y.0) come first, since breaking changes are announced there, then
the rest, up to a size limit. Notes are context for the model; a failure means no notes, never
a blocked adaptation. Responses are cached beside the registry metadata.
"""

from __future__ import annotations

import gzip
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, List, Optional, Tuple

from frame.sca.cpp import normalize_repo
from frame.sca.model import CARGO, NPM, PYPI, RUBYGEMS
from frame.sca.registry import TIMEOUT, cache_dir
from frame.sca.versions import sort_key

CHANGELOGS = ("CHANGES.rst", "CHANGELOG.md", "CHANGES.md", "CHANGELOG.rst", "HISTORY.md", "HISTORY.rst",
              "NEWS.md", "NEWS.rst", "CHANGELOG", "CHANGES", "docs/changelog.rst", "docs/changes.rst")
MAX_CHARS = 12000
_VERSION = re.compile(r"(?<![\w.])v?(\d+\.\d+(?:\.\d+)?(?:[-.]?(?:a|b|rc|alpha|beta|dev|post)\.?\d*)?)(?![\w.])")


def _get(url: str, accept: str = "application/json") -> Optional[bytes]:
    key = cache_dir() / "notes" / (urllib.parse.quote(url, safe="")[:200] + ".gz")
    if key.is_file():
        data = gzip.decompress(key.read_bytes())
        return data or None
    headers = {"Accept": accept, "User-Agent": "frame-sca"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        headers["Authorization"] = f"Bearer {token}"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=TIMEOUT) as r:  # nosec
            data = r.read()
    except urllib.error.HTTPError as e:
        if e.code != 404:
            return None                                   # rate limits and errors are not cached
        data = b""
    except (urllib.error.URLError, OSError):
        return None
    key.parent.mkdir(parents=True, exist_ok=True)
    key.write_bytes(gzip.compress(data))
    return data or None


def _json(url: str) -> Optional[dict]:
    data = _get(url)
    try:
        return json.loads(data) if data else None
    except ValueError:
        return None


def repository(ecosystem: str, name: str) -> Optional[Tuple[str, str]]:
    """(owner, repo) on GitHub, from the registry's record of the package."""
    urls: List[str] = []
    if ecosystem == NPM:
        doc = _json(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}") or {}
        repo = doc.get("repository")
        urls.append(repo.get("url", "") if isinstance(repo, dict) else str(repo or ""))
    elif ecosystem == PYPI:
        info = (_json(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json") or {}).get("info") or {}
        urls += [str(u) for u in (info.get("project_urls") or {}).values()] + [str(info.get("home_page") or "")]
    elif ecosystem == CARGO:
        urls.append(str(((_json(f"https://crates.io/api/v1/crates/{urllib.parse.quote(name)}") or {})
                         .get("crate") or {}).get("repository") or ""))
    elif ecosystem == RUBYGEMS:
        doc = _json(f"https://rubygems.org/api/v1/gems/{urllib.parse.quote(name)}.json") or {}
        urls += [str(doc.get(k) or "") for k in ("source_code_uri", "homepage_uri")]
    for u in urls:
        r = normalize_repo(re.sub(r"^git\+", "", u.strip()))
        if r and r.startswith("github.com/"):
            _, owner, repo = r.split("/", 2)
            return owner, repo
    return None


def _between(ecosystem: str, version: str, current: str, target: str) -> bool:
    k, lo, hi = sort_key(ecosystem, version), sort_key(ecosystem, current), sort_key(ecosystem, target)
    return None not in (k, lo, hi) and lo < k <= hi


def _feature(version: str) -> bool:
    parts = re.findall(r"\d+", version)
    return len(parts) >= 2 and (len(parts) < 3 or parts[2] == "0")


def slice_changelog(text: str, ecosystem: str, current: str, target: str) -> Dict[str, str]:
    """{version: its section}, for the headings that name a version in (current, target]. A
    heading is a short line naming one version that is a Markdown heading, underlined (rst),
    or starts with `Version` / `[`."""
    lines = text.splitlines()
    heads: List[Tuple[int, str]] = []
    for i, line in enumerate(lines):
        s = line.strip()
        if not s or len(s) > 100:
            continue
        nxt = lines[i + 1].strip() if i + 1 < len(lines) else ""
        is_heading = (s.startswith("#") or re.fullmatch(r"[-=~^*]{3,}", nxt) is not None
                      or re.match(r"(?i)^(version|release|\[)", s) is not None)
        m = _VERSION.search(s)
        if is_heading and m:
            heads.append((i, m.group(1)))
    out: Dict[str, str] = {}
    for n, (i, v) in enumerate(heads):
        end = heads[n + 1][0] if n + 1 < len(heads) else len(lines)
        if _between(ecosystem, v, current, target) and v not in out:
            out[v] = "\n".join(lines[i:end]).strip()
    return out


def _tag_candidates(name: str, version: str) -> List[str]:
    short = name.split("/")[-1].split(":")[-1]
    return [version, f"v{version}", f"{short}-{version}", f"{short}@{version}", f"release-{version}"]


def release_notes(ecosystem: str, name: str, current: str, target: str, max_chars: int = MAX_CHARS) -> str:
    try:
        repo = repository(ecosystem, name)
    except Exception:
        return ""
    if repo is None:
        return ""
    owner, rname = repo
    api = f"https://api.github.com/repos/{owner}/{rname}"
    sections: Dict[str, str] = {}
    for ref in _tag_candidates(name, target) + ["HEAD"]:
        for fname in CHANGELOGS:
            raw = _get(f"{api}/contents/{fname}?ref={urllib.parse.quote(ref)}", "application/vnd.github.raw")
            if raw:
                sections = slice_changelog(raw.decode("utf-8", "replace"), ecosystem, current, target)
                if sections:
                    break
        if sections:
            break
    if not sections:
        for page in (1, 2, 3):
            rels = _json(f"{api}/releases?per_page=100&page={page}")
            if not rels:
                break
            for rel in rels:
                m = _VERSION.search(str(rel.get("tag_name") or ""))
                if m and _between(ecosystem, m.group(1), current, target) and rel.get("body"):
                    sections.setdefault(m.group(1), f"{rel['tag_name']}\n{rel['body'].strip()}")
    if not sections:
        return ""
    order = sorted(sections, key=lambda v: (not _feature(v), sort_key(ecosystem, v) or ()))
    out, used = [], 0
    for v in order:
        block = sections[v][:4000]
        if used + len(block) > max_chars:
            continue
        out.append(block)
        used += len(block)
    return "\n\n".join(out)
