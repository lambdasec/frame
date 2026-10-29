"""Backported fixes for npm packages (`frame deps --vulns --backport`): an advisory's own upstream
fix commit, applied to the version installed, as a `patch-package` patch.

When an upgrade is not possible (no fixed release, or the fix is a major jump), the fix commit
the advisory links to can often be applied to the installed version. For each npm finding whose
package is installed (`node_modules/<name>` at that version), the commits come from the advisory's
OSV record (`references`), their changes from GitHub (`mine.GitHubSource`, cached). A commit's
files are mapped to the package as published (a monorepo's `packages/x/index.js` is the package's
`index.js`; files the package does not ship, and tests and docs as the fix-commit miner reads
them, are left out), and every commit
whose changes apply cleanly, in order, is kept (one advisory often links the fix for each release
line; only the one for this line applies). The result is `patches/<name>+<version>.patch` in
patch-package's layout, and a `postinstall` running patch-package.

A patch that applies is evidence that it fits this version, not that it fixes it: run the project's
tests (`--verify`), and prefer the upgrade when one exists.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from frame.sca.apply import Change
from frame.sca.mine import _TEST_PATH, commit_links

OSV_VULN = "https://api.osv.dev/v1/vulns/{}"


class BackportError(RuntimeError):
    pass


@dataclass
class Backport:
    package: str
    version: str
    advisories: List[str]
    commits: List[str]                       # owner/repo@sha applied
    skipped: List[str] = field(default_factory=list)    # commits that did not apply, and why
    patch: str = ""                          # patch-package's format


def cache_dir() -> Path:
    """Where OSV records and GitHub commits are kept (`FRAME_BACKPORT_CACHE`): fetched once, and an
    air-gapped run reads a directory recorded elsewhere."""
    return Path(os.environ.get("FRAME_BACKPORT_CACHE") or Path.home() / ".cache" / "frame" / "backport")


def osv_record(advisory: str, cache: Optional[Path] = None) -> dict:
    p = (cache or cache_dir()) / "osv" / f"{advisory}.json"
    if p.is_file():
        return json.loads(p.read_text(encoding="utf-8"))
    try:
        with urllib.request.urlopen(OSV_VULN.format(advisory), timeout=60) as r:
            data = json.loads(r.read())
    except (OSError, ValueError) as e:
        raise BackportError(f"OSV record {advisory}: {e}") from e
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data), encoding="utf-8")
    return data


def installed(root: Path, lock_rel: str, name: str, version: str) -> Optional[Path]:
    """`node_modules/<name>` beside the lockfile, if it holds this version."""
    d = (root / lock_rel).parent / "node_modules" / name
    try:
        meta = json.loads((d / "package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return d if meta.get("version") == version else None


def _published_path(repo_path: str, pkg_dir: Path) -> Optional[str]:
    """The file a repository path is in the published package: the path itself, else with its
    leading folders removed (a monorepo's `packages/minimist/index.js`)."""
    parts = repo_path.split("/")
    for i in range(len(parts)):
        cand = "/".join(parts[i:])
        if (pkg_dir / cand).is_file():
            return cand
    return None


def _git(cwd: Path, *args: str, stdin: Optional[str] = None) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-c", "core.autocrlf=false", *args], cwd=cwd, input=stdin, text=True,
                          capture_output=True)


def backport(name: str, version: str, pkg_dir: Path, records: List[dict], source) -> Backport:
    """Apply each advisory's fix commits to a copy of the installed package."""
    bp = Backport(name, version, [r["id"] for r in records], [])
    with tempfile.TemporaryDirectory(prefix="frame-backport-") as tmp:
        work = Path(tmp) / "pkg"
        shutil.copytree(pkg_dir, work, ignore=shutil.ignore_patterns("node_modules"))
        _git(work, "init", "-q")
        _git(work, "add", "-A")
        _git(work, "-c", "user.name=frame", "-c", "user.email=frame@localhost", "commit", "-qm", "installed")
        for rec in records:
            for owner, repo, sha in commit_links(rec):
                label = f"{owner}/{repo}@{sha[:12]}"
                if label in bp.commits:
                    continue
                try:
                    commit = source.commit(owner, repo, sha)
                except Exception as e:                       # a commit GitHub cannot serve
                    bp.skipped.append(f"{label}: {e}")
                    continue
                diff = []
                for f in commit["files"]:
                    target = _published_path(f["filename"], work) if f.get("status") != "added" else None
                    if target is None or not f.get("patch") or _TEST_PATH.search(f["filename"]):
                        continue           # not shipped in the package, or its tests and docs (as the miner)
                    diff.append(f"--- a/{target}\n+++ b/{target}\n{f['patch'].rstrip(chr(10))}\n")
                if not diff:
                    bp.skipped.append(f"{label}: changes no source file the package ships")
                    continue
                text = "".join(diff)
                check = _git(work, "apply", "--check", "-", stdin=text)
                if check.returncode != 0:
                    bp.skipped.append(f"{label}: does not apply to {version} ({check.stderr.strip().splitlines()[0] if check.stderr.strip() else 'conflict'})")
                    continue
                _git(work, "apply", "-", stdin=text)
                bp.commits.append(label)
        if bp.commits:
            prefix = f"node_modules/{name}/"
            out = _git(work, "diff", "--no-color", f"--src-prefix=a/{prefix}", f"--dst-prefix=b/{prefix}")
            bp.patch = out.stdout
    return bp


def patch_file(name: str, version: str) -> str:
    return f"patches/{name.replace('/', '+')}+{version}.patch"       # patch-package's naming


def _postinstall(text: str) -> Optional[str]:
    """package.json with `"postinstall": "patch-package"`, edited in place (only that line); None
    when a different postinstall is already there (a person combines them)."""
    if re.search(r'"postinstall"\s*:\s*"[^"]*patch-package', text):
        return text
    if re.search(r'"postinstall"\s*:', text):
        return None
    m = re.search(r'"scripts"\s*:\s*\{(\s*)', text)
    if m:
        ws, rest = m.group(1), text[m.end():]
        if rest.startswith("}"):                                  # "scripts": {}
            return text[:m.start(1)] + '"postinstall": "patch-package"' + text[m.start(1):]
        return text[:m.end()] + '"postinstall": "patch-package",' + (ws if "\n" in ws else " ") + rest
    m = re.match(r"\s*\{(\s*)", text)
    if not m:
        return None
    ws = m.group(1) if "\n" in m.group(1) else "\n  "
    return text[:m.end()] + '"scripts": {' + ws + '  "postinstall": "patch-package"' + ws + '},' + ws + text[m.end():]


def propose(findings: List[dict], root: Path, source,
            records: Callable[[str], dict] = osv_record) -> Tuple[List[Change], List[str], List[Backport]]:
    """Edits for the npm findings whose fix commits apply to the installed version."""
    root = Path(root)
    by_pkg: Dict[Tuple[str, str, str], List[dict]] = {}
    for f in findings:
        if f.get("ecosystem") == "npm":
            by_pkg.setdefault((f["path"], f["package"], f["version"]), []).append(f)
    changes: List[Change] = []
    manual: List[str] = []
    done: List[Backport] = []
    edited_pkg: Dict[str, str] = {}
    for (lock, name, version), fs in sorted(by_pkg.items()):
        pkg_dir = installed(root, lock, name, version)
        if pkg_dir is None:
            manual.append(f"{name}@{version}: not installed in node_modules beside {lock} (run npm install first)")
            continue
        recs = []
        for f in fs:
            try:
                recs.append(records(f["id"]))
            except BackportError as e:
                manual.append(f"{name}@{version} {f['id']}: {e}")
        recs = [r for r in recs if commit_links(r)]
        if not recs:
            manual.append(f"{name}@{version}: its advisories link no fix commit")
            continue
        bp = backport(name, version, pkg_dir, recs, source)
        if not bp.commits:
            manual.append(f"{name}@{version}: no fix commit applies to this version"
                          + (f" ({'; '.join(bp.skipped[:3])})" if bp.skipped else ""))
            continue
        done.append(bp)
        home = Path(lock).parent
        rel = (home / patch_file(name, version)).as_posix()
        cur = (root / rel).read_text() if (root / rel).is_file() else ""
        changes.append(Change(rel, cur, bp.patch, f"{name}@{version}: backport {', '.join(bp.commits)} "
                                                   f"({', '.join(bp.advisories)})"))
        pj = (home / "package.json").as_posix()
        if pj not in edited_pkg and (root / pj).is_file():
            before = (root / pj).read_text()
            after = _postinstall(before)
            if after is None:
                manual.append(f"{pj}: add `patch-package` to the existing postinstall script")
            elif after != before:
                changes.append(Change(pj, before, after, "run patch-package after every install"))
            edited_pkg[pj] = after or before
    if done:
        manual.append("install patch-package once: npm install --save-dev patch-package")
    return changes, manual, done


__all__ = ["Backport", "BackportError", "backport", "propose", "installed", "patch_file", "osv_record", "cache_dir"]
