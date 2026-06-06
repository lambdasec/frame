"""Real SecBench.js benchmark (Staicu et al., ICSE 2023).

This is the genuine academic benchmark -- 600 publicly-reported server-side
JavaScript vulnerabilities curated from Snyk / GitHub Advisories / Huntr --
NOT the regex-generated `secbench_js` division in this tree (which is circular).

Repo: https://github.com/cristianstaicu/SecBench.js

Each vulnerability lives in `<category>/<package>_<version>/package.json` with:
  - id:            the CVE
  - dependencies:  {package: vulnerable_version}
  - fixedVersion:  the patched version (or "n/a")
  - sink:          "relative/file.js:line:col" -- ground-truth sink location

The vulnerable source is the actual npm package, fetched on demand via
`npm pack` and cached. Ground truth is line-level and externally authored.

Evaluation methodology (standard vulnerable-vs-patched):
  - recall:    scan the vulnerable package's sink file; expect the category's CWE
  - precision: scan the *patched* version's same file; a finding there is an FP
"""

import os
import json
import glob
import shutil
import subprocess
from typing import Dict, List, Optional


REPO = "https://github.com/cristianstaicu/SecBench.js.git"

CATEGORY_CWE = {
    "command-injection": "CWE-78",
    "code-injection": "CWE-94",
    "path-traversal": "CWE-22",
    "prototype-pollution": "CWE-1321",
    "redos": "CWE-1333",
}


def download_secbench_real(cache_dir: str) -> str:
    """Clone the SecBench.js repo into the cache. Returns the repo path."""
    base = os.path.join(cache_dir, "secbench_real")
    repo = os.path.join(base, "repo")
    if os.path.isdir(os.path.join(repo, ".git")) or os.path.isdir(
            os.path.join(repo, "command-injection")):
        return repo
    os.makedirs(base, exist_ok=True)
    print("Cloning SecBench.js (real academic benchmark)...")
    subprocess.run(["git", "clone", "--depth", "1", REPO, repo],
                   check=True, capture_output=True, timeout=300)
    return repo


def _fetch_package(cache_dir: str, pkg: str, ver: str) -> Optional[str]:
    """npm pack + extract a package@version; return the extracted package root
    (the directory containing its package.json), or None on failure. Cached."""
    pkgs_dir = os.path.join(cache_dir, "secbench_real", "pkgs")
    safe = f"{pkg.replace('/', '_')}_{ver}"
    dest = os.path.join(pkgs_dir, safe)
    root = os.path.join(dest, "package")
    if os.path.isdir(root):
        return root
    os.makedirs(dest, exist_ok=True)
    try:
        r = subprocess.run(
            ["npm", "pack", f"{pkg}@{ver}", "--pack-destination", dest],
            capture_output=True, text=True, timeout=180)
        if r.returncode != 0:
            return None
        tgz = glob.glob(os.path.join(dest, "*.tgz"))
        if not tgz:
            return None
        subprocess.run(["tar", "xzf", tgz[0], "-C", dest],
                       capture_output=True, timeout=120)
        return root if os.path.isdir(root) else None
    except (subprocess.SubprocessError, OSError):
        return None


def get_secbench_real_entries(
    cache_dir: str,
    categories: Optional[List[str]] = None,
    max_per_cat: Optional[int] = None,
    with_patched: bool = True,
) -> List[Dict]:
    """Build the list of benchmark entries, fetching package sources as needed.

    Each entry: {category, cwe, package, version, sink, sink_line,
                 vuln_file (abs path or None), fixed_version, fixed_file}.
    """
    repo = download_secbench_real(cache_dir)
    categories = categories or list(CATEGORY_CWE)
    entries: List[Dict] = []

    for cat in categories:
        cwe = CATEGORY_CWE[cat]
        dirs = sorted(glob.glob(os.path.join(repo, cat, "*", "")))
        n = 0
        for d in dirs:
            pj = os.path.join(d, "package.json")
            if not os.path.exists(pj):
                continue
            try:
                meta = json.load(open(pj, encoding="utf-8"))
            except (ValueError, OSError):
                continue
            sink = meta.get("sink", "n/a")
            deps = meta.get("dependencies", {})
            if not sink or sink == "n/a" or ":" not in sink or not deps:
                continue
            pkg = list(deps)[0]
            ver = deps[pkg]
            rel_file = sink.split(":")[0]
            try:
                sink_line = int(sink.split(":")[1])
            except (IndexError, ValueError):
                sink_line = None

            vuln_root = _fetch_package(cache_dir, pkg, ver)
            vuln_file = (os.path.join(vuln_root, rel_file)
                         if vuln_root and os.path.exists(os.path.join(vuln_root, rel_file))
                         else None)

            fixed_version = meta.get("fixedVersion", "n/a")
            fixed_file = None
            if with_patched and fixed_version and fixed_version != "n/a":
                fixed_root = _fetch_package(cache_dir, pkg, fixed_version)
                if fixed_root:
                    cand = os.path.join(fixed_root, rel_file)
                    if os.path.exists(cand):
                        fixed_file = cand

            entries.append({
                "category": cat,
                "cwe": cwe,
                "package": pkg,
                "version": ver,
                "sink": sink,
                "sink_line": sink_line,
                "vuln_file": vuln_file,
                "fixed_version": fixed_version,
                "fixed_file": fixed_file,
            })
            n += 1
            if max_per_cat and n >= max_per_cat:
                break

    return entries
