"""C and C++ dependencies: where each comes from (its upstream repository) and which release
tag it is, so it can be matched against OSV's GIT advisories (commit ranges in upstream
repositories, with the affected tags listed).

Repositories are normalised to `host/owner/name` (lower case, no scheme, no `.git`). Conan
and vcpkg packages are mapped to repositories with `data/cpp-repos.json`, generated from the
vcpkg port files (`vcpkg_from_github(REPO ...)`, the tag pattern in `REF`) and Conan Center's
`conandata.yml` (the exact source URL of every version, hence its tag). Both MIT-licensed.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import List, Optional, Tuple

_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "sourceware.org", "git.savannah.gnu.org")


def normalize_repo(url: str) -> Optional[str]:
    """`https://github.com/Madler/zlib.git`, `git@github.com:madler/zlib`, an archive or release
    URL of the repository -> `github.com/madler/zlib`. None when it is not a repository URL."""
    u = (url or "").strip().strip('"').strip("'")
    if not u:
        return None
    u = re.sub(r"^git@([^:]+):", r"https://\1/", u)
    u = re.sub(r"^(git\+)?(https?|ssh|git)://(git@)?", "", u, flags=re.I)
    u = u.split("?", 1)[0].split("#", 1)[0]
    if u.startswith("codeload.github.com/"):
        u = "github.com/" + u[len("codeload.github.com/"):]
    parts = [p for p in u.split("/") if p]
    if len(parts) < 3 or parts[0].lower() not in _HOSTS:
        return None
    name = parts[2][:-4] if parts[2].endswith(".git") else parts[2]
    return f"{parts[0].lower()}/{parts[1].lower()}/{name.lower()}"


_ARCHIVE = [
    re.compile(r"/-/archive/([^/]+)/"),                                              # GitLab
    re.compile(r"/archive/refs/tags/([^/]+?)\.(?:tar\.gz|tar\.bz2|tar\.xz|tgz|zip)$"),
    re.compile(r"/archive/(?!refs/)([^/]+?)\.(?:tar\.gz|tar\.bz2|tar\.xz|tgz|zip)$"),
    re.compile(r"/releases/download/([^/]+)/"),
    re.compile(r"codeload\.github\.com/[^/]+/[^/]+/(?:tar\.gz|zip)/(?:refs/tags/)?([^/]+)$"),
]


def tag_from_url(url: str) -> Optional[str]:
    """The tag a GitHub / GitLab archive or release URL downloads (None for a commit)."""
    for pat in _ARCHIVE:
        m = pat.search(url or "")
        if m:
            tag = m.group(1)
            return None if re.fullmatch(r"[0-9a-f]{40}", tag) else tag
    return None


# ---------------------------------------------------------------------------------------------
# the package -> repository map

def build_repo_map(vcpkg_root: Path, cci_root: Path) -> dict:
    """{"vcpkg": {port: {"repo", "ref"}}, "conan": {recipe: {"repo", "tags": {version: tag}}}}."""
    from frame.sca import _yaml
    from frame.sca.cmake import commands
    out: dict = {"vcpkg": {}, "conan": {}}
    for portfile in sorted(Path(vcpkg_root).glob("ports/*/portfile.cmake")):
        port = portfile.parent.name
        for cmd in commands(portfile.read_text(encoding="utf-8", errors="replace")):
            repo = None
            if cmd.name == "vcpkg_from_github" and cmd.keyword("REPO"):
                repo = normalize_repo(f"https://github.com/{cmd.keyword('REPO')}")
            elif cmd.name == "vcpkg_from_gitlab" and cmd.keyword("REPO"):
                host = normalize_repo((cmd.keyword("GITLAB_URL") or "https://gitlab.com") + "/x/y")
                repo = normalize_repo(f"https://{host.split('/')[0]}/{cmd.keyword('REPO')}") if host else None
            elif cmd.name == "vcpkg_from_git" and cmd.keyword("URL"):
                repo = normalize_repo(cmd.keyword("URL"))
            if repo:
                out["vcpkg"][port] = {"repo": repo, "ref": cmd.keyword("REF") or ""}
                break                                   # the first source is the port's own
    for conandata in sorted(Path(cci_root).glob("recipes/*/*/conandata.yml")):
        recipe = conandata.parent.parent.name
        try:
            data = _yaml.loads(conandata.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        entry = out["conan"].setdefault(recipe, {"repo": None, "tags": {}})
        for version, src in ((data or {}).get("sources") or {}).items():
            urls = _urls(src)
            for u in urls:
                repo = normalize_repo(u)
                if repo and entry["repo"] in (None, repo):
                    entry["repo"] = repo
                    tag = tag_from_url(u)
                    if tag:
                        entry["tags"][str(version)] = tag
                    break
        if entry["repo"] is None:
            del out["conan"][recipe]
        else:
            pattern = tag_pattern(entry["tags"])
            if pattern:
                entry["pattern"] = pattern
    # corroboration: a vcpkg port of the same repository whose REF is the version alone
    # (`v${VERSION}`) and agrees with every version -> tag pair Conan records (at least one)
    by_repo = {v["repo"]: v.get("ref", "") for v in out["vcpkg"].values()}
    for entry in out["conan"].values():
        ref = by_repo.get(entry["repo"], "")
        if entry.get("pattern") or not entry["tags"] or ref.count("${") != 1 or "${VERSION}" not in ref:
            continue
        template = ref.replace("${VERSION}", "{V}")
        if all(template.replace("{V}", v) == t for v, t in entry["tags"].items()):
            entry["pattern"] = template
    return out


def tag_pattern(pairs: dict) -> Optional[str]:
    """The one template every known version -> tag pair follows (`v{V}`, `curl-{V_}` where V_
    is the version with `.` as `_`, `R_{V_}`), from at least two pairs; None when they do not
    all agree (OpenSSL's tags changed form between 1.1.1 and 3.x)."""
    if len(pairs) < 2:
        return None
    templates = set()
    for version, tag in pairs.items():
        cands = set()
        if version in tag:
            cands.add(tag.replace(version, "{V}", 1))
        underscored = version.replace(".", "_")
        if underscored != version and underscored in tag:
            cands.add(tag.replace(underscored, "{V_}", 1))
        if not cands:
            return None
        templates.add(frozenset(cands))
    common = frozenset.intersection(*templates)
    return sorted(common)[0] if len(common) >= 1 else None


def _urls(node) -> List[str]:
    out: List[str] = []
    stack = [node]
    while stack:
        x = stack.pop()
        if isinstance(x, str) and x.startswith(("http://", "https://")):
            out.append(x)
        elif isinstance(x, dict):
            stack.extend(x.values())
        elif isinstance(x, list):
            stack.extend(x)
    return out


@lru_cache(maxsize=1)
def repo_map() -> dict:
    p = Path(__file__).parent / "data" / "cpp-repos.json"
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return {"vcpkg": {}, "conan": {}}


def repo_and_tags(manager: str, name: str, version: Optional[str]) -> Tuple[Optional[str], List[str]]:
    """The repository of a Conan / vcpkg package and the tags its version may carry: the exact
    tag the recipe downloads when known, else the port's REF pattern, else none (never a guess
    such as adding a `v`)."""
    entry = repo_map().get(manager, {}).get(name)
    if not entry:
        return None, []
    tags: List[str] = []
    if version:
        if manager == "conan" and version in entry.get("tags", {}):
            tags.append(entry["tags"][version])
        elif manager == "conan" and entry.get("pattern"):    # every listed version follows it
            tags.append(entry["pattern"].replace("{V_}", version.replace(".", "_")).replace("{V}", version))
        elif manager == "vcpkg" and "${VERSION}" in entry.get("ref", ""):
            tags.append(entry["ref"].replace("${VERSION}", version))
    return entry["repo"], tags


__all__: List[str] = ["normalize_repo", "tag_from_url", "build_repo_map", "repo_map", "repo_and_tags"]