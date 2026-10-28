"""Is a commit inside an advisory's GIT ranges? Decided on the repository's own history.

OSV's GIT ranges are commits, not versions: a commit is affected when an `introduced` commit is
its ancestor (or itself; "0" is the start of history) and no `fixed` commit lies between that
`introduced` and it (a fix on another branch does not count). With `last_affected`, it must also
be an ancestor of one (inclusive); with `limit`, an ancestor of one (exclusive). Ancestry comes
from `git merge-base --is-ancestor` in a local checkout, so it costs no network; a commit the
checkout does not have (a shallow clone) leaves the answer undecided, never guessed.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

Ancestry = Callable[[str, str], Optional[bool]]


def git_ancestry(checkout: Path) -> Ancestry:
    """`is_ancestor(a, b)`: a is b or an ancestor of it; None when git cannot say."""
    cache: Dict[Tuple[str, str], Optional[bool]] = {}

    def is_ancestor(a: str, b: str) -> Optional[bool]:
        if a == b:
            return True
        if (a, b) not in cache:
            try:
                r = subprocess.run(["git", "-C", str(checkout), "merge-base", "--is-ancestor", a, b],
                                   capture_output=True, timeout=60)
                cache[(a, b)] = True if r.returncode == 0 else False if r.returncode == 1 else None
            except (OSError, subprocess.TimeoutExpired):
                cache[(a, b)] = None
        return cache[(a, b)]
    return is_ancestor


def _range_affects(commit: str, events: List[dict], is_ancestor: Ancestry) -> Optional[bool]:
    def get(kind: str) -> List[str]:
        return [str(e[kind]) for e in events if isinstance(e, dict) and e.get(kind)]
    intros, fixes, lasts, limits = get("introduced"), get("fixed"), get("last_affected"), get("limit")
    unknown = False

    def anc(a: str, b: str) -> Optional[bool]:
        return True if a == "0" else is_ancestor(a, b)

    if limits:
        under = [is_ancestor(commit, lim) for lim in limits]
        if not any(u for u in under) or commit in limits:
            return None if any(u is None for u in under) else False
    for intro in intros:
        start = anc(intro, commit)
        if start is None:
            unknown = True
            continue
        if not start:
            continue
        blocked: Optional[bool] = False
        for fix in fixes:
            between = [anc(intro, fix), is_ancestor(fix, commit)]
            if all(between):
                blocked = True
                break
            if None in between and False not in between:
                blocked = None
        if blocked is None:
            unknown = True
            continue
        if blocked:
            continue
        if lasts:
            within = [(anc(intro, last), is_ancestor(commit, last)) for last in lasts]
            if any(a and b for a, b in within):
                return True
            if any(a is None or b is None for a, b in within):
                unknown = True
            continue
        return True
    return None if unknown else False


def commit_affected(commit: str, ranges: List[List[dict]], is_ancestor: Ancestry) -> Optional[bool]:
    """True when any of the advisory's GIT ranges (each a list of events) affects `commit`,
    False when none does, None when the history at hand cannot decide."""
    unknown = False
    for events in ranges:
        r = _range_affects(commit, events, is_ancestor)
        if r:
            return True
        unknown = unknown or r is None
    return None if unknown else False
