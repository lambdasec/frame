"""Version ordering per ecosystem, as each registry defines it. Advisory ranges are only as
correct as these comparisons: `1.10` after `1.9`, `2.0.0-rc.1` before `2.0.0`, Maven's
`1.0-alpha` < `1.0-SNAPSHOT` < `1.0` < `1.0-sp`, PEP 440's `1.0.dev1` < `1.0a1` < `1.0` <
`1.0.post1`.

`sort_key(ecosystem, version)` returns a value that orders like the registry does; `None`
when the text is not a version of that ecosystem (a range never matches it).
"""

from __future__ import annotations

import re
from functools import cmp_to_key, lru_cache
from typing import Any, List, Optional, Tuple

from frame.sca.model import CARGO, GO, HEX, MAVEN, NPM, NUGET, PACKAGIST, PUB, PYPI, RUBYGEMS, SWIFT


class _Inf:
    """Sorts after everything (an absent pre-release, a missing local part...)."""
    def __lt__(self, other):
        return False

    def __gt__(self, other):
        return not isinstance(other, _Inf)

    def __le__(self, other):
        return isinstance(other, _Inf)

    def __ge__(self, other):
        return True

    def __eq__(self, other):
        return isinstance(other, _Inf)

    def __hash__(self):
        return 0


class _NegInf:
    def __lt__(self, other):
        return not isinstance(other, _NegInf)

    def __gt__(self, other):
        return False

    def __le__(self, other):
        return True

    def __ge__(self, other):
        return isinstance(other, _NegInf)

    def __eq__(self, other):
        return isinstance(other, _NegInf)

    def __hash__(self):
        return 1


INF, NEG_INF = _Inf(), _NegInf()

# ---------------------------------------------------------------------------------------------
# PEP 440 (PyPI)

_PEP440 = re.compile(r"""
    ^\s*v?
    (?:(?P<epoch>\d+)!)?
    (?P<release>\d+(?:\.\d+)*)
    (?:[-_.]?(?P<pre_l>a|b|c|rc|alpha|beta|pre|preview)[-_.]?(?P<pre_n>\d+)?)?
    (?:-(?P<post_n1>\d+)|[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>\d+)?)?
    (?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>\d+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    \s*$""", re.VERBOSE | re.IGNORECASE)
_PRE = {"a": "a", "alpha": "a", "b": "b", "beta": "b", "c": "rc", "rc": "rc", "pre": "rc", "preview": "rc"}


def _pep440(v: str) -> Optional[Tuple]:
    m = _PEP440.match(v)
    if not m:
        return None
    release = tuple(int(x) for x in m.group("release").split("."))
    while len(release) > 1 and release[-1] == 0:
        release = release[:-1]
    pre = (_PRE[m.group("pre_l").lower()], int(m.group("pre_n") or 0)) if m.group("pre_l") else None
    post_n = m.group("post_n1") or m.group("post_n2")
    post = int(post_n or 0) if (m.group("post_n1") or m.group("post_l")) else None
    dev = int(m.group("dev_n") or 0) if m.group("dev_l") else None
    # PEP 440 ordering: X.devN < X.aN < X.bN < X.rcN < X < X.postN
    if pre is None and post is None and dev is not None:
        pre_k: Any = NEG_INF                     # 1.0.dev1 sorts before 1.0a1
    elif pre is None:
        pre_k = INF
    else:
        pre_k = pre
    post_k: Any = NEG_INF if post is None else post
    dev_k: Any = INF if dev is None else dev
    local = m.group("local")
    local_k: Any = NEG_INF if local is None else tuple(
        (1, int(p), "") if p.isdigit() else (0, 0, p.lower()) for p in re.split(r"[-_.]", local))
    return (int(m.group("epoch") or 0), release, pre_k, post_k, dev_k, local_k)


# ---------------------------------------------------------------------------------------------
# SemVer 2 (npm, crates.io, SwiftURL, Go without its `v`)

_SEMVER = re.compile(r"^\s*[v=]?\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?\s*$")


def _prerelease_key(pre: Optional[str]) -> Any:
    if pre is None:
        return INF                               # a release sorts after its pre-releases
    return tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))


def _semver(v: str) -> Optional[Tuple]:
    m = _SEMVER.match(v)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0), _prerelease_key(m.group(4)))


# ---------------------------------------------------------------------------------------------
# NuGet: up to four numeric parts, SemVer pre-release labels compared case-insensitively

_NUGET = re.compile(r"^\s*(\d+(?:\.\d+){0,3})(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?\s*$")


def _nuget(v: str) -> Optional[Tuple]:
    m = _NUGET.match(v)
    if not m:
        return None
    nums = [int(x) for x in m.group(1).split(".")] + [0, 0, 0]
    return (*nums[:4], _prerelease_key(m.group(2).lower() if m.group(2) else None))


# ---------------------------------------------------------------------------------------------
# Maven: org.apache.maven.artifact.versioning.ComparableVersion

_QUALIFIERS = ["alpha", "beta", "milestone", "rc", "snapshot", "", "sp"]
_ALIASES = {"ga": "", "final": "", "release": "", "cr": "rc"}


def _qualifier_key(q: str) -> str:
    """Comparable form of a string item: known qualifiers by rank, others after them by text."""
    if q in _QUALIFIERS:
        return f"{_QUALIFIERS.index(q)}"
    return f"{len(_QUALIFIERS)}-{q}"


def _maven_items(v: str) -> List:
    """Parse into nested lists of ints and strings, the way ComparableVersion does."""
    v = v.lower()
    root: List = []
    lst = root
    stack = [root]
    buf, is_digit = "", False

    def item(text: str, digit: bool, followed_by_digit: bool):
        if digit:
            return int(text)
        if followed_by_digit and len(text) == 1:
            text = {"a": "alpha", "b": "beta", "m": "milestone"}.get(text, text)
        return _ALIASES.get(text, text)

    i = 0
    while i < len(v):
        c = v[i]
        if c == ".":
            lst.append(item(buf, is_digit, False) if buf else 0)
            buf = ""
        elif c == "-":
            lst.append(item(buf, is_digit, False) if buf else 0)
            buf = ""
            new: List = []
            lst.append(new)
            lst = new
            stack.append(new)
        elif c.isdigit():
            if buf and not is_digit:              # letter -> digit transition starts a sub-list
                lst.append(item(buf, False, True))
                buf = ""
                new = []
                lst.append(new)
                lst = new
                stack.append(new)
            is_digit = True
            buf += c
        else:
            if not buf and i > 0 and v[i - 1] == ".":     # `.` then a letter: a sub-list, like `-`
                new = []
                lst.append(new)
                lst = new
                stack.append(new)
            elif buf and is_digit:                # digit -> letter transition starts a sub-list
                lst.append(int(buf))
                buf = ""
                new = []
                lst.append(new)
                lst = new
                stack.append(new)
            is_digit = False
            buf += c
        i += 1
    if buf:
        lst.append(item(buf, is_digit, False))
    for lst_ in reversed(stack):                  # normalize: drop trailing "null" items
        _normalize(lst_)
    return root


def _is_null(x) -> bool:
    return x == 0 or x == "" or (isinstance(x, list) and not x)


def _normalize(lst: List) -> None:
    i = len(lst) - 1
    while i >= 0:
        last = lst[i]
        if _is_null(last):
            del lst[i]
        elif not isinstance(last, list):
            break
        i -= 1


def _cmp_item(a, b) -> int:
    """ComparableVersion.Item.compareTo; `None` stands for a missing item."""
    if a is None:
        if b is None:
            return 0
        return -_cmp_item(b, None)
    if isinstance(a, int):
        if b is None:
            return 0 if a == 0 else 1
        if isinstance(b, int):
            return (a > b) - (a < b)
        return 1                                  # int > string, int > list
    if isinstance(a, str):
        if b is None:                             # qualifier vs nothing: compare with ""
            ka, kb = _qualifier_key(a), _qualifier_key("")
            return (ka > kb) - (ka < kb)
        if isinstance(b, int):
            return -1
        if isinstance(b, str):
            ka, kb = _qualifier_key(a), _qualifier_key(b)
            return (ka > kb) - (ka < kb)
        return -1                                 # string < list
    # list
    if b is None:
        if not a:
            return 0
        return _cmp_item(a[0], None)
    if isinstance(b, int):
        return -1
    if isinstance(b, str):
        return 1
    for x, y in zip(a + [None] * (len(b) - len(a)), b + [None] * (len(a) - len(b))):
        r = _cmp_item(x, y)
        if r:
            return r
    return 0


class _MavenKey:
    __slots__ = ("items",)

    def __init__(self, items: List):
        self.items = items

    def _c(self, other) -> int:
        return _cmp_item(self.items, other.items)

    def __lt__(self, other):
        return self._c(other) < 0

    def __gt__(self, other):
        return self._c(other) > 0

    def __le__(self, other):
        return self._c(other) <= 0

    def __ge__(self, other):
        return self._c(other) >= 0

    def __eq__(self, other):
        return isinstance(other, _MavenKey) and self._c(other) == 0

    def __hash__(self):
        return hash(repr(self.items))


def _maven(v: str) -> Optional[_MavenKey]:
    v = v.strip()
    if not v or not re.fullmatch(r"[0-9A-Za-z._+-]+", v):
        return None
    return _MavenKey(_maven_items(v))


# ---------------------------------------------------------------------------------------------

# ---------------------------------------------------------------------------------------------
# RubyGems: Gem::Version. Segments are runs of digits or letters; a letter segment makes a
# prerelease and sorts before any number; trailing zeros do not count (1.0 == 1).

class _GemKey:
    __slots__ = ("segs",)

    def __init__(self, segs):
        self.segs = segs

    def _c(self, other) -> int:
        a, b = self.segs, other.segs
        for i in range(max(len(a), len(b))):
            x = a[i] if i < len(a) else 0
            y = b[i] if i < len(b) else 0
            if x == y:
                continue
            if isinstance(x, str) and not isinstance(y, str):
                return -1
            if isinstance(y, str) and not isinstance(x, str):
                return 1
            return -1 if x < y else 1
        return 0

    def __lt__(self, o): return self._c(o) < 0
    def __gt__(self, o): return self._c(o) > 0
    def __le__(self, o): return self._c(o) <= 0
    def __ge__(self, o): return self._c(o) >= 0
    def __eq__(self, o): return isinstance(o, _GemKey) and self._c(o) == 0
    def __hash__(self): return hash(tuple(self.segs))


def _rubygems(v: str) -> Optional[_GemKey]:
    v = v.strip().replace("-", ".pre.")                 # Gem::Version reads `-` as `.pre.`
    if not re.fullmatch(r"[0-9]+(?:[.-]?[0-9A-Za-z]+)*", v):
        return None
    segs: List = [int(s) if s.isdigit() else s for s in re.findall(r"[0-9]+|[A-Za-z]+", v)]
    # canonical segments: trailing zeros go, and so do zeros right before the prerelease part
    first_str = next((i for i, s in enumerate(segs) if isinstance(s, str)), len(segs))
    release, pre = segs[:first_str], segs[first_str:]
    while release and release[-1] == 0:
        release.pop()
    while pre and pre[-1] == 0:
        pre.pop()
    return _GemKey(release + pre)


# ---------------------------------------------------------------------------------------------
# Packagist: Composer's VersionParser. Up to four numbers, then a stability: dev < alpha <
# beta < RC < stable < patch (`-p1`, `-pl1`); a leading `v` is ignored; `dev-<branch>` is not a
# version.

_COMPOSER_STABILITY = {"dev": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2, "rc": 3, "": 4, "stable": 4,
                       "patch": 5, "pl": 5, "p": 5}
_COMPOSER = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?"
                       r"(?:[._-]?(stable|beta|b|rc|alpha|a|patch|pl|p|dev)(?:[.-]?(\d+))?)?$", re.I)


def _packagist(v: str) -> Optional[Tuple]:
    m = _COMPOSER.match(v.strip())
    if not m:
        return None
    nums = tuple(int(g or 0) for g in m.groups()[:4])
    stability = _COMPOSER_STABILITY[(m.group(5) or "").lower()]
    return (*nums, stability, int(m.group(6) or 0))


def _go(v: str) -> Optional[Tuple]:
    v = v.strip()
    v = v[:-len("+incompatible")] if v.endswith("+incompatible") else v
    return _semver(v if v.startswith("v") else "v" + v)


_PARSERS = {PYPI: _pep440, NPM: _semver, CARGO: _semver, SWIFT: _semver, NUGET: _nuget, MAVEN: _maven, GO: _go,
            RUBYGEMS: _rubygems, PACKAGIST: _packagist, PUB: _semver, HEX: _semver}


def _distro_parser(ecosystem: str):
    """Linux distribution ecosystems carry their release (`Debian:12`, `Alpine:v3.18`,
    `Ubuntu:22.04:LTS`): the family decides the order."""
    from frame.sca.distro_versions import apk_key, azure_linux_key, dpkg_key, rpm_key
    return {"Debian": dpkg_key, "Ubuntu": dpkg_key, "Alpine": apk_key,
            "AlmaLinux": rpm_key, "Rocky Linux": rpm_key, "Red Hat": rpm_key, "Wolfi": apk_key,
            "Azure Linux": azure_linux_key, "openSUSE": rpm_key,
            "SUSE": rpm_key}.get(ecosystem.split(":", 1)[0])


@lru_cache(maxsize=65536)
def sort_key(ecosystem: str, version: str) -> Optional[Any]:
    parse = _PARSERS.get(ecosystem) or _distro_parser(ecosystem)
    if parse is None or not isinstance(version, str):
        return None
    try:
        return parse(version)
    except (ValueError, TypeError):
        return None


def compare(ecosystem: str, a: str, b: str) -> int:
    ka, kb = sort_key(ecosystem, a), sort_key(ecosystem, b)
    if ka is None or kb is None:
        raise ValueError(f"not a {ecosystem} version: {a if ka is None else b!r}")
    return (ka > kb) - (ka < kb)


def sorted_versions(ecosystem: str, versions) -> List[str]:
    return sorted((v for v in versions if sort_key(ecosystem, v) is not None),
                  key=cmp_to_key(lambda a, b: compare(ecosystem, a, b)))
