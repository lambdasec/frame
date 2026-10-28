"""Version order of Linux distribution packages, as their package managers define it.

dpkg (Debian, Ubuntu): `[epoch:]upstream[-revision]`. Upstream and revision are compared by
alternating runs of non-digits and digits: in a non-digit run, `~` sorts before everything
(even the end of the string), then letters, then everything else; digit runs compare as
numbers. (deb-version(7), dpkg's lib/dpkg/version.c `verrevcmp`.)

apk (Alpine): `number{.number}...{letter}{_suffix{number}}...{~hash}{-r#}`, where the suffixes
_alpha < _beta < _pre < _rc < (none) < _cvs < _svn < _git < _hg < _p, and `-rN` is the package
revision (apk-tools' src/version.c).

Both are checked against the real tools (`dpkg --compare-versions`, `apk version -t`) in
tests/test_distro_versions.py.
"""

from __future__ import annotations

import re
from typing import Tuple


def _order(c: str) -> int:
    if c == "~":
        return -1
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i]) if i < len(a) and not a[i].isdigit() else 0
            bc = _order(b[j]) if j < len(b) and not b[j].isdigit() else 0
            if ac != bc:
                return -1 if ac < bc else 1
            i += 1 if i < len(a) and not a[i].isdigit() else 0
            j += 1 if j < len(b) and not b[j].isdigit() else 0
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not diff:
                diff = (a[i] > b[j]) - (a[i] < b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if diff:
            return diff
    return 0


def _split_dpkg(v: str) -> Tuple[int, str, str]:
    v = v.strip()
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        if not e.isdigit():
            raise ValueError(f"bad epoch in {v!r}")
        epoch = int(e)
    upstream, _, revision = v.rpartition("-") if "-" in v else (v, "", "")
    if not upstream:
        raise ValueError("empty version")
    return epoch, upstream, revision


def dpkg_compare(a: str, b: str) -> int:
    ea, ua, ra = _split_dpkg(a)
    eb, ub, rb = _split_dpkg(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _verrevcmp(ua, ub) or _verrevcmp(ra, rb)


# -- apk ---------------------------------------------------------------------------------------
# A port of apk-tools 2.14.4 src/version.c (next_token, get_token, apk_version_compare_blob_fuzzy),
# the version Alpine 3.20 ships; tests/test_distro_versions.py checks it against `apk version -t`.

(_INVALID, _DIGIT_OR_ZERO, _DIGIT, _LETTER, _SUFFIX, _SUFFIX_NO, _REVISION_NO, _END) = range(-1, 7)
_PRE = ("alpha", "beta", "pre", "rc")
_POST = ("cvs", "svn", "git", "hg", "p")


class _Blob:
    __slots__ = ("s", "i")

    def __init__(self, s: str):
        self.s, self.i = s, 0

    def __len__(self):
        return len(self.s) - self.i

    def at(self, k: int = 0) -> str:
        return self.s[self.i + k] if self.i + k < len(self.s) else "\0"


def _next_token(t: int, b: _Blob) -> int:
    n = _INVALID
    c = b.at()
    if len(b) == 0 or c == "\0":
        n = _END
    elif t in (_DIGIT, _DIGIT_OR_ZERO) and c.islower() and c.isascii():
        n = _LETTER
    elif t == _LETTER and c.isdigit():
        n = _DIGIT
    elif t == _SUFFIX and c.isdigit():
        n = _SUFFIX_NO
    else:
        if c == ".":
            n = _DIGIT_OR_ZERO
        elif c == "_":
            n = _SUFFIX
        elif c == "-":
            if len(b) > 1 and b.at(1) == "r":
                n = _REVISION_NO
                b.i += 1
        b.i += 1
    if n < t and not ((n == _DIGIT_OR_ZERO and t == _DIGIT) or (n == _SUFFIX and t == _SUFFIX_NO)
                      or (n == _DIGIT and t == _LETTER)):
        n = _INVALID
    return n


def _get_token(t: int, b: _Blob) -> Tuple[int, int]:
    """(value, next type)."""
    if len(b) <= 0:
        return 0, _END
    i, nt, v = 0, _INVALID, 0
    if t == _DIGIT_OR_ZERO and b.at() == "0":
        while i + 1 < len(b) and b.at(i + 1) == "0":     # leading zeros: a special, negative value
            i += 1
        nt, v = _DIGIT, -i
    elif t in (_DIGIT_OR_ZERO, _DIGIT, _SUFFIX_NO, _REVISION_NO):
        while i < len(b) and b.at(i).isdigit():
            v = v * 10 + int(b.at(i))
            i += 1
        if i >= 18:
            return -1, _INVALID
    elif t == _LETTER:
        v = ord(b.at())
        i = 1
    elif t == _SUFFIX:
        rest = b.s[b.i:]
        for k, suf in enumerate(_PRE):
            if rest.startswith(suf):
                v, i = k - len(_PRE), len(suf)
                break
        else:
            for k, suf in enumerate(_POST):
                if rest.startswith(suf):
                    v, i = k, len(suf)
                    break
            else:
                return -1, _INVALID
    else:
        return -1, _INVALID
    b.i += i
    if len(b) == 0:
        return v, _END
    if nt != _INVALID:
        return v, nt
    return v, _next_token(t, b)


def apk_compare(a: str, b: str) -> int:
    ba, bb = _Blob(a.strip()), _Blob(b.strip())
    at = bt = _DIGIT
    av = bv = 0
    while at == bt and at not in (_END, _INVALID) and av == bv:
        av, at = _get_token(at, ba)
        bv, bt = _get_token(bt, bb)
    if av != bv:
        return -1 if av < bv else 1
    if at == bt:
        return 0
    if at == _SUFFIX and _get_token(at, ba)[0] < 0:
        return -1
    if bt == _SUFFIX and _get_token(bt, bb)[0] < 0:
        return 1
    if at > bt:
        return -1
    if bt > at:
        return 1
    return 0


# -- rpm ---------------------------------------------------------------------------------------
# rpmvercmp from rpm's rpmio/rpmvercmp.c (rpm 4.15+: `~` sorts before anything, `^` after the base
# version but before any other suffix), line by line, then epoch:version-release as rpm compares it.

def _ralpha(c: str) -> bool:
    return ("a" <= c <= "z") or ("A" <= c <= "Z")


def _rdigit(c: str) -> bool:
    return "0" <= c <= "9"


def rpmvercmp(a: str, b: str) -> int:
    if a == b:
        return 0
    one, two, n1, n2 = 0, 0, len(a), len(b)
    at = lambda s, i: s[i] if i < len(s) else ""                       # noqa: E731
    while one < n1 or two < n2:
        while one < n1 and not (_ralpha(a[one]) or _rdigit(a[one])) and a[one] not in "~^":
            one += 1
        while two < n2 and not (_ralpha(b[two]) or _rdigit(b[two])) and b[two] not in "~^":
            two += 1
        c1, c2 = at(a, one), at(b, two)
        if c1 == "~" or c2 == "~":                     # tilde: before everything else
            if c1 != "~":
                return 1
            if c2 != "~":
                return -1
            one, two = one + 1, two + 1
            continue
        if c1 == "^" or c2 == "^":                     # caret: after the base, before anything else
            if not c1:
                return -1
            if not c2:
                return 1
            if c1 != "^":
                return 1
            if c2 != "^":
                return -1
            one, two = one + 1, two + 1
            continue
        if not (c1 and c2):
            break
        s1, s2 = one, two
        if _rdigit(a[s1]):
            while s1 < n1 and _rdigit(a[s1]):
                s1 += 1
            while s2 < n2 and _rdigit(b[s2]):
                s2 += 1
            isnum = True
        else:
            while s1 < n1 and _ralpha(a[s1]):
                s1 += 1
            while s2 < n2 and _ralpha(b[s2]):
                s2 += 1
            isnum = False
        if one == s1:
            return -1                                  # arbitrary (rpm says so)
        if two == s2:
            return 1 if isnum else -1                  # numeric segments are newer than alpha
        seg1, seg2 = a[one:s1], b[two:s2]
        if isnum:
            seg1, seg2 = seg1.lstrip("0"), seg2.lstrip("0")
            if len(seg1) != len(seg2):
                return 1 if len(seg1) > len(seg2) else -1
        if seg1 != seg2:
            return -1 if seg1 < seg2 else 1
        one, two = s1, s2
    if one >= n1 and two >= n2:
        return 0
    return -1 if one >= n1 else 1


def _split_evr(v: str):
    epoch, _, rest = v.partition(":") if ":" in v else ("0", "", v)
    if not epoch.isdigit():
        raise ValueError(f"bad rpm epoch in {v!r}")
    version, sep, release = rest.rpartition("-")
    return int(epoch), (version if sep else rest), (release if sep else None)


def rpm_compare(a: str, b: str) -> int:
    """epoch:version-release order as rpm's labelCompare: a missing epoch is 0, a missing
    release is empty (so `1.0` sorts before `1.0-1`)."""
    ea, va, ra = _split_evr(a)
    eb, vb, rb = _split_evr(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return rpmvercmp(va, vb) or rpmvercmp(ra or "", rb or "")


class _CmpKey:
    __slots__ = ("v", "cmp")

    def __init__(self, v: str, cmp):
        self.v, self.cmp = v, cmp
        cmp(v, v)                                          # raises ValueError for a malformed version

    def __lt__(self, o): return self.cmp(self.v, o.v) < 0
    def __gt__(self, o): return self.cmp(self.v, o.v) > 0
    def __le__(self, o): return self.cmp(self.v, o.v) <= 0
    def __ge__(self, o): return self.cmp(self.v, o.v) >= 0
    def __eq__(self, o): return isinstance(o, _CmpKey) and self.cmp(self.v, o.v) == 0
    def __hash__(self): return hash(self.v)


def dpkg_key(v: str) -> _CmpKey:
    return _CmpKey(v, dpkg_compare)


def apk_key(v: str) -> _CmpKey:
    return _CmpKey(v, apk_compare)


def rpm_key(v: str) -> _CmpKey:
    return _CmpKey(v, rpm_compare)
