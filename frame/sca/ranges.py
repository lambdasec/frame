"""Version requirements per registry: does a version satisfy a declared range.

    npm (also yarn, pnpm):  ^1.2.3  ~1.2  >=1 <2  1.x  1.2 - 1.4  a || b  *   (node-semver)
    PyPI:                   >=1.0,<2  ~=1.4  ==1.2.*  !=1.3   and Poetry's ^1.2 / ~1.2
    NuGet, Maven:           [1.0,2.0)  (,1.0]  [1.2]   bare `1.0` (NuGet: >=1.0; Maven: a soft
                            requirement the build may override, so any version satisfies it)

`satisfies` returns None when the text is not a range of that registry (a git URL, a tag,
`workspace:*`): the planner then says the requirement is unknown instead of guessing.
"""

from __future__ import annotations

import re
from typing import Callable, List, Optional, Tuple

from frame.sca.model import CARGO, HEX, MAVEN, NPM, NUGET, PACKAGIST, PUB, PYPI, RUBYGEMS
from frame.sca.versions import compare, sort_key

Comparator = Tuple[str, str]                   # (op, version), op in < <= > >= =


def _cmp(eco: str, v: str, op: str, w: str) -> bool:
    c = compare(eco, v, w)
    return {"<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0, "=": c == 0, "!=": c != 0}[op]


# ---------------------------------------------------------------------------------------------
# npm (node-semver), also Cargo's requirement syntax (caret by default)

_XR = r"(?:[xX*]|\d+)"
_PARTIAL = re.compile(rf"^v?\s*({_XR})(?:\.({_XR})(?:\.({_XR})(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?)?)?$")


def _partial(s: str) -> Optional[Tuple[Optional[int], Optional[int], Optional[int], Optional[str]]]:
    m = _PARTIAL.match(s.strip())
    if not m:
        return None
    nums = [None if g is None or g in "xX*" else int(g) for g in m.groups()[:3]]
    for i in range(1, 3):                      # 1.x.3 means 1.x
        if nums[i - 1] is None:
            nums[i] = None
    return nums[0], nums[1], nums[2], m.group(4)


def _v(ma, mi, pa, pre=None) -> str:
    return f"{ma}.{mi}.{pa}" + (f"-{pre}" if pre else "")


def _npm_simple(tok: str, default_caret: bool = False) -> Optional[List[Comparator]]:
    tok = tok.strip()
    if tok in ("", "*", "x", "X", "latest"):
        return [(">=", "0.0.0-0")]
    m = re.match(r"^(<=|>=|<|>|=|\^|~>|~)?\s*(.*)$", tok)
    op, rest = m.group(1) or "", m.group(2)
    p = _partial(rest)
    if p is None:
        return None
    ma, mi, pa, pre = p
    if op == "" and default_caret:
        op = "^"
    if op in ("", "="):
        if ma is None:
            return [(">=", "0.0.0-0")]
        if mi is None:
            return [(">=", _v(ma, 0, 0)), ("<", _v(ma + 1, 0, 0, "0"))]
        if pa is None:
            return [(">=", _v(ma, mi, 0)), ("<", _v(ma, mi + 1, 0, "0"))]
        return [("=", _v(ma, mi, pa, pre))]
    if op in ("~", "~>"):
        if ma is None:
            return [(">=", "0.0.0-0")]
        if mi is None:
            return [(">=", _v(ma, 0, 0)), ("<", _v(ma + 1, 0, 0, "0"))]
        return [(">=", _v(ma, mi, pa or 0, pre)), ("<", _v(ma, mi + 1, 0, "0"))]
    if op == "^":
        if ma is None:
            return [(">=", "0.0.0-0")]
        lo = _v(ma, mi or 0, pa or 0, pre)
        if ma > 0 or mi is None:
            hi = _v(ma + 1, 0, 0, "0")
        elif mi > 0 or pa is None:
            hi = _v(0, mi + 1, 0, "0")
        else:
            hi = _v(0, 0, pa + 1, "0")
        return [(">=", lo), ("<", hi)]
    # comparison operators with a partial version
    if ma is None:
        return [("<", "0.0.0-0")] if op in ("<", ">") else [(">=", "0.0.0-0")]
    if op == ">":
        if mi is None:
            return [(">=", _v(ma + 1, 0, 0))]
        if pa is None:
            return [(">=", _v(ma, mi + 1, 0))]
        return [(">", _v(ma, mi, pa, pre))]
    if op == ">=":
        return [(">=", _v(ma, mi or 0, pa or 0, pre))]
    if op == "<":
        return [("<", _v(ma, mi or 0, pa or 0, pre or ("0" if mi is None or pa is None else None)))]
    if op == "<=":
        if mi is None:
            return [("<", _v(ma + 1, 0, 0, "0"))]
        if pa is None:
            return [("<", _v(ma, mi + 1, 0, "0"))]
        return [("<=", _v(ma, mi, pa, pre))]
    return None


def _npm_range(spec: str, default_caret: bool = False) -> Optional[List[List[Comparator]]]:
    """A range set: OR of ANDs of comparators."""
    spec = spec.strip()
    if spec.startswith(("npm:", "workspace:", "file:", "link:", "git", "http", "github:")) or "/" in spec:
        return None
    alternatives = []
    for alt in spec.split("||"):
        alt = alt.strip()
        hy = re.match(r"^(\S+)\s+-\s+(\S+)$", alt)
        if hy:
            lo, hi = _partial(hy.group(1)), _partial(hy.group(2))
            if lo is None or hi is None:
                return None
            comps = [(">=", _v(lo[0] or 0, lo[1] or 0, lo[2] or 0, lo[3]))]
            if hi[0] is not None:
                if hi[1] is None:
                    comps.append(("<", _v(hi[0] + 1, 0, 0, "0")))
                elif hi[2] is None:
                    comps.append(("<", _v(hi[0], hi[1] + 1, 0, "0")))
                else:
                    comps.append(("<=", _v(hi[0], hi[1], hi[2], hi[3])))
            alternatives.append(comps)
            continue
        comps: List[Comparator] = []
        toks = re.findall(r"(?:<=|>=|<|>|=|\^|~>|~)?\s*[^\s<>=^~,]+", alt.replace(",", " ")) if alt else [""]
        for tok in toks or [""]:
            c = _npm_simple(tok, default_caret)
            if c is None:
                return None
            comps += c
        alternatives.append(comps)
    return alternatives


def _semver_prerelease(v: str) -> Optional[Tuple[int, int, int]]:
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)-", v.strip())
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def _npm_satisfies(version: str, spec: str, eco: str = NPM, default_caret: bool = False) -> Optional[bool]:
    alts = _npm_range(spec, default_caret)
    if alts is None or sort_key(NPM, version) is None:
        return None
    pre = _semver_prerelease(version)
    for comps in alts:
        if not all(_cmp(NPM, version, op, w) for op, w in comps):
            continue
        # node-semver: a prerelease satisfies a range only through a comparator on the same
        # [major, minor, patch] that itself has a prerelease
        if pre is not None and not any(_semver_prerelease(w) == pre and not w.endswith("-0")
                                       for _, w in comps):
            continue
        return True
    return False


# ---------------------------------------------------------------------------------------------
# PEP 440 specifiers (and Poetry's caret / tilde)

def _pep440_release(v: str) -> List[int]:
    m = re.match(r"^\s*v?(?:\d+!)?(\d+(?:\.\d+)*)", v)
    return [int(x) for x in m.group(1).split(".")] if m else []


def _is_prerelease_pep440(v: str) -> bool:
    return bool(re.search(r"(a|b|c|rc|alpha|beta|pre|preview|dev)\d*", v.lower().split("+", 1)[0]))


def _poetry(spec: str) -> Optional[str]:
    """Poetry's `^1.2.3` / `~1.2` as PEP 440."""
    m = re.match(r"^(\^|~(?!=))\s*(\d+(?:\.\d+)*)$", spec.strip())
    if not m:
        return None
    parts = [int(x) for x in m.group(2).split(".")]
    if m.group(1) == "^":
        i = next((k for k, p in enumerate(parts) if p != 0), len(parts) - 1)
        upper = parts[:i + 1]
        upper[-1] += 1
    else:
        upper = parts[:2] if len(parts) >= 2 else parts[:1]
        upper[-1] += 1
    return f">={m.group(2)},<{'.'.join(map(str, upper))}"


def _pep440_satisfies(version: str, spec: str, allow_pre: bool = False) -> Optional[bool]:
    spec = spec.strip().strip("()")
    if not spec or spec == "*":
        if sort_key(PYPI, version) is None:
            return None
        return allow_pre or not _is_prerelease_pep440(version)
    if spec[0] in "^~" and not spec.startswith("~="):
        spec = _poetry(spec) or spec
    if sort_key(PYPI, version) is None:
        return None
    pre_ok = allow_pre or any(_is_prerelease_pep440(c) for c in re.split(r"[<>=!~,\s]+", spec) if c)
    if _is_prerelease_pep440(version) and not pre_ok:
        return False
    for clause in [c.strip() for c in spec.split(",") if c.strip()]:
        m = re.match(r"^(===|~=|==|!=|<=|>=|<|>)\s*(.+)$", clause)
        if not m:
            m = re.match(r"^()(\d[\w.!+*-]*)$", clause)         # a bare version: ==
            if not m:
                return None
        op, w = m.group(1) or "==", m.group(2).strip()
        if op == "===":
            if version != w:
                return False
            continue
        if w.endswith(".*"):
            prefix = _pep440_release(w[:-2])
            got = _pep440_release(version)
            match = got[:len(prefix)] + [0] * max(0, len(prefix) - len(got)) == prefix
            if (op == "==" and not match) or (op == "!=" and match):
                return False
            continue
        if sort_key(PYPI, w) is None:
            return None
        if op == "~=":
            rel = _pep440_release(w)
            if len(rel) < 2 or compare(PYPI, version, w) < 0:
                return False
            if _pep440_release(version)[:len(rel) - 1] != rel[:-1]:
                return False
            continue
        if not _cmp(PYPI, version, {"==": "=", "!=": "!="}.get(op, op), w):
            return False
        # PEP 440: `<V` excludes pre-releases of V (unless V is one); `>V` excludes
        # post-releases of V (unless V is one)
        same = _pep440_release(version) == _pep440_release(w)
        if op == "<" and same and _is_prerelease_pep440(version) and not _is_prerelease_pep440(w):
            return False
        if op == ">" and same and ".post" in version.lower() and ".post" not in w.lower() and \
                re.sub(r"\.post\d*.*$", "", version.lower()) == w.lower():
            return False
    return True


# ---------------------------------------------------------------------------------------------
# NuGet and Maven interval notation

def _interval_satisfies(eco: str, version: str, spec: str) -> Optional[bool]:
    spec = spec.strip()
    if sort_key(eco, version) is None:
        return None
    if not spec:
        return True
    if spec[0] not in "[(":
        if sort_key(eco, spec) is None:
            return None
        return True if eco == MAVEN else compare(eco, version, spec) >= 0   # Maven: a soft requirement
    for part in re.findall(r"[\[(][^\])]*[\])]", spec):             # Maven allows several, OR'ed
        lo_inc, hi_inc = part[0] == "[", part[-1] == "]"
        body = part[1:-1]
        if "," not in body:
            if sort_key(eco, body) is None:
                return None
            if compare(eco, version, body) == 0:
                return True
            continue
        lo, hi = (x.strip() for x in body.split(",", 1))
        if (lo and sort_key(eco, lo) is None) or (hi and sort_key(eco, hi) is None):
            return None
        if lo and not (compare(eco, version, lo) >= 0 if lo_inc else compare(eco, version, lo) > 0):
            continue
        if hi and not (compare(eco, version, hi) <= 0 if hi_inc else compare(eco, version, hi) < 0):
            continue
        return True
    return False


# ---------------------------------------------------------------------------------------------
# RubyGems (Gem::Requirement: comma = and; `~> 2.2` is `>= 2.2, < 3`) and Hex (Elixir's
# Version requirements: `and` / `or`; `~> 2.1.2` is `>= 2.1.2 and < 2.2.0`)

def _pessimistic_upper(eco: str, v: str) -> Optional[str]:
    """Gem::Version#bump / Elixir's ~>: drop the prerelease and the last release segment, then
    increment the new last one (`2.2` -> `3`, `2.2.0` -> `2.3`)."""
    nums = re.findall(r"\d+", v.split("-")[0] if eco == HEX else v)
    if eco == RUBYGEMS:
        m = re.match(r"^[\d.]*", v.strip())
        nums = [x for x in (m.group(0) if m else "").split(".") if x]
    if not nums:
        return None
    nums = [int(x) for x in nums]
    if len(nums) > 1:
        nums.pop()
    nums[-1] += 1
    return ".".join(map(str, nums))


def _ops_satisfies(eco: str, version: str, clauses: List[str]) -> Optional[bool]:
    for clause in clauses:
        m = re.match(r"^\s*(~>|>=|<=|!=|==|=|>|<)?\s*v?(\S+)\s*$", clause)
        if not m or sort_key(eco, m.group(2)) is None:
            return None
        op, w = m.group(1) or "=", m.group(2)
        if op == "~>":
            upper = _pessimistic_upper(eco, w)
            # RubyGems compares the release part (`3.0.0.beta1` -> `3.0.0`) with the upper bound
            below = re.match(r"^[\d.]*\d", version).group(0) if eco == RUBYGEMS and \
                re.match(r"^[\d.]*\d", version) else version
            if upper is None or not (_cmp(eco, version, ">=", w) and _cmp(eco, below, "<", upper)):
                return False
            continue
        if not _cmp(eco, version, {"==": "=", "=": "="}.get(op, op), w):
            return False
    return True


def _rubygems_satisfies(version: str, spec: str) -> Optional[bool]:
    if sort_key(RUBYGEMS, version) is None:
        return None
    clauses = [c for c in spec.strip().strip("()").split(",") if c.strip()]
    return _ops_satisfies(RUBYGEMS, version, clauses or [">= 0"])


def _hex_satisfies(version: str, spec: str) -> Optional[bool]:
    if sort_key(HEX, version) is None:
        return None
    results = [_ops_satisfies(HEX, version, [c for c in alt.split(" and ") if c.strip()])
               for alt in spec.split(" or ")]
    if any(r is None for r in results):
        return None
    return any(results)


# ---------------------------------------------------------------------------------------------
# Composer constraints: `||` (or `|`) between alternatives, `,` or space within one; `^` like
# npm; `~1.2` is `>=1.2 <2.0` and `~1.2.3` is `>=1.2.3 <1.3.0`; `1.2.*`; `1.0 - 2.0`; `@dev`
# stability flags are ignored here (they decide which releases are installable, not ranges)

def _composer_simple(tok: str) -> Optional[List[Comparator]]:
    tok = tok.split("@", 1)[0].strip()
    if tok in ("", "*"):
        return [(">=", "0")]
    m = re.match(r"^(\^|~|>=|<=|!=|==|=|>|<)?\s*v?([\d.*xX]+(?:[-.]?[A-Za-z]+\d*)?)$", tok)
    if not m:
        return None
    op, ver = m.group(1) or "", m.group(2)
    nums = [p for p in ver.split(".") if p not in ("*", "x", "X")]
    if "*" in ver or "x" in ver.lower() and re.search(r"\.[xX*]", ver):
        base = [int(re.match(r"\d+", p).group(0)) for p in nums]
        if not base:
            return [(">=", "0")]
        upper = base[:-1] + [base[-1] + 1]
        return [(">=", ".".join(map(str, base))), ("<", ".".join(map(str, upper)) + "-dev")]
    if op == "^":
        parts = [int(re.match(r"\d+", p).group(0)) for p in nums]
        i = next((k for k, x in enumerate(parts) if x != 0), len(parts) - 1)
        upper = parts[:i + 1]
        upper[-1] += 1
        return [(">=", ver), ("<", ".".join(map(str, upper)) + "-dev")]
    if op == "~":
        parts = [int(re.match(r"\d+", p).group(0)) for p in nums]
        upper = parts[:-1] if len(parts) > 1 else parts[:]
        upper[-1] += 1
        return [(">=", ver), ("<", ".".join(map(str, upper)) + "-dev")]
    return [({"": "=", "==": "=", "=": "="}.get(op, op), ver)]


def _packagist_satisfies(version: str, spec: str) -> Optional[bool]:
    if sort_key(PACKAGIST, version) is None:
        return None
    for alt in re.split(r"\s*\|\|?\s*", spec.strip()):
        hy = re.match(r"^(\S+)\s+-\s+(\S+)$", alt)
        if hy:
            comps = [(">=", hy.group(1)), ("<=", hy.group(2))]
        else:
            comps = []
            for tok in [t for t in re.split(r"\s*,\s*|\s+", alt) if t]:
                c = _composer_simple(tok)
                if c is None:
                    return None
                comps += c
        if all(sort_key(PACKAGIST, w) is not None for _, w in comps) and \
                all(_cmp(PACKAGIST, version, op, w) for op, w in comps):
            return True
    return False


def _pub_satisfies(version: str, spec: str) -> Optional[bool]:
    return _npm_satisfies(version, "*" if spec.strip() == "any" else spec)


_SATISFIES: dict = {
    NPM: lambda v, s: _npm_satisfies(v, s),
    CARGO: lambda v, s: _npm_satisfies(v, s, CARGO, default_caret=True),
    PYPI: _pep440_satisfies,
    NUGET: lambda v, s: _interval_satisfies(NUGET, v, s),
    MAVEN: lambda v, s: _interval_satisfies(MAVEN, v, s),
    RUBYGEMS: _rubygems_satisfies,
    HEX: _hex_satisfies,
    PACKAGIST: _packagist_satisfies,
    PUB: _pub_satisfies,
}


def satisfies(ecosystem: str, version: str, spec: str) -> Optional[bool]:
    fn: Optional[Callable] = _SATISFIES.get(ecosystem)
    if fn is None or not isinstance(spec, str):
        return None
    try:
        return fn(version, spec)
    except (ValueError, TypeError, KeyError):
        return None
