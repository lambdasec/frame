"""Cross-package upgrade planning with Z3.

When a package in between pins a range that excludes the fix (express@4.17.1 requires
qs 6.7.0), the per-package plan can only override. Often a newer version of that package
in between admits the fix, and upgrading it is the cleaner change. Choosing which packages to
upgrade, to which versions, so that every declared range is still satisfied and no vulnerable
version remains, is a constraint problem over all of them together.

Encoding, per lockfile, over the vulnerable packages and all their ancestors up to the direct
dependencies (the only packages whose choice can matter):

    x_p        index of the chosen version of p among its candidates (current, then every
               newer stable, non-deprecated release from the registry)
    present_p  p is still installed: it is direct, or some present parent's chosen version
               still depends on it (a newer parent may drop the dependency altogether)

    hard   present_q and x_q = i  =>  x_p in { j : C_p[j] satisfies range_{C_q[i]}(p) }
           a direct dependency stays installed
    soft   present_p  =>  C_p[x_p] is affected by no advisory      (weight: one per package)
    min    1) major-version jumps, 2) direct requirements raised, 3) packages changed (leaving
           the tree included), 4) distance of the direct dependencies from their current
           versions, 5) distance of the rest

The current version's ranges are the lockfile's where it records them (npm), else the
registry's (uv.lock records none); a range known nowhere holds the child at its current
version, and a candidate whose dependencies the registry does not give is never chosen for a
parent. Never `*`: an unknown range is not an open one. What the solver cannot model it does
not claim: the other dependencies of an upgraded package are resolved by re-locking, which may
pick other versions of packages outside this set.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from frame.sca.model import CARGO, NPM, NUGET, PYPI, DependencyFile, normalize_name
from frame.sca.osv import is_affected
from frame.sca.ranges import satisfies
from frame.sca.registry import is_prerelease
from frame.sca.versions import sort_key, sorted_versions

MAX_CANDIDATES = 150
SUPPORTED = (NPM, PYPI, CARGO, NUGET)
# NuGet resolves a transitive package to the LOWEST version every requirer admits ("lowest
# applicable"), not the newest: a child is what its parents' ranges force, nothing above it
LOWEST_APPLICABLE = (NUGET,)
_HOLD, _UNKNOWN = "\0hold", "\0unknown"       # range markers: keep the current child / never choose


def _major(v: str) -> Optional[int]:
    k = v.lstrip("v").split(".", 1)[0]
    return int(k) if k.isdigit() else None


@dataclass
class Change:
    package: str
    current: str
    target: Optional[str]          # None: no longer installed
    direct: bool
    raise_requirement: bool        # the project's own range excludes the target
    vulnerable: bool               # this package had a vulnerable version


@dataclass
class Solution:
    path: str
    changes: List[Change] = field(default_factory=list)
    fixed: Set[str] = field(default_factory=set)          # vulnerable package keys no longer vulnerable
    unresolved: Set[str] = field(default_factory=set)     # vulnerable package keys the upgrades cannot fix
    reason: str = ""


def _candidates(eco: str, current: str, meta: Optional[Dict[str, dict]]) -> List[str]:
    if not meta:
        return [current]
    cur = sort_key(eco, current)
    newer = [v for v, m in meta.items() if not m["deprecated"] and not is_prerelease(v, eco)
             and sort_key(eco, v) is not None and cur is not None and sort_key(eco, v) > cur]
    return [current] + sorted_versions(eco, newer)[:MAX_CANDIDATES]


def solve_file(df: DependencyFile, vulnerable: Set[str], db, registry, timeout_ms: int = 20000) -> Optional[Solution]:
    """`vulnerable`: keys of the vulnerable packages in `df` to fix. None when the ecosystem is
    not supported or the registry has nothing for these packages."""
    import z3
    eco = df.ecosystem
    if eco not in SUPPORTED or not vulnerable:
        return None
    parents: Dict[str, Set[str]] = {}
    for q, cs in df.edges.items():
        for c in cs:
            parents.setdefault(c, set()).add(q)
    scope: Set[str] = set()
    stack = list(vulnerable)
    while stack:
        k = stack.pop()
        if k in scope or k not in df.packages:
            continue
        scope.add(k)
        stack.extend(parents.get(k, ()))
    pkg = {k: df.packages[k] for k in scope}
    meta = {k: registry.versions(p.name) for k, p in pkg.items()}
    if not any(meta.values()):
        return Solution(df.path, reason="no registry metadata for these packages")
    cands = {k: _candidates(eco, p.version, meta[k]) for k, p in pkg.items()}
    from frame.sca.plan import fixable
    advisories = {k: fixable(db.advisories(eco, p.name)) for k, p in pkg.items()}   # an unfixable one blocks nothing
    bad = {k: [any(is_affected(eco, v, a) for a in advisories[k]) for v in cands[k]] for k in scope}
    roots = {k for k, p in pkg.items() if p.direct or not parents.get(k)}

    opt = z3.Optimize()
    opt.set("timeout", timeout_ms)
    x = {k: z3.Int(f"x_{i}") for i, k in enumerate(sorted(scope))}
    present = {k: z3.Bool(f"p_{i}") for i, k in enumerate(sorted(scope))}
    for k in scope:
        opt.add(x[k] >= 0, x[k] < len(cands[k]))

    def registry_range(q: str, version: str, n: str) -> Optional[str]:
        deps = registry.deps(pkg[q].name, version)
        if deps is None:
            return _UNKNOWN
        return next((r for name, r in deps.items() if normalize_name(eco, name) == n), None)

    def range_of(q: str, i: int, child: str) -> Optional[str]:
        """The range version C_q[i] declares for `child`; None if it does not depend on it."""
        n = normalize_name(eco, pkg[child].name)
        if i == 0:                                        # the current version: it does depend on it
            if child not in df.edges.get(q, ()):
                return None
            recorded = df.requires.get(q, {}).get(n)
            if recorded:
                return recorded
            r = registry_range(q, pkg[q].version, n)
            return r if r not in (None, _UNKNOWN) else _HOLD
        return registry_range(q, cands[q][i], n)

    for p in scope:
        if p in roots:
            opt.add(present[p])
            continue
        holders = []
        admits: List[Tuple[object, List[int]]] = []          # (holder condition, the child versions it admits)
        for q in parents.get(p, ()):
            if q not in scope:
                continue
            for i in range(len(cands[q])):
                r = range_of(q, i, p)
                if r is None:
                    continue
                if r == _UNKNOWN:                         # its dependencies are not known: never chosen
                    opt.add(z3.Not(z3.And(present[q], x[q] == i)))
                    continue
                holders.append(z3.And(present[q], x[q] == i))
                allowed = [0] if r == _HOLD else [j for j, v in enumerate(cands[p]) if satisfies(eco, v, r) is True]
                admits.append((z3.And(present[q], x[q] == i), allowed))
                opt.add(z3.Implies(z3.And(present[q], x[q] == i),
                                   z3.Or([x[p] == j for j in allowed]) if allowed else z3.BoolVal(False)))
        opt.add(present[p] == (z3.Or(holders) if holders else z3.BoolVal(False)))
        if eco in LOWEST_APPLICABLE and admits:
            # the child IS the lowest candidate every present holder admits
            ok = [z3.And([z3.Implies(cond, z3.BoolVal(j in allowed)) for cond, allowed in admits])
                  for j in range(len(cands[p]))]
            for j in range(len(cands[p])):
                opt.add(z3.Implies(z3.And(present[p], x[p] == j), z3.And(ok[j], *[z3.Not(ok[k]) for k in range(j)])))

    for k in vulnerable & scope:
        safe = [j for j, b in enumerate(bad[k]) if not b]
        opt.add_soft(z3.Implies(present[k], z3.Or([x[k] == j for j in safe]) if safe else z3.BoolVal(False)),
                     weight=1000, id="safe")
    # a package leaving the tree is a change too (otherwise dropping one looks free)
    changed = z3.Sum([z3.If(z3.Or(x[k] != 0, z3.Not(present[k])), 1, 0) for k in scope])
    project = df.requires.get("", {})
    raised = []
    for k in roots:
        spec = project.get(normalize_name(eco, pkg[k].name))
        if spec:
            excluded = [j for j, v in enumerate(cands[k]) if satisfies(eco, v, spec) is False]
            raised.append(z3.If(z3.Or([x[k] == j for j in excluded]) if excluded else z3.BoolVal(False), 1, 0))
    majors = []
    for k in scope:
        m0 = _major(cands[k][0])
        jumps = [j for j, v in enumerate(cands[k]) if m0 is not None and (_major(v) or 0) > m0]
        if jumps:
            majors.append(z3.If(z3.Or([x[k] == j for j in jumps]), 1, 0))
    opt.minimize(z3.Sum(majors) if majors else z3.IntVal(0))     # a major jump may break the API
    opt.minimize(z3.Sum(raised) if raised else z3.IntVal(0))
    opt.minimize(changed)
    # the nearest versions: of what the project declares first, then of the rest (a package that
    # leaves the tree has no distance, so it must not beat a smaller step on a direct one)
    opt.minimize(z3.Sum([x[k] for k in roots]) if roots else z3.IntVal(0))
    rest = [z3.If(present[k], x[k], 0) for k in scope if k not in roots]
    opt.minimize(z3.Sum(rest) if rest else z3.IntVal(0))
    if opt.check() != z3.sat:
        return Solution(df.path, unresolved=set(vulnerable), reason="no combination of versions satisfies every range")
    model = opt.model()
    sol = Solution(df.path)
    for k in sorted(scope):
        i = model.eval(x[k]).as_long()
        is_present = z3.is_true(model.eval(present[k]))
        p = pkg[k]
        if k in vulnerable:
            if not is_present or not bad[k][i]:
                sol.fixed.add(k)
            else:
                sol.unresolved.add(k)
        if i == 0 and is_present:
            continue
        spec = project.get(normalize_name(eco, p.name)) if k in roots else None
        target = cands[k][i] if is_present else None
        sol.changes.append(Change(p.name, p.version, target, bool(p.direct),
                                  bool(spec and target and satisfies(eco, target, spec) is False), k in vulnerable))
    return sol


def range_exposure(files: List[DependencyFile], db, registries) -> List[dict]:
    """For each range the project itself declares (a manifest or a lockfile's root
    requirements): the released versions it admits that an advisory affects, and the lowest
    floor that leaves none. A library's consumers resolve its ranges, not its lockfile, so a
    range that admits a vulnerable version passes it on even when the lockfile is safe."""
    out: List[dict] = []
    seen: Set[Tuple[str, str, str]] = set()
    for df in files:
        reg = registries.for_ecosystem(df.ecosystem) if hasattr(registries, "for_ecosystem") else registries
        if reg is None or df.ecosystem not in SUPPORTED:
            continue
        eco = df.ecosystem
        for name, spec in sorted(df.requires.get("", {}).items()):
            key = (eco, normalize_name(eco, name), spec)
            if key in seen or not spec:
                continue
            seen.add(key)
            meta = reg.versions(name)
            advisories = db.advisories(eco, name)
            if not meta or not advisories:
                continue
            released = sorted_versions(eco, [v for v, m in meta.items() if not is_prerelease(v, eco)])
            admitted = [v for v in released if satisfies(eco, v, spec) is True]
            bad = [v for v in admitted if any(is_affected(eco, v, a) for a in advisories)]
            if not bad:
                continue
            ids = sorted({a["id"] for a in advisories for v in bad if is_affected(eco, v, a)})
            above = [v for v in admitted if sort_key(eco, v) > sort_key(eco, bad[-1])]
            out.append({"ecosystem": eco, "package": name, "range": spec, "path": df.path,
                        "admits": len(admitted), "vulnerable": len(bad), "lowest": bad[0], "highest": bad[-1],
                        "advisories": ids, "floor": above[0] if above else None})
    return out


def format_exposure(rows: List[dict]) -> str:
    if not rows:
        return ""
    lines = [f"\nDeclared ranges that admit vulnerable versions ({len(rows)}): consumers who resolve "
             "these ranges can install them"]
    for r in rows:
        fix = (f"raise the floor to {r['floor']}" if r["floor"] else
               "every version it admits is vulnerable: widen it" if r["vulnerable"] == r["admits"] else
               "a vulnerable version is the newest it admits: widen it")
        lines.append(f"  {r['package']} {r['range']}: admits {r['vulnerable']} vulnerable of {r['admits']} "
                     f"({r['lowest']} .. {r['highest']}; {', '.join(r['advisories'][:3])}"
                     f"{'...' if len(r['advisories']) > 3 else ''}); {fix}  [{r['path']}]")
    return "\n".join(lines)
