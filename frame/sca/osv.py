"""OSV records -> Frame's compact advisory tables, and "is this version affected".

The dataset (`lambdasec/frame-advisories`) holds one table per ecosystem:

    {"schema": 1, "ecosystem": "PyPI", "packages": {"<normalised name>": [advisory, ...]}}

where an advisory is

    {"id", "aliases", "summary", "severity", "score", "cvss", "published", "modified",
     "ranges": [{"type": "ECOSYSTEM" | "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2"}]}],
     "versions": [...],                       # explicitly listed affected versions
     "functions": [{"id": "pkg.mod.func", "source": "osv"}]}

Records about the same vulnerability under several ids (a GHSA and a PYSEC entry naming each
other as aliases) are merged into one advisory per package, so a finding is reported once with
every id. Withdrawn records are dropped. Matching follows the OSV schema: a version is affected
if it is listed, or if walking a range's events in version order leaves it introduced and not
yet fixed (`fixed` excludes the fixed version, `last_affected` includes the last one, `limit`
ends the range). GIT ranges (commit hashes) are kept for C/C++ but never match a version.
"""

from __future__ import annotations

import math
from typing import Dict, Iterable, List, Optional, Tuple

from frame.sca.model import normalize_name
from frame.sca.versions import sort_key

SCHEMA = 1
SEVERITIES = ("low", "medium", "high", "critical")


# ---------------------------------------------------------------------------------------------
# CVSS v3 base score (FIRST CVSS v3.1 specification, section 7)

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62}, "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0}, "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> Optional[float]:
    if not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    m = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
    try:
        scope_changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _W["C"][m["C"]]) * (1 - _W["I"][m["I"]]) * (1 - _W["A"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
        exploitability = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def severity_of_score(score: float) -> Optional[str]:
    if score <= 0:
        return None
    return "low" if score < 4 else "medium" if score < 7 else "high" if score < 9 else "critical"


def _severity(record: dict, affected: dict) -> Tuple[Optional[str], Optional[float], Optional[str]]:
    """(severity, CVSS v3 score, vector): the CVSS v3 vector when there is one, else the
    database's own rating (GHSA's LOW/MODERATE/HIGH/CRITICAL)."""
    vector = None
    for s in list(record.get("severity") or []) + list(affected.get("severity") or []):
        if isinstance(s, dict) and str(s.get("type", "")).startswith("CVSS_V3"):
            vector = str(s.get("score", ""))
            break
    score = cvss3_base_score(vector) if vector else None
    if score is not None:
        return severity_of_score(score), score, vector
    for src in (record.get("database_specific") or {}, affected.get("database_specific") or {},
                affected.get("ecosystem_specific") or {}):
        label = str(src.get("severity", "")).lower() if isinstance(src, dict) else ""
        label = {"moderate": "medium", "important": "high"}.get(label, label)
        if label in SEVERITIES:
            return label, None, vector
    if vector is None:
        for s in record.get("severity") or []:
            if isinstance(s, dict) and s.get("score"):
                vector = str(s["score"])                      # CVSS v4 and others: kept, not scored
                break
    return None, None, vector


def _functions(affected: dict) -> List[dict]:
    """Affected functions an advisory states itself: Go's `imports[].symbols`, RustSec's
    `affects.functions`."""
    out: List[dict] = []
    es = affected.get("ecosystem_specific") or {}
    for imp in es.get("imports") or []:
        path = imp.get("path") if isinstance(imp, dict) else None
        for sym in (imp.get("symbols") or []) if path else []:
            out.append({"id": f"{path}.{sym}", "source": "osv"})
    for fn in ((es.get("affects") or {}).get("functions") or []):
        out.append({"id": str(fn), "source": "osv"})
    return out


def entries(rec: dict, ecosystems: Iterable[str]) -> Iterable[Tuple[str, str, dict]]:
    """(ecosystem, normalised package name, advisory entry) for each `affected` package of a
    record in `ecosystems`. Malicious-package records (OpenSSF, `MAL-` ids) carry no rating;
    installing one runs attacker code, so they are critical."""
    if not isinstance(rec, dict) or rec.get("withdrawn") or not rec.get("id"):
        return
    wanted = set(ecosystems)
    for aff in rec.get("affected") or []:
        pkg = aff.get("package") or {}
        eco = pkg.get("ecosystem", "").split(":", 1)[0]
        if eco not in wanted or not pkg.get("name"):
            continue
        ranges = [{"type": r["type"], "events": [e for e in r.get("events") or [] if isinstance(e, dict)]}
                  for r in aff.get("ranges") or [] if isinstance(r, dict) and r.get("type")]
        sev, score, vector = _severity(rec, aff)
        if sev is None and rec["id"].startswith("MAL-"):
            sev = "critical"
        yield eco, normalize_name(eco, pkg["name"]), {
            "id": rec["id"], "aliases": sorted(set(rec.get("aliases") or [])),
            "summary": (rec.get("summary") or rec.get("details") or "")[:300].strip(),
            "severity": sev, "score": score, "cvss": vector,
            "published": rec.get("published"), "modified": rec.get("modified"),
            "ranges": ranges, "versions": [str(v) for v in aff.get("versions") or []],
            "functions": _functions(aff)}


def git_entries(rec: dict) -> Iterable[Tuple[str, dict]]:
    """(repository, advisory entry) for each upstream repository a record's GIT ranges name,
    with the affected release tags OSV lists. Repositories outside the hosts Frame knows
    (`cpp.normalize_repo`: GitHub, GitLab, ...) are not C/C++ library dependencies Frame reads
    -- the Linux kernel's git.kernel.org is left to the operating-system work."""
    from frame.sca.cpp import normalize_repo
    if not isinstance(rec, dict) or rec.get("withdrawn") or not rec.get("id"):
        return
    for aff in rec.get("affected") or []:
        repos = {normalize_repo(r.get("repo", "")) for r in aff.get("ranges") or []
                 if isinstance(r, dict) and r.get("type") == "GIT"}
        repos.discard(None)
        versions = sorted({str(v) for v in aff.get("versions") or []})
        if not repos or not versions:
            continue                                  # no tags: only a commit graph could decide
        sev, score, vector = _severity(rec, aff)
        for repo in sorted(repos):
            yield repo, {"id": rec["id"], "aliases": sorted(set(rec.get("aliases") or [])),
                         "summary": (rec.get("summary") or rec.get("details") or "")[:300].strip(),
                         "severity": sev, "score": score, "cvss": vector,
                         "published": rec.get("published"), "modified": rec.get("modified"),
                         "ranges": [], "versions": versions, "functions": _functions(aff)}


def table(ecosystem: str, by_pkg: Dict[str, List[dict]]) -> dict:
    packages = {name: _merge_aliases(advs) for name, advs in sorted(by_pkg.items())}
    return {"schema": SCHEMA, "ecosystem": ecosystem, "packages": packages}


def compact(records: Iterable[dict], ecosystem: str) -> dict:
    """The table for `ecosystem` from OSV records (any ecosystem's records may be passed;
    only `affected` entries of this ecosystem are kept)."""
    by_pkg: Dict[str, List[dict]] = {}
    for rec in records:
        for _, name, entry in entries(rec, (ecosystem,)):
            by_pkg.setdefault(name, []).append(entry)
    return table(ecosystem, by_pkg)


_ID_RANK = (("GHSA-", 0), ("CVE-", 1))


def _primary(ids: Iterable[str]) -> str:
    def rank(i: str) -> Tuple[int, str]:
        return next((r for p, r in _ID_RANK if i.startswith(p)), 2), i
    return min(ids, key=rank)


def _merge_aliases(advs: List[dict]) -> List[dict]:
    """Advisories for one package that name each other (directly or through a shared alias)
    become one: ids united, ranges kept side by side (affected if any says so), the highest
    severity, functions united."""
    parent = list(range(len(advs)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    owner: Dict[str, int] = {}
    for i, a in enumerate(advs):
        for ident in [a["id"], *a["aliases"]]:
            j = owner.setdefault(ident, i)
            if j != i:
                parent[find(i)] = find(j)
    groups: Dict[int, List[dict]] = {}
    for i, a in enumerate(advs):
        groups.setdefault(find(i), []).append(a)
    out = []
    for group in groups.values():
        ids = {a["id"] for a in group}
        aliases = {x for a in group for x in a["aliases"]} | ids
        primary = _primary(ids)
        ranked = sorted(group, key=lambda a: (a["score"] or -1, SEVERITIES.index(a["severity"]) if a["severity"] else -1),
                        reverse=True)
        best = ranked[0]
        seen_fn, functions = set(), []
        for a in group:
            for f in a["functions"]:
                if f["id"] not in seen_fn:
                    seen_fn.add(f["id"])
                    functions.append(f)
        summary = next((a["summary"] for a in group if a["id"] == primary and a["summary"]),
                       next((a["summary"] for a in group if a["summary"]), ""))
        out.append({
            "id": primary, "aliases": sorted(aliases - {primary}), "summary": summary,
            "severity": best["severity"], "score": best["score"], "cvss": best["cvss"],
            "published": min((a["published"] for a in group if a["published"]), default=None),
            "modified": max((a["modified"] for a in group if a["modified"]), default=None),
            "ranges": [r for a in group for r in a["ranges"]],
            "versions": sorted({v for a in group for v in a["versions"]}),
            "functions": functions})
    return sorted(out, key=lambda a: a["id"])


# ---------------------------------------------------------------------------------------------

def _event_key(ecosystem: str, rtype: str, e: dict):
    kind, value = next(iter(e.items()))
    if kind == "introduced" and value == "0":
        return (0, None)
    key = sort_key(ecosystem, str(value)) if rtype == "ECOSYSTEM" else sort_key("npm", str(value))
    return (1, key) if key is not None else None


def in_range(ecosystem: str, version: str, rng: dict) -> bool:
    rtype = rng.get("type")
    if rtype not in ("ECOSYSTEM", "SEMVER"):
        return False                                         # GIT: commit ranges
    v = sort_key(ecosystem, version) if rtype == "ECOSYSTEM" else sort_key("npm", version)
    if v is None:
        return False
    events = []
    for e in rng.get("events") or []:
        if not isinstance(e, dict) or len(e) != 1:
            continue
        k = _event_key(ecosystem, rtype, e)
        if k is not None:
            events.append((k, next(iter(e))))
    events.sort(key=lambda x: _sortable(x[0]))
    affected = False
    for (rank, ev_key), kind in events:
        if kind == "introduced":
            if rank == 0 or v >= ev_key:
                affected = True
        elif kind == "fixed":
            if v >= ev_key:
                affected = False
        elif kind == "last_affected":
            if v > ev_key:
                affected = False
        elif kind == "limit":
            if v >= ev_key:
                affected = False
    return affected


class _Bottom:
    def __lt__(self, other):
        return not isinstance(other, _Bottom)

    def __gt__(self, other):
        return False

    def __le__(self, other):
        return True

    def __ge__(self, other):
        return isinstance(other, _Bottom)

    def __eq__(self, other):
        return isinstance(other, _Bottom)

    def __hash__(self):
        return 2


_BOTTOM = _Bottom()


def _sortable(k):
    rank, key = k
    return (rank, _BOTTOM if key is None else key)


def is_affected(ecosystem: str, version: str, advisory: dict) -> bool:
    if version in advisory.get("versions", ()):
        return True
    return any(in_range(ecosystem, version, r) for r in advisory.get("ranges", ()))


def fixed_versions(ecosystem: str, version: str, advisory: dict) -> List[str]:
    """`fixed` events above `version`, lowest first: the upgrades that leave this range."""
    v = sort_key(ecosystem, version)
    out = set()
    for r in advisory.get("ranges", ()):
        if r.get("type") not in ("ECOSYSTEM", "SEMVER"):
            continue
        for e in r.get("events") or []:
            f = e.get("fixed") if isinstance(e, dict) else None
            k = sort_key(ecosystem, str(f)) if f is not None else None
            if k is not None and v is not None and k > v:
                out.add(str(f))
    from frame.sca.versions import sorted_versions
    return sorted_versions(ecosystem, out)

