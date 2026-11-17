"""CVE records (CVE JSON 5, the CVE Program's `cvelistV5`) -> OSV-shaped records naming the
packages the CNA itself names.

OSV converts every CVE record, but its conversion keeps only what it can tie to a repository: an
`affected` entry that names a registry package (`packageURL`, or `collectionURL` + `packageName`)
with registry version ranges can come out as GIT commit ranges alone. CVE-2026-90436 (Apache Axis
1.x) is one: the CNA lists `pkg:maven/axis/axis` and `pkg:maven/org.apache.axis/axis`, versions
`0` through `1.4`, and OSV's record has only the commit range, so no Maven project was matched.

`to_osv` reads only those package entries, with nothing guessed:

* the ecosystem and name come from the purl or from a registry `collectionURL` Frame knows,
  never from the product or vendor text;
* a version entry counts only when its status is `affected`, its `versionType` is the registry's
  own scheme (or absent), and its versions look like versions; `version` + `lessThan` is a range
  ending in a fix, `lessThanOrEqual` one ending in a last affected version, a lone `version` one
  listed version;
* an entry with `changes` (status changes along the line) is skipped: reading it as one range
  could claim fixed versions are affected;
* `defaultStatus` is used only when an entry lists no versions at all ("every version is
  affected"); it never widens a listed range;
* GIT entries are not converted (OSV's own record already carries them, and the C/C++ matching
  reads that), so adding CVE records to a build changes no GIT shard.

The result goes through the same `osv.entries` as every OSV record, as a fallback
(`osv._merge_aliases`): where an OSV record names the same vulnerability (by id or alias) for the
same package, OSV's reviewed ranges win and the CNA's are dropped. The two disagree on real
advisories (a version GHSA calls fixed is the CNA's `lessThanOrEqual`), and a merge would report
the fixed version.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import unquote

from frame.sca.model import CARGO, GO, HEX, MAVEN, NPM, NUGET, PACKAGIST, PUB, PYPI, RUBYGEMS
from frame.sca.osv import SEVERITIES

# purl type -> OSV ecosystem (https://github.com/package-url/purl-spec, PURL-TYPES)
_PURL_TYPES = {"maven": MAVEN, "npm": NPM, "pypi": PYPI, "nuget": NUGET, "gem": RUBYGEMS, "cargo": CARGO,
               "golang": GO, "composer": PACKAGIST, "pub": PUB, "hex": HEX}
# a registry's collectionURL (scheme and trailing slash dropped, lower case) -> OSV ecosystem
_COLLECTIONS = {
    "repo.maven.apache.org/maven2": MAVEN, "repo1.maven.org/maven2": MAVEN, "search.maven.org": MAVEN,
    "central.sonatype.com": MAVEN,
    "registry.npmjs.org": NPM, "www.npmjs.com": NPM, "npmjs.com": NPM,
    "pypi.org": PYPI, "pypi.org/simple": PYPI, "pypi.python.org": PYPI, "pypi.python.org/pypi": PYPI,
    "www.nuget.org": NUGET, "nuget.org": NUGET, "api.nuget.org/v3/index.json": NUGET,
    "rubygems.org": RUBYGEMS, "crates.io": CARGO, "packagist.org": PACKAGIST, "pub.dev": PUB,
    "hex.pm": HEX, "repo.hex.pm": HEX, "proxy.golang.org": GO, "pkg.go.dev": GO,
}
# versionType values that are the registry's own order (CVE JSON 5 leaves the vocabulary open);
# `custom`, `git` and anything else are not compared with the registry's order
_VERSION_TYPES = {
    MAVEN: {"maven"}, NPM: {"npm", "semver"}, PYPI: {"python", "pep440", "pypi"}, NUGET: {"nuget", "semver"},
    RUBYGEMS: {"rubygems", "gem"}, CARGO: {"cargo", "semver"}, GO: {"go", "golang", "semver"},
    PACKAGIST: {"composer", "packagist", "semver"}, PUB: {"pub", "semver"}, HEX: {"hex", "semver"},
}
_VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+_~:-]*")
SOURCE = "cve-record"          # `database_specific.source` of a converted record


def is_cve_record(doc: object) -> bool:
    return isinstance(doc, dict) and doc.get("dataType") == "CVE_RECORD" and isinstance(doc.get("cveMetadata"), dict)


def parse_purl(purl: str) -> Optional[Tuple[str, str]]:
    """(OSV ecosystem, package name as OSV writes it) for a package URL Frame reads, else None."""
    m = re.fullmatch(r"pkg:([A-Za-z0-9.+-]+)/([^?#@]+)(?:@[^?#]*)?(?:\?[^#]*)?(?:#.*)?", purl.strip())
    if not m:
        return None
    eco = _PURL_TYPES.get(m.group(1).lower())
    parts = [unquote(p) for p in m.group(2).strip("/").split("/") if p]
    if eco is None or not parts:
        return None
    if eco == MAVEN:
        return (eco, f"{parts[0]}:{parts[1]}") if len(parts) == 2 else None
    if eco in (GO, PACKAGIST, NPM):
        if eco == PACKAGIST and len(parts) != 2:
            return None
        return eco, "/".join(parts)                          # npm: "@scope/name"
    return (eco, parts[0]) if len(parts) == 1 else None


def _package(aff: dict) -> Optional[Tuple[str, str]]:
    if isinstance(aff.get("packageURL"), str):
        return parse_purl(aff["packageURL"])
    url, name = aff.get("collectionURL"), aff.get("packageName")
    if not isinstance(url, str) or not isinstance(name, str) or not name.strip():
        return None
    key = re.sub(r"^[a-z]+://", "", url.strip().lower()).rstrip("/")
    eco = _COLLECTIONS.get(key)
    if eco is None or (eco == MAVEN and name.count(":") != 1):
        return None
    return eco, name.strip()


def _ranges(eco: str, aff: dict) -> Tuple[List[dict], List[str]]:
    """(ECOSYSTEM ranges, listed versions) of one affected entry, as the CNA states them."""
    entries = aff.get("versions")
    if not entries:
        return ([{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}], []) \
            if aff.get("defaultStatus") == "affected" else ([], [])
    ranges, listed = [], []
    for v in entries if isinstance(entries, list) else []:
        if not isinstance(v, dict) or v.get("status") != "affected" or v.get("changes"):
            continue
        vtype = v.get("versionType")
        if vtype is not None and str(vtype).lower() not in _VERSION_TYPES.get(eco, set()):
            continue
        start = str(v.get("version", "")).strip()
        lt, le = v.get("lessThan"), v.get("lessThanOrEqual")
        if start in ("*", ""):
            start = "0"
        if not _VERSION.fullmatch(start):
            continue
        if lt is None and le is None:
            if start != "0":
                listed.append(start)
            continue
        end = str(lt if lt is not None else le).strip()
        events: List[dict] = [{"introduced": start}]
        if end != "*":
            if not _VERSION.fullmatch(end):
                continue
            events.append({"fixed": end} if lt is not None else {"last_affected": end})
        ranges.append({"type": "ECOSYSTEM", "events": events})
    return ranges, listed


def _severity(containers: dict) -> Tuple[List[dict], Optional[str]]:
    """(OSV `severity` entries, a textual rating): the CNA's CVSS v3 vector, else an ADP's (CISA's
    Vulnrichment), else the CNA's own textual severity."""
    cna = containers.get("cna") or {}
    for metrics in [cna.get("metrics") or []] + [a.get("metrics") or [] for a in containers.get("adp") or []
                                                 if isinstance(a, dict)]:
        for m in metrics if isinstance(metrics, list) else []:
            for key in ("cvssV3_1", "cvssV3_0"):
                vec = (m.get(key) or {}).get("vectorString") if isinstance(m, dict) else None
                if isinstance(vec, str) and vec.startswith("CVSS:3"):
                    return [{"type": "CVSS_V3", "score": vec}], None
    for m in cna.get("metrics") or []:
        text = (((m.get("other") or {}).get("content") or {}).get("text")) if isinstance(m, dict) else None
        label = str(text or "").strip().lower()
        label = {"moderate": "medium", "important": "high"}.get(label, label)
        if label in SEVERITIES:
            return [], label
    return [], None


def to_osv(doc: dict) -> Optional[dict]:
    """An OSV-shaped record of the registry packages a published CVE record names, or None when it
    names none Frame reads."""
    meta = doc.get("cveMetadata") or {}
    if not is_cve_record(doc) or meta.get("state") != "PUBLISHED" or not meta.get("cveId"):
        return None
    containers = doc.get("containers") or {}
    cna = containers.get("cna") or {}
    affected: List[dict] = []
    seen: Dict[Tuple[str, str], dict] = {}
    for aff in cna.get("affected") or []:
        if not isinstance(aff, dict):
            continue
        pkg = _package(aff)
        if pkg is None:
            continue
        ranges, listed = _ranges(pkg[0], aff)
        if not ranges and not listed:
            continue
        if pkg in seen:                                        # one package named in two entries
            seen[pkg]["ranges"] += ranges
            seen[pkg]["versions"] += listed
            continue
        seen[pkg] = {"package": {"ecosystem": pkg[0], "name": pkg[1]}, "ranges": ranges, "versions": listed}
        affected.append(seen[pkg])
    if not affected:
        return None
    severity, label = _severity(containers)
    summary = cna.get("title") or next((d.get("value") for d in cna.get("descriptions") or []
                                        if isinstance(d, dict) and str(d.get("lang", "")).startswith("en")), "")
    rec = {"id": meta["cveId"], "aliases": [], "summary": str(summary or ""),
           "published": meta.get("datePublished"), "modified": meta.get("dateUpdated"),
           "severity": severity, "affected": affected,
           # a fallback: where OSV files this CVE under the package itself, OSV's record wins
           "database_specific": {"source": SOURCE, **({"severity": label} if label else {})}}
    return rec
