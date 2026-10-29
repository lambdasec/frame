"""SUSE Linux Enterprise advisories from SUSE's own OVAL (CC-BY-4.0).

OSV's SUSE records cover a service pack's own patches and file each under the module that ships the
package (Basesystem, Server Applications, ...), which an image does not record. SUSE's patch OVAL
for a service pack (`suse.linux.enterprise.15-sp7-patch.xml.gz` at
https://ftp.suse.com/pub/projects/security/oval/) is cumulative: every patch that applies to an
installed SLES 15 SP7, older packages included. On SP6 and SP7 it names 17,000 and 20,000 CVEs for
the base product where OSV's module records name 5,900 and 8,600, so SLES is read from it.

A patch definition says: on a platform of the product (`SUSE Linux Enterprise Server 15 SP7`, or a
module of it), a binary package older than a version is affected (`rpminfo` tests with `less than`).
Each one becomes an advisory per package (`SUSE-SU-2026:1234-1` when the definition names one, else
its OVAL id), with its CVEs as aliases and SUSE's severity, keyed by the binary package name, in
the table `SUSE:Linux Enterprise 15 SP7`. Definitions only for other products (SAP, HA, LTSS, Live
Patching, Desktop) are left out.
"""

from __future__ import annotations

import gzip
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

_O = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
_L = "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"
FILE = re.compile(r"suse\.linux\.enterprise\.15-(sp\d+)-patch\.xml(\.gz)?$")
_SEVERITY = {"critical": "critical", "important": "high", "moderate": "medium", "low": "low"}


def ecosystem_of(path: Path) -> Optional[str]:
    """`SUSE:Linux Enterprise 15 SP7` for SUSE's SP7 patch OVAL file, else None."""
    m = FILE.search(Path(path).name)
    return f"SUSE:Linux Enterprise 15 {m.group(1).upper()}" if m else None


def _base_platform(sp: str):
    return re.compile(rf"SUSE Linux Enterprise (?:Server|Module for [^\n]+) 15 {sp}")


def entries(path: Path) -> Iterator[Tuple[str, str, dict]]:
    """(ecosystem, binary package name, advisory entry) for each package a definition of the base
    product affects."""
    eco = ecosystem_of(path)
    if eco is None:
        return
    base = _base_platform(eco.rsplit(" ", 1)[-1])
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rb") as f:
        root = ET.parse(f).getroot()
    objects = {o.get("id"): o.findtext(f"{{{_L}}}name") for o in root.iter(f"{{{_L}}}rpminfo_object")}
    states: Dict[str, str] = {}
    for s in root.iter(f"{{{_L}}}rpminfo_state"):
        evr = s.find(f"{{{_L}}}evr")
        if evr is not None and evr.get("operation") == "less than" and evr.text:
            states[s.get("id")] = evr.text
    tests: Dict[str, Tuple[str, str]] = {}
    for t in root.iter(f"{{{_L}}}rpminfo_test"):
        obj, st = t.find(f"{{{_L}}}object"), t.find(f"{{{_L}}}state")
        if obj is not None and st is not None and st.get("state_ref") in states:
            tests[t.get("id")] = (objects.get(obj.get("object_ref")) or "", states[st.get("state_ref")])
    for d in root.iter(f"{{{_O}}}definition"):
        meta = d.find(f"{{{_O}}}metadata")
        if meta is None or d.get("class") != "patch":
            continue
        platforms = [p.text or "" for p in meta.iter(f"{{{_O}}}platform")]
        if not any(base.fullmatch(p) for p in platforms):
            continue
        refs = [(r.get("source"), r.get("ref_id")) for r in meta.iter(f"{{{_O}}}reference")]
        ident = next((i for s, i in refs if s == "SUSE-SU"), None) or d.get("id")
        cves = sorted({i for s, i in refs if s == "CVE" and i})
        sev = _SEVERITY.get((meta.findtext(f"{{{_O}}}advisory/{{{_O}}}severity") or "").strip().lower())
        issued = meta.find(f"{{{_O}}}advisory/{{{_O}}}issued")
        title = (meta.findtext(f"{{{_O}}}title") or "").strip()
        summary = re.sub(r"\s+", " ", (meta.findtext(f"{{{_O}}}description") or title)).strip()[:300]
        fixed: Dict[str, str] = {}
        for c in d.iter(f"{{{_O}}}criterion"):
            hit = tests.get(c.get("test_ref"))
            if hit and hit[0]:
                fixed.setdefault(hit[0], hit[1])
        for name, evr in fixed.items():
            version = evr[2:] if evr.startswith("0:") else evr         # rpm's epoch 0 is no epoch
            yield eco, name, {
                "id": ident, "aliases": [c for c in cves if c != ident], "summary": summary,
                "severity": sev, "score": None, "cvss": None,
                "published": issued.get("date") if issued is not None else None, "modified": None,
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": version}]}],
                "versions": [], "functions": []}


__all__ = ["FILE", "ecosystem_of", "entries"]
