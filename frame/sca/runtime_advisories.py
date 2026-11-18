"""Advisories of language runtimes OSV does not cover, as OSV-shaped records for
`frame kb build-advisories` (matched against what `frame.sca.runtimes` reads in an image).

A runtimes directory given to the build holds each project's own data, as published:

    openjdk/<date>.html        OpenJDK Vulnerability Group advisories
                               (https://openjdk.org/groups/vulnerability/advisories/<date>)
    nodejs/vulns.json          Node.js security WG's core advisories (nodejs/security-wg
                               vuln/core/index.json, MIT)
    nodejs/releases.json       Node.js's release list (https://nodejs.org/dist/index.json)
    ruby/advisories/*.yml      The Ruby advisory database's `rubies/ruby` entries (rubysec)
    ruby/releases.yml          Ruby's release list (ruby/www.ruby-lang.org `_data/releases.yml`)

Nothing is guessed:

* OpenJDK: a CVE affects the release lines its risk-matrix row marks, each up to the version
  the advisory names as that line's last affected one ("The affected versions are 21.0.13.0.3,
  17.0.21.0.3, ..., 8u512, and earlier"): `introduced` the line, `last_affected` that version. A
  marked line the sentence names no version for is left out. The advisories give no fixed
  version, so none is invented. The CVSS vector is the matrix's abbreviation, expanded.
* Node.js and Ruby state affected versions as ranges (`vulnerable` / `patched` in node-semver;
  `patched_versions` / `unaffected_versions` as RubyGems requirements). They are evaluated with
  Frame's own range code (`frame.sca.ranges`, pinned to node-semver and RubyGems) over every
  release in the project's release list, and the affected releases become events: each run of
  affected releases is `introduced` at its first and `fixed` at the release after it (or
  `last_affected` at the newest release). A range Frame cannot read skips the advisory.
"""

from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence, Tuple

from frame.sca.model import NODEJS, NPM, OPENJDK, RUBY, RUBYGEMS
from frame.sca.versions import sort_key, sorted_versions

SOURCE = "runtime"                 # database_specific.source of a record built here


def is_runtimes_dir(p: Path) -> bool:
    p = Path(p)
    return p.is_dir() and ((p / "openjdk").is_dir() or (p / "nodejs" / "vulns.json").is_file()
                           or (p / "ruby" / "releases.yml").is_file())


def _record(id_: str, aliases: List[str], summary: str, published: Optional[str], eco: str, name: str,
            ranges: List[dict], vector: Optional[str] = None, label: Optional[str] = None, refs: Sequence[str] = ()) -> dict:
    return {"id": id_, "aliases": aliases, "summary": summary, "published": published, "modified": published,
            "severity": [{"type": "CVSS_V3", "score": vector}] if vector else [],
            "affected": [{"package": {"ecosystem": eco, "name": name}, "ranges": ranges}],
            "references": [{"type": "ADVISORY", "url": u} for u in refs if u],
            "database_specific": {"source": SOURCE, **({"severity": label} if label else {})}}


# ---------------------------------------------------------------------------------------------
# OpenJDK

class _Page(HTMLParser):
    """The h1, the paragraphs and every table (rows of cell texts) of an advisory page; a table
    is kept with the h2 heading above it."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.h1, self.paragraphs, self.tables = "", [], []
        self._heading, self._in, self._text, self._row = "", None, [], None

    def handle_starttag(self, tag, attrs):
        if tag in ("h1", "h2", "p"):
            self._in, self._text = tag, []
        elif tag == "table":
            self.tables.append((self._heading, []))
        elif tag == "tr" and self.tables:
            self._row = []
            self.tables[-1][1].append(self._row)
        elif tag in ("td", "th") and self._row is not None:
            self._in, self._text = "cell", []
        elif tag == "br" and self._in:
            self._text.append(" ")

    def handle_endtag(self, tag):
        text = re.sub(r"\s+", " ", "".join(self._text)).strip()
        if tag in ("h1", "h2", "p") and self._in == tag:
            if tag == "h1":
                self.h1 = text
            elif tag == "h2":
                self._heading = text
            else:
                self.paragraphs.append(text)
            self._in = None
        elif tag in ("td", "th") and self._in == "cell":
            self._row.append(text)
            self._in = None
        elif tag == "tr":
            self._row = None

    def handle_data(self, data):
        if self._in:
            self._text.append(data)


_CVSS_LETTERS = (("AV", "NALP"), ("AC", "LH"), ("PR", "NLH"), ("UI", "NR"), ("S", "UC"),
                 ("C", "HLN"), ("I", "HLN"), ("A", "HLN"))


def _vector(abbrev: str) -> Optional[str]:
    """The risk matrix's `NHNNUHHH` as a CVSS 3.1 vector (AV, AC, PR, UI, S, C, I, A)."""
    if len(abbrev) != 8 or any(c not in allowed for c, (_, allowed) in zip(abbrev, _CVSS_LETTERS)):
        return None
    return "CVSS:3.1/" + "/".join(f"{k}:{c}" for c, (k, _) in zip(abbrev, _CVSS_LETTERS))


def _feature(version: str) -> Optional[int]:
    key = sort_key(OPENJDK, version)
    return key[0][0] if key else None


def openjdk_records(page: str, url: str = "") -> Tuple[List[dict], List[str]]:
    """(records, warnings) of one OpenJDK Vulnerability Group advisory page."""
    doc = _Page()
    doc.feed(page)
    m = re.search(r"(\d{4})/(\d{1,2})/(\d{1,2})", doc.h1)          # 2019's pages write 2019/4/16
    if not m or "OpenJDK Vulnerability Advisory" not in doc.h1:
        return [], [f"{url or 'page'}: not an OpenJDK vulnerability advisory"]
    date = f"{m.group(1)}-{int(m.group(2)):02d}-{int(m.group(3)):02d}"
    sentence = next((p for p in doc.paragraphs if "affected versions are" in p), "")
    listed = re.search(r"affected versions are (.*?),? and earlier", sentence)
    last: Dict[int, str] = {}
    for v in (listed.group(1).split(",") if listed else []):
        v = v.strip()
        f = _feature(v)
        if f is not None:
            last[f] = v
    warnings: List[str] = []
    if not last:
        return [], [f"{date}: no affected versions found in the advisory text"]
    table = next((rows for heading, rows in doc.tables
                  if heading in ("OpenJDK Risk matrix", "Risk matrix")), None)
    if table is None:
        return [], [f"{date}: no OpenJDK risk matrix"]
    header = next((r for r in table if r and r[0] == "CVE ID"), None)
    if header is None:
        return [], [f"{date}: the risk matrix has no CVE ID column"]
    lines = header[3:]                                        # after CVE ID, Component, CVSS
    out: List[dict] = []
    for row in table:
        if not row or not re.fullmatch(r"CVE-\d{4}-\d+", row[0]) or len(row) != len(header):
            continue
        cve, component = row[0], row[1].replace(" ", "")
        score_vector = row[2].split()
        marked = [line for line, cell in zip(lines, row[3:]) if cell.strip()]
        ranges = []
        for line in marked:
            f = _feature(line)
            if f is None or f not in last:
                warnings.append(f"{date} {cve}: line {line} is marked but no last affected version is named; left out")
                continue
            ranges.append({"type": "ECOSYSTEM", "events": [{"introduced": str(f)}, {"last_affected": last[f]}]})
        if not ranges:
            continue
        vector = _vector(score_vector[1]) if len(score_vector) == 2 else None
        label = None
        if vector is None and score_vector:
            from frame.sca.osv import severity_of_score
            try:
                label = severity_of_score(float(score_vector[0]))
            except ValueError:
                label = None
        out.append(_record(cve, [], f"OpenJDK {component} vulnerability", date, OPENJDK, "openjdk", ranges,
                           vector, label, [url or f"https://openjdk.org/groups/vulnerability/advisories/{date}"]))
    return out, warnings


# ---------------------------------------------------------------------------------------------
# ranges over a release list

def _runs(eco: str, releases: List[str], affected) -> List[dict]:
    """ECOSYSTEM ranges for the releases `affected(v)` holds for, in the registry's order."""
    ranges, start, prev = [], None, None
    for v in releases:
        if affected(v):
            start = start or v
        elif start:
            ranges.append({"type": "ECOSYSTEM", "events": [{"introduced": start}, {"fixed": v}]})
            start = None
        prev = v
    if start:
        ranges.append({"type": "ECOSYSTEM", "events": [{"introduced": start}, {"last_affected": prev}]})
    return ranges


def _final(eco: str, versions) -> List[str]:
    """Releases only (no pre-releases), in the registry's order."""
    return sorted_versions(eco, [v for v in versions if re.fullmatch(r"\d+\.\d+\.\d+", v)])


def node_records(vulns: dict, releases: list) -> Tuple[List[dict], List[str]]:
    """(records, warnings) from the security WG's core index and Node's release list."""
    from frame.sca.ranges import satisfies
    versions = _final(NODEJS, [str(r.get("version", "")).lstrip("v") for r in releases if isinstance(r, dict)])
    out, warnings = [], []
    for key in sorted(vulns, key=lambda k: int(k) if str(k).isdigit() else 0):
        v = vulns[key]
        if not isinstance(v, dict):
            continue
        vulnerable, patched = str(v.get("vulnerable") or "").strip(), str(v.get("patched") or "").strip()
        if not vulnerable:
            continue
        verdicts = {}
        for r in versions:
            a = satisfies(NPM, r, vulnerable)
            p = satisfies(NPM, r, patched) if patched else False
            if a is None or p is None:
                verdicts = None
                break
            verdicts[r] = a and not p
        cves = [c for c in v.get("cve") or [] if isinstance(c, str) and c.startswith("CVE-")]
        own = f"NSWG-CORE-{key}"
        if verdicts is None:
            warnings.append(f"{own}: range not read ({vulnerable!r} / {patched!r}); skipped")
            continue
        ranges = _runs(NODEJS, versions, verdicts.get)
        if not ranges:
            continue
        summary = str(v.get("description") or v.get("overview") or "").strip().split("\n")[0][:300]
        label = str(v.get("severity") or "").lower()
        label = label if label in ("low", "medium", "high", "critical") else None
        vector = v.get("cvss") if isinstance(v.get("cvss"), str) and str(v.get("cvss")).startswith("CVSS:3") else None
        out.append(_record(cves[0] if cves else own, cves[1:] + ([own] if cves else []), summary,
                           v.get("publish_date"), NODEJS, "node", ranges, vector, None if vector else label,
                           [v.get("ref")] if isinstance(v.get("ref"), str) else []))
    return out, warnings


def ruby_records(advisories: List[dict], releases: List[str]) -> Tuple[List[dict], List[str]]:
    """(records, warnings) from the Ruby advisory database's `rubies/ruby` entries."""
    from frame.sca.osv import severity_of_score
    from frame.sca.ranges import satisfies
    versions = _final(RUBY, releases)
    out, warnings = [], []
    for adv in advisories:
        if not isinstance(adv, dict) or adv.get("engine") != "ruby":
            continue
        cve = f"CVE-{adv['cve']}" if adv.get("cve") else None
        ghsa = f"GHSA-{adv['ghsa']}" if adv.get("ghsa") else None
        own = cve or ghsa
        if own is None:
            continue
        reqs = [str(r) for r in (adv.get("patched_versions") or []) + (adv.get("unaffected_versions") or [])]
        verdicts = {}
        for r in versions:
            hits = [satisfies(RUBYGEMS, r, q) for q in reqs]
            if None in hits:
                verdicts = None
                break
            verdicts[r] = not any(hits)
        if verdicts is None:
            warnings.append(f"{own}: requirement not read ({reqs!r}); skipped")
            continue
        ranges = _runs(RUBY, versions, verdicts.get)
        if not ranges:
            continue
        score = adv.get("cvss_v3") or adv.get("cvss_v4") or adv.get("cvss_v2")
        label = severity_of_score(float(score)) if isinstance(score, (int, float)) else None
        date = adv.get("date")
        out.append(_record(own, [ghsa] if cve and ghsa else [], str(adv.get("title") or ""),
                           str(date) if date else None, RUBY, "ruby", ranges, None, label,
                           [str(adv.get("url") or "")]))
    return out, warnings


# ---------------------------------------------------------------------------------------------

def records(root: Path) -> Iterator[dict]:
    """Every record of a runtimes directory (layout above). Warnings go to stderr."""
    import sys
    root = Path(root)
    warnings: List[str] = []
    for f in sorted((root / "openjdk").glob("*.html")) if (root / "openjdk").is_dir() else []:
        recs, w = openjdk_records(f.read_text(encoding="utf-8", errors="replace"),
                                  f"https://openjdk.org/groups/vulnerability/advisories/{f.stem}")
        warnings += w
        yield from recs
    node = root / "nodejs"
    if (node / "vulns.json").is_file():
        if not (node / "releases.json").is_file():
            raise ValueError(f"{node}: vulns.json needs releases.json (https://nodejs.org/dist/index.json)")
        recs, w = node_records(json.loads((node / "vulns.json").read_text()),
                               json.loads((node / "releases.json").read_text()))
        warnings += w
        yield from recs
    ruby = root / "ruby"
    if (ruby / "releases.yml").is_file():
        import yaml
        rels = yaml.safe_load((ruby / "releases.yml").read_text()) or []
        advs = [yaml.safe_load(f.read_text()) for f in sorted((ruby / "advisories").glob("*.yml"))]
        recs, w = ruby_records(advs, [str(r.get("version")) for r in rels if isinstance(r, dict)])
        warnings += w
        yield from recs
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)
