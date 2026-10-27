"""Software bills of materials from the dependency graph: CycloneDX 1.6 and SPDX 2.3 (JSON).

Everything comes from what `frame deps` reads (lockfiles, build-tool reports, manifests);
nothing is fetched. A package appears once per package URL, with the manifests that declare
it; dev-only packages are CycloneDX `scope: optional` and SPDX `DEV_DEPENDENCY_OF`; edges
become the CycloneDX `dependencies` graph and SPDX `DEPENDS_ON` relationships. Licences are
only what a lockfile records (npm's); otherwise CycloneDX says nothing and SPDX says
NOASSERTION -- never a guess. A requirement without an exact version (a range in a manifest
with no lockfile) is listed with its range as a property and no package URL.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from frame.sca.discover import DependencyReport
from frame.sca.model import Package, normalize_name


def _now(timestamp: Optional[str]) -> str:
    return timestamp or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@lru_cache(maxsize=1)
def _spdx_ids() -> Set[str]:
    """SPDX licence identifiers (package data: frame/sca/data/spdx-license-ids.txt)."""
    path = Path(__file__).parent / "data" / "spdx-license-ids.txt"
    try:
        return {ln.strip() for ln in path.read_text().splitlines() if ln.strip() and not ln.startswith("#")}
    except OSError:
        return set()


def _cdx_license(text: str) -> Optional[dict]:
    t = text.strip()
    if not t:
        return None
    if re.search(r"\s(OR|AND|WITH)\s", t) or t.startswith("("):
        return {"expression": t}
    if t in _spdx_ids():
        return {"license": {"id": t}}
    return {"license": {"name": t}}


def _ref(p: Package) -> str:
    return p.purl or f"{p.ecosystem}:{normalize_name(p.ecosystem, p.name)}@{p.spec or '*'}"


class _Graph:
    """Packages merged across manifests by reference, with the edges between them."""

    def __init__(self, report: DependencyReport):
        self.packages: Dict[str, Package] = {}
        self.paths: Dict[str, List[str]] = {}
        self.direct: Set[str] = set()
        self.dev: Dict[str, bool] = {}
        self.edges: Dict[str, Set[str]] = {}
        for f in report.files:
            refs = {k: _ref(p) for k, p in f.packages.items()}
            for k, p in f.packages.items():
                r = refs[k]
                self.packages.setdefault(r, p)
                self.paths.setdefault(r, [])
                if f.path not in self.paths[r]:
                    self.paths[r].append(f.path)
                self.dev[r] = self.dev.get(r, True) and p.dev
                if p.direct:
                    self.direct.add(r)
            for a, bs in f.edges.items():
                for b in bs:
                    if a in refs and b in refs:
                        self.edges.setdefault(refs[a], set()).add(refs[b])
        # with no direct information at all, the roots are the packages nothing depends on
        if not self.direct:
            children = {b for bs in self.edges.values() for b in bs}
            self.direct = {r for r in self.packages if r not in children}


def to_cyclonedx(report: DependencyReport, product: str, timestamp: Optional[str] = None) -> dict:
    from frame import __version__
    g = _Graph(report)
    ts = _now(timestamp)
    components = []
    for r in sorted(g.packages):
        p = g.packages[r]
        c = {"type": "library", "bom-ref": r, "name": p.name}
        if p.ecosystem == "Maven" and ":" in p.name:
            c["group"], c["name"] = p.name.split(":", 1)
        if p.version:
            c["version"] = p.version
        if p.purl:
            c["purl"] = p.purl
        if g.dev.get(r):
            c["scope"] = "optional"
        lic = _cdx_license(p.license)
        if lic:
            c["licenses"] = [lic]
        props = [{"name": "frame:ecosystem", "value": p.ecosystem}]
        props += [{"name": "frame:declared-in", "value": path} for path in g.paths[r]]
        if g.dev.get(r):
            props.append({"name": "frame:dev", "value": "true"})
        if not p.version and p.spec:
            props.append({"name": "frame:requirement", "value": p.spec})
        c["properties"] = props
        components.append(c)
    deps = [{"ref": product, "dependsOn": sorted(g.direct)}]
    deps += [{"ref": r, "dependsOn": sorted(g.edges.get(r, ()))} for r in sorted(g.packages)]
    key = product + "|" + ts + "|" + "|".join(sorted(g.packages))
    return {"bomFormat": "CycloneDX", "specVersion": "1.6",
            "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, key)}", "version": 1,
            "metadata": {"timestamp": ts,
                         "tools": {"components": [{"type": "application", "name": "Frame", "version": __version__}]},
                         "component": {"type": "application", "bom-ref": product, "name": product}},
            "components": components, "dependencies": deps}


def _spdx_id(ref: str) -> str:
    """`SPDXRef-` plus a readable, unique id ([A-Za-z0-9.-] only)."""
    readable = re.sub(r"[^A-Za-z0-9.-]+", "-", ref.split("/")[-1])[:60].strip("-")
    return f"SPDXRef-Package-{readable}-{hashlib.sha256(ref.encode()).hexdigest()[:8]}"


def to_spdx(report: DependencyReport, product: str, timestamp: Optional[str] = None) -> dict:
    from frame import __version__
    g = _Graph(report)
    ts = _now(timestamp)
    root = "SPDXRef-Package-" + (re.sub(r"[^A-Za-z0-9.-]+", "-", product).strip("-") or "project")
    packages = [{"SPDXID": root, "name": product, "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
                 "primaryPackagePurpose": "APPLICATION"}]
    ids = {r: _spdx_id(r) for r in g.packages}
    for r in sorted(g.packages):
        p = g.packages[r]
        pkg = {"SPDXID": ids[r], "name": p.name, "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
               "licenseConcluded": "NOASSERTION", "licenseDeclared": p.license.strip() or "NOASSERTION",
               "primaryPackagePurpose": "LIBRARY"}
        if p.version:
            pkg["versionInfo"] = p.version
        if p.purl:
            pkg["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                    "referenceLocator": p.purl}]
        notes = [f"declared in {', '.join(g.paths[r])}"]
        if not p.version and p.spec:
            notes.append(f"requirement {p.spec} (no exact version recorded)")
        pkg["comment"] = "; ".join(notes)
        packages.append(pkg)
    rels = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": root}]
    for r in sorted(g.direct):
        if g.dev.get(r):
            rels.append({"spdxElementId": ids[r], "relationshipType": "DEV_DEPENDENCY_OF", "relatedSpdxElement": root})
        else:
            rels.append({"spdxElementId": root, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": ids[r]})
    for a in sorted(g.edges):
        for b in sorted(g.edges[a]):
            rels.append({"spdxElementId": ids[a], "relationshipType": "DEPENDS_ON", "relatedSpdxElement": ids[b]})
    ns = uuid.uuid5(uuid.NAMESPACE_URL, product + "|" + ts + "|" + "|".join(sorted(g.packages)))
    return {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": product,
            "documentNamespace": f"https://github.com/lambdasec/frame/spdx/{ns}",
            "creationInfo": {"created": ts, "creators": [f"Tool: Frame-{__version__}"]},
            "packages": packages, "relationships": rels}
