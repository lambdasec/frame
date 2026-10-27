"""VEX: what Frame knows about each vulnerable dependency, as OpenVEX (v0.2.0) or as a
CycloneDX 1.6 BOM with `vulnerabilities[].analysis`.

What Frame states follows its evidence, which is positive only (reachability never proves a
package unreachable):

    reachability tainted                  affected      CycloneDX exploitable, the flow as evidence
    reachability called/imported/installed affected     CycloneDX in_triage (the version is present)
    a decision in .frame/vex.toml          as recorded  (not_affected with its justification, ...)
    --dev-not-shipped and dev only         not_affected component_not_present

A recorded `not_affected` that a verified flow contradicts is not emitted: the statement stays
`affected` and the conflict is reported, so Frame never certifies against its own evidence.
Every `affected` statement carries the remediation from the upgrade plan.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
STATUSES = ("not_affected", "affected", "fixed", "under_investigation")
JUSTIFICATIONS = ("component_not_present", "vulnerable_code_not_present", "vulnerable_code_not_in_execute_path",
                  "vulnerable_code_cannot_be_controlled_by_adversary", "inline_mitigations_already_exist")
# OpenVEX justification -> CycloneDX impactAnalysisJustification
_CDX_JUSTIFICATION = {
    "component_not_present": "code_not_present",
    "vulnerable_code_not_present": "code_not_present",
    "vulnerable_code_not_in_execute_path": "code_not_reachable",
    "vulnerable_code_cannot_be_controlled_by_adversary": "protected_by_mitigating_control",
    "inline_mitigations_already_exist": "protected_by_mitigating_control",
}
_LEVELS = ("installed", "imported", "called", "tainted")
DECISIONS_FILE = Path(".frame") / "vex.toml"


class VexError(ValueError):
    pass


@dataclass
class Decision:
    vulnerability: str                     # an advisory id or any alias (CVE, GHSA, PYSEC...)
    status: str
    package: Optional[str] = None          # limit to one package (all matching packages otherwise)
    justification: Optional[str] = None
    impact_statement: str = ""
    author: str = ""
    used: bool = False


def load_decisions(root: Path) -> List[Decision]:
    """`.frame/vex.toml`: [[statement]] vulnerability, status, justification, impact_statement,
    package, author. Strict: an unknown key, status or justification is an error."""
    path = Path(root) / DECISIONS_FILE
    if not path.is_file():
        return []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as e:
        raise VexError(f"{path}: {e}") from e
    out = []
    allowed = {"vulnerability", "status", "package", "justification", "impact_statement", "author"}
    for i, s in enumerate(data.get("statement", [])):
        where = f"{path}: [[statement]] #{i + 1}"
        if set(s) - allowed:
            raise VexError(f"{where}: unknown key(s) {sorted(set(s) - allowed)}")
        if not isinstance(s.get("vulnerability"), str) or s.get("status") not in STATUSES:
            raise VexError(f"{where}: needs vulnerability and a status in {list(STATUSES)}")
        if s.get("justification") is not None and s["justification"] not in JUSTIFICATIONS:
            raise VexError(f"{where}: justification must be one of {list(JUSTIFICATIONS)}")
        if s["status"] == "not_affected" and not (s.get("justification") or s.get("impact_statement")):
            raise VexError(f"{where}: not_affected needs a justification or an impact_statement")
        out.append(Decision(s["vulnerability"], s["status"], s.get("package"), s.get("justification"),
                            s.get("impact_statement", ""), s.get("author", "")))
    return out


@dataclass
class Statement:
    advisory: dict                          # one finding of the group (id, aliases, summary, severity...)
    packages: List[dict] = field(default_factory=list)      # the findings: package, version, purl, path
    status: str = "affected"
    justification: Optional[str] = None
    impact_statement: str = ""
    action_statement: str = ""
    notes: List[str] = field(default_factory=list)
    level: str = "installed"
    evidence: str = "matched"
    conflict: str = ""


def _level(f: dict) -> str:
    return (f.get("reachability") or {}).get("level") or "installed"


def _action(f: dict, plans: Dict[Tuple[str, str, str], dict]) -> str:
    p = plans.get((f["path"], f["package"], f["version"]))
    if p and p.get("target"):
        how = {"update-lockfile": "re-lock", "raise-requirement": "raise the requirement",
               "override": f"override ({p.get('how', '')})"}.get(p["action"], "")
        return f"Upgrade {f['package']} to {p['target']} ({how}; frame deps --vulns --apply)."
    if f.get("fixed"):
        return f"Upgrade {f['package']} to {f['fixed'][0]}."
    return (f"No fixed version of {f['package']} is known: mitigate how the code uses it "
            "(frame fix --deps) or remove the dependency.")


def build_statements(findings: List[dict], plans: Optional[List[dict]] = None,
                     decisions: Optional[List[Decision]] = None,
                     dev_not_shipped: bool = False) -> Tuple[List[Statement], List[str]]:
    """One statement per advisory and package version; warnings for conflicts and decisions
    that matched nothing (stale)."""
    plan_index = {(p["path"], p["package"], p["current"]): p for p in (plans or [])}
    decisions = decisions or []
    groups: Dict[Tuple[str, str, str], List[dict]] = {}
    for f in findings:
        groups.setdefault((f["id"], f["package"], f["version"]), []).append(f)
    out: List[Statement] = []
    warnings: List[str] = []
    for (adv_id, pkg, ver), fs in sorted(groups.items()):
        st = Statement(advisory=fs[0], packages=fs)
        st.level = max((_level(f) for f in fs), key=_LEVELS.index)
        st.evidence = max((f.get("evidence", "matched") for f in fs),
                          key=lambda e: ("matched", "data-flow", "solver-verified").index(e)
                          if e in ("matched", "data-flow", "solver-verified") else 0)
        ids = {adv_id, *fs[0].get("aliases", [])}
        decision = next((d for d in decisions if d.vulnerability in ids and (d.package in (None, pkg))), None)
        flows = [fl["location"] for f in fs for fl in (f.get("reachability") or {}).get("flows", [])]
        calls = [c["location"] for f in fs for c in (f.get("reachability") or {}).get("calls", [])]
        st.notes.append(f"Frame reachability: {st.level} ({st.evidence})")
        if flows:
            st.notes.append("attacker data reaches the vulnerable function at " + ", ".join(sorted(set(flows))[:5]))
        elif calls:
            st.notes.append("the vulnerable function is called at " + ", ".join(sorted(set(calls))[:5]))
        if decision is not None:
            decision.used = True
            if decision.status == "not_affected" and st.level == "tainted":
                st.conflict = (f"{adv_id} {pkg}@{ver}: recorded not_affected, but attacker data reaches the "
                               f"vulnerable function ({', '.join(sorted(set(flows))[:3])}); kept as affected")
                warnings.append(st.conflict)
            else:
                st.status, st.justification = decision.status, decision.justification
                st.impact_statement = decision.impact_statement
                st.notes.append(f"decision recorded in {DECISIONS_FILE}" + (f" by {decision.author}" if decision.author else ""))
        elif dev_not_shipped and all(f.get("dev") for f in fs):
            st.status, st.justification = "not_affected", "component_not_present"
            st.impact_statement = "Development-only dependency: not part of the shipped application."
        if st.status == "affected":
            st.action_statement = _action(fs[0], plan_index)
        out.append(st)
    for d in decisions:
        if not d.used:
            warnings.append(f"{DECISIONS_FILE}: the decision for {d.vulnerability}"
                            + (f" ({d.package})" if d.package else "") + " matches no current finding")
    return out, warnings


def _now(timestamp: Optional[str]) -> str:
    return timestamp or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _doc_id(product: str, statements: List[Statement], ts: str) -> str:
    key = product + "|" + ts + "|" + "|".join(f"{s.advisory['id']}:{s.packages[0]['package']}" for s in statements)
    return f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, key)}"


def to_openvex(statements: List[Statement], product: str, author: str = "Frame",
               timestamp: Optional[str] = None) -> dict:
    from frame import __version__
    ts = _now(timestamp)
    out = []
    for s in statements:
        a = s.advisory
        st = {"vulnerability": {"name": a["id"], **({"aliases": a["aliases"]} if a.get("aliases") else {}),
                                **({"description": a["summary"]} if a.get("summary") else {})},
              "products": [{"@id": product,
                            "subcomponents": [{"@id": p["purl"]} for p in _unique_purls(s.packages)]}],
              "status": s.status,
              "status_notes": "; ".join(s.notes)}
        if s.justification:
            st["justification"] = s.justification
        if s.impact_statement:
            st["impact_statement"] = s.impact_statement
        if s.action_statement:
            st["action_statement"] = s.action_statement
        out.append(st)
    return {"@context": OPENVEX_CONTEXT, "@id": _doc_id(product, statements, ts), "author": author,
            "role": "Document Creator", "timestamp": ts, "version": 1,
            "tooling": f"Frame {__version__} (https://github.com/lambdasec/frame)", "statements": out}


def _unique_purls(packages: List[dict]) -> List[dict]:
    seen, out = set(), []
    for p in packages:
        if p.get("purl") and p["purl"] not in seen:
            seen.add(p["purl"])
            out.append(p)
    return out


def to_cyclonedx(statements: List[Statement], product: str, timestamp: Optional[str] = None) -> dict:
    from frame import __version__
    ts = _now(timestamp)
    components, vulns = {}, []
    for s in statements:
        for p in _unique_purls(s.packages):
            components[p["purl"]] = {"type": "library", "bom-ref": p["purl"], "name": p["package"],
                                     "version": p["version"], "purl": p["purl"]}
        a = s.advisory
        state = {"affected": "exploitable" if s.level == "tainted" else "in_triage",
                 "not_affected": "not_affected", "fixed": "resolved", "under_investigation": "in_triage"}[s.status]
        analysis = {"state": state, "detail": "; ".join(s.notes + ([s.impact_statement] if s.impact_statement else [])
                                                         + ([s.action_statement] if s.action_statement else []))}
        if s.justification:
            analysis["justification"] = _CDX_JUSTIFICATION[s.justification]
        if s.status == "affected":
            analysis["response"] = ["update"] if (a.get("fixed")) else ["workaround_available"]
        v = {"id": a["id"], "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{a['id']}"},
             "analysis": analysis,
             "affects": [{"ref": p["purl"]} for p in _unique_purls(s.packages)]}
        if a.get("aliases"):
            v["references"] = [{"id": x, "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{x}"}}
                               for x in a["aliases"]]
        if a.get("summary"):
            v["description"] = a["summary"]
        rating = {}
        if a.get("severity") in ("critical", "high", "medium", "low"):
            rating["severity"] = a["severity"]
        if a.get("score") is not None:
            rating["score"] = a["score"]
        if a.get("cvss", "") and str(a["cvss"]).startswith("CVSS:3"):
            rating["method"] = "CVSSv31" if str(a["cvss"]).startswith("CVSS:3.1") else "CVSSv3"
            rating["vector"] = a["cvss"]
        if rating:
            v["ratings"] = [rating]
        vulns.append(v)
    root_ref = product
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": _doc_id(product, statements, ts),
            "version": 1,
            "metadata": {"timestamp": ts,
                         "tools": {"components": [{"type": "application", "name": "Frame", "version": __version__,
                                                   "externalReferences": [{"type": "website",
                                                                           "url": "https://github.com/lambdasec/frame"}]}]},
                         "component": {"type": "application", "bom-ref": root_ref, "name": product}},
            "components": sorted(components.values(), key=lambda c: c["bom-ref"]),
            "vulnerabilities": vulns}


def product_id(root: Path, given: Optional[str] = None) -> str:
    """The product the statements are about: `--product`, else `pkg:generic/<directory name>`."""
    return given or f"pkg:generic/{Path(root).resolve().name}"
