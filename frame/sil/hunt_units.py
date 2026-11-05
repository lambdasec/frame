"""Investigation units for the authorization hunt: the engine decides WHAT gets looked at.

One agent over a whole repository spends its budget where its curiosity takes it. Frame's v11
hunt was that shape and missed 7 of 30 BAC-Bench cases whose vulnerable handler was in the
engine's own handler list; ABSENTIA's ablation (arXiv 2610.00977) measures the same effect,
3/30 for one agent against 18/30 for one agent per route. So coverage belongs to the engine:
it groups the handlers into small units (a class's handlers, or a file's module-level ones,
siblings together so a check one of them lacks stands out), ranks the units by what its facts
say is risky, and the hunt gives each unit a fresh agent that must leave a verdict on every
handler in it. The service functions and authorization gates the handlers delegate to get
units of their own -- real access-control bugs often live there, not in the route.

Pure functions over an `EngineIndex` (frame/sil/llm_hunt.py); no model state.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# The authorization classes the hunt is about. An engine finding of one of these at a handler is
# a candidate the unit's agent must confirm or refute; anything else (XSS, a secret) is not.
AUTHZ_CWES = frozenset({"CWE-639", "CWE-862", "CWE-863", "CWE-285", "CWE-284", "CWE-269",
                        "CWE-915", "CWE-840", "CWE-566", "CWE-732"})

# Sink kinds that read or change stored data: what makes a handler worth an authorization look.
_DATA_KINDS = frozenset({"resource_select", "resource_modify", "sql", "nosql", "orm"})
_WRITE_KINDS = frozenset({"resource_modify"})

MAX_PER_UNIT = 8


@dataclass
class Unit:
    """One investigation: a few handlers (or service functions) one agent audits end to end."""
    id: str                       # stable across checkouts of one repository (verdict reuse keys on it)
    kind: str                     # "handlers" | "service" | "scouted" | "coverage"
    title: str
    files: List[str]
    members: List[Any]            # HandlerFact for "handlers", dicts {name, file, line, role} for "service"
    candidates: List[Dict[str, Any]] = field(default_factory=list)   # unverified engine authz findings here
    leads: List[Dict[str, Any]] = field(default_factory=list)        # soundness leads / gates in these files
    score: float = 0.0
    reasons: List[str] = field(default_factory=list)

    def names(self) -> List[str]:
        return [m.name if hasattr(m, "name") else str(m.get("name", "")) for m in self.members]


def proc_end_line(proc, start: int) -> int:
    """The last source line of a procedure: the frontend's `end_line`, else the last line any of
    its instructions sits on, else `start`. Never `span`: that is a BYTE range (reading its end as
    a line made a 6-line handler at line 10 run to "line 348", pulling other handlers' findings
    and sinks into it)."""
    end = int(getattr(proc, "end_line", 0) or 0) if proc is not None else 0
    if end >= start > 0:
        return end
    lines = [getattr(getattr(i, "loc", None), "line", 0) or 0
             for n in (getattr(proc, "nodes", {}) or {}).values()
             for i in (getattr(n, "instrs", []) or [])] if proc is not None else []
    return max([start] + [ln for ln in lines if ln >= start])


def simple_name(name: str) -> str:
    """`pkg::Cls.method#2` -> `method` (the last component, without an overload suffix)."""
    return str(name or "").split("::")[-1].split("#")[0].rsplit(".", 1)[-1]


def class_of(name: str) -> str:
    """The class part of a handler name (`AddonViewSet.destroy` -> `AddonViewSet`), "" for a
    module-level function."""
    base = str(name or "").split("::")[-1].split("#")[0]
    return base.rsplit(".", 1)[0] if "." in base else ""


def _is_test_code(h, language: str) -> bool:
    program = getattr(h, "program", None)
    if program is None:
        return False
    try:
        from frame.sil.test_code import test_framework
        return test_framework(program, getattr(program, "language", "") or language) is not None
    except Exception:
        return False


def _chunks(items: List[Any], size: int) -> List[List[Any]]:
    return [items[i:i + size] for i in range(0, len(items), size)] or [[]]


def _handler_units(index, language: str, max_per_unit: int) -> List[Unit]:
    groups: Dict[Tuple[str, str], List[Any]] = {}
    for h in index.handlers:
        if _is_test_code(h, language):
            continue
        groups.setdefault((h.file, class_of(h.name)), []).append(h)
    units: List[Unit] = []
    for (path, cls), hs in sorted(groups.items()):
        hs = sorted(hs, key=lambda h: (h.line, h.name))
        parts = _chunks(hs, max_per_unit)
        for k, part in enumerate(parts):
            uid = f"{path}::{cls or '<module>'}" + (f"#{k + 1}" if len(parts) > 1 else "")
            title = f"{path} :: {cls}" if cls else f"{path} (module-level)"
            units.append(Unit(id=uid, kind="handlers", title=title, files=[path], members=part))
    return units


def _service_units(index, handler_keys: set) -> List[Unit]:
    by_file: Dict[str, List[Dict[str, Any]]] = {}
    seen: set = set()

    def add(item: Dict[str, Any], role: str) -> None:
        key = (item.get("file", ""), item.get("name", ""))
        if not key[0] or key in seen or key in handler_keys:
            return
        seen.add(key)
        entry = {"name": item.get("name", ""), "file": item.get("file", ""),
                 "line": int(item.get("line") or 0), "role": role}
        if role == "service":
            entry["scoped"] = bool(item.get("scoped"))
        if item.get("reason"):
            entry["reason"] = item["reason"]
        by_file.setdefault(key[0], []).append(entry)

    for lead in getattr(index, "soundness_leads", []) or []:
        add(lead, "soundness")
    for gate in getattr(index, "authz_gates", []) or []:
        add(gate, "gate")
    for svc in getattr(index, "service_functions", []) or []:
        add(svc, "service")
    units: List[Unit] = []
    for path, items in sorted(by_file.items()):
        items.sort(key=lambda m: (m["line"], m["name"]))
        parts = _chunks(items, MAX_PER_UNIT)
        for k, part in enumerate(parts):
            uid = f"{path}::<service>" + (f"#{k + 1}" if len(parts) > 1 else "")
            units.append(Unit(id=uid, kind="service", title=f"{path} (service layer)",
                              files=[path], members=part))
    return units


def _covered(item: Dict[str, Any], handlers_by_file: Dict[str, List[str]],
             services_by_file: Dict[str, List[str]]) -> bool:
    """A scouted function the engine already puts in a unit: a handler or service function of the
    same file with that name (`Cls.m` must match the class too; a bare `m` matches any)."""
    file, name = item.get("file", ""), str(item.get("name", ""))
    want, cls = simple_name(name), class_of(name)
    for known in handlers_by_file.get(file, []) + services_by_file.get(file, []):
        if known == name or (simple_name(known) == want and (not cls or class_of(known) == cls)):
            return True
    return False


def _scouted_units(scouted: List[Dict[str, Any]], index, units: List[Unit]) -> List[Unit]:
    """Units for what the scouts found and the engine does not cover: a route, service function or
    authorization helper in code no pack describes (a framework convention Frame does not know, a
    data layer it cannot type). Grouped by file like the handlers; the id carries a hash of the
    members, so a verdict cached for one scouted set is never reused for a different one."""
    import hashlib
    handlers_by_file: Dict[str, List[str]] = {}
    for h in getattr(index, "handlers", []) or []:
        handlers_by_file.setdefault(h.file, []).append(h.name)
    services_by_file: Dict[str, List[str]] = {}
    for u in units:
        if u.kind == "service":
            for m in u.members:
                services_by_file.setdefault(m.get("file", ""), []).append(m.get("name", ""))
    by_file: Dict[str, List[Dict[str, Any]]] = {}
    seen: set = set()
    for item in scouted or []:
        key = (item.get("file", ""), str(item.get("name", "")))
        if not key[0] or not key[1] or key in seen or _covered(item, handlers_by_file, services_by_file):
            continue
        seen.add(key)
        by_file.setdefault(key[0], []).append(dict(item))
    out: List[Unit] = []
    for path, items in sorted(by_file.items()):
        items.sort(key=lambda m: (int(m.get("line") or 0), m.get("name", "")))
        parts = _chunks(items, MAX_PER_UNIT)
        for part in parts:
            digest = hashlib.sha256("\0".join(m["name"] for m in part).encode()).hexdigest()[:8]
            out.append(Unit(id=f"{path}::<scouted:{digest}>", kind="scouted",
                            title=f"{path} (found by the scouts)", files=[path], members=part))
    return out


def coverage_units(reads: Dict[str, Dict[str, List[Tuple[int, int]]]], owned: set,
                   procs_by_file: Dict[str, List[Dict[str, Any]]],
                   min_readers: int = 2) -> List[Unit]:
    """The coverage wave: code the units' agents relied on that no unit owns. `reads` is
    file -> unit id -> the line ranges that unit's agent read there. A file read by at least
    `min_readers` units and owned by none is a layer several verdicts depend on (an enforcement
    helper, a data service) that no agent was asked to judge: parse-server's `enforceRoleSecurity`
    and strapi's document-service repository were each read by four units in BAC-Bench and audited
    by none. Its members are the procedures (`procs_by_file`: name, line, end_line) the agents'
    reads covered, most-read first, one unit per file. A file with no such procedure (a URL
    table, a type declaration) has nothing to judge and gets no unit."""
    import hashlib
    out: List[Unit] = []
    for path in sorted(reads):
        by_unit = reads[path]
        if path in owned or len(by_unit) < max(1, min_readers):
            continue
        members: List[Dict[str, Any]] = []
        for p in procs_by_file.get(path, []):
            lo, hi = int(p.get("line") or 0), int(p.get("end_line") or p.get("line") or 0)
            n = sum(1 for rs in by_unit.values() if any(a <= hi and lo <= b for a, b in rs))
            if n and lo:
                members.append({"name": p["name"], "file": path, "line": lo, "end_line": hi,
                                "role": "delegate", "readers": n,
                                "reason": f"read by {n} of the units that rely on it"})
        if not members:
            continue
        # The most-read first; a one-line callback ranks below a function with a body.
        members.sort(key=lambda m: (-m["readers"], m["end_line"] <= m["line"], m["line"], m["name"]))
        part = sorted(members[:MAX_PER_UNIT], key=lambda m: (m["line"], m["name"]))
        digest = hashlib.sha256("\0".join(m["name"] for m in part).encode()).hexdigest()[:8]
        out.append(Unit(id=f"{path}::<coverage:{digest}>", kind="coverage",
                        title=f"{path} (relied on by {len(by_unit)} units, audited by none)",
                        files=[path], members=part))
    return out


def _in_range(f: Dict[str, Any], h) -> bool:
    try:
        line = int(f.get("line") or 0)
    except (TypeError, ValueError):
        return False
    return f.get("file") == h.file and h.line <= line <= max(h.end_line or h.line, h.line)


def _attach_candidates(units: List[Unit], index) -> None:
    """Each unverified engine authorization finding goes to the unit whose handler contains it
    (else the first unit of its file), for that unit's agent to confirm or refute."""
    by_file: Dict[str, List[Unit]] = {}
    for u in units:
        for p in u.files:
            by_file.setdefault(p, []).append(u)
    for f in getattr(index, "findings", []) or []:
        if str(f.get("cwe") or "").upper() not in AUTHZ_CWES or f.get("proven"):
            continue
        owners = by_file.get(f.get("file", ""), [])
        home = next((u for u in owners if u.kind == "handlers"
                     and any(_in_range(f, h) for h in u.members)), owners[0] if owners else None)
        if home is not None:
            home.candidates.append(f)
    for lead in getattr(index, "soundness_leads", []) or []:
        for u in by_file.get(lead.get("file", ""), []):
            if u.kind == "handlers":
                u.leads.append({"role": "soundness", **lead})


def _score(u: Unit) -> None:
    """Rank by what the engine knows, never by names: open candidates, data access without a
    gate, siblings that disagree about protection, writes."""
    s = 0.0
    if u.candidates:
        s += 5 * min(len(u.candidates), 2)
        u.reasons.append(f"{len(u.candidates)} unverified engine candidate(s)")
    if u.kind == "coverage":
        readers = max((int(m.get("readers") or 0) for m in u.members), default=0)
        s += readers
        u.reasons.append(f"read by {readers} units to reach their verdicts; no unit audited it")
        u.score = s
        return
    if u.kind == "scouted":
        # No engine facts to rank by: the scouts found code the engine cannot see, which is
        # itself the reason to look (every unit is audited unless a max_units budget is set).
        roles = {m.get("role") for m in u.members}
        s += 3 if "route" in roles else 2
        u.reasons.append("found by the scouts; the engine has no facts for it")
        u.score = s
        return
    if u.kind == "service":
        roles = {m.get("role") for m in u.members}
        if "soundness" in roles:
            s += 5
            u.reasons.append("authorization-soundness lead")
        if "gate" in roles:
            s += 3
            u.reasons.append("authorization gate the handlers delegate to")
        if any(m.get("role") == "service" and not m.get("scoped") for m in u.members):
            s += 4
            u.reasons.append("data access with no caller identity in scope")
        u.score = s
        return
    if u.leads:
        s += 4
        u.reasons.append("authorization-soundness lead in this file")
    data = [h for h in u.members if h.reaches_resource
            or any(str(k.get("kind")) in _DATA_KINDS for k in (h.sinks or []))]
    open_ = [h for h in data if not h.protected]
    if open_:
        s += 3 * min(len(open_), 2)
        u.reasons.append(f"{len(open_)} unprotected handler(s) reaching data")
    if data and len({h.protected for h in data}) > 1:
        s += 2
        u.reasons.append("siblings disagree about protection")
    if any(str(k.get("kind")) in _WRITE_KINDS for h in u.members for k in (h.sinks or [])):
        s += 1
        u.reasons.append("modifies stored data")
    if data:
        s += 1
    u.score = s


def plan_units(index, language: str = "", max_units: Optional[int] = None,
               max_per_unit: int = MAX_PER_UNIT,
               scouted: Optional[List[Dict[str, Any]]] = None) -> Tuple[List[Unit], List[Unit]]:
    """The hunt's units, highest-ranked first: (selected, deferred). `deferred` is what the
    `max_units` budget left out -- reported, never silently dropped, so the coverage of a run
    is known. Test code is not audited. `scouted` are the routes / service functions / helpers
    the scouts listed (dicts: name, file, line, end_line, role, note); those the engine does
    not already cover get units of their own."""
    units = _handler_units(index, language, max_per_unit)
    handler_keys = {(h.file, h.name) for u in units for h in u.members}
    units += _service_units(index, handler_keys)
    units += _scouted_units(scouted or [], index, units)
    _attach_candidates(units, index)
    for u in units:
        _score(u)
    order = sorted(units, key=lambda u: (-u.score, u.id))
    if max_units is None or max_units <= 0:
        return order, []
    return order[:max_units], order[max_units:]


# ---- Scout areas ---------------------------------------------------------------------------

# Directories a scout never needs: vendored or generated code, and tests / docs / examples,
# which hold no routes of the application (choosing what to SCOUT; findings are tagged as test
# code from the program, never from a path).
_SCOUT_SKIP = frozenset({".git", "node_modules", "__pycache__", ".venv", "venv", ".tox", "dist",
                         "build", ".next", ".nuxt", "coverage", "site-packages", "vendor",
                         "test", "tests", "__tests__", "spec", "specs", "e2e", "fixtures",
                         "__mocks__", "docs", "examples", "example"})
AREA_FILES = 300
MAX_SCOUTS = 16


@dataclass
class Area:
    """A directory one scout maps: everything beneath it, or with `own_only` only the files
    directly in it (its subdirectories are areas of their own)."""
    path: str                      # repo-relative; "" is the repository root
    files: int
    own_only: bool = False

    def holds(self, rel: str) -> bool:
        d = os.path.dirname(rel)
        if self.own_only:
            return d == self.path
        return not self.path or d == self.path or d.startswith(self.path + "/")

    def label(self) -> str:
        return (self.path or ".") + (" (files directly in it)" if self.own_only else "/")


def _source_exts(language: str) -> Tuple[str, ...]:
    from frame.sil.scanner import language_extensions
    langs = {"javascript": ("javascript", "typescript"), "typescript": ("javascript", "typescript")}
    exts: List[str] = []
    for lang in langs.get(language, (language or None,)):
        exts += language_extensions(lang)
    return tuple(sorted(set(exts)))


def scout_areas(repo_root: str, language: str = "", max_files: int = AREA_FILES,
                max_scouts: int = MAX_SCOUTS) -> List[List[Area]]:
    """The repository split for the scouts: directories of at most `max_files` source files of
    the language (a larger one is split into its subdirectories, its own files an area of their
    own), packed into at most `max_scouts` scouts in PATH order with about equal file counts, so a
    scout gets neighbouring directories (one package's `src/*` together, not a controller folder
    beside twenty integration folders). Every source file outside the skipped directories is in
    exactly one area."""
    exts = _source_exts(language)
    own: Dict[str, int] = {}
    for dp, dns, fns in os.walk(repo_root):
        dns[:] = sorted(d for d in dns if d not in _SCOUT_SKIP and not d.startswith("."))
        n = sum(1 for f in fns if f.endswith(exts) and not f.endswith((".min.js", ".d.ts")))
        if n:
            rel = os.path.relpath(dp, repo_root).replace(os.sep, "/")
            own["" if rel == "." else rel] = n
    total: Dict[str, int] = {}
    for d, n in own.items():
        parts = d.split("/") if d else []
        for i in range(len(parts) + 1):
            k = "/".join(parts[:i])
            total[k] = total.get(k, 0) + n

    def children(d: str) -> List[str]:
        depth = len(d.split("/")) + 1 if d else 1
        return sorted(k for k in total if k and len(k.split("/")) == depth
                      and (not d or k.startswith(d + "/")))

    def split(d: str) -> List[Area]:
        kids = children(d)
        if total.get(d, 0) <= max_files or not kids:
            return [Area(d, total.get(d, 0))]
        out: List[Area] = []
        for k in kids:
            out += split(k)
        if own.get(d):
            out.append(Area(d, own[d], own_only=True))
        return out

    areas = split("") if total else []
    areas = [a for a in areas if a.files]
    if not areas:
        return []
    areas.sort(key=lambda a: (a.path, a.own_only))
    k = max(1, min(max_scouts, len(areas)))
    total_files = sum(a.files for a in areas)
    bins: List[List[Area]] = [[]]
    load = 0
    for i, a in enumerate(areas):
        left_bins = k - len(bins)
        # close this scout once it holds its share, keeping one area per scout still to fill
        if bins[-1] and left_bins > 0 and load + a.files / 2 > total_files * len(bins) / k \
                and len(areas) - i >= left_bins:
            bins.append([])
        bins[-1].append(a)
        load += a.files
    return [b for b in bins if b]
