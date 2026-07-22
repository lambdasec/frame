"""CWE hierarchy: relate a specific weakness to the broader classes it belongs to.

Frame reports the most specific CWE it can prove, for example CWE-89 for SQL
injection. Advisories, policies and compliance mappings routinely cite a broader
ancestor instead, for example CWE-74 (Injection). Without hierarchy awareness a
query for CWE-74 misses every SQL-injection finding Frame produced, which is a
correctness bug in advisory-driven triage, not a detection gap.

The edges below are `ChildOf` relations from MITRE's CWE-1000 Research view,
curated to cover the CWEs Frame emits plus their ancestors. This is deliberately
a *strict* encoding of the published hierarchy:

  * Only real CWE-1000 `ChildOf` edges are recorded. Weaknesses that merely feel
    related are not linked. In particular CWE-20 (Improper Input Validation) is a
    SIBLING of the injection classes under CWE-707, not their parent, so a query
    for CWE-20 does NOT match a CWE-89 finding. Advisories often use CWE-20
    loosely; matching that looseness would manufacture agreement we cannot
    justify, so we do not.
  * A CWE with no recorded parent is treated as a root. Unknown CWEs never match
    anything but themselves, so an incomplete table can only lose matches, never
    invent them.

Reference: https://cwe.mitre.org/data/definitions/1000.html
"""

from typing import Dict, Iterable, Optional, Set, Tuple

# child -> parents (a weakness may have more than one parent in CWE-1000)
CHILD_OF: Dict[str, Tuple[str, ...]] = {
    # --- Improper Neutralization / Injection (under CWE-707) -----------------
    "CWE-74": ("CWE-707",),
    "CWE-20": ("CWE-707",),            # sibling of CWE-74, NOT its parent
    "CWE-79": ("CWE-74",),
    "CWE-94": ("CWE-74",),
    "CWE-77": ("CWE-74",),
    "CWE-78": ("CWE-77",),
    "CWE-91": ("CWE-74",),
    "CWE-93": ("CWE-74",),
    "CWE-113": ("CWE-93",),
    "CWE-917": ("CWE-74",),
    "CWE-943": ("CWE-74",),
    "CWE-89": ("CWE-943",),
    "CWE-90": ("CWE-943",),
    "CWE-643": ("CWE-943",),
    "CWE-1336": ("CWE-94",),
    "CWE-116": ("CWE-707",),
    "CWE-117": ("CWE-116",),
    "CWE-838": ("CWE-116",),

    # --- Access control ------------------------------------------------------
    "CWE-284": ("CWE-664",),
    "CWE-285": ("CWE-284",),
    "CWE-862": ("CWE-285",),
    "CWE-863": ("CWE-285",),
    "CWE-639": ("CWE-863",),
    "CWE-287": ("CWE-284",),
    "CWE-306": ("CWE-287",),
    "CWE-307": ("CWE-287",),
    "CWE-384": ("CWE-287",),
    "CWE-521": ("CWE-287",),
    "CWE-522": ("CWE-287",),
    "CWE-269": ("CWE-284",),
    "CWE-352": ("CWE-863",),

    # --- Resource control / availability ------------------------------------
    "CWE-664": (),                      # pillar: Improper Control of a Resource
    "CWE-400": ("CWE-664",),
    "CWE-770": ("CWE-400",),
    "CWE-1333": ("CWE-400",),
    "CWE-404": ("CWE-664",),
    "CWE-772": ("CWE-404",),
    "CWE-401": ("CWE-772",),
    "CWE-691": (),                      # pillar: Insufficient Control Flow Management
    "CWE-834": ("CWE-691",),
    "CWE-674": ("CWE-834",),
    "CWE-835": ("CWE-834",),
    "CWE-362": ("CWE-691",),
    "CWE-667": ("CWE-664",),

    # --- Memory safety -------------------------------------------------------
    "CWE-118": ("CWE-664",),
    "CWE-119": ("CWE-118",),
    "CWE-120": ("CWE-119",),
    "CWE-125": ("CWE-119",),
    "CWE-787": ("CWE-119",),
    "CWE-672": ("CWE-664",),
    "CWE-416": ("CWE-672",),
    "CWE-415": ("CWE-672",),
    "CWE-476": ("CWE-710",),
    "CWE-457": ("CWE-908",),
    "CWE-908": ("CWE-664",),
    "CWE-843": ("CWE-664",),

    # --- Path / resource exposure -------------------------------------------
    "CWE-668": ("CWE-664",),
    "CWE-706": ("CWE-664",),
    "CWE-22": ("CWE-668", "CWE-706"),
    "CWE-610": ("CWE-664",),
    "CWE-611": ("CWE-610",),
    "CWE-918": ("CWE-610",),
    "CWE-601": ("CWE-610",),
    "CWE-377": ("CWE-668",),
    "CWE-200": ("CWE-664",),
    "CWE-209": ("CWE-200",),
    "CWE-532": ("CWE-200",),
    "CWE-215": ("CWE-200",),
    "CWE-501": ("CWE-664",),

    # --- Crypto --------------------------------------------------------------
    "CWE-693": (),                      # pillar: Protection Mechanism Failure
    "CWE-327": ("CWE-693",),
    "CWE-328": ("CWE-327",),
    "CWE-326": ("CWE-327",),
    "CWE-780": ("CWE-327",),
    "CWE-330": ("CWE-693",),
    "CWE-311": ("CWE-693",),
    "CWE-295": ("CWE-693",),
    "CWE-345": ("CWE-693",),
    "CWE-347": ("CWE-345",),
    "CWE-494": ("CWE-345",),
    "CWE-798": ("CWE-344",),
    "CWE-344": ("CWE-664",),

    # --- Misc ----------------------------------------------------------------
    "CWE-707": (),                      # pillar: Improper Neutralization
    "CWE-710": (),                      # pillar: Improper Adherence to Coding Standards
    "CWE-502": ("CWE-913",),
    "CWE-913": ("CWE-664",),
    "CWE-915": ("CWE-913",),
    "CWE-1321": ("CWE-915",),
    "CWE-470": ("CWE-913",),
    "CWE-614": ("CWE-311",),
    "CWE-1004": ("CWE-311",),
    "CWE-190": ("CWE-682",),
    "CWE-369": ("CWE-682",),
    "CWE-682": (),                      # pillar: Incorrect Calculation
    "CWE-134": ("CWE-74",),
    "CWE-755": ("CWE-703",),
    "CWE-388": ("CWE-703",),
    "CWE-617": ("CWE-703",),
    "CWE-703": (),                      # pillar: Improper Check of Exceptional Conditions
    "CWE-754": ("CWE-703",),
    "CWE-676": ("CWE-710",),
    "CWE-16": (),
    "CWE-840": (),
    "CWE-778": ("CWE-693",),
    "CWE-942": ("CWE-284",),
    "CWE-1395": (),
}


def normalize(cwe) -> Optional[str]:
    """Canonicalize a CWE identifier to `CWE-<n>`; None if unrecognizable.

    Accepts "CWE-79", "cwe_79", "79", 79 and similar.
    """
    if cwe is None:
        return None
    s = str(cwe).strip().upper().replace("_", "-").replace(" ", "")
    if not s:
        return None
    if s.startswith("CWE-"):
        s = s[4:]
    elif s.startswith("CWE"):
        s = s[3:]
    s = s.lstrip("-")
    if not s.isdigit():
        return None
    return f"CWE-{int(s)}"


def parents(cwe) -> Tuple[str, ...]:
    """Direct CWE-1000 parents of `cwe` (empty for roots and unknown CWEs)."""
    key = normalize(cwe)
    return CHILD_OF.get(key, ()) if key else ()


def ancestors(cwe) -> Set[str]:
    """All ancestors of `cwe`, excluding itself. Cycle-safe."""
    key = normalize(cwe)
    if not key:
        return set()
    seen: Set[str] = set()
    stack = list(CHILD_OF.get(key, ()))
    while stack:
        node = stack.pop()
        if node in seen:
            continue
        seen.add(node)
        stack.extend(CHILD_OF.get(node, ()))
    seen.discard(key)
    return seen


def is_a(reported, queried) -> bool:
    """Does a finding reported as `reported` satisfy a query for `queried`?

    True when they are the same weakness, or when `queried` is an ancestor of
    `reported` (a SQL-injection finding satisfies a query for Injection). The
    relation is deliberately one-way: a query for the specific CWE-89 is NOT
    satisfied by a generic CWE-74 finding.
    """
    r, q = normalize(reported), normalize(queried)
    if not r or not q:
        return False
    return r == q or q in ancestors(r)


def matches_any(reported, queried: Iterable) -> bool:
    """True if `reported` satisfies at least one of the `queried` CWEs."""
    return any(is_a(reported, q) for q in (queried or ()))
