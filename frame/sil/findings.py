"""One finding model for every domain: a category (what kind of weakness) and an evidence
level (how strongly it is proven). Both are reported in the JSON and SARIF output.

Evidence, weakest to strongest:
- ``matched``: a usage or a pattern, with no data flow (a weak hash call, a hardcoded key,
  a protection switched off).
- ``llm-detected``: proposed by the LLM layer, not grounded in a sink Frame recognises.
- ``llm-verified``: proposed by the LLM layer and grounded in a sink Frame recognises.
- ``data-flow``: a source-to-sink path found by the taint analysis.
- ``solver-verified``: a path the solver proved reachable (incorrectness logic witness).
- ``exploit-confirmed``: reproduced against a live target (``frame exploit``).

Categories: ``taint`` (injection and other attacker-data flows), ``memory`` (C/C++ memory and
undefined behaviour), ``crypto``, ``secret``, ``access-control``, ``hardening``, and, for the
domains still to come, ``dependency``, ``iac``, ``container`` and ``ai``.
"""

from __future__ import annotations

EVIDENCE_LEVELS = ("matched", "llm-detected", "llm-verified", "data-flow", "solver-verified",
                   "exploit-confirmed")
from frame.sil.kinds import CATEGORIES, load as _load_kinds

_CATEGORY_OF = _load_kinds().category             # finding type -> category (specs/data/kinds.toml)


def category_of(vuln_type: str, explicit: str = "") -> str:
    """The finding's category: an explicit one (set by a domain, e.g. ``hardening``), else
    its type's (`specs/data/kinds.toml`), else ``taint``."""
    return explicit or _CATEGORY_OF.get(vuln_type, "taint")


def evidence_of_check(verified: bool, has_flow: bool) -> str:
    """Evidence for a finding from the symbolic analysis."""
    if verified and has_flow:
        return "solver-verified"
    return "data-flow" if has_flow else "matched"
