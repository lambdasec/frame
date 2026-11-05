#!/usr/bin/env python3
"""LLM adjudication of BAC-Bench findings, following the benchmark's own protocol.

BAC-Bench scores a tool by whether it reported the disclosed bug, decided in two stages
(ABSENTIA paper, arXiv:2610.00977, Section 5.2 "Adjudication"; the paired metric is Section 7.1):

  1. A deterministic LOCATION GATE: a finding survives if its location overlaps the instance's
     implicated files, or its route matches an affected route.
  2. An LLM JUDGE (the paper uses Claude Sonnet 4.6, temperature zero) reads each surviving
     finding against the instance's invariant and the way the vulnerable code breaks it. It is
     not told which tool produced the finding and reads no repository source: it adjudicates the
     claim the tool made. A finding that persists on the fixed commit goes through the same judge
     (and, when it matches, is a false positive for the paired metric).

The paper publishes no judge prompt, so the prompt here is ours; its inputs are the dataset's own
fields for exactly what the paper names (`invariant`, `violation`) plus `match_criteria`, the
affected routes, the implicated files and symbols and the expected CWEs. Two deliberate
deviations, both for cost: candidates are capped per checkout (ranked by closeness to the sink
lines), and one call judges all of a checkout's candidates, each independently, instead of one call
per finding. The tool's identity is withheld (no tier, no source_var, and the "[LLM-...]" prefix is
stripped from the claim). This complements `match.py`, whose file+line window can under-credit a
correct finding at another line of an implicated function and cannot read the claim at all.

Verdicts are cached on disk (keyed by system/case/checkout and a hash of the candidates, the judge
model and the prompt version), so re-scoring never re-bills. A transport failure or an unparseable
reply is `judge-error` for that checkout, never a miss.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:                                    # imported as benchmarks.bacbench.judge (tests) or as a script
    from .match import ACCESS_CONTROL_CWES, _same_file, norm_cwe
except ImportError:                     # pragma: no cover - script mode (sys.path holds this dir)
    from match import ACCESS_CONTROL_CWES, _same_file, norm_cwe  # type: ignore

PROMPT_VERSION = "bacbench-judge-v1"
DEFAULT_CAP = 25

JUDGE_SYSTEM = (
    "You adjudicate whether findings reported by a security tool describe one specific, "
    "disclosed broken-access-control vulnerability. You are not told which tool produced the "
    "findings and you cannot read the source code: judge the claim each finding makes against "
    "the advisory's invariant and the way the vulnerable code breaks it.\n\n"
    "A finding MATCHES only if it identifies this same defect: the same missing or broken "
    "authorization or scoping, at the same place, route or helper, with an explanation "
    "consistent with the violation. It does NOT match if it is merely another weakness in the "
    "same file, a different route or object, a generic remark, or a different vulnerability "
    "class. Judge every finding independently.\n\n"
    "Reply with strict JSON only, no prose: "
    "{\"verdicts\": [{\"index\": <int>, \"match\": <true|false>, \"rationale\": \"<one sentence>\"}]} "
    "with exactly one entry per finding index."
)

_TOOL_PREFIX = re.compile(r"^\s*\[(?:LLM|llm)[-_ ][^\]]*\]\s*")
_THINK = re.compile(r"<think>.*?</think>", re.S)


def implicated_files(case: Dict[str, Any]) -> List[str]:
    files = list(case.get("sink_files") or []) + list(case.get("root_files") or [])
    files += [loc.get("file", "") for loc in (case.get("sink_locations") or [])]
    out: List[str] = []
    for f in files:
        if f and f not in out:
            out.append(f)
    return out


def _route_path(route: str) -> str:
    """'GET /api/v1/files/{id}' -> '/api/v1/files/{id}'."""
    parts = str(route or "").split(None, 1)
    return parts[1] if len(parts) == 2 else parts[0] if parts else ""


def location_gate(finding: Dict[str, Any], case: Dict[str, Any]) -> bool:
    """Stage 1 of the BAC-Bench adjudication: the finding's location overlaps an implicated file,
    or its claim names an affected route (findings carry no route field, so the route is read
    from the claim text)."""
    if any(_same_file(finding.get("file", ""), f) for f in implicated_files(case)):
        return True
    text = str(finding.get("description") or "")
    for r in case.get("affected_routes") or []:
        path = _route_path(r)
        if len(path) > 1 and path in text:
            return True
    return False


def _distance(finding: Dict[str, Any], case: Dict[str, Any]) -> int:
    """Lines from the nearest recorded sink range in the same file (0 inside; large when the
    file has no range or the finding has no line)."""
    try:
        line = int(finding.get("line") or 0)
    except (TypeError, ValueError):
        line = 0
    best = 10 ** 6
    for loc in case.get("sink_locations") or []:
        if not _same_file(finding.get("file", ""), loc.get("file", "")) or not line:
            continue
        lo = int(loc.get("line_start", 0) or 0)
        hi = int(loc.get("line_end", lo) or lo)
        best = min(best, 0 if lo <= line <= hi else min(abs(line - lo), abs(line - hi)))
    return best


def candidates(findings: Optional[List[Dict[str, Any]]], case: Dict[str, Any],
               cap: int = DEFAULT_CAP) -> List[Tuple[int, Dict[str, Any]]]:
    """(index into `findings`, finding) pairs that pass the location gate, best first, capped.
    Ranked by distance to a sink range, then access-control CWE before others, then the agent's
    findings (which carry a written claim) before the engine's."""
    gated = [(i, f) for i, f in enumerate(findings or []) if location_gate(f, case)]

    def key(item):
        i, f = item
        ac = norm_cwe(f.get("cwe")) in ACCESS_CONTROL_CWES
        return (_distance(f, case), 0 if ac else 1, 0 if f.get("tier") == "llm" else 1, i)
    return sorted(gated, key=key)[:max(0, cap)]


def _claim(f: Dict[str, Any]) -> str:
    return _TOOL_PREFIX.sub("", str(f.get("description") or "")).strip()[:400]


def build_messages(case: Dict[str, Any], cands: List[Tuple[int, Dict[str, Any]]]) -> List[Dict[str, str]]:
    advisory = {
        "invariant": case.get("invariant", ""),
        "violation": case.get("violation", ""),
        "match_criteria": case.get("match_criteria", ""),
        "affected_routes": case.get("affected_routes") or [],
        "implicated_files": implicated_files(case),
        "implicated_symbols": case.get("root_symbols") or [],
        "expected_cwes": case.get("expected_cwes") or [],
    }
    items = [{"index": k, "file": f.get("file", ""), "line": f.get("line"),
              "cwe": f.get("cwe", ""), "type": f.get("type", ""), "claim": _claim(f)}
             for k, (_, f) in enumerate(cands)]
    user = ("ADVISORY:\n" + json.dumps(advisory, indent=1) +
            "\n\nFINDINGS:\n" + json.dumps(items, indent=1) +
            "\n\nFor each finding index, does it describe this advisory's defect?")
    return [{"role": "system", "content": JUDGE_SYSTEM}, {"role": "user", "content": user}]


def parse_verdicts(text: str, n: int) -> Optional[Dict[int, Tuple[bool, str]]]:
    """{candidate index: (match, rationale)} from the judge's reply, or None when the reply is not
    the required JSON. An index the reply leaves out is not a match."""
    text = _THINK.sub("", str(text or ""))
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        obj = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return None
    verdicts = obj.get("verdicts") if isinstance(obj, dict) else None
    if not isinstance(verdicts, list):
        return None
    out: Dict[int, Tuple[bool, str]] = {k: (False, "") for k in range(n)}
    for v in verdicts:
        if not isinstance(v, dict):
            return None
        idx, match = v.get("index"), v.get("match")
        if not isinstance(idx, int) or isinstance(idx, bool) or not 0 <= idx < n:
            continue
        if not isinstance(match, bool):
            return None
        out[idx] = (match, str(v.get("rationale") or "")[:300])
    return out


def judge_config(model: Optional[str] = None, base_url: Optional[str] = None,
                 key_env: str = "FRAME_LLM_API_KEY"):
    """The judge's endpoint: the hunt's own FRAME_LLM_* settings unless overridden. `key_env`
    names the environment variable holding the judge's key (e.g. an OpenRouter key), so a
    different provider needs no new Frame variable."""
    from frame.sil.llm_client import LLMConfig
    cfg = LLMConfig.from_env()
    if model:
        cfg.model = model
    if base_url:
        cfg.base_url = base_url.rstrip("/")
    if key_env and os.environ.get(key_env):
        cfg.api_key = os.environ[key_env]
    cfg.temperature = 0.0
    cfg.enabled = bool(cfg.base_url and cfg.model)
    return cfg


class Judge:
    """Adjudicates one checkout's findings against a case; caches verdicts in `cache_path`."""

    def __init__(self, client, cache_path: Optional[Path] = None, model: str = "",
                 cap: int = DEFAULT_CAP):
        self.client = client
        self.model = model or getattr(getattr(client, "config", None), "model", "") or ""
        self.cap = cap
        self.cache_path = Path(cache_path) if cache_path else None
        self.cache: Dict[str, Any] = {}
        self.calls = 0
        if self.cache_path and self.cache_path.is_file():
            try:
                self.cache = json.loads(self.cache_path.read_text())
            except (OSError, json.JSONDecodeError):
                self.cache = {}

    def _key(self, system: str, case_id: str, checkout: str,
             cands: List[Tuple[int, Dict[str, Any]]]) -> str:
        payload = json.dumps([[i, f.get("file"), f.get("line"), f.get("cwe"), f.get("type"), _claim(f)]
                              for i, f in cands], sort_keys=True)
        h = hashlib.sha256(f"{PROMPT_VERSION}|{self.model}|{payload}".encode()).hexdigest()[:16]
        return f"{system}/{case_id}/{checkout}/{h}"

    def _save(self) -> None:
        if self.cache_path:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(self.cache, indent=1, sort_keys=True))

    def judge(self, system: str, case_id: str, checkout: str,
              findings: Optional[List[Dict[str, Any]]], case: Dict[str, Any]) -> Dict[str, Any]:
        """{"status": "ok" | "no-candidates" | "judge-error", "matched": [indices into findings],
        "rationale": {index: text}}. Cached verdicts are reused."""
        cands = candidates(findings, case, self.cap)
        if not cands:
            return {"status": "no-candidates", "matched": [], "rationale": {}}
        key = self._key(system, case_id, checkout, cands)
        if key in self.cache:
            hit = self.cache[key]
            return {"status": "ok", "matched": list(hit["matched"]),
                    "rationale": {int(k): v for k, v in hit.get("rationale", {}).items()}}
        self.calls += 1
        msg = self.client.chat_raw(build_messages(case, cands))
        if msg is None:
            return {"status": "judge-error", "error": "transport", "matched": [], "rationale": {}}
        verdicts = parse_verdicts((msg or {}).get("content") or "", len(cands))
        if verdicts is None:
            return {"status": "judge-error", "error": "unparseable", "matched": [], "rationale": {}}
        matched = [cands[k][0] for k, (m, _) in verdicts.items() if m]
        rationale = {cands[k][0]: r for k, (m, r) in verdicts.items() if m}
        self.cache[key] = {"matched": matched, "rationale": {str(k): v for k, v in rationale.items()},
                           "candidates": [i for i, _ in cands], "model": self.model}
        self._save()
        return {"status": "ok", "matched": matched, "rationale": rationale}
