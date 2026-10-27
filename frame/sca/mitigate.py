"""Code mitigation of vulnerable dependencies (`frame fix DIR --deps`): change how the
application uses a vulnerable function, the dependency version unchanged, and prove it with the
taint engine.

For each call site that reaches a vulnerable function (`tainted`, or `called`), an LLM proposes
a minimal patch. A patch is kept only if re-running the whole analysis on a copy of the project
with the patch applied shows the goal met:

    tainted  ->  no attacker data reaches the function any more (`untainted`), or the call is
                 gone (`removed`)
    called   ->  the call is gone (`removed`): without a flow there is nothing to cut

and the patched file has no finding it did not have before. Re-running the full analysis (not
the one file) matters: a flow that crosses files must still be seen, or an unfixed patch would
look verified.
"""

from __future__ import annotations

import shutil
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple

SYSTEM = (
    "You are a senior application-security engineer. A dependency in this project has a known "
    "vulnerability in one function, and the project cannot upgrade it right now. Change how THIS "
    "file uses that function so the vulnerability cannot be triggered: stop attacker-controlled "
    "data from reaching it (validate against a fixed allowlist, use a constant, reject bad input) "
    "or replace the call with the library's safe equivalent (for example yaml.safe_load instead of "
    "yaml.load). Do not upgrade the dependency, do not add unrelated changes, and keep the "
    "behaviour for legitimate input. First reason briefly, THEN output ONLY a JSON object giving "
    "the exact code span to replace (`original`, copied verbatim, no line-number prefixes) and its "
    "`replacement`, with a one-line `rationale`.")


@dataclass
class Site:
    file: str                      # relative to the project root
    line: int
    function: str                  # the vulnerable function's canonical id
    call: str                      # the call as written
    level: str                     # tainted | called
    advisories: List[dict] = field(default_factory=list)


@dataclass
class Result:
    site: Site
    applied: bool = False
    verdict: str = ""              # removed | untainted | still-tainted | still-called | introduces-findings | ...
    rationale: str = ""
    introduced: List[str] = field(default_factory=list)
    diff: str = ""

    @property
    def verified(self) -> bool:
        return self.verdict in ("removed", "untainted")


def analyse(target: Path, excluded: Iterable) -> Tuple[object, list]:
    """The `frame scan --sca` analysis: advisories matched, vulnerable functions as sinks,
    findings linked. Returns (ScaRun, scan results)."""
    from frame.sca.scan import link, prepare, sink_packs
    from frame.sil.scanner import FrameScanner
    excluded = list(excluded)
    run = prepare(target, excluded)
    scanner = FrameScanner(verify=True)
    scanner.add_packs(sink_packs(run))
    results = scanner.scan_directory(str(target), None, exclude_dirs=excluded)
    link(run, results, target)
    return run, results


def sites(run, include_called: bool = True) -> List[Site]:
    by_key: Dict[Tuple[str, int, str], Site] = {}
    for f in run.findings:
        reach = f.get("reachability") or {}
        level = reach.get("level")
        if level not in ("tainted", "called") or (level == "called" and not include_called):
            continue
        tainted_at = {fl["location"] for fl in reach.get("flows", [])}
        for c in reach.get("calls", []):
            rel, _, line = c["location"].rpartition(":")
            lvl = "tainted" if c["location"] in tainted_at else "called"
            if lvl == "called" and not include_called:
                continue
            s = by_key.setdefault((rel, int(line), c["function"]),
                                  Site(rel, int(line), c["function"], c.get("call", c["function"]), lvl))
            if lvl == "tainted":
                s.level = "tainted"
            s.advisories.append({k: f[k] for k in ("id", "package", "version", "summary", "fixed", "severity")})
    return sorted(by_key.values(), key=lambda s: (s.file, s.line, s.function))


def propose(site: Site, source: str, config, client=None) -> dict:
    """Ask the model for a mitigation patch for one site ({original, replacement, rationale})."""
    from frame.sil.llm_client import LLMClient, _extract_json_object
    from frame.sil.llm_detect import _detect_max_chars, _numbered
    from frame.sil.llm_fix import _fix_response_format
    client = client or LLMClient(config)
    advs = "\n".join(f"- {a['id']} in {a['package']}@{a['version']}: {a['summary']}"
                     + (f" (fixed upstream in {a['fixed'][0]}, not an option here)" if a.get("fixed") else "")
                     for a in site.advisories)
    how = ("Attacker-controlled data reaches it at that line (Frame's taint analysis found the flow)."
           if site.level == "tainted" else "It is called at that line.")
    prompt = (f"Vulnerable function: {site.function} (written `{site.call}`), at line {site.line}. {how}\n"
              f"Advisories:\n{advs}\n\nSource (numbered lines):\n{_numbered(source, _detect_max_chars(config))}\n\n"
              "Reason briefly, then output the JSON object with `original` (verbatim code span, no "
              "line-number prefixes), its `replacement`, and a one-line `rationale`.")
    rf = _fix_response_format(getattr(config, "json_mode", "json_object"))
    raw = client.complete([{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}],
                          response_format=rf, force_json=(rf is not None), max_tokens=config.max_tokens)
    return _extract_json_object(raw) or {}


def _file_findings(results: list, root: Path, rel: str) -> Counter:
    from frame.sca.scan import _rel
    return Counter(v.type.value for r in results for v in r.vulnerabilities if _rel(v.location, root) == rel)


def verify(target: Path, excluded: Iterable, site: Site, patched: str, before: Counter) -> Tuple[str, List[str]]:
    """Re-run the analysis on a copy of the project with `site.file` replaced by `patched`."""
    from frame.sil.scanner import FrameScanner
    excluded = list(excluded)
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp).resolve() / "project"

        def ignore(d, names):
            return [n for n in names if FrameScanner._is_excluded_dir_member(Path(d) / n / "x", target, frozenset(excluded))]
        shutil.copytree(target, copy, ignore=ignore, symlinks=True)
        (copy / site.file).write_text(patched, encoding="utf-8")
        run, results = analyse(copy, excluded)
        ids = {a["id"] for a in site.advisories}
        still_called = still_tainted = False
        for f in run.findings:
            if f["id"] not in ids:
                continue
            reach = f.get("reachability") or {}
            for c in reach.get("calls", []):
                if c["location"].rpartition(":")[0] == site.file and c["function"] == site.function:
                    still_called = True
            for fl in reach.get("flows", []):
                if fl["location"].rpartition(":")[0] == site.file:
                    still_tainted = True
        after = _file_findings(results, copy, site.file)
    linked = {"vulnerable_dependency"}
    introduced = sorted(t for t, n in (after - before).items() if t not in linked)
    if still_tainted:
        return "still-tainted", introduced
    if site.level == "called" and still_called:
        return "still-called", introduced
    if introduced:
        return "introduces-findings", introduced
    return ("untainted" if still_called else "removed"), introduced


def mitigate(target: Path, excluded: Iterable, config, write: bool = False, include_called: bool = True,
             proposer: Optional[Callable[[Site, str], dict]] = None) -> List[Result]:
    """Propose, apply and verify a mitigation per site; with `write`, keep the verified ones."""
    from frame.sil.llm_fix import apply_fix, make_diff
    target = Path(target).resolve()
    excluded = list(excluded)
    run, results = analyse(target, excluded)
    propose_ = proposer or (lambda s, src: propose(s, src, config))
    out: List[Result] = []
    current: Dict[str, str] = {}
    for site in sites(run, include_called):
        path = target / site.file
        src = current.get(site.file) or path.read_text(encoding="utf-8")
        patch = propose_(site, src)
        new, applied = apply_fix(src, patch)
        res = Result(site, applied=applied and new != src, rationale=(patch or {}).get("rationale", ""))
        if not res.applied:
            res.verdict = "could-not-apply"
            out.append(res)
            continue
        res.verdict, res.introduced = verify(target, excluded, site, new, _file_findings(results, target, site.file))
        res.diff = make_diff(site.file, src, new)
        if res.verified:
            current[site.file] = new                   # later sites in the file build on it
        out.append(res)
    if write:
        for rel, text in current.items():
            (target / rel).write_text(text, encoding="utf-8")
    return out
