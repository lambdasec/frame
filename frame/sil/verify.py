"""Re-scan the files behind earlier findings and say which are fixed.

`verify_findings` takes findings from `frame scan -f json` (they carry `path` and
fingerprints), re-scans each file they name, and matches the file's earlier
findings against its current ones with `fingerprints.match_findings`. Each
requested finding gets one status:

- ``fixed``: no current finding matches it, and no unmatched finding of the
  same CWE remains in the file.
- ``file_removed``: its file no longer exists.
- ``present``: a current finding matches it (possibly on another line).
- ``suppressed``: it matches a finding silenced by `frame: ignore` or a disabled
  rule -- hidden, not fixed.
- ``uncertain``: nothing matches it, but a finding of the same CWE that is not
  one of the file's earlier findings is reported there: it may be the same bug,
  moved or renamed.
- ``unverifiable``: an LLM-tier finding (a symbolic re-scan cannot show it is
  gone), or the file could not be scanned.

Only ``fixed`` and ``file_removed`` count as resolved.
"""

from collections import OrderedDict
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Optional

from frame.sil.fingerprints import assign_fingerprints, match_findings, project_root

RESOLVED = frozenset({"fixed", "file_removed"})
_LLM_TIERS = frozenset({"llm_detect", "llm_verified"})


class VerifyError(Exception):
    """The findings cannot be verified as given (no fingerprints, unknown ids)."""


@dataclass
class Verdict:
    fingerprint: str
    path: str
    line: int
    cwe_id: Optional[str]
    status: str
    detail: str = ""
    current_line: Optional[int] = None

    def to_dict(self) -> dict:
        return asdict(self)


def _root_for(file: Path, rel: str) -> Path:
    """The root under which `file` is named `rel` -- the root the original scan
    used -- so fingerprints are recomputed over the same path wherever verify
    runs from. Falls back to the project root."""
    resolved = file.resolve()
    parts = PurePosixPath(rel).parts
    if parts and not PurePosixPath(rel).is_absolute() and resolved.parts[-len(parts):] == parts:
        return Path(*resolved.parts[:-len(parts)])
    return project_root(resolved)


def _locate(finding: dict, root: Optional[Path]) -> Optional[Path]:
    """The finding's file: under the scan's recorded root first (a relative
    `location` is relative to wherever that scan ran), then as named, then under
    this directory's project root."""
    rel, loc = finding.get("path"), finding.get("location")
    cands = []
    if root is not None and rel:
        cands.append(root / rel)
    if loc and Path(loc).is_absolute():
        cands.append(Path(loc))
    if root is None:
        if loc:
            cands.append(Path(loc))
        if rel:
            cands.append(project_root(Path.cwd()) / rel)
    return next((c for c in cands if c.is_file()), None)


def verify_findings(findings: List[dict], ids: Optional[Iterable[str]] = None,
                    timeout_ms: int = 5000, context: Iterable[dict] = (),
                    root: Optional[str] = None, cross_file: bool = False,
                    cross_file_limit: Optional[int] = None) -> List[Verdict]:
    """Verdicts for `findings` (all of them, or those whose fingerprint is in
    `ids`). `context` holds the scan's other findings (baselined, suppressed):
    they and every finding of a re-scanned file are used for matching, so a
    finding that was already there is never mistaken for a moved one. `root` is
    the scan's project root (the JSON's `root`); without it a file that cannot
    be found is unverifiable rather than removed. `cross_file` (the JSON's
    `scope.cross_file`) re-scans the files inside the same cross-file scope the
    scan used: a finding in a helper that only exists because a caller in another
    file passes it request data is judged with that caller present -- re-scanning
    the helper alone would call it fixed whatever the caller still does."""
    from frame.sil.scanner import FrameScanner, language_for_file

    context = [c for c in context if c.get("fingerprint")]
    root_path = Path(root) if root else None
    if any(not f.get("fingerprint") for f in findings):
        raise VerifyError("findings have no fingerprints; produce them with "
                          "`frame scan -f json` from this version of Frame")
    ids = list(ids or [])
    known = {f["fingerprint"] for f in list(findings) + context}
    unknown = [i for i in ids if i not in known]
    if unknown:
        raise VerifyError(f"no finding with fingerprint {', '.join(unknown)}")
    every = list(findings) + context
    wanted = [f for f in every if f["fingerprint"] in ids] if ids else list(findings)

    groups: "OrderedDict[str, List[dict]]" = OrderedDict()
    for f in every:
        groups.setdefault(f.get("path") or f.get("location") or "", []).append(f)

    prefetched: Dict[Path, Any] = {}
    if cross_file and root_path is not None and root_path.is_dir():
        located = []
        for rel, pool in groups.items():
            if not any(f is w for f in pool for w in wanted):
                continue
            found = next((p for p in (_locate(f, root_path) for f in pool) if p is not None), None)
            if found is not None:
                located.append(found)
        if located:
            from frame.sil.scanner import DEFAULT_CROSS_FILE_LIMIT
            scanner = FrameScanner(language="python", verify=True, timeout=timeout_ms)
            try:
                for r in scanner.scan_directory(
                        str(root_path), None, only_files=located, cross_file=True,
                        cross_file_limit=cross_file_limit or DEFAULT_CROSS_FILE_LIMIT):
                    prefetched[Path(r.filename).resolve()] = r
            except Exception:
                prefetched = {}                 # fall back to scanning each file alone

    verdicts: Dict[int, Verdict] = {}
    for rel, pool in groups.items():
        asked = [f for f in pool if any(f is w for w in wanted)]
        if not asked:
            continue

        def verdict(f, status, detail="", current_line=None):
            verdicts[id(f)] = Verdict(f["fingerprint"], rel, f.get("line") or 0,
                                      f.get("cwe_id"), status, detail, current_line)

        file = next((p for p in (_locate(f, root_path) for f in pool) if p is not None), None)
        if file is None:
            if root_path is not None and root_path.is_dir():
                for f in asked:
                    verdict(f, "file_removed", "the file no longer exists")
            else:
                for f in asked:
                    verdict(f, "unverifiable", "cannot find the file: the findings carry no "
                            "scan root, so run verify where the scan ran")
            continue

        result = prefetched.get(file.resolve())
        if result is None:
            result = FrameScanner(language=language_for_file(file, default="python"),
                                  verify=True, timeout=timeout_ms).scan_file(str(file))
        if result.errors:
            for f in asked:
                verdict(f, "unverifiable", "re-scan failed: " + "; ".join(result.errors))
            continue
        assign_fingerprints([result], _root_for(file, rel))
        suppressed = {id(v) for v in result.suppressed}
        matched = match_findings(pool, list(result.vulnerabilities) + list(result.suppressed))
        pair_of = {id(e): v for e, v in matched.pairs}
        leftover = [v for v in matched.unmatched_current if id(v) not in suppressed]

        for f in asked:
            v = pair_of.get(id(f))
            if v is not None and id(v) in suppressed:
                verdict(f, "suppressed", "still detected, but silenced by `frame: ignore` "
                        "or a disabled rule", v.line)
            elif v is not None:
                verdict(f, "present", "still detected", v.line)
            elif f.get("source_var") in _LLM_TIERS:
                verdict(f, "unverifiable", "an LLM-tier finding: a symbolic re-scan cannot "
                        "show it is gone")
            else:
                same = [v for v in leftover if f.get("cwe_id") and v.cwe_id == f.get("cwe_id")]
                if same:
                    verdict(f, "uncertain", f"no exact match, but a {same[0].cwe_id} finding "
                            f"is reported at line {same[0].line}", same[0].line)
                else:
                    verdict(f, "fixed")
    return [verdicts[id(f)] for f in wanted]
