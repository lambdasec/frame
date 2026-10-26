"""Stable finding identities, baselines, and matching a scan against earlier findings.

A finding's line number moves whenever code is added above it, so it cannot be an
identity. Each finding gets two keys, both over the file's path relative to the
project root (`project_root`: an explicit `--root`, else the git top level, else
the directory of the project's Frame config, else the scanned directory):

- ``fingerprint`` (exact): the path, CWE, function, taint source and sink kind,
  the whitespace-normalised text of the finding's line, and the finding's ordinal
  among findings that share all of those.
- ``fingerprint_loose``: the same without the line text and the ordinal.

`match_findings` pairs earlier findings with current ones by exact key first, then
one-for-one by loose key (nearest line first). A reformatted or edited line still
matches its earlier finding; a second instance of the same flow in the same
function does not, so it is new.

A baseline file records a project's accepted findings so a later scan reports
only what is new (`apply_baseline`). Writing one replaces the entries of every
file that run scanned and keeps the rest (`write_baseline`), so a scan of the
changed files updates a baseline instead of truncating it.
"""

import hashlib
import json
import re
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Dict, Iterable, List, Optional, Tuple, Union

if TYPE_CHECKING:
    from frame.sil.scanner import ScanResult, Vulnerability

FINGERPRINT_VERSION = 1
BASELINE_FORMAT = 1

# Source-position suffixes that disambiguate same-named JS functions
# (`anonymous_L12`, `handler_L5C3`) and indices of synthetic analyzer
# procedures (`<unsafe-deserialize>-0`). Both change when code moves.
_POSITION_SUFFIX = re.compile(r"_L\d+(?:C\d+)?$")
_SYNTHETIC_INDEX = re.compile(r"^(<[^>]+>)-\d+$")


class BaselineError(Exception):
    """A baseline file is missing, unreadable or not a Frame baseline."""


def project_root(path: Union[str, Path], explicit: Optional[Union[str, Path]] = None,
                 config_file: Optional[Union[str, Path]] = None) -> Path:
    """The root finding paths are relative to. Fingerprints only compare across
    runs that resolve the same root, so it never depends on the directory the
    scan is run from: `explicit` (`--root`), else the git top level containing
    `path`, else the directory of the project's Frame config (`.frame.toml` or a
    `pyproject.toml` with `[tool.frame]`), else the scanned directory."""
    if explicit:
        return Path(explicit).resolve()
    p = Path(path).resolve()
    start = p if p.is_dir() else p.parent
    try:
        out = subprocess.run(
            ["git", "-C", str(start), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=10)
        if out.returncode == 0 and out.stdout.strip():
            return Path(out.stdout.strip()).resolve()
    except (OSError, subprocess.SubprocessError):
        pass
    if config_file:
        return Path(config_file).resolve().parent
    return start


def relative_path(filename: Union[str, Path], root: Path) -> str:
    """`filename` relative to `root`, POSIX-style; the absolute path when it is
    outside the root."""
    p = Path(filename)
    try:
        p = p.resolve()
    except OSError:
        pass
    try:
        return p.relative_to(root).as_posix()
    except ValueError:
        return p.as_posix()


def normalize_procedure(name: Optional[str]) -> str:
    name = name or ""
    m = _SYNTHETIC_INDEX.match(name)
    if m:
        return m.group(1)
    return _POSITION_SUFFIX.sub("", name)


def _digest(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode("utf-8", "replace")).hexdigest()[:16]


def loose_key(rel_path: str, v: "Vulnerability") -> str:
    return _digest(f"v{FINGERPRINT_VERSION}", rel_path, v.cwe_id or v.type.value,
                   normalize_procedure(v.procedure), v.source_var or "", v.sink_type or "")


def _read_lines(path: str) -> List[str]:
    try:
        return Path(path).read_text(encoding="utf-8-sig", errors="replace").splitlines()
    except OSError:
        return []


def assign_fingerprints(results: Iterable["ScanResult"], root: Path) -> None:
    """Set `path`, `fingerprint` and `fingerprint_loose` on every reported and
    suppressed finding. Reads each finding's file for its line text."""
    lines_by_file: Dict[str, List[str]] = {}
    for r in results:
        findings = list(r.vulnerabilities) + list(r.suppressed) + list(r.baselined)
        seen: Dict[Tuple[str, str], int] = defaultdict(int)
        for v in sorted(findings, key=lambda v: (v.line or 0, v.column or 0, v.description)):
            filename = v.location or r.filename
            rel = relative_path(filename, root)
            if filename not in lines_by_file:
                lines_by_file[filename] = _read_lines(filename)
            lines = lines_by_file[filename]
            text = lines[v.line - 1] if v.line and 0 < v.line <= len(lines) else ""
            loose = loose_key(rel, v)
            norm = " ".join(text.split())
            ordinal = seen[(loose, norm)]
            seen[(loose, norm)] += 1
            v.path = rel
            v.fingerprint_loose = loose
            v.fingerprint = _digest(loose, norm, str(ordinal))


def baseline_entry(v: "Vulnerability") -> dict:
    return {
        "fingerprint": v.fingerprint,
        "fingerprint_loose": v.fingerprint_loose,
        "path": v.path,
        "line": v.line,
        "cwe_id": v.cwe_id,
        "type": v.type.value,
        "severity": v.severity.value,
        "procedure": v.procedure,
    }


@dataclass
class MatchResult:
    pairs: List[Tuple[dict, "Vulnerability"]] = field(default_factory=list)
    unmatched_prior: List[dict] = field(default_factory=list)
    unmatched_current: List["Vulnerability"] = field(default_factory=list)


def match_findings(prior: List[dict], current: List["Vulnerability"]) -> MatchResult:
    """Pair earlier findings (dicts with `fingerprint`, `fingerprint_loose`,
    `line`) with current ones: exact fingerprints first, then loose keys one for
    one, nearest line first."""
    out = MatchResult()
    used = set()
    by_exact: Dict[str, List[int]] = defaultdict(list)
    for i, e in enumerate(prior):
        by_exact[e.get("fingerprint")].append(i)
    rest = []
    for v in current:
        idx = next((i for i in by_exact.get(v.fingerprint, []) if i not in used), None)
        if idx is None:
            rest.append(v)
        else:
            used.add(idx)
            out.pairs.append((prior[idx], v))
    by_loose: Dict[str, List[int]] = defaultdict(list)
    for i, e in enumerate(prior):
        if i not in used:
            by_loose[e.get("fingerprint_loose")].append(i)
    for v in rest:
        free = [i for i in by_loose.get(v.fingerprint_loose, []) if i not in used]
        if not free:
            out.unmatched_current.append(v)
            continue
        idx = min(free, key=lambda i: abs((prior[i].get("line") or 0) - (v.line or 0)))
        used.add(idx)
        out.pairs.append((prior[idx], v))
    out.unmatched_prior = [e for i, e in enumerate(prior) if i not in used]
    return out


def load_baseline(path: Union[str, Path]) -> List[dict]:
    p = Path(path)
    if not p.is_file():
        raise BaselineError(f"baseline not found: {p} (create it with --write-baseline)")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise BaselineError(f"cannot read baseline {p}: {e}")
    if not isinstance(data, dict) or data.get("frame_baseline") != BASELINE_FORMAT:
        raise BaselineError(f"{p} is not a Frame baseline (format {BASELINE_FORMAT})")
    if data.get("fingerprint_version") != FINGERPRINT_VERSION:
        raise BaselineError(
            f"{p} was written with fingerprint version {data.get('fingerprint_version')}; "
            f"this Frame uses {FINGERPRINT_VERSION}. Re-create it with --write-baseline.")
    findings = data.get("findings")
    if not isinstance(findings, list):
        raise BaselineError(f"{p} has no findings list")
    return findings


def baseline_root_mismatch(entries: List[dict], root: Path) -> bool:
    """True when no baseline entry names a file that exists under `root`: the
    baseline was almost certainly written against a different root, and every
    finding would look new."""
    paths = {str(e.get("path")) for e in entries if e.get("path")}
    return bool(paths) and not any((root / p).is_file() for p in paths)


def scanned_paths(results: Iterable["ScanResult"], root: Path) -> set:
    return {relative_path(r.filename, root) for r in results}


def apply_baseline(results: List["ScanResult"], entries: List[dict], root: Path) -> List[dict]:
    """Move every finding the baseline already knows from `vulnerabilities` to
    `baselined`. Returns the baseline entries of scanned files that no longer
    occur -- findings fixed since the baseline was written."""
    current = [v for r in results for v in r.vulnerabilities]
    matched = match_findings(entries, current)
    known = {id(v) for _, v in matched.pairs}
    for r in results:
        r.baselined.extend(v for v in r.vulnerabilities if id(v) in known)
        r.vulnerabilities = [v for v in r.vulnerabilities if id(v) not in known]
    scanned = scanned_paths(results, root)
    return [e for e in matched.unmatched_prior if e.get("path") in scanned]


def write_baseline(path: Union[str, Path], results: List["ScanResult"], root: Path) -> int:
    """Write the baseline: this run's findings (new and already known, not
    suppressed) for every file it scanned, plus the existing entries of files it
    did not scan that still exist. Returns the number of entries written."""
    p = Path(path)
    kept: List[dict] = []
    if p.is_file():
        try:
            previous = load_baseline(p)
        except BaselineError:
            previous = []
        scanned = scanned_paths(results, root)
        kept = [e for e in previous
                if e.get("path") not in scanned and (root / str(e.get("path", ""))).is_file()]
    entries = kept + [baseline_entry(v) for r in results
                      for v in list(r.vulnerabilities) + list(r.baselined)]
    entries.sort(key=lambda e: (str(e.get("path")), e.get("line") or 0, str(e.get("fingerprint"))))
    doc = {"frame_baseline": BASELINE_FORMAT, "fingerprint_version": FINGERPRINT_VERSION,
           "findings": entries}
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return len(entries)
