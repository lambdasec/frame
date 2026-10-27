"""
Frame Security Scanner.

High-level interface for scanning source code for vulnerabilities.
Integrates the full pipeline:
    Source Code → Frontend → SIL → Translator → Frame Verification → Report

Usage:
    from frame.sil.scanner import FrameScanner

    scanner = FrameScanner(language="python")
    result = scanner.scan_file("app.py")

    for vuln in result.vulnerabilities:
        print(f"{vuln.type}: {vuln.description}")
        print(f"  Location: {vuln.location}")
        if vuln.witness:
            print(f"  Exploit: {vuln.witness}")
"""

from dataclasses import dataclass, field
from typing import FrozenSet, Iterable, List, Dict, Optional, Any, Union
from pathlib import Path
from enum import Enum
import json
import os
import time

from frame.sil.llm_client import LLMUnavailableError

import math
import re
from collections import Counter
from typing import Tuple

from frame.sil.procedure import Program
from frame.sil.instructions import Assign
from frame.sil.types import ExpConst


class BufferSizeTracker:
    """
    Tracks buffer sizes using separation logic principles.

    Models heap/stack regions as: var |-> (size, initialized_bytes)
    Uses this to verify if buffer copies are safe (source <= dest).

    This enables context-aware vulnerability detection:
    - Bad code: strcpy(small_buf, large_source)  -> VULNERABLE
    - Good code: strcpy(large_buf, small_source) -> SAFE (filter out)
    """

    def __init__(self, source_code: str):
        self.lines = source_code.split('\n')
        # Map: variable_name -> (declared_size, initialized_size)
        self.buffer_sizes: Dict[str, Tuple[int, int]] = {}
        self._analyze_buffer_sizes()

    def _analyze_buffer_sizes(self):
        """Analyze source code to extract buffer size declarations."""
        for line_num, line in enumerate(self.lines):
            # Pattern 1: Array declaration - char buf[100]
            array_match = re.search(r'(\w+)\s*\[\s*(\d+)\s*\]', line)
            if array_match:
                var_name = array_match.group(1)
                size = int(array_match.group(2))
                self.buffer_sizes[var_name] = (size, 0)

            # Pattern 2: malloc/calloc allocation - ptr = malloc(100)
            alloc_match = re.search(r'(\w+)\s*=\s*(?:\([^)]*\*\))?\s*malloc\s*\(\s*(\d+)\s*\)', line)
            if alloc_match:
                var_name = alloc_match.group(1)
                size = int(alloc_match.group(2))
                self.buffer_sizes[var_name] = (size, 0)

            # Pattern 3: calloc - ptr = calloc(count, size)
            calloc_match = re.search(r'(\w+)\s*=\s*(?:\([^)]*\*\))?\s*calloc\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)', line)
            if calloc_match:
                var_name = calloc_match.group(1)
                size = int(calloc_match.group(2)) * int(calloc_match.group(3))
                self.buffer_sizes[var_name] = (size, 0)

            # Pattern 4: memset initialization - memset(buf, 'A', N-1)
            # This tells us how much data is being written
            memset_match = re.search(r'memset\s*\(\s*(\w+)\s*,\s*[^,]+,\s*(\d+)(?:\s*-\s*(\d+))?\s*\)', line)
            if memset_match:
                var_name = memset_match.group(1)
                init_size = int(memset_match.group(2))
                if memset_match.group(3):
                    init_size -= int(memset_match.group(3))
                init_size += 1  # Account for null terminator
                if var_name in self.buffer_sizes:
                    declared_size, _ = self.buffer_sizes[var_name]
                    self.buffer_sizes[var_name] = (declared_size, init_size)
                else:
                    self.buffer_sizes[var_name] = (init_size, init_size)

            # Pattern 5: String literal initialization with explicit size
            # For char buf[50] = "", use 50 as the size (not the literal length)
            str_init_match = re.search(r'(\w+)\s*\[\s*(\d+)\s*\]\s*=\s*"([^"]*)"', line)
            if str_init_match:
                var_name = str_init_match.group(1)
                array_size = int(str_init_match.group(2))  # Use declared size
                str_len = len(str_init_match.group(3)) + 1  # +1 for null terminator
                # Use the declared array size, initialized with the string length
                self.buffer_sizes[var_name] = (array_size, str_len)

    def is_copy_safe(self, dest: str, source: str, line_num: int) -> bool:
        """
        Check if a buffer copy from source to dest is safe.

        Uses separation logic reasoning:
        - If dest |-> (dest_size, _) and source |-> (_, src_init)
        - Copy is safe if src_init <= dest_size

        Returns True if copy is provably safe (should NOT flag).
        Returns False if copy is potentially dangerous (should flag).
        """
        dest_size = self._get_dest_size(dest, line_num)
        src_init = self._get_source_init_size(source, line_num)

        # If we know both sizes and source fits in dest, it's safe
        if dest_size > 0 and src_init > 0:
            return src_init <= dest_size

        # Unknown sizes - be conservative and flag
        return False

    def _get_dest_size(self, var: str, line_num: int) -> int:
        """Get the declared size of destination buffer."""
        # Check direct variable name
        if var in self.buffer_sizes:
            return self.buffer_sizes[var][0]

        # Check in local context (nearby lines)
        context_start = max(0, line_num - 15)
        context_end = min(len(self.lines), line_num + 5)

        for i in range(context_start, context_end):
            line = self.lines[i]
            # Look for array declaration with this name
            match = re.search(rf'{re.escape(var)}\s*\[\s*(\d+)\s*\]', line)
            if match:
                return int(match.group(1))

        return 0

    def _get_source_init_size(self, var: str, line_num: int) -> int:
        """Get the initialized size of source buffer."""
        # Check direct variable name
        if var in self.buffer_sizes:
            _, init_size = self.buffer_sizes[var]
            if init_size > 0:
                return init_size

        # Check in local context for memset of this variable
        context_start = max(0, line_num - 15)
        context_end = line_num

        for i in range(context_start, context_end):
            line = self.lines[i]
            # Look for memset(var, ..., N-1)
            memset_match = re.search(rf'memset\s*\(\s*{re.escape(var)}\s*,\s*[^,]+,\s*(\d+)(?:\s*-\s*(\d+))?\s*\)', line)
            if memset_match:
                init_size = int(memset_match.group(1))
                if memset_match.group(2):
                    init_size -= int(memset_match.group(2))
                return init_size + 1  # +1 for null terminator

        return 0

    def get_context_sizes(self, line_num: int) -> Tuple[int, int]:
        """
        Get buffer sizes from the context around a copy operation.
        Returns (dest_size, source_size) if found in context.
        """
        context_start = max(0, line_num - 15)
        context_end = min(len(self.lines), line_num + 5)

        dest_size = 0
        source_size = 0

        for i in range(context_start, context_end):
            line = self.lines[i]

            # Look for dest array declaration
            dest_match = re.search(r'dest\s*\[\s*(\d+)\s*\]', line)
            if dest_match:
                dest_size = int(dest_match.group(1))

            # Look for source array declaration
            source_match = re.search(r'source\s*\[\s*(\d+)\s*\]', line)
            if source_match:
                source_size = int(source_match.group(1))

            # Look for data initialization via memset
            data_memset = re.search(r'memset\s*\(\s*data\s*,\s*[^,]+,\s*(\d+)(?:\s*-\s*(\d+))?\s*\)', line)
            if data_memset:
                size = int(data_memset.group(1))
                if data_memset.group(2):
                    size -= int(data_memset.group(2))
                source_size = size + 1

        return (dest_size, source_size)


from frame.sil.translator import SILTranslator, VulnerabilityCheck, VulnType
from frame.checking.incorrectness import IncorrectnessChecker, BugReport, BugWitness


# NOTE: the per-language regex pattern layer was removed. Detection is now
# performed entirely by the separation-logic taint engine, the Tier-2 SIL
# literal scanner, and the C/C++ memory analyzer.


class Severity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Vulnerability:
    """A confirmed vulnerability"""
    type: VulnType
    severity: Severity
    location: str
    line: int
    column: int
    description: str
    procedure: str
    source_var: str = ""
    source_location: str = ""
    sink_type: str = ""
    data_flow: List[str] = field(default_factory=list)
    witness: Optional[str] = None
    confidence: float = 1.0
    cwe_id: Optional[str] = None
    # Set by `fingerprints.assign_fingerprints`: the file relative to the project
    # root and the finding's stable identities (see that module).
    path: Optional[str] = None
    fingerprint: Optional[str] = None
    fingerprint_loose: Optional[str] = None
    # "naming-convention" when the source is a JS/TS `req.*` name and neither the
    # file nor the project shows a web framework (see framework_evidence.py).
    source_evidence: str = ""
    # "hardening" for configuration that switches a protection off (debug mode, a cookie
    # declared insecure); empty for ordinary findings. Never mixed into taint results.
    category: str = ""

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization"""
        d = {
            "type": self.type.value,
            "severity": self.severity.value,
            "location": self.location,
            "line": self.line,
            "column": self.column,
            "description": self.description,
            "procedure": self.procedure,
            "source_var": self.source_var,
            "source_location": self.source_location,
            "sink_type": self.sink_type,
            "data_flow": self.data_flow,
            "witness": self.witness,
            "confidence": self.confidence,
            "cwe_id": self.cwe_id,
        }
        if self.source_evidence:
            d["source_evidence"] = self.source_evidence
        if self.category:
            d["category"] = self.category
        if self.fingerprint:
            d["path"] = self.path
            d["fingerprint"] = self.fingerprint
            d["fingerprint_loose"] = self.fingerprint_loose
        return d


@dataclass
class ScanResult:
    """Result of scanning a file or project"""
    filename: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    scan_time_ms: float = 0.0
    lines_scanned: int = 0
    procedures_analyzed: int = 0
    suppressed: List[Vulnerability] = field(default_factory=list)
    # Findings a baseline already records (`fingerprints.apply_baseline`):
    # kept, like suppressed ones, but not reported as new.
    baselined: List[Vulnerability] = field(default_factory=list)
    baseline_applied: bool = False
    # Framework packs ("language/name") that applied to this file's program.
    packs: List[str] = field(default_factory=list)

    @property
    def has_vulnerabilities(self) -> bool:
        return len(self.vulnerabilities) > 0

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH)

    def to_dict(self) -> dict:
        return {
            "filename": self.filename,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            # Kept, never silently dropped: what a baseline or suppression hid.
            # `frame verify` matches against them so a known finding is not
            # mistaken for a new one moving.
            "baselined": [v.to_dict() for v in self.baselined],
            "suppressed": [v.to_dict() for v in self.suppressed],
            "errors": self.errors,
            "warnings": self.warnings,
            "scan_time_ms": self.scan_time_ms,
            "lines_scanned": self.lines_scanned,
            "procedures_analyzed": self.procedures_analyzed,
            **({"packs": list(self.packs)} if self.packs else {}),
            "summary": {
                "total": len(self.vulnerabilities),
                "critical": self.critical_count,
                "high": self.high_count,
                "suppressed": len(self.suppressed),
                "baselined": len(self.baselined),
            }
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_sarif(self) -> dict:
        """Convert to SARIF format for GitHub/Azure DevOps integration"""
        rules = {}
        results = []

        for vuln in self.vulnerabilities:
            rule_id = f"frame/{vuln.type.value}"

            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": vuln.type.value.replace("_", " ").title(),
                    "shortDescription": {"text": vuln.type.value},
                    "defaultConfiguration": {
                        "level": self._severity_to_sarif_level(vuln.severity)
                    },
                    "properties": {
                        "tags": ["security"],
                        "security-severity": self._SARIF_SECURITY_SEVERITY.get(vuln.severity, "5.0"),
                    },
                }
            cwe = getattr(vuln, "cwe_id", None)
            if cwe:
                props = rules[rule_id]["properties"]
                tag = f"external/cwe/{cwe.lower()}"
                if tag not in props["tags"]:
                    props["tags"].append(tag)
                    rules[rule_id].setdefault(
                        "helpUri", f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[-1]}.html")

            result = {
                "ruleId": rule_id,
                "level": self._severity_to_sarif_level(vuln.severity),
                "message": {"text": vuln.description},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": self.filename},
                        "region": {
                            "startLine": vuln.line,
                            "endLine": getattr(vuln, "end_line", None) or vuln.line,
                            "startColumn": vuln.column,
                        }
                    }
                }],
            }

            if cwe:
                result["properties"] = {"cwe": cwe}
            if vuln.witness:
                result["message"]["text"] += f"\n\nExploit witness: {vuln.witness}"
            if vuln.fingerprint:
                result["partialFingerprints"] = {
                    "frame/v1": vuln.fingerprint,
                    "frame-loose/v1": vuln.fingerprint_loose,
                }
            if self.baseline_applied:
                result["baselineState"] = "new"

            results.append(result)

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Frame Security Scanner",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/frame/frame",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }]
        }

    # GitHub code scanning ranks alerts by this CVSS-like number
    _SARIF_SECURITY_SEVERITY = {
        Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5",
        Severity.LOW: "3.0", Severity.INFO: "1.0",
    }

    def _severity_to_sarif_level(self, severity: Severity) -> str:
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }
        return mapping.get(severity, "warning")


# A source line this long does not occur in code people write and review; it is
# the signature of a bundler, a minifier, or a code generator. Overridable for
# codebases with unusual formatting.
GENERATED_LINE_THRESHOLD = int(
    os.environ.get("FRAME_GENERATED_LINE_THRESHOLD", "2000"))


def is_generated_source(source_code: str,
                        threshold: int = None) -> bool:
    """Does this look like minified or generated output rather than source?

    Judged on line geometry alone, never on the filename: a `.min.js` suffix is a
    convention, not a guarantee, and plenty of generated files do not carry one.
    A file qualifies when any single line exceeds `threshold` characters, which
    is the reliable signature of bundled or minified output.

    Conservative by construction: ordinary source, including long string literals
    and wide tables, stays well under the threshold, so real code is never
    skipped. Empty input is not generated.
    """
    if not source_code:
        return False
    limit = GENERATED_LINE_THRESHOLD if threshold is None else threshold
    if limit <= 0:
        return False
    longest = 0
    for line in source_code.splitlines():
        if len(line) > longest:
            longest = len(line)
            if longest > limit:
                return True
    # A single unterminated line (no newlines at all) is the classic minified
    # bundle shape; splitlines already covers it, but guard the no-newline case.
    return len(source_code) > limit and "\n" not in source_code


# Directory names (or component sequences) skipped by default during a
# directory scan, for every language -- the exclusion happens on the file
# walk, before any frontend sees a path. An entry is either a single
# component (matches that name anywhere) or a tuple of components that must
# appear consecutively (see `FrameScanner._is_excluded_dir_member`). None of
# these hold project source in the common case:
#   - .git                          VCS internals.
#   - (".claude", "worktrees"),
#     (".cursor", "worktrees")      Agent worktree copies specifically, not
#                                   the tool's whole state directory:
#                                   `.claude/worktrees/<branch>/` holds a full
#                                   copy of the repository that a Claude Code
#                                   agent works in, and scanning it multiplies
#                                   every finding once per worktree. A bare
#                                   `.claude` exclusion would also hide
#                                   `.claude/hooks/*.py` and skill scripts,
#                                   which are real, user-authored project
#                                   code a security scanner should see -- so
#                                   only the `worktrees` subdirectory is
#                                   excluded, not the whole tool state dir.
#   - .worktrees                    Same shape (a tool's own worktree
#                                   copies), for tools that keep it at the
#                                   repo root instead of nested under their
#                                   own state directory.
#   - .idea, .vscode                IDE project configuration, not source.
#   - node_modules                  Vendored JS dependencies -- someone
#                                   else's code.
#   - .venv, .tox                   Python virtualenvs. These can contain
#                                   thousands of third-party `.py` files,
#                                   which is exactly the "full copy that
#                                   isn't project source" problem.
#   - venv                          Same shape, but the bare name collides
#                                   with CPython's stdlib `venv` package and
#                                   is a plausible real source directory
#                                   name, so it is excluded conditionally:
#                                   only when the directory actually
#                                   contains `pyvenv.cfg`, the marker every
#                                   `venv`/`virtualenv`-created environment
#                                   carries (see `_is_excluded_dir_member`).
#   - __pycache__                   Python bytecode cache.
#   - .mypy_cache, .pytest_cache    Tool caches, not source.
#
# Matching is on path components relative to the scan root (see
# `scan_directory`), so a scan root that itself sits inside one of these
# directories still scans normally -- only descendants named like this are
# skipped.
DEFAULT_EXCLUDED_SCAN_DIRS: FrozenSet[Union[str, Tuple[str, ...]]] = frozenset({
    ".git",
    (".claude", "worktrees"),
    (".cursor", "worktrees"),
    ".worktrees",
    ".idea",
    ".vscode",
    "node_modules",
    ".venv",
    "venv",
    ".tox",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
})


# Files a cross-file analysis may span. A directory scan over this many Python
# and JS/TS files analyses each file alone (with a warning); a `--changed` scan
# keeps the files nearest the change.
DEFAULT_CROSS_FILE_LIMIT = 2000

_SEVERITY_ORDER = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


def _vuln_is_better(new_vuln: "Vulnerability", existing: "Vulnerability") -> bool:
    """Is `new_vuln` the better report of the same finding: higher severity,
    then a witness, more data-flow detail, higher confidence."""
    new_sev = _SEVERITY_ORDER.get(new_vuln.severity, 0)
    old_sev = _SEVERITY_ORDER.get(existing.severity, 0)
    if new_sev > old_sev:
        return True
    if new_sev == old_sev:
        if new_vuln.witness and not existing.witness:
            return True
        if len(new_vuln.data_flow) > len(existing.data_flow):
            return True
        if new_vuln.confidence > existing.confidence:
            return True
    return False


def _keep_best_per_key(vulns: List["Vulnerability"], key) -> List["Vulnerability"]:
    """The best vulnerability per `key(v)`, at the position of the first one
    with that key. Findings without a CWE are kept as they are."""
    best: Dict[Any, "Vulnerability"] = {}
    for v in vulns:
        if not v.cwe_id:
            continue
        k = key(v)
        if k not in best or _vuln_is_better(v, best[k]):
            best[k] = v
    out, added = [], set()
    for v in vulns:
        if not v.cwe_id:
            out.append(v)
            continue
        k = key(v)
        if k not in added:
            out.append(best[k])
            added.add(k)
    return out


def collapse_per_file_cwe(vulns: List["Vulnerability"]) -> List["Vulnerability"]:
    """The view of benchmarks that label a whole test file with one CWE and
    count every further report as a false positive (OWASP, Juliet, IssueBlot).
    Scoring code applies it; the scanner itself reports every finding.

    - One finding per (file, CWE).
    - An XSS at an HTML sink is dropped from a procedure that also has a
      non-XSS finding: such a test case returns the injected page, and its
      label is the other CWE.

    IDOR findings are per endpoint and are left alone."""
    from frame.sil.translator import VulnType as _VT
    idor = [v for v in vulns if v.type == _VT.IDOR]
    rest = [v for v in vulns if v.type != _VT.IDOR]
    has_other = {(v.location, v.procedure) for v in rest if v.type != _VT.XSS}
    rest = [v for v in rest
            if not (v.type == _VT.XSS and v.sink_type == "html"
                    and (v.location, v.procedure) in has_other)]
    return _keep_best_per_key(rest, lambda v: (v.location, v.cwe_id)) + idor


# Source extension -> symbolic frontend language. The one table both
# `FrameScanner.scan_file` and the module-level `scan_file` use, and the set a
# directory scan with no pattern walks.
EXTENSION_LANGUAGES: Dict[str, str] = {
    '.py': 'python',
    '.js': 'javascript',
    '.jsx': 'javascript',
    '.mjs': 'javascript',
    '.cjs': 'javascript',
    '.ts': 'typescript',
    '.tsx': 'typescript',
    '.mts': 'typescript',
    '.cts': 'typescript',
    '.java': 'java',
    '.c': 'c',
    '.h': 'c',          # refined by `language_for_file` (C++ headers)
    '.cpp': 'cpp',
    '.cc': 'cpp',
    '.cxx': 'cpp',
    '.c++': 'cpp',
    '.hpp': 'cpp',
    '.hh': 'cpp',
    '.hxx': 'cpp',
    '.h++': 'cpp',
    '.cs': 'csharp',
}

# Constructs a C compiler rejects: a `.h` that uses one is a C++ header, and
# C vs C++ changes the analysis (reference out-parameters, see `_arg_may_define`).
_CPP_HEADER_RE = re.compile(
    r"^\s*(?:class\s+\w+\s*[:{]|namespace\s+\w*\s*\{|template\s*<|"
    r"(?:public|private|protected)\s*:)|\bstd::|\busing\s+namespace\b",
    re.MULTILINE)


# An extensionless script (`bin/deploy`) names its interpreter on the `#!` line.
_SHEBANG_INTERPRETERS = {'python': 'python', 'node': 'javascript', 'nodejs': 'javascript'}


def shebang_language(source: str) -> Optional[str]:
    """The language a `#!` first line runs (`#!/usr/bin/python3`,
    `#!/usr/bin/env -S node --flag`), else None."""
    if not source.startswith('#!'):
        return None
    words = source[2:].split('\n', 1)[0].split()
    if not words:
        return None
    prog = words[0].rsplit('/', 1)[-1]
    if prog == 'env':
        rest = [w for w in words[1:] if not w.startswith('-') and '=' not in w]
        if not rest:
            return None
        prog = rest[0].rsplit('/', 1)[-1]
    return _SHEBANG_INTERPRETERS.get(re.sub(r'[\d.]+$', '', prog))


def _script_language(path: Path) -> Optional[str]:
    """`shebang_language` of an extensionless file, reading only its first line."""
    try:
        with open(path, 'rb') as f:
            head = f.read(256)
    except OSError:
        return None
    return shebang_language(head.decode('utf-8', errors='replace'))


def language_for_file(path: Union[str, Path], source: Optional[str] = None,
                      default: Optional[str] = None) -> Optional[str]:
    """The frontend language for `path` by extension (a `.h` whose `source`
    uses C++ syntax is `cpp`; an extensionless script by its `#!` line),
    else `default`."""
    suffix = Path(path).suffix.lower()
    lang = EXTENSION_LANGUAGES.get(suffix)
    if lang is None:
        lang = (shebang_language(source) if not suffix and source else None) or default
    if lang == 'c' and Path(path).suffix.lower() == '.h' and source \
            and _CPP_HEADER_RE.search(source):
        return 'cpp'
    return lang


def language_extensions(language: Optional[str]) -> List[str]:
    """Extensions a directory scan for `language` walks: every supported one
    when `language` is None, else that language's (`c` and `cpp` share
    headers). A language with no symbolic frontend (LLM-detect only, e.g.
    php) gets its conventional extension."""
    if language is None:
        return sorted(EXTENSION_LANGUAGES)
    family = {'c': {'c', 'cpp'}, 'cpp': {'c', 'cpp'}}.get(language, {language})
    exts = sorted(e for e, lang in EXTENSION_LANGUAGES.items()
                  if lang in family and (language != 'c' or e in ('.c', '.h')))
    return exts or ['.' + _LLM_ONLY_EXTENSIONS.get(language, language)]


_LLM_ONLY_EXTENSIONS = {
    'ruby': 'rb', 'golang': 'go', 'rust': 'rs', 'kotlin': 'kt',
    'python3': 'py', 'perl': 'pl', 'shell': 'sh', 'bash': 'sh',
}


class FrameScanner:
    """
    Main vulnerability scanner.

    Scans source code for security vulnerabilities using:
    1. Language-specific frontend (tree-sitter)
    2. SIL intermediate representation
    3. Frame verification engine (incorrectness logic)
    """

    # Severity mapping for vulnerability types (OWASP Top 10 2025 aligned)
    SEVERITY_MAP = {
        # A01: Broken Access Control
        VulnType.PATH_TRAVERSAL: Severity.HIGH,
        VulnType.OPEN_REDIRECT: Severity.MEDIUM,
        VulnType.SSRF: Severity.HIGH,
        VulnType.AUTHORIZATION_BYPASS: Severity.CRITICAL,
        VulnType.CORS_MISCONFIGURATION: Severity.MEDIUM,
        VulnType.IDOR: Severity.HIGH,

        # A02: Security Misconfiguration
        VulnType.HEADER_INJECTION: Severity.MEDIUM,
        VulnType.SECRET_EXPOSURE: Severity.CRITICAL,
        VulnType.DEBUG_ENABLED: Severity.MEDIUM,
        VulnType.SECURITY_MISCONFIGURATION: Severity.MEDIUM,

        # A03: Software Supply Chain Failures
        # Note: Requires SCA tools, out of scope for SAST/taint analysis

        # A04: Cryptographic Failures
        VulnType.WEAK_CRYPTOGRAPHY: Severity.HIGH,
        VulnType.HARDCODED_SECRET: Severity.CRITICAL,
        VulnType.INSECURE_RANDOM: Severity.MEDIUM,
        VulnType.INSECURE_COOKIE: Severity.MEDIUM,
        VulnType.INSECURE_COOKIE_HTTPONLY: Severity.MEDIUM,
        VulnType.CSRF: Severity.MEDIUM,
        VulnType.WEAK_HASH: Severity.HIGH,
        VulnType.MISSING_ENCRYPTION: Severity.HIGH,
        VulnType.SENSITIVE_DATA_EXPOSURE: Severity.HIGH,

        # A05: Injection (CRITICAL category)
        VulnType.SQL_INJECTION: Severity.CRITICAL,
        VulnType.XSS: Severity.HIGH,
        VulnType.COMMAND_INJECTION: Severity.CRITICAL,
        VulnType.LDAP_INJECTION: Severity.HIGH,
        VulnType.XPATH_INJECTION: Severity.MEDIUM,
        VulnType.CODE_INJECTION: Severity.CRITICAL,
        VulnType.TEMPLATE_INJECTION: Severity.HIGH,
        VulnType.NOSQL_INJECTION: Severity.HIGH,
        VulnType.XXE: Severity.HIGH,
        VulnType.REGEX_DOS: Severity.MEDIUM,
        VulnType.ORM_INJECTION: Severity.HIGH,
        VulnType.EL_INJECTION: Severity.HIGH,

        # A06: Insecure Design
        VulnType.MASS_ASSIGNMENT: Severity.MEDIUM,
        VulnType.PROTOTYPE_POLLUTION: Severity.HIGH,
        VulnType.BUSINESS_LOGIC_FLAW: Severity.MEDIUM,
        VulnType.RACE_CONDITION: Severity.HIGH,
        VulnType.INSECURE_TEMP_FILE: Severity.MEDIUM,

        # A07: Authentication Failures
        VulnType.BROKEN_AUTHENTICATION: Severity.CRITICAL,
        VulnType.CREDENTIAL_STUFFING: Severity.HIGH,
        VulnType.SESSION_FIXATION: Severity.HIGH,
        VulnType.WEAK_PASSWORD: Severity.MEDIUM,

        # A08: Software/Data Integrity Failures
        VulnType.DESERIALIZATION: Severity.CRITICAL,
        VulnType.CODE_INTEGRITY: Severity.HIGH,
        VulnType.CI_CD_VULNERABILITY: Severity.HIGH,

        # A09: Logging & Alerting Failures
        VulnType.LOG_INJECTION: Severity.LOW,
        VulnType.SENSITIVE_DATA_LOGGED: Severity.MEDIUM,
        VulnType.INSUFFICIENT_LOGGING: Severity.LOW,

        # A10: Mishandling of Exceptional Conditions
        VulnType.ERROR_DISCLOSURE: Severity.LOW,
        VulnType.UNHANDLED_EXCEPTION: Severity.MEDIUM,
        VulnType.IMPROPER_ERROR_HANDLING: Severity.MEDIUM,

        # Memory Safety
        VulnType.NULL_DEREFERENCE: Severity.MEDIUM,
        VulnType.USE_AFTER_FREE: Severity.CRITICAL,
        VulnType.BUFFER_OVERFLOW: Severity.CRITICAL,
        VulnType.DOUBLE_FREE: Severity.HIGH,
        VulnType.INVALID_FREE: Severity.HIGH,
        VulnType.MEMORY_LEAK: Severity.LOW,
        VulnType.MISMATCHED_FREE: Severity.HIGH,
        VulnType.RETURN_STACK_ADDRESS: Severity.HIGH,
        VulnType.FORMAT_STRING: Severity.HIGH,
        VulnType.INTEGER_OVERFLOW: Severity.HIGH,
        VulnType.UNINITIALIZED_VAR: Severity.MEDIUM,
        VulnType.DANGEROUS_FUNCTION: Severity.MEDIUM,
        VulnType.DIVIDE_BY_ZERO: Severity.MEDIUM,
        VulnType.TYPE_CONFUSION: Severity.HIGH,
        VulnType.ASSERTION_FAILURE: Severity.MEDIUM,
        VulnType.PRIVILEGE_MANAGEMENT: Severity.HIGH,

        # Resource exhaustion (CWE-400 cluster). Availability impact only, and a
        # non-terminating procedure is a self-inflicted hang rather than an
        # attacker-steered one, so these sit below the injection classes.
        VulnType.UNBOUNDED_ALLOCATION: Severity.MEDIUM,
        VulnType.UNCONTROLLED_RECURSION: Severity.MEDIUM,
        VulnType.INFINITE_LOOP: Severity.MEDIUM,

        # Directional memory safety. A write past the end corrupts adjacent
        # memory and is the usual route to code execution, so it keeps the
        # CRITICAL rating CWE-120 carries; an over-read discloses memory
        # without altering it.
        VulnType.OOB_WRITE: Severity.CRITICAL,
        VulnType.OOB_READ: Severity.HIGH,

        # The under-* pair mirror the over-the-top write/read severities.
        VulnType.OOB_UNDERWRITE: Severity.CRITICAL,
        VulnType.OOB_UNDERREAD: Severity.HIGH,

        # A stack allocation too large to fit crashes the process: availability
        # only, like the rest of the CWE-400 family.
        VulnType.EXCESSIVE_ALLOCATION: Severity.MEDIUM,

        # A world-writable resource lets any local user alter it.
        VulnType.INCORRECT_PERMISSIONS: Severity.HIGH,

        # A dropped privilege-drop result leaves the process running with
        # privileges it believes it no longer has.
        VulnType.UNCHECKED_RETURN: Severity.HIGH,

        # Generic
        VulnType.TAINT_FLOW: Severity.MEDIUM,
    }

    # CWE mapping for all vulnerability types
    CWE_MAP = {
        # A01: Broken Access Control
        VulnType.PATH_TRAVERSAL: "CWE-22",
        VulnType.OPEN_REDIRECT: "CWE-601",
        VulnType.SSRF: "CWE-918",
        VulnType.AUTHORIZATION_BYPASS: "CWE-863",
        VulnType.CORS_MISCONFIGURATION: "CWE-942",
        VulnType.IDOR: "CWE-639",

        # A02: Security Misconfiguration
        VulnType.HEADER_INJECTION: "CWE-113",
        VulnType.SECRET_EXPOSURE: "CWE-200",
        VulnType.DEBUG_ENABLED: "CWE-215",
        VulnType.SECURITY_MISCONFIGURATION: "CWE-16",

        # A03: Software Supply Chain Failures
        # Note: Requires SCA tools, out of scope for SAST/taint analysis

        # A04: Cryptographic Failures
        VulnType.WEAK_CRYPTOGRAPHY: "CWE-327",
        VulnType.HARDCODED_SECRET: "CWE-798",
        VulnType.INSECURE_RANDOM: "CWE-330",
        VulnType.WEAK_HASH: "CWE-328",
        VulnType.IMPROPER_CERT_VALIDATION: "CWE-295",
        VulnType.INSUFFICIENT_KEY_SIZE: "CWE-326",
        VulnType.WEAK_RSA_PADDING: "CWE-780",
        VulnType.INSUFFICIENT_CREDENTIAL_PROTECTION: "CWE-522",
        VulnType.MISSING_ENCRYPTION: "CWE-311",
        VulnType.SENSITIVE_DATA_EXPOSURE: "CWE-200",

        # A05: Injection
        VulnType.SQL_INJECTION: "CWE-89",
        VulnType.XSS: "CWE-79",
        VulnType.COMMAND_INJECTION: "CWE-78",
        VulnType.LDAP_INJECTION: "CWE-90",
        VulnType.XPATH_INJECTION: "CWE-643",
        VulnType.XML_INJECTION: "CWE-91",
        VulnType.CODE_INJECTION: "CWE-94",
        VulnType.TEMPLATE_INJECTION: "CWE-1336",
        VulnType.NOSQL_INJECTION: "CWE-943",
        VulnType.XXE: "CWE-611",
        VulnType.REGEX_DOS: "CWE-1333",
        VulnType.ORM_INJECTION: "CWE-89",
        VulnType.EL_INJECTION: "CWE-917",

        # A06: Insecure Design
        VulnType.MASS_ASSIGNMENT: "CWE-915",
        VulnType.PROTOTYPE_POLLUTION: "CWE-1321",
        VulnType.BUSINESS_LOGIC_FLAW: "CWE-840",
        VulnType.RACE_CONDITION: "CWE-362",
        VulnType.INSECURE_TEMP_FILE: "CWE-377",

        # A07: Authentication Failures
        VulnType.BROKEN_AUTHENTICATION: "CWE-287",
        VulnType.CREDENTIAL_STUFFING: "CWE-307",
        VulnType.SESSION_FIXATION: "CWE-384",
        VulnType.WEAK_PASSWORD: "CWE-521",
        VulnType.TRUST_BOUNDARY_VIOLATION: "CWE-501",
        VulnType.INSECURE_COOKIE: "CWE-614",
        VulnType.INSECURE_COOKIE_HTTPONLY: "CWE-1004",
        VulnType.CSRF: "CWE-352",

        # A08: Software/Data Integrity Failures
        VulnType.DESERIALIZATION: "CWE-502",
        VulnType.CODE_INTEGRITY: "CWE-494",
        VulnType.CI_CD_VULNERABILITY: "CWE-1395",

        # A09: Logging & Alerting Failures
        VulnType.LOG_INJECTION: "CWE-117",
        VulnType.SENSITIVE_DATA_LOGGED: "CWE-532",
        VulnType.INSUFFICIENT_LOGGING: "CWE-778",

        # A10: Mishandling of Exceptional Conditions
        VulnType.ERROR_DISCLOSURE: "CWE-209",
        VulnType.UNHANDLED_EXCEPTION: "CWE-755",
        VulnType.IMPROPER_ERROR_HANDLING: "CWE-388",

        # Memory Safety
        VulnType.NULL_DEREFERENCE: "CWE-476",
        VulnType.USE_AFTER_FREE: "CWE-416",
        VulnType.BUFFER_OVERFLOW: "CWE-120",
        VulnType.DOUBLE_FREE: "CWE-415",
        VulnType.INVALID_FREE: "CWE-590",
        VulnType.MEMORY_LEAK: "CWE-401",
        VulnType.MISMATCHED_FREE: "CWE-762",
        VulnType.RETURN_STACK_ADDRESS: "CWE-562",
        VulnType.FORMAT_STRING: "CWE-134",
        VulnType.INTEGER_OVERFLOW: "CWE-190",
        VulnType.UNINITIALIZED_VAR: "CWE-457",
        VulnType.DANGEROUS_FUNCTION: "CWE-676",
        VulnType.DIVIDE_BY_ZERO: "CWE-369",
        VulnType.TYPE_CONFUSION: "CWE-843",
        VulnType.ASSERTION_FAILURE: "CWE-617",
        VulnType.PRIVILEGE_MANAGEMENT: "CWE-269",

        # Resource exhaustion. Always the specific child weakness: a query for
        # the CWE-400 parent is satisfied through `cwe_taxonomy.is_a`.
        VulnType.UNBOUNDED_ALLOCATION: "CWE-770",
        VulnType.UNCONTROLLED_RECURSION: "CWE-674",
        VulnType.INFINITE_LOOP: "CWE-835",

        # Directional memory safety. CWE-120 remains the answer wherever the
        # direction is not established; these are used only where the IR settles
        # it, and both are children of CWE-119 so either still answers a query
        # for the broader class.
        VulnType.OOB_WRITE: "CWE-787",
        VulnType.OOB_READ: "CWE-125",

        # Directional memory safety, the below-the-start siblings. Each is a child
        # of the same CWE-119 family through `cwe_taxonomy.is_a`, so a query for
        # the broader class still resolves.
        VulnType.OOB_UNDERWRITE: "CWE-124",
        VulnType.OOB_UNDERREAD: "CWE-127",

        # Excessive constant allocation, the sibling of CWE-770.
        VulnType.EXCESSIVE_ALLOCATION: "CWE-789",

        # Permission assignment, and the dropped privilege-drop result. Frame
        # reports the specific CWE-252; a query for its CWE-754 parent is
        # answered through `cwe_taxonomy.is_a`, so CWE-754 is not a detector of
        # its own any more than CWE-400 is.
        VulnType.INCORRECT_PERMISSIONS: "CWE-732",
        VulnType.UNCHECKED_RETURN: "CWE-252",
    }

    def __init__(
        self,
        language: str = "python",
        verify: bool = True,
        timeout: int = 5000,
        verbose: bool = False,
        library_mode: bool = False,
        llm_triage: bool = False,
        llm_detect: bool = False,
        llm_config: Any = None,
        llm_repo_scale: bool = False,
        respect_suppressions: bool = True,
        disabled_rules: Optional[Iterable[str]] = None,
        packs: Optional[Iterable[str]] = None,
        use_builtin_packs: bool = True,
    ):
        """
        Initialize the scanner.

        Args:
            language: Source language ("python", "javascript", etc.)
            verify: Whether to verify findings with Frame (slower but no FPs)
            timeout: Verification timeout in milliseconds
            verbose: Enable verbose output
            library_mode: Treat exported-function parameters as untrusted input.
                Correct threat model when analyzing a *library* (its public API
                receives attacker-controlled data) rather than an application.
            respect_suppressions: Honor inline ``frame: ignore`` comments (see
                frame/sil/suppressions.py). Suppressed findings are kept on
                ``ScanResult.suppressed`` rather than silently discarded.
            disabled_rules: CWE ids or finding types to drop from results
                (e.g. ``["CWE-798", "weak_hash"]``).
            packs: extra framework pack files / directories (see frame/sil/packs),
                loaded on top of the built-in ones and the project's .frame/packs.
            use_builtin_packs: load the packs that ship with Frame.
        """
        from frame.sil.packs import PackSet
        self._pack_paths = list(packs or [])
        self._use_builtin_packs = use_builtin_packs
        self.pack_set = PackSet.build(self._pack_paths, builtin=use_builtin_packs)
        self.respect_suppressions = respect_suppressions
        self.disabled_rules = list(disabled_rules or [])
        self.language = language
        self.verify = verify
        self.timeout = timeout
        self.verbose = verbose
        # Optional neuro-symbolic LLM layers (see frame/sil/llm_triage.py,
        # llm_detect.py). Triage filters findings (precision); detect adds findings
        # (recall). Both off by default -- the sound symbolic layer is the default.
        self.llm_triage = llm_triage
        self.llm_detect = llm_detect
        # Repository-scale detection: one LLM session for the whole tree
        # instead of one per file. Opt-in, so per-file behaviour (and every
        # benchmark number measured against it) is unchanged by default.
        self.llm_repo_scale = llm_repo_scale
        self._llm_config = llm_config
        self._llm_client = None
        self.library_mode = library_mode

        # Initialize frontend
        self.frontend = self._get_frontend(language)
        # Set while a directory scan runs with cross-file analysis (`ProjectContext`),
        # and what it covered (for the CLI to report).
        self._project: Any = None
        self.last_project_scope: Optional[Dict[str, Any]] = None

        # Initialize verifier
        if verify:
            self.checker = IncorrectnessChecker(timeout=timeout)
        else:
            self.checker = None

    def use_project_packs(self, start) -> None:
        """Add the `.frame/packs` of the project containing `start` to this scan's
        packs (the nearest ancestor that has one, up to the repository root)."""
        from frame.sil.packs import PackSet, discover_project_packs
        found = tuple(str(p) for p in discover_project_packs(Path(start)))
        if found == getattr(self, "_project_pack_dirs", ()):
            return
        self._project_pack_dirs = found
        self.pack_set = PackSet.build(self._pack_paths, builtin=self._use_builtin_packs,
                                      project_start=Path(start))
        if self.frontend is not None:
            self.frontend.packs = self.pack_set

    def _get_frontend(self, language: str):
        """Get frontend for specified language"""
        fe = self._make_frontend(language)
        if fe is not None:
            fe.packs = self.pack_set
        return fe

    def _make_frontend(self, language: str):
        if language == "python":
            from frame.sil.frontends.python_frontend import PythonFrontend
            return PythonFrontend()
        elif language == "javascript":
            from frame.sil.frontends.javascript_frontend import JavaScriptFrontend
            fe = JavaScriptFrontend()
            fe.taint_function_params = self.library_mode
            return fe
        elif language == "typescript":
            from frame.sil.frontends.javascript_frontend import TypeScriptFrontend
            fe = TypeScriptFrontend()
            fe.taint_function_params = self.library_mode
            return fe
        elif language == "java":
            from frame.sil.frontends.java_frontend import JavaFrontend
            return JavaFrontend()
        elif language == "c":
            from frame.sil.frontends.c_frontend import CFrontend
            return CFrontend()
        elif language == "cpp":
            from frame.sil.frontends.c_frontend import CppFrontend
            return CppFrontend()
        elif language == "csharp":
            from frame.sil.frontends.csharp_frontend import CSharpFrontend
            return CSharpFrontend()
        else:
            # No symbolic frontend for this language. Return None rather than raise:
            # under --ai the scan still runs the language-agnostic LLM-detect layer
            # (LLM-tier findings only -- no sound symbolic analysis for this language).
            return None

    def scan(self, source_code: str, filename: str = "<unknown>",
             program: Optional[Program] = None, translator: Any = None) -> ScanResult:
        """
        Scan source code for vulnerabilities.

        Args:
            source_code: Source code string
            filename: Filename for reporting
            program: The file's already-translated SIL (a project scan translates
                every file once, up front); parsed here when omitted
            translator: With `program`, the project's translator for this file,
                which resolves calls into other files and holds the summaries

        Returns:
            ScanResult with vulnerabilities found
        """
        start_time = time.time()
        # Strip a leading UTF-8 BOM if present. scan_file() reads with utf-8-sig
        # and strips it, but callers of scan() with raw text may not -- a stray
        # BOM (common in C#/.NET files) corrupts the first token and silently
        # suppresses findings, making scan() and scan_file() disagree.
        if source_code.startswith('﻿'):
            source_code = source_code[1:]
        result = ScanResult(filename=filename)
        result.lines_scanned = source_code.count('\n') + 1

        # No symbolic frontend for this language: fall back to LLM-detect-only so
        # `frame scan --ai` works on ANY language (PHP, Rust, Go, ...). The findings
        # are LLM-tier only (source_var="llm_detect") -- there is no sound symbolic
        # analysis for a language without a frontend, and the tiering makes that
        # explicit. Without --ai there is nothing sound to do, so we say so.
        if self.frontend is None:
            if self.llm_detect:
                result.vulnerabilities = self._apply_llm_detect(
                    [], source_code, filename, program=None)
                if self.llm_triage:
                    result.vulnerabilities = self._apply_llm_triage(
                        result.vulnerabilities, source_code, filename)
            else:
                result.errors.append(
                    f"Language '{self.language}' has no symbolic frontend; "
                    f"re-run with --ai for LLM-based detection.")
            self._apply_suppressions(result, source_code)
            result.scan_time_ms = (time.time() - start_time) * 1000
            return result

        try:
            # Step 1: Parse source to SIL
            if self.verbose:
                print(f"[Scanner] Parsing {filename}...")

            if program is None:
                program = self.frontend.translate(source_code, filename)
            result.procedures_analyzed = len(program.procedures)
            result.packs = list(program.packs_applied)
            if program.syntax_error_line is not None:
                result.warnings.append(
                    f"Syntax error near line {program.syntax_error_line}: the file was "
                    f"parsed partially, so findings may be missing")

            if self.verbose:
                print(f"[Scanner] Found {len(program.procedures)} procedures")

            # Step 2: Generate vulnerability checks
            if self.verbose:
                print(f"[Scanner] Generating vulnerability checks...")

            if translator is None:
                translator = SILTranslator(program, verbose=self.verbose)
            checks = translator.translate_program()

            if self.verbose:
                print(f"[Scanner] Generated {len(checks)} potential vulnerabilities")

            # Step 3: Verify each check
            for check in checks:
                vuln = self._process_check(check)
                if vuln:
                    result.vulnerabilities.append(vuln)

            # Step 3b: Tier-2 structural scan over the SIL (all languages).
            # AST/IR-based detection for code-shape vulnerabilities that are not
            # data flows -- currently hardcoded secrets. Replaces the per-
            # language hardcoded_secret regexes.
            literal_vulns = self._scan_literals(program, filename)
            result.vulnerabilities.extend(literal_vulns)
            if self.verbose:
                print(f"[Scanner] Literal scan found {len(literal_vulns)} vulnerabilities")

            # Step 3c: hardening -- explicit off switches (debug mode, insecure cookie flags).
            hardening_vulns = self._scan_hardening(source_code, filename)
            result.vulnerabilities.extend(hardening_vulns)

            # (Regex pattern layer removed -- the SL taint engine, Tier-2
            #  literal scanner, and memory analyzer are the only detectors.)
            # Step 4b: Memory safety analysis for C/C++ using separation logic
            if self.language in ('c', 'cpp', 'c++'):
                memory_vulns = self._analyze_memory_safety(source_code, filename)
                result.vulnerabilities.extend(memory_vulns)
                if self.verbose:
                    print(f"[Scanner] Memory safety analysis found {len(memory_vulns)} vulnerabilities")

            # Step 4c: Interprocedural taint analysis for C#
            if self.language == 'csharp':
                ipa_vulns = self._analyze_csharp_interprocedural(source_code, filename)
                result.vulnerabilities.extend(ipa_vulns)
                if self.verbose:
                    print(f"[Scanner] C# interprocedural analysis found {len(ipa_vulns)} vulnerabilities")

            # Step 5: Deduplicate vulnerabilities
            result.vulnerabilities = self._deduplicate_vulnerabilities(result.vulnerabilities)

            if self.verbose:
                print(f"[Scanner] After deduplication: {len(result.vulnerabilities)} unique vulnerabilities")

            # Step 6: Apply confidence-based filtering
            result.vulnerabilities = self._filter_by_confidence(result.vulnerabilities, source_code)
            self._tag_source_evidence(result.vulnerabilities, source_code)

            if self.verbose:
                print(f"[Scanner] After confidence filter: {len(result.vulnerabilities)} vulnerabilities")

            # Step 7 (optional): LLM DETECTION -- adds findings the symbolic layer
            # missed (recall). Runs BEFORE triage so that, when both are enabled,
            # triage also filters the (noisier) detection findings.
            if self.llm_detect:
                result.vulnerabilities = self._apply_llm_detect(
                    result.vulnerabilities, source_code, filename, program)
                if self.verbose:
                    print(f"[Scanner] After LLM detect: {len(result.vulnerabilities)} vulnerabilities")

            # Step 8 (optional): neuro-symbolic LLM triage -- drops confident false
            # positives from ALL findings (symbolic + detection), raising precision.
            if self.llm_triage:
                result.vulnerabilities = self._apply_llm_triage(
                    result.vulnerabilities, source_code, filename)
                if self.verbose:
                    print(f"[Scanner] After LLM triage: {len(result.vulnerabilities)} vulnerabilities")

        except LLMUnavailableError:
            # Never mask an unreachable LLM as a clean scan -- propagate so the
            # caller reports "LLM unavailable", not "no vulnerabilities found".
            raise
        except Exception as e:
            result.errors.append(f"Scan error: {str(e)}")
            if self.verbose:
                import traceback
                traceback.print_exc()

        self._apply_suppressions(result, source_code)
        result.scan_time_ms = (time.time() - start_time) * 1000

        if self.verbose:
            print(f"[Scanner] Scan complete: {len(result.vulnerabilities)} vulnerabilities found")
            print(f"[Scanner] Time: {result.scan_time_ms:.2f}ms")

        return result

    def _apply_suppressions(self, result: ScanResult, source_code: str) -> None:
        """Move findings silenced by config or inline comments to ``result.suppressed``."""
        from frame.sil.suppressions import matches_rules, split_suppressed
        vulns = result.vulnerabilities
        if self.disabled_rules:
            kept = [v for v in vulns if not matches_rules(v, self.disabled_rules)]
            result.suppressed.extend(v for v in vulns if v not in kept)
            vulns = kept
        if self.respect_suppressions:
            vulns, inline = split_suppressed(vulns, source_code)
            result.suppressed.extend(inline)
        result.vulnerabilities = vulns

    def _apply_llm_triage(self, vulns, source_code: str, filename: str):
        """Adjudicate findings with an OpenAI-compatible LLM, dropping confident
        false positives. Lazily builds the client/config; on any import or config
        problem it returns findings unchanged (fail-safe)."""
        try:
            from frame.sil.llm_triage import (
                TriageConfig, LLMTriageClient, triage_vulnerabilities)
        except ImportError:
            return vulns
        config = self._llm_config or TriageConfig.from_env()
        if not getattr(config, "base_url", "") or not getattr(config, "model", ""):
            if self.verbose:
                print("[Scanner] LLM triage requested but no endpoint/model configured; skipping.")
            return vulns
        if self._llm_client is None:
            self._llm_client = LLMTriageClient(config)
        kept, self._llm_client = triage_vulnerabilities(
            vulns, source_code, self.language, filename, config, self._llm_client)
        return kept

    def _apply_llm_detect(self, vulns, source_code: str, filename: str, program=None):
        """LLM detection pass: add findings the symbolic layer missed, on
        security-relevant files. Each LLM finding is symbolically VERIFIED against
        Frame's own sink model -- one grounded in a recognized dangerous sink is
        promoted to a higher-confidence tier (source_var="llm_verified"); the rest
        stay "llm_detect". Additive per (file, CWE). Fail-safe on any error."""
        try:
            from frame.sil.llm_detect import (detect_agentic, is_detection_candidate,
                                              collect_sinks, is_sink_grounded,
                                              cross_file_grounded)
            from frame.sil.llm_triage import TriageConfig, LLMTriageClient
        except ImportError:
            return vulns
        config = self._llm_config or TriageConfig.from_env()
        if not getattr(config, "base_url", "") or not getattr(config, "model", ""):
            if self.verbose:
                print("[Scanner] LLM detect requested but no endpoint/model; skipping.")
            return vulns
        # Supported languages gate on the candidate heuristic (avoid calling the
        # model on every file). For an unsupported language (LLM-only mode) the user
        # explicitly opted in with --ai, so detection always runs -- the heuristic's
        # patterns are tuned for the symbolic languages and would miss PHP/Ruby/etc.
        if self.frontend is not None and not is_detection_candidate(source_code, bool(vulns)):
            return vulns
        if self._llm_client is None:
            self._llm_client = LLMTriageClient(config)
        existing_cwes = {v.cwe_id for v in vulns}
        # detect_agentic uses read_file/grep tools when config.repo_root is set
        # (cross-file flows), else falls back to single-file detection.
        new = detect_agentic(source_code, self.language, filename, config, self._llm_client)
        sinks = collect_sinks(program) if program is not None else []
        # Cross-file grounding (v2): collect sink kinds from the files the agent
        # explored, so a finding whose sink lives in another file can be verified.
        explored_kinds = set()
        repo_root = getattr(config, "repo_root", "")
        explored = getattr(self._llm_client, "_explored", None) or set()
        # Grounding needs a symbolic frontend to translate explored files; in
        # LLM-only mode (unsupported language) there is none, so findings stay
        # LLM-tier (correct -- no symbolic verification is available).
        if repo_root and explored and self.frontend is not None:
            root = os.path.realpath(repo_root)
            for rel in explored:
                try:
                    fp = os.path.realpath(os.path.join(root, str(rel).lstrip("/")))
                    if fp.startswith(root) and os.path.isfile(fp):
                        prog2 = self.frontend.translate(
                            open(fp, encoding="utf-8", errors="replace").read(), rel)
                        explored_kinds |= {k for _, k in collect_sinks(prog2)}
                except Exception:
                    continue
        added = []
        for v in new:
            if v.cwe_id in existing_cwes:   # don't duplicate a proven finding
                continue
            grounded = (sinks and is_sink_grounded(v.cwe_id, v.line, sinks)) \
                or cross_file_grounded(v.cwe_id, explored_kinds)
            if grounded:
                # Grounded in a real sink Frame recognizes (same file or a file the
                # agent explored) -> higher-confidence tier.
                v.source_var = "llm_verified"
                v.confidence = max(v.confidence, 0.9)
                v.description = v.description.replace(
                    "[LLM-detected]", "[LLM-detected, sink-verified]")
            added.append(v)
        return list(vulns) + added

    def scan_file(self, filepath: str) -> ScanResult:
        """
        Scan a source file for vulnerabilities.

        Args:
            filepath: Path to source file

        Returns:
            ScanResult with vulnerabilities found
        """
        path = Path(filepath)
        self.use_project_packs(path)

        if not path.exists():
            result = ScanResult(filename=str(path))
            result.errors.append(f"File not found: {filepath}")
            return result

        # Use utf-8-sig to automatically strip BOM (common in C# files)
        try:
            source_code = path.read_text(encoding='utf-8-sig', errors='replace')
        except OSError as e:
            # An unreadable file (permissions, vanished mid-scan) must not stop
            # a directory scan: report it as this file's error and move on.
            result = ScanResult(filename=str(path))
            result.errors.append(f"Could not read {filepath}: {e.strerror or e}")
            return result

        # Auto-detect language from extension if not already set correctly
        detected_lang = language_for_file(path, source_code, self.language)

        # If detected language differs from current, update
        if detected_lang != self.language:
            self.language = detected_lang
            self.frontend = self._get_frontend(detected_lang)

        # Minified and generated artifacts are not source: they are build output,
        # they are never the file a security advisory points at, and analysing them
        # costs enormous time for no signal (a single 277KB line of bundled JS can
        # burn minutes of CPU). Detect them structurally, by line geometry, rather
        # than by filename, so the check does not depend on naming conventions.
        if is_generated_source(source_code):
            result = ScanResult(filename=str(path))
            result.warnings.append(
                "Skipped: file looks generated or minified (extremely long lines)")
            return result

        if self._project is not None:
            translator = self._project.translator_for(path)
            if translator is not None:
                return self.scan(source_code, str(path), program=translator.program,
                                 translator=translator)
        return self.scan(source_code, str(path))

    @staticmethod
    def _is_excluded_dir_member(
            filepath: Path, root: Path,
            excluded_dirs: FrozenSet[Union[str, Tuple[str, ...]]]) -> bool:
        """Does `filepath` sit under one of `excluded_dirs`, relative to `root`?

        Only directory components between `root` and the file are checked --
        never the filename itself, and never anything above `root` -- so a
        scan root that itself happens to be named (or nested in) an excluded
        directory still has its own files scanned normally.

        An entry in `excluded_dirs` is either a plain string, matched against
        any single directory component, or a tuple of components that must
        appear consecutively (e.g. `(".claude", "worktrees")` matches
        `.claude/worktrees/...` but not a bare `.claude/hooks/...`).

        The single name `"venv"` is a special case: it collides with
        CPython's own `venv` stdlib package and is a plausible real source
        directory name, so it only counts as a virtualenv -- and is only
        excluded -- when it actually contains `pyvenv.cfg`, the marker every
        `venv`/`virtualenv`-created environment carries. `.venv` has no such
        ambiguity and is excluded unconditionally.
        """
        if not excluded_dirs:
            return False
        try:
            rel_parts = filepath.relative_to(root).parts
        except ValueError:
            # Not actually under `root` (e.g. a differently-resolved symlink) --
            # conservative default is to scan it, never to inspect components
            # above `root` that this guarantee was never meant to cover.
            return False
        dir_parts = rel_parts[:-1]  # drop the filename: only dirs can match
        if not dir_parts:
            return False

        single = {e for e in excluded_dirs if isinstance(e, str)}
        multi = [e for e in excluded_dirs if isinstance(e, tuple) and e]

        for i, part in enumerate(dir_parts):
            if part not in single:
                continue
            if part == "venv":
                venv_dir = root.joinpath(*dir_parts[:i + 1])
                if not (venv_dir / "pyvenv.cfg").is_file():
                    continue
            return True

        for seq in multi:
            n = len(seq)
            for i in range(len(dir_parts) - n + 1):
                if tuple(dir_parts[i:i + n]) == seq:
                    return True
        return False

    def scan_directory(self, dirpath: str, pattern: Optional[str] = "**/*.py",
                        exclude_dirs: Optional[Iterable[Union[str, Tuple[str, ...]]]] = None,
                        extensions: Optional[Iterable[str]] = None,
                        only_files: Optional[Iterable[Union[str, Path]]] = None,
                        cross_file: bool = True,
                        cross_file_limit: int = DEFAULT_CROSS_FILE_LIMIT,
                        project_root: Optional[Union[str, Path]] = None
                        ) -> List[ScanResult]:
        """
        Scan all matching files in a directory.

        Args:
            dirpath: Directory path
            pattern: Glob pattern for files. None scans every file with a
                supported source extension (`EXTENSION_LANGUAGES`), each in
                its own language -- what a mixed-language repository needs.
            extensions: With `pattern=None`, scan only these extensions
                (e.g. `language_extensions("java")`).
            only_files: Scan only these files (e.g. what `git diff` names),
                still subject to the pattern/extensions and the excludes. Files
                outside `dirpath` are ignored. With `cross_file` the scan widens
                to the files a change to these can affect (see below).
            cross_file: Follow taint across the imports of Python and JS/TS
                files (`ProjectIndex`): a handler that passes request data to a
                helper in another file, or calls a helper that returns it, is
                one flow. With `only_files`, the scan covers those files, the
                files that import them (their callee summaries changed), and
                everything those import (so each is analysed exactly as a full
                scan would). `last_project_scope` says what was done.
            cross_file_limit: Most files a cross-file analysis spans.
            exclude_dirs: Directory names (or component-sequence tuples) to
                skip anywhere under `dirpath` (matched against path
                components relative to `dirpath`, so a scan root that itself
                sits inside such a directory is not affected). Defaults to
                `DEFAULT_EXCLUDED_SCAN_DIRS` -- VCS/IDE/dependency/build
                state such as `.git` and `.claude/worktrees` that is not
                project source in the common case. Pass `[]` to disable
                filtering.

        Returns:
            List of ScanResult for each file
        """
        results = []
        dir_path = Path(dirpath)
        excluded_dirs = (DEFAULT_EXCLUDED_SCAN_DIRS if exclude_dirs is None
                          else frozenset(exclude_dirs))
        self.last_project_scope = None
        self.use_project_packs(project_root or dir_path)

        # The agentic detector can trace flows across files with its read_file and
        # grep tools, but only when it has a repo root; without one it silently
        # degrades to single-file analysis and cross-file flows are lost. A
        # directory scan knows the root, so supply it.
        self._default_repo_root(dir_path)

        # Repository-scale mode runs the LLM layer ONCE over the whole tree rather
        # than once per file. Per-file costs a session for every candidate, which is
        # unusable on real projects: the model re-derives the same context each time
        # and the wall clock scales with file count. The symbolic pass is unaffected
        # and still runs per file, so only the LLM tier changes.
        repo_scale = self.llm_repo_scale and self.llm_detect
        per_file_detect = self.llm_detect
        if repo_scale:
            self.llm_detect = False          # suppress the per-file LLM pass

        try:
            candidates = self._candidate_files(dir_path, pattern, extensions,
                                               excluded_dirs, only_files)
            if cross_file:
                candidates = self._start_project(
                    dir_path, pattern, extensions, excluded_dirs,
                    candidates, only_files is not None, cross_file_limit, project_root)
            for filepath in candidates:
                result = self.scan_file(str(filepath))
                results.append(result)
        finally:
            self.llm_detect = per_file_detect
            self._project = None

        if repo_scale:
            selected = None if only_files is None else {Path(r.filename).resolve() for r in results}
            results = self._apply_repo_scale_detect(dir_path, results, excluded_dirs, selected)

        return results

    def _candidate_files(self, dir_path: Path, pattern: Optional[str],
                         extensions: Optional[Iterable[str]],
                         excluded_dirs: FrozenSet[Union[str, Tuple[str, ...]]],
                         only_files: Optional[Iterable[Union[str, Path]]] = None) -> List[Path]:
        """The files a directory scan covers: the glob (or the supported
        extensions), or `only_files` among them, minus excluded directories."""
        if only_files is not None:
            raw: Iterable[Path] = self._selected_files(dir_path, only_files, pattern, extensions)
        elif pattern is None:
            exts = {e.lower() for e in (extensions or EXTENSION_LANGUAGES)}
            raw = sorted(p for p in dir_path.rglob("*") if p.suffix.lower() in exts or not p.suffix)
        else:
            raw = dir_path.glob(pattern)
        return [p for p in raw
                if p.is_file() and not self._is_excluded_dir_member(p, dir_path, excluded_dirs)
                and (p.suffix or pattern is not None or self._is_script(p, extensions))]

    @staticmethod
    def _is_script(path: Path, extensions: Optional[Iterable[str]]) -> bool:
        """Is extensionless `path` a script in a language the scan covers?"""
        langs = {EXTENSION_LANGUAGES.get(e.lower()) for e in (extensions or EXTENSION_LANGUAGES)}
        return _script_language(path) in langs - {None}

    def _start_project(self, dir_path: Path, pattern: Optional[str],
                       extensions: Optional[Iterable[str]],
                       excluded_dirs: FrozenSet[Union[str, Tuple[str, ...]]],
                       selected: List[Path], narrowed: bool, limit: int,
                       root: Optional[Union[str, Path]] = None) -> List[Path]:
        """Build the cross-file project for this directory scan (sets
        `self._project` and `last_project_scope`) and return the files to scan:
        `selected` itself, or -- for a narrowed scan -- everything the selected
        files can affect. Without at least two Python/JS/TS files, or over
        `limit` files in a full scan, files are scanned alone."""
        from frame.sil.project import (
            ProjectContext, ProjectIndex, language_family)
        from frame.sil.fingerprints import project_root as resolve_project_root
        target = dir_path.resolve()
        base = resolve_project_root(dir_path, root)
        # A scan of a subdirectory still resolves imports rooted above it
        # (`from sqli.dao.student import ...` when scanning `sqli/`): the files
        # between the target and the project root are context, analysed as
        # callees/callers but never reported.
        widen = base != target and target.is_relative_to(base)
        context_note = None
        universe = None
        if widen:
            chosen = {s.resolve() for s in selected}
            context = [p for p in self._candidate_files(base, None, None, excluded_dirs)
                       if language_family(p) is not None and p.resolve() not in chosen]
            if len(selected) + len(context) > limit:     # decided before reading any of them
                widen = False
                context_note = (f"the project root {base} has more than {limit} Python/JS/TS files, so "
                                f"imports rooted above the scan target will not resolve "
                                f"(scan from the package root or raise --cross-file-limit)")
            else:
                universe = list(selected) + context
        if universe is None:
            universe = (self._candidate_files(dir_path, pattern, extensions, excluded_dirs)
                        if narrowed else selected)
        files = []
        for p in universe:
            if language_family(p) is None:
                continue
            try:
                if is_generated_source(p.read_text(encoding="utf-8-sig", errors="replace")):
                    continue
            except (OSError, UnicodeError):
                continue
            files.append(p)
        if len(files) < 2:
            if context_note:
                self.last_project_scope = {"cross_file": False, "reason": context_note}
            return selected
        if not narrowed and not widen and len(files) > limit:
            self.last_project_scope = {
                "cross_file": False,
                "reason": f"{len(files)} Python/JS/TS files exceed the cross-file limit "
                          f"({limit}); each is analysed alone (--cross-file-limit raises it)"}
            return selected

        frontends: Dict[str, Any] = {}

        def frontend_for(lang: str):
            if lang not in frontends:
                frontends[lang] = self._get_frontend(lang)
            return frontends[lang]

        index = ProjectIndex(base if widen else target, files,
                             lambda lang: frontend_for(lang).parser)
        original = {p.resolve(): p for p in files}
        to_scan = selected
        scope_keys = list(index.modules)
        truncated = False
        if narrowed or widen:
            seeds = [k for k in (index.key_for(p) for p in selected) if k]
            closure = index.closure(seeds, limit)
            scope_keys, truncated = closure.files, closure.truncated
            if narrowed:
                in_scope = [original[index.modules[k].path] for k in scope_keys
                            if index.modules[k].path in original
                            and index.modules[k].path.is_relative_to(target)]
                others = [p for p in selected if index.key_for(p) is None]
                to_scan = in_scope + [p for p in others if p not in in_scope]
        display = {k: str(original[index.modules[k].path]) for k in index.modules
                   if index.modules[k].path in original}
        self._project = ProjectContext.build(index, scope_keys, frontend_for,
                                             verbose=self.verbose, display=display)
        self.last_project_scope = {
            "cross_file": True, "files": len(scope_keys), "selected": len(selected),
            "truncated": truncated, "limit": limit,
            "complete": not self._project.ipa.incomplete}
        if widen:
            self.last_project_scope["context_root"] = str(base)
        if context_note:
            self.last_project_scope["context"] = context_note
        return to_scan

    @staticmethod
    def _selected_files(dir_path: Path, only_files: Iterable[Union[str, Path]],
                        pattern: Optional[str],
                        extensions: Optional[Iterable[str]]) -> List[Path]:
        """`only_files` that lie under `dir_path` and match `pattern` (or, with no
        pattern, have one of `extensions`), as paths under `dir_path` the way a
        directory walk would name them."""
        root = dir_path.resolve()
        exts = {e.lower() for e in (extensions or EXTENSION_LANGUAGES)}
        globbed = {p.resolve() for p in dir_path.glob(pattern)} if pattern else None
        out = []
        for f in only_files:
            p = Path(f).resolve()
            if not p.is_relative_to(root):
                continue
            if globbed is not None and p not in globbed:
                continue
            if globbed is None and p.suffix.lower() not in exts and not (
                    not p.suffix and p.is_file() and FrameScanner._is_script(p, extensions)):
                continue
            out.append(dir_path / p.relative_to(root))
        return sorted(set(out))

    def _apply_repo_scale_detect(self, dir_path: Path,
                                 results: List[ScanResult],
                                 excluded_dirs: FrozenSet[Union[str, Tuple[str, ...]]] = frozenset(),
                                 selected: Optional[set] = None
                                 ) -> List[ScanResult]:
        """Run one repository-wide LLM detection pass and merge its findings.

        Findings are attached to the ScanResult for the file they name, creating one
        if the file was not otherwise scanned (the model may legitimately flag a file
        the glob did not match). That legitimate case is exactly how an excluded
        directory could sneak back in: the agent's own read_file/grep tools are not
        limited to the glob's matches, so a newly-created result is still checked
        against `excluded_dirs` before being kept. Fail-safe: any error leaves the
        symbolic results untouched, because a broken LLM tier must never discard
        proven findings. With `selected` (a narrowed scan, e.g. `--changed`), a
        finding in a file outside it is dropped.
        """
        try:
            from frame.sil.llm_detect import detect_repo
            from frame.sil.llm_triage import TriageConfig
        except ImportError:
            return results
        try:
            config = self._llm_config or TriageConfig.from_env()
            if not getattr(config, "base_url", "") or not getattr(config, "model", ""):
                if self.verbose:
                    print("[Scanner] repo-scale detect requested but no endpoint/model.")
                return results
            resolved_root = dir_path.resolve()
            found = detect_repo(str(resolved_root), self.language, config, self._llm_client)
        except Exception as e:
            if self.verbose:
                print(f"[Scanner] repo-scale detect failed: {e}")
            return results

        by_file = {r.filename: r for r in results}
        for vuln in found or []:
            target = getattr(vuln, "location", "") or ""
            if not target:
                continue
            if selected is not None and Path(target).resolve() not in selected:
                continue
            result = by_file.get(target)
            if result is None:
                if self._is_excluded_dir_member(Path(target), resolved_root, excluded_dirs):
                    if self.verbose:
                        print(f"[Scanner] repo-scale finding dropped, "
                              f"path is under an excluded directory: {target}")
                    continue
                result = ScanResult(filename=target)
                by_file[target] = result
                results.append(result)
            # Additive per (file, CWE): never displace a symbolic finding.
            if not any(v.cwe_id == vuln.cwe_id for v in result.vulnerabilities):
                result.vulnerabilities.append(vuln)
        return results

    def _default_repo_root(self, dir_path: Path) -> None:
        """Point the LLM layer's investigation tools at the directory being scanned.

        Only fills in a root that is not already configured, so an explicit
        FRAME_LLM_REPO_ROOT still wins. No-op when the LLM layer is off.
        """
        if not (self.llm_detect or self.llm_triage):
            return
        try:
            from frame.sil.llm_triage import TriageConfig
        except ImportError:
            return
        try:
            if self._llm_config is None:
                self._llm_config = TriageConfig.from_env()
            if not getattr(self._llm_config, "repo_root", ""):
                self._llm_config.repo_root = str(dir_path.resolve())
        except Exception:
            pass   # never let this break a scan

    def _process_check(self, check: VulnerabilityCheck) -> Optional[Vulnerability]:
        """
        Process a vulnerability check, optionally verifying with Frame.

        Returns:
            Vulnerability if confirmed, None otherwise
        """
        witness_str = None

        verified = False
        verification_failed = False
        if self.verify and self.checker:
            # Verify using incorrectness logic
            # Key insight: incorrectness logic proves bugs ARE reachable
            # - SAT (reachable) → definitely a bug (zero false positives)
            # - UNSAT (not reachable) → NOT a bug (filter it out)
            try:
                # Use the appropriate checker method based on vulnerability type
                report = self._verify_check(check)

                if report.reachable:
                    verified = True
                    # Extract witness
                    if report.witness:
                        witness_str = str(report.witness)
                else:
                    # Bug is NOT reachable - this is a false positive, filter it out
                    if self.verbose:
                        print(f"[Scanner] Filtering out unreachable bug: {check.vuln_type.value}")
                    return None

            except Exception as e:
                if self.verbose:
                    print(f"[Scanner] Verification error: {e}")
                # If verification throws an exception, be conservative and report
                verification_failed = True

        # Create vulnerability object
        severity = self.SEVERITY_MAP.get(check.vuln_type, Severity.MEDIUM)
        cwe_id = self.CWE_MAP.get(check.vuln_type)

        # Set confidence based on verification status
        # - verified: highest confidence (formal proof of reachability)
        # - verification error: medium confidence (taint analysis found it, verification had issues)
        # - no verification mode: lower confidence
        if verified:
            confidence = 1.0
        elif verification_failed:
            confidence = 0.7  # Verification had errors, but taint analysis found it
        else:
            confidence = 0.8  # No verification mode

        return Vulnerability(
            type=check.vuln_type,
            severity=severity,
            location=check.location.file,
            line=check.location.line,
            column=check.location.column,
            description=check.description,
            procedure=check.procedure_name,
            source_var=check.source_var,
            source_location=str(check.source_location) if check.source_location else "",
            sink_type=check.sink_type,
            data_flow=check.data_flow_path,
            witness=witness_str,
            confidence=confidence,
            cwe_id=cwe_id,
        )

    def _deduplicate_vulnerabilities(self, vulns: List[Vulnerability]) -> List[Vulnerability]:
        """
        Remove duplicate vulnerability reports.

        Duplicates occur when:
        - Same vulnerability type at same location (line) in same procedure
        - Same CWE at same location (even different vuln types if same underlying issue)
        - A synthetic file-wide pass reports the same CWE on several lines
        - Two analyzers report the same line and CWE under different procedure names

        Priority: Keep the highest severity, most detailed report.
        """
        if not vulns:
            return vulns

        # IDOR/authz findings are PER-ENDPOINT: every route/handler is a distinct
        # finding, so they must not be collapsed by the windowed / one-per-file
        # dedup below (which exists to squash repeated taint-flow reports of the
        # same bug). Pull them out, dedup them per (procedure, selector), re-attach.
        from frame.sil.translator import VulnType as _VT
        idor_vulns = [v for v in vulns if v.type == _VT.IDOR]
        vulns = [v for v in vulns if v.type != _VT.IDOR]

        is_better = _vuln_is_better

        # Phase 1: Group by exact location (line, procedure, vuln_type/cwe)
        exact_seen = {}  # key -> best vulnerability

        for vuln in vulns:
            # Primary key: same line, procedure, and vulnerability type
            primary_key = (vuln.line, vuln.procedure, vuln.type.value)

            # Secondary key: same line, procedure, and CWE (for related vulns)
            secondary_key = (vuln.line, vuln.procedure, vuln.cwe_id) if vuln.cwe_id else None

            # Check if we've seen this vulnerability
            existing = exact_seen.get(primary_key)
            if existing is None and secondary_key:
                existing = exact_seen.get(secondary_key)

            if existing is None:
                # New vulnerability
                exact_seen[primary_key] = vuln
                if secondary_key:
                    exact_seen[secondary_key] = vuln
            elif is_better(vuln, existing):
                exact_seen[primary_key] = vuln
                if secondary_key:
                    exact_seen[secondary_key] = vuln

        # Extract unique from Phase 1
        phase1_vulns = []
        seen_ids = set()

        for vuln in vulns:
            primary_key = (vuln.line, vuln.procedure, vuln.type.value)
            best = exact_seen.get(primary_key)
            if best is not None:
                vuln_id = (best.line, best.column, best.procedure, best.type.value, best.cwe_id)
                if vuln_id not in seen_ids:
                    phase1_vulns.append(best)
                    seen_ids.add(vuln_id)

        # (There is no line-window merge. A 5-line window used to fold
        # same-CWE findings together as "control-flow variants"; measured on
        # 1,500 npm files, 600 OWASP Java and 500 OWASP Python files it merged
        # only distinct call sites -- and it hid a new sink added beside a known
        # one behind a baseline. Phase 1 already merges reports of one line.)
        final_vulns = phase1_vulns

        # Phase 3: a synthetic file-wide pass (`<module-proto-pollution>`,
        # `<cookie-secure>-0`, ...) reports one finding per (file, CWE): it flags
        # every matching line of a file, and its per-line reports are one issue.
        # A real function keeps each distinct sink: a second injectable query added to a
        # function that already has one is a new finding, and five injectable
        # endpoints in one controller are five. (Benchmarks that score one label
        # per file collapse further with `collapse_per_file_cwe`.)
        from frame.sil.fingerprints import normalize_procedure
        deduplicated = _keep_best_per_key(
            final_vulns,
            lambda v: (v.location, normalize_procedure(v.procedure), v.cwe_id)
            + (() if (v.procedure or "").startswith("<") else (v.line,)))
        # Phase 4: two analyzers reporting the same line under different
        # procedure names (`main` and `<interprocedural-analysis>`) are one finding.
        deduplicated = _keep_best_per_key(
            deduplicated, lambda v: (v.location, v.line, v.cwe_id))

        # Re-attach IDOR findings, deduped per endpoint+selector (one per distinct
        # procedure + attacker-controlled selector), not per file.
        idor_seen = {}
        for v in idor_vulns:
            key = (v.location, v.procedure, v.source_var, v.cwe_id)
            existing = idor_seen.get(key)
            if existing is None or is_better(v, existing):
                idor_seen[key] = v
        deduplicated.extend(idor_seen.values())

        return deduplicated

    def _tag_source_evidence(self, vulns: List[Vulnerability], source_code: str) -> None:
        """Mark JS/TS findings whose source is the guessed `req.*` name with no
        web framework in the file or project (`source_evidence`)."""
        if self.language not in ("javascript", "typescript") or not vulns:
            return
        from frame.sil.framework_evidence import has_framework_evidence, source_is_named_request
        guessed = [v for v in vulns if source_is_named_request(v.source_var)]
        if not guessed or has_framework_evidence(source_code):
            return
        project = self._project
        if project is not None:
            cached = getattr(project, "_framework_evidence", None)
            if cached is None:
                cached = False
                for mod in project.index.modules.values():
                    try:
                        if has_framework_evidence(mod.path.read_text(encoding="utf-8", errors="replace")):
                            cached = True
                            break
                    except OSError:
                        continue
                project._framework_evidence = cached
            if cached:
                return
        for v in guessed:
            v.source_evidence = "naming-convention"

    def _filter_by_confidence(self, vulns: List[Vulnerability], source_code: str) -> List[Vulnerability]:
        """
        Filter vulnerabilities by confidence threshold and context.

        1. Apply confidence threshold (default 0.7)
        2. Reduce confidence for detections with safe patterns nearby
        3. Filter out low-confidence results

        Args:
            vulns: List of vulnerabilities to filter
            source_code: Original source code for context analysis

        Returns:
            Filtered list of high-confidence vulnerabilities
        """
        if not vulns:
            return vulns

        MIN_CONFIDENCE = 0.7

        filtered = []
        for vuln in vulns:
            adjusted_confidence = vuln.confidence

            # Check for common "safe" patterns that reduce confidence
            # Pattern: variable is checked before use
            if vuln.type == VulnType.NULL_DEREFERENCE:
                # If there's a NULL check nearby, reduce confidence
                context_start = max(0, vuln.line - 5)
                context_end = min(len(source_code.split('\n')), vuln.line + 2)
                context_lines = source_code.split('\n')[context_start:context_end]
                context = '\n'.join(context_lines)
                if vuln.source_var:
                    if f'if ({vuln.source_var}' in context or f'if({vuln.source_var}' in context:
                        adjusted_confidence *= 0.6
                    if f'{vuln.source_var} != NULL' in context or f'{vuln.source_var} == NULL' in context:
                        adjusted_confidence *= 0.6

            # Update confidence and filter
            vuln.confidence = adjusted_confidence
            if adjusted_confidence >= MIN_CONFIDENCE:
                filtered.append(vuln)

        return filtered

    def _verify_check(self, check: VulnerabilityCheck) -> BugReport:
        """Verify vulnerability check using Frame's incorrectness checker

        Note: Incorrectness logic is designed for memory safety bugs (null deref, UAF, etc.)
        where we can prove reachability of error states. For taint flow vulnerabilities,
        the symbolic execution has already proven that data flows from source to sink,
        so we mark them as verified without additional Z3 checks.
        """
        from frame.checking.incorrectness import BugReport, BugType

        # Taint-based vulnerabilities: already proven through symbolic taint analysis
        # The formula encodes Source * Taint * Sink which would fail SepConj self-composition
        taint_based_vulns = {
            VulnType.SQL_INJECTION,
            VulnType.XSS,
            VulnType.COMMAND_INJECTION,
            VulnType.PATH_TRAVERSAL,
            VulnType.SSRF,
            VulnType.LDAP_INJECTION,
            VulnType.XPATH_INJECTION,
            VulnType.WEAK_HASH,
            VulnType.WEAK_CRYPTOGRAPHY,
            VulnType.INSECURE_RANDOM,
            VulnType.INSECURE_COOKIE,
            VulnType.INSECURE_COOKIE_HTTPONLY,
            VulnType.CSRF,
            VulnType.TRUST_BOUNDARY_VIOLATION,
            VulnType.SENSITIVE_DATA_EXPOSURE,
            VulnType.IDOR,
        }

        if check.vuln_type in taint_based_vulns:
            # For taint flow: symbolic execution already proved the flow exists
            # Mark as reachable (verified)
            return BugReport(
                reachable=True,
                bug_type=BugType.TAINT_FLOW,
                description=f"Taint flow verified by symbolic execution: {check.vuln_type.value}",
                witness=None,
                confidence=1.0
            )

        # Memory safety bugs: use full incorrectness logic
        if check.vuln_type == VulnType.NULL_DEREFERENCE:
            # Incorrectness logic: is `pc * null_deref(p)` satisfiable? The path
            # condition the translator proved p nil under is the precondition; a
            # SAT answer comes with a concrete witness, UNSAT drops the finding.
            from frame.core.ast import And as _And, True_ as _True
            pre = _True()
            for fact in (check.path_condition or []):
                pre = fact if isinstance(pre, _True) else _And(pre, fact)
            return self.checker.check_null_dereference(pre, check.tainted_var)
        elif check.vuln_type == VulnType.USE_AFTER_FREE:
            return self.checker.check_bug_reachability(
                check.formula,
                check.formula
            )
        elif check.vuln_type == VulnType.DOUBLE_FREE:
            return self.checker.check_bug_reachability(
                check.formula,
                check.formula
            )
        else:
            # Unknown type - mark as verified to be safe
            return BugReport(
                reachable=True,
                bug_type=BugType.TAINT_FLOW,
                description=f"Unknown vulnerability type: {check.vuln_type.value}",
                witness=None,
                confidence=0.8
            )


    # Tier 2 (structural / AST-level) detection for hardcoded secrets.
    # Credential-named assignment targets whose value is a literal string.
    # Matched against the SIL (the normalized IR), so one rule covers every
    # language and only real `name = "literal"` assignments are flagged -- never
    # text inside comments or unrelated code.
    _SECRET_NAME_RULES = [
        # (regex on target name, cwe, label)
        (re.compile(r'(?i)(^|[._])(pass(word|wd)?|pwd)([._]|$)'), 'CWE-259', 'Hardcoded password'),
        (re.compile(r'(?i)(crypt|secret|private|signing)[._]?key'), 'CWE-321', 'Hardcoded cryptographic key'),
        (re.compile(r'(?i)(^|[._])(api[._]?key|access[._]?key|secret|token|client[._]?secret|auth[._]?token)([._]|$)'),
         'CWE-798', 'Hardcoded secret'),
    ]
    # An embedded credential inside a value, e.g. a connection string
    # "Server=db;Password=s3cret;". Requires a non-trivial value after '='.
    _CONNSTR_SECRET = re.compile(r'(?i)(password|pwd)\s*=\s*\S{3,}')
    # Values that are obviously not real secrets (placeholders / templates).
    _SECRET_VALUE_PLACEHOLDERS = {
        '', 'password', 'changeme', 'change_me', 'your_password', 'your_password_here',
        'xxx', 'xxxx', 'todo', 'none', 'null', 'example', 'test', 'placeholder',
    }

    # Value-shape gate for the name-based rules (Rule A). The target name only
    # says the variable is *about* a credential; constants such as
    # `SSH_AUTH_PRIVATE_KEY = "ssh-privatekey"` (a secret's field name),
    # `SA_PRIVATE_KEY_NAME = "sa.key"` (a filename) or
    # `EC_PRIVATE_KEY_BLOCK_TYPE = "EC PRIVATE KEY"` (a PEM label) hold no
    # secret. A literal is suppressed only when, in order:
    #   1. it is NOT key material and carries no known credential prefix
    #      (veto: such values are always reported);
    #   2. it has a strict non-secret shape: PEM block-type label, bare PEM
    #      armor line, key/cert filename, filesystem path, or placeholder; or
    #   3. it is identifier-shaped (lowercase words joined by - _ . or
    #      UPPER_SNAKE) AND tied to the target name: the name carries a
    #      descriptor token (`..._ENV`, `...Name`, `...Field`, `...Path`, ...),
    #      or every value token echoes a name token / a concatenation of
    #      adjacent name tokens / a structural word (id, name, field, ...).
    #      A Kubernetes qualified key (`<dns-subdomain>/<name>`, e.g.
    #      "csi.storage.k8s.io/node-expand-secret-name") is judged by its
    #      name part under the same tie-to-name test; or
    #   4. it exactly matches a standard HTTP auth header / scheme name
    #      ("Authorization", "X-Api-Key", "Bearer", ...; case-insensitive,
    #      exact match only) and the target is not password-named -- "cookie"
    #      or "basic" is a plausible weak password.
    # Everything else is reported as before -- human passwords are low
    # entropy by nature ("hunter2pass", "super-secret-key"), so the gate never
    # requires positive evidence of a secret.
    # Literal values arrive with escapes unprocessed (a "\n" in source is the
    # two characters backslash + n), so newline matching accepts both forms.
    _PEM_WITH_BODY = re.compile(
        r'-----BEGIN [A-Z0-9 ]+-----(?:(?!-----END).){0,512}?[A-Za-z0-9+/]{16,}', re.DOTALL)
    _KNOWN_CREDENTIAL = re.compile(
        r'\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]{16}\b'   # AWS access key id
        r'|\bgh[pousr]_[A-Za-z0-9]{36,}'                                 # GitHub token
        r'|\bgithub_pat_[A-Za-z0-9_]{22,}'                               # GitHub fine-grained PAT
        r'|\bglpat-[A-Za-z0-9_-]{20,}'                                   # GitLab PAT
        r'|\bxox[baprs]-[A-Za-z0-9-]{10,}'                               # Slack token
        r'|\bAIza[0-9A-Za-z_-]{35}'                                      # Google API key
        r'|\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}'                       # Stripe secret key
        r'|\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}'  # JWT
    )
    # Credential prefixes at any length: a value carrying one is never
    # suppressed, even when too short to be a full-format token.
    _CREDENTIAL_PREFIX = re.compile(
        r'\b(?:[srp]k_(?:live|test)_|gh[pousr]_|github_pat_|glpat-|xox[baprs]-|SG\.)'
        r'|\b(?:AKIA|ASIA|AIza|eyJ)')
    _HEX_BLOB = re.compile(r'[0-9a-f]{32,}|[0-9A-F]{32,}')
    _TOKEN_CHARS = re.compile(r'[A-Za-z0-9+/=_\-.~]+')
    _STRICT_NONSECRET_SHAPES = [
        # PEM block type label ("EC PRIVATE KEY", "CERTIFICATE REQUEST").
        re.compile(r'(?:[A-Z][A-Z0-9]* )+(?:KEY|CERTIFICATE|REQUEST|CRL|PARAMETERS|PKCS7|CMS|SIGNATURE)'),
        # PEM armor line with no body ("-----BEGIN RSA PRIVATE KEY-----").
        re.compile(r'-----(?:BEGIN|END) [A-Z0-9 ]+-----(?:\s|\\[nr])*'),
        # Key / certificate filename ("sa.key", "tls.crt").
        re.compile(r'(?i)[\w.-]+\.(?:key|pem|crt|cer|csr|der|p8|p12|pfx|jks|keystore|pub|'
                   r'kdbx|asc|gpg)'),
        # Filesystem path ("/etc/kubernetes/pki/sa.key", "./certs", "~/.ssh/id_rsa").
        re.compile(r'(?:~|\.{1,2})?/[\w.\-/]*'),
        # Placeholders ("<your-secret-key>", "********", "xxxx", "$SECRET",
        # "${SECRET}", "$(cat key)").
        re.compile(r'<[^<>]+>|\*+|(?i:x+)|\$[A-Z_][A-Z0-9_]*|\$\{[^}]*\}|\$\(.*\)'),
    ]
    # Identifier-shaped value: lowercase words joined by - _ . , or UPPER_SNAKE.
    _IDENTIFIER_VALUE = re.compile(r'[a-z][a-z0-9]*(?:[-_.][a-z0-9]+)+|[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+')
    # Target-name tokens saying the constant describes/locates a secret.
    # `action` / `permission` name an authorization object ("ABAC action
    # export-certificate-private-key") but only as the LEADING name token,
    # exact and singular (Go `ActionX` / `PermissionX`); elsewhere they say
    # where a credential is used (GITHUB_ACTIONS_TOKEN, DEPLOY_ACTION_TOKEN).
    # `annotation` is the sibling of `label`.
    # Deliberately NOT descriptors: role (DB_ROLE_PASSWORD), event
    # (WEBHOOK_EVENT_SECRET), metric (METRICS_AUTH_TOKEN) -- each commonly
    # names a real credential; scope/route values are not identifier-shaped
    # or are already paths; kind is too generic.
    _NAME_DESCRIPTORS = frozenset({
        'env', 'var', 'name', 'field', 'header', 'label', 'type', 'file', 'path',
        'dir', 'prefix', 'suffix', 'param', 'attr', 'column', 'prop',
        'annotation'})
    _LEADING_DESCRIPTORS = frozenset({'action', 'permission'})
    # Head nouns that make a credential-named variable METADATA about the
    # credential: the last word of a compound name is what it denotes, so
    # `secretKeyAlgorithm = "DESede"` names an algorithm, not a key.
    _METADATA_HEADS = frozenset({
        'algorithm', 'algorithms', 'alg', 'algo', 'cipher', 'transformation',
        'mode', 'length', 'size', 'bits', 'format', 'provider', 'scheme',
        'version', 'iterations', 'spec', 'kind'})
    # Kubernetes qualified key: DNS subdomain (2+ lowercase labels) + '/' +
    # name, e.g. "csi.storage.k8s.io/node-expand-secret-name".
    _QUALIFIED_KEY = re.compile(
        r'[a-z0-9](?:[-a-z0-9]*[a-z0-9])?(?:\.[a-z0-9](?:[-a-z0-9]*[a-z0-9])?)+/(?P<name>[^/]+)')
    # Standard HTTP auth header / auth-scheme names (lowercased; exact match).
    _HTTP_AUTH_NAMES = frozenset({
        'authorization', 'proxy-authorization', 'www-authenticate', 'proxy-authenticate',
        'cookie', 'set-cookie', 'x-api-key', 'x-auth-token', 'x-access-token',
        'x-csrf-token', 'x-xsrf-token', 'bearer', 'basic'})
    _PASSWORD_WORDS = frozenset({'pass', 'password', 'passwd', 'pwd'})
    # Structural words allowed in a value that otherwise echoes the name.
    _STRUCTURAL_WORDS = frozenset({'id', 'name', 'field', 'ref', 'data'})

    @staticmethod
    def _name_tokens(target: str) -> List[str]:
        """Split an identifier on camelCase and separators, lowercased:
        'SSHAuthPrivateKey' -> ['ssh', 'auth', 'private', 'key']."""
        t = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1_\2', target)
        t = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', t)
        return [x for x in re.split(r'[^A-Za-z0-9]+', t.lower()) if x]

    @staticmethod
    def _shannon_entropy(value: str) -> float:
        n = len(value)
        return -sum(c / n * math.log2(c / n) for c in Counter(value).values())

    @classmethod
    def _is_key_material(cls, value: str) -> bool:
        """Unambiguous secret: a PEM block with a base64 body, a known
        credential format, or a high-entropy token (16+ non-whitespace token
        chars; 32+ hex, or upper + lower + digit with Shannon entropy >= 3.5
        bits/char)."""
        if cls._PEM_WITH_BODY.search(value) or cls._KNOWN_CREDENTIAL.search(value):
            return True
        if len(value) < 16 or not cls._TOKEN_CHARS.fullmatch(value):
            return False
        if cls._HEX_BLOB.fullmatch(value):
            return True
        classes = (any(c.islower() for c in value) + any(c.isupper() for c in value)
                   + any(c.isdigit() for c in value))
        return classes == 3 and cls._shannon_entropy(value) >= 3.5

    _REGEX_LITERAL = re.compile(r"/(?=.*[\^$\\\[\](){}*+?|]).+/[dgimsuyv]*")

    @classmethod
    def _is_nonsecret_value(cls, target: str, value: str) -> bool:
        """True when the literal bound to credential-named `target` names,
        labels or locates a secret rather than being one (see the rule
        comment above). Key material and credential prefixes always veto."""
        if cls._is_key_material(value) or cls._CREDENTIAL_PREFIX.search(value):
            return False
        v = value.strip()
        if any(p.fullmatch(v) for p in cls._STRICT_NONSECRET_SHAPES):
            return True
        if cls._REGEX_LITERAL.fullmatch(v):      # `const PASS_RE = /^.{1,20}$/` validates a password
            return True
        name = cls._name_tokens(target)
        if name and name[-1] in cls._METADATA_HEADS:
            return True
        if v.lower() in cls._HTTP_AUTH_NAMES:
            return not any(tok in cls._PASSWORD_WORDS for tok in name)
        qualified = cls._QUALIFIED_KEY.fullmatch(v)
        if qualified:
            v = qualified.group('name')
        if not cls._IDENTIFIER_VALUE.fullmatch(v):
            return False
        if name and name[0] in cls._LEADING_DESCRIPTORS:
            return True
        if any(tok.rstrip('s') in cls._NAME_DESCRIPTORS for tok in name):
            return True
        grams = {''.join(name[i:j]) for i in range(len(name)) for j in range(i + 1, len(name) + 1)}
        vals = [x for x in re.split(r'[-_.]', v.lower()) if x]
        return (any(x in grams for x in vals)
                and all(x in grams or x in cls._STRUCTURAL_WORDS for x in vals))

    def _scan_hardening(self, source_code: str, filename: str) -> List[Vulnerability]:
        """Debug mode and explicit insecure cookie flags, read from the syntax tree
        (`hardening.py`); Python and JS/TS."""
        from frame.sil import hardening
        if self.language == "python":
            scan, lang = hardening.scan_python, "python"
        elif self.language in ("javascript", "typescript"):
            scan, lang = hardening.scan_javascript, self.language
        else:
            return []
        try:
            parser = self._get_frontend(lang).parser
            root = parser.parse(source_code.encode("utf-8")).root_node
            found = scan(source_code, root, filename)
        except Exception:
            return []
        types = {"debug": VulnType.DEBUG_ENABLED, "cookie_secure": VulnType.INSECURE_COOKIE,
                 "cookie_httponly": VulnType.INSECURE_COOKIE_HTTPONLY}
        out = []
        for f in found:
            vt = types[f.kind]
            out.append(Vulnerability(
                type=vt, severity=self.SEVERITY_MAP.get(vt, Severity.MEDIUM), location=filename,
                line=f.line, column=f.column, description=f.description, procedure="<module>",
                sink_type=f.kind, confidence=0.95, cwe_id=self.CWE_MAP.get(vt), category=hardening.CATEGORY))
        return out

    def _scan_literals(self, program: Program, filename: str) -> List[Vulnerability]:
        """Tier-2 structural scan over the SIL for hardcoded secrets (CWE-798/
        259/321): a credential-named assignment target bound to a literal string.

        This is the principled, AST/IR-based replacement for the per-language
        `hardcoded_secret` regexes -- language-agnostic and syntax-aware.
        """
        vulns: List[Vulnerability] = []
        for proc in program.procedures.values():
            for node in proc.cfg_iter():
                for instr in node.instrs:
                    if not isinstance(instr, Assign):
                        continue
                    if not isinstance(instr.exp, ExpConst) or not isinstance(instr.exp.value, str):
                        continue

                    target = str(instr.id)
                    value = instr.exp.value
                    if len(value) < 4 or value.strip().lower() in self._SECRET_VALUE_PLACEHOLDERS:
                        continue
                    # Skip template / interpolation / env placeholders.
                    if '${' in value or '{{' in value or value.startswith('%'):
                        continue

                    cwe = label = None
                    # Rule A: credential-named target bound to a literal whose
                    # value is not merely a name/label/filename for a secret.
                    if not self._is_nonsecret_value(target, value):
                        for pattern, c, lbl in self._SECRET_NAME_RULES:
                            if pattern.search(target):
                                cwe, label = c, lbl
                                break
                    # Rule B: value embeds a credential (e.g. connection string
                    # "...;Password=secret;..."), regardless of the target name.
                    if cwe is None and self._CONNSTR_SECRET.search(value):
                        cwe, label = 'CWE-798', 'Hardcoded credential in connection string'

                    if cwe is not None:
                        loc = instr.loc
                        vulns.append(Vulnerability(
                            type=VulnType.HARDCODED_SECRET,
                            severity=self.SEVERITY_MAP.get(VulnType.HARDCODED_SECRET, Severity.HIGH),
                            location=filename,
                            line=loc.line if loc else 0,
                            column=loc.column if loc else 0,
                            description=f"{label}: '{target}' is assigned a literal value",
                            procedure=proc.name,
                            sink_type="hardcoded_secret",
                            confidence=0.9,
                            cwe_id=cwe,
                        ))
        return vulns

    def _analyze_memory_safety(self, source_code: str, filename: str) -> List[Vulnerability]:
        """
        Analyze C/C++ source code for memory safety vulnerabilities.

        Uses THREE analyzers for comprehensive coverage:
        1. InterproceduralAnalyzer - Full inter-procedural analysis for class lifecycles
        2. SLMemoryAnalyzer - Separation logic-based analysis for precise heap tracking
        3. MemorySafetyAnalyzer - Pattern-based analysis for additional coverage

        The inter-procedural analyzer tracks member variables across class methods
        to detect double-free and UAF that span constructor/destructor boundaries.

        Args:
            source_code: Source code string
            filename: Filename for reporting

        Returns:
            List of memory safety vulnerabilities
        """
        from frame.sil.analyzers.memory_safety import analyze_c_memory_safety
        from frame.sil.analyzers.sl_memory_analyzer import analyze_with_separation_logic
        from frame.sil.analyzers.interprocedural_analyzer import analyze_interprocedural

        vulnerabilities = []
        seen_locations = set()  # (line, vuln_type) to deduplicate

        # Analyze ALL files - combined files contain vulnerable code paths
        # and must be analyzed for proper vulnerability detection

        # First, run inter-procedural analyzer for class lifecycle analysis
        try:
            ipa_vulns = analyze_interprocedural(source_code, filename, verbose=self.verbose)

            for mem_vuln in ipa_vulns:
                key = (mem_vuln.location.line, mem_vuln.vuln_type.value)
                if key in seen_locations:
                    continue
                seen_locations.add(key)

                severity = self.SEVERITY_MAP.get(mem_vuln.vuln_type, Severity.MEDIUM)

                vuln = Vulnerability(
                    type=mem_vuln.vuln_type,
                    severity=severity,
                    location=filename,
                    line=mem_vuln.location.line,
                    column=mem_vuln.location.column,
                    description=mem_vuln.description,
                    procedure="<interprocedural-analysis>",
                    source_var=mem_vuln.var_name,
                    source_location=str(mem_vuln.alloc_location.line) if mem_vuln.alloc_location else "",
                    sink_type=mem_vuln.vuln_type.value,
                    data_flow=[],
                    witness=None,
                    confidence=mem_vuln.confidence,
                    cwe_id=mem_vuln.cwe_id,
                )
                vulnerabilities.append(vuln)

        except Exception as e:
            if self.verbose:
                print(f"[Scanner] Inter-procedural analysis error: {e}")
                import traceback
                traceback.print_exc()

        # Run PATH-SENSITIVE analysis using Frame's SL solver
        try:
            from frame.sil.analyzers.path_sensitive_analyzer import analyze_path_sensitive

            ps_vulns = analyze_path_sensitive(source_code, filename, verbose=self.verbose)

            for ps_vuln in ps_vulns:
                key = (ps_vuln.location.line, ps_vuln.cwe_id)
                if key in seen_locations:
                    continue
                seen_locations.add(key)

                severity = self.SEVERITY_MAP.get(ps_vuln.vuln_type, Severity.MEDIUM)

                vuln = Vulnerability(
                    type=ps_vuln.vuln_type,
                    severity=severity,
                    location=filename,
                    line=ps_vuln.location.line,
                    column=ps_vuln.location.column,
                    description=ps_vuln.description,
                    procedure="<path-sensitive>",
                    source_var=ps_vuln.var_name,
                    source_location=str(ps_vuln.alloc_loc.line) if ps_vuln.alloc_loc else "",
                    sink_type="sl_verified",
                    data_flow=[],
                    witness=ps_vuln.sl_check,
                    confidence=ps_vuln.confidence,
                    cwe_id=ps_vuln.cwe_id,
                )
                vulnerabilities.append(vuln)

            if self.verbose and ps_vulns:
                print(f"[Scanner] Path-sensitive analysis found {len(ps_vulns)} issues")

        except Exception as e:
            if self.verbose:
                print(f"[Scanner] Path-sensitive analysis error: {e}")
                import traceback
                traceback.print_exc()

        # Run separation logic-based analyzer (more precise)
        try:
            sl_vulns = analyze_with_separation_logic(source_code, filename, verbose=self.verbose)

            for mem_vuln in sl_vulns:
                key = (mem_vuln.location.line, mem_vuln.vuln_type.value)
                if key in seen_locations:
                    continue
                seen_locations.add(key)

                severity = self.SEVERITY_MAP.get(mem_vuln.vuln_type, Severity.MEDIUM)

                vuln = Vulnerability(
                    type=mem_vuln.vuln_type,
                    severity=severity,
                    location=filename,
                    line=mem_vuln.location.line,
                    column=mem_vuln.location.column,
                    description=mem_vuln.description,
                    procedure="<sl-memory-safety>",
                    source_var=mem_vuln.var_name,
                    source_location=str(mem_vuln.alloc_loc.line) if mem_vuln.alloc_loc else "",
                    sink_type=mem_vuln.vuln_type.value,
                    data_flow=[],
                    witness=None,
                    confidence=mem_vuln.confidence,
                    cwe_id=mem_vuln.cwe_id,
                )
                vulnerabilities.append(vuln)

        except Exception as e:
            if self.verbose:
                print(f"[Scanner] SL memory analysis error: {e}")

        # Second, run traditional pattern-based analyzer for additional coverage
        try:
            mem_vulns = analyze_c_memory_safety(source_code, filename, verbose=self.verbose)

            for mem_vuln in mem_vulns:
                key = (mem_vuln.location.line, mem_vuln.vuln_type.value)
                if key in seen_locations:
                    continue  # Already found by SL analyzer
                seen_locations.add(key)

                severity = self.SEVERITY_MAP.get(mem_vuln.vuln_type, Severity.MEDIUM)

                vuln = Vulnerability(
                    type=mem_vuln.vuln_type,
                    severity=severity,
                    location=filename,
                    line=mem_vuln.location.line,
                    column=mem_vuln.location.column,
                    description=mem_vuln.description,
                    procedure="<memory-safety>",
                    source_var=mem_vuln.var_name,
                    source_location=str(mem_vuln.alloc_location.line) if mem_vuln.alloc_location else "",
                    sink_type=mem_vuln.vuln_type.value,
                    data_flow=[],
                    witness=None,
                    confidence=mem_vuln.confidence,
                    cwe_id=mem_vuln.cwe_id,
                )
                vulnerabilities.append(vuln)

        except Exception as e:
            if self.verbose:
                print(f"[Scanner] Memory safety analysis error: {e}")
                import traceback
                traceback.print_exc()

        # Code quality and resource leak analyzers are available but disabled
        # to maintain high precision. They can be enabled via verbose mode or
        # when precision is less critical than coverage.
        #
        # Available analyzers (in frame/sil/analyzers/):
        # - code_quality_analyzer.py: Logic errors, dead code, unchecked returns
        # - resource_leak_analyzer.py: File handle and socket leaks
        #
        # To enable, uncomment the blocks below.

        return vulnerabilities

    def _analyze_csharp_interprocedural(self, source_code: str, filename: str) -> List[Vulnerability]:
        """
        Analyze C# source code for cross-method taint vulnerabilities.

        Uses interprocedural taint analysis to track user input from ASP.NET
        controller actions through helper methods to dangerous sinks.

        Args:
            source_code: Source code string
            filename: Filename for reporting

        Returns:
            List of taint flow vulnerabilities
        """
        try:
            from frame.sil.analyzers.csharp_interprocedural_taint import analyze_csharp_taint
        except ImportError:
            if self.verbose:
                print("[Scanner] C# interprocedural taint analyzer not available")
            return []

        vulnerabilities = []
        seen_locations = set()

        try:
            ipa_vulns = analyze_csharp_taint(source_code, filename, verbose=self.verbose)

            for vuln_info in ipa_vulns:
                location = vuln_info.get('location')
                if not location:
                    continue

                key = (location.line, vuln_info.get('sink_kind', ''))
                if key in seen_locations:
                    continue
                seen_locations.add(key)

                # Map sink kind to vulnerability type
                sink_kind = vuln_info.get('sink_kind', '')
                vuln_type = self._map_sink_to_vuln_type(sink_kind)
                cwe_id = self._get_cwe_for_sink(sink_kind)

                vuln = Vulnerability(
                    type=vuln_type,
                    severity=Severity.HIGH,
                    location=filename,
                    line=location.line,
                    column=location.column,
                    description=vuln_info.get('description', f"Cross-method taint flow to {sink_kind}"),
                    procedure=vuln_info.get('caller', '<unknown>'),
                    source_var=vuln_info.get('argument', ''),
                    source_location=vuln_info.get('caller', ''),
                    sink_type=sink_kind,
                    data_flow=[vuln_info.get('caller', ''), vuln_info.get('callee', '')],
                    witness=None,
                    confidence=0.85,
                    cwe_id=cwe_id,
                )
                vulnerabilities.append(vuln)

        except Exception as e:
            if self.verbose:
                print(f"[Scanner] C# interprocedural analysis error: {e}")
                import traceback
                traceback.print_exc()

        return vulnerabilities

    def _map_sink_to_vuln_type(self, sink_kind: str) -> VulnType:
        """Map sink kind to VulnType."""
        sink_map = {
            'sql_query': VulnType.SQL_INJECTION,
            'command_exec': VulnType.COMMAND_INJECTION,
            'file_path': VulnType.PATH_TRAVERSAL,
            'deserialization': VulnType.DESERIALIZATION,
            'xxe': VulnType.XXE,
            'ssrf': VulnType.SSRF,
            'code_injection': VulnType.CODE_INJECTION,
            'ldap_query': VulnType.LDAP_INJECTION,
            'xpath_query': VulnType.XPATH_INJECTION,
            'log_injection': VulnType.LOG_INJECTION,
        }
        return sink_map.get(sink_kind, VulnType.TAINT_FLOW)

    def _get_cwe_for_sink(self, sink_kind: str) -> str:
        """Get CWE ID for sink kind."""
        cwe_map = {
            'sql_query': 'CWE-89',
            'command_exec': 'CWE-78',
            'file_path': 'CWE-22',
            'deserialization': 'CWE-502',
            'xxe': 'CWE-611',
            'ssrf': 'CWE-918',
            'code_injection': 'CWE-94',
            'ldap_query': 'CWE-90',
            'xpath_query': 'CWE-643',
            'log_injection': 'CWE-117',
        }
        return cwe_map.get(sink_kind, 'CWE-20')


def scan_code(source_code: str, language: str = "python", filename: str = "<unknown>") -> ScanResult:
    """
    Convenience function to scan source code.

    Args:
        source_code: Source code string
        language: Programming language
        filename: Filename for reporting

    Returns:
        ScanResult with vulnerabilities found
    """
    scanner = FrameScanner(language=language)
    return scanner.scan(source_code, filename)


def scan_file(filepath: str, language: str = None) -> ScanResult:
    """
    Convenience function to scan a file.

    Args:
        filepath: Path to source file
        language: Programming language (auto-detected if not specified)

    Returns:
        ScanResult with vulnerabilities found
    """
    # Auto-detect language from extension (FrameScanner.scan_file refines it
    # from the source, e.g. a C++ `.h`)
    if language is None:
        language = language_for_file(filepath, default="python")

    scanner = FrameScanner(language=language)
    return scanner.scan_file(filepath)
