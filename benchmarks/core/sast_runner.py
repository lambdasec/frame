"""Base SAST benchmark runner - integrates with Frame's security scanner"""

import os
import sys
import time
import json
from pathlib import Path
from typing import List, Optional, Dict, Tuple

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from benchmarks.core.sast_result import (
    SASTBenchmarkResult,
    ExpectedVulnerability,
    DetectedVulnerability,
    VulnerabilityCategory,
)


# CWE to category mapping
CWE_TO_CATEGORY = {
    # Injection
    "89": VulnerabilityCategory.SQL_INJECTION,
    "79": VulnerabilityCategory.XSS,
    "78": VulnerabilityCategory.COMMAND_INJECTION,
    "22": VulnerabilityCategory.PATH_TRAVERSAL,
    "94": VulnerabilityCategory.CODE_INJECTION,
    "95": VulnerabilityCategory.CODE_INJECTION,  # Eval injection
    "90": VulnerabilityCategory.LDAP_INJECTION,
    "643": VulnerabilityCategory.XPATH_INJECTION,
    "611": VulnerabilityCategory.XXE,
    "918": VulnerabilityCategory.SSRF,
    "502": VulnerabilityCategory.DESERIALIZATION,

    # Crypto
    "327": VulnerabilityCategory.WEAK_CRYPTO,
    "328": VulnerabilityCategory.WEAK_HASH,
    "330": VulnerabilityCategory.WEAK_CRYPTO,  # Weak random
    "798": VulnerabilityCategory.HARDCODED_SECRET,

    # Memory safety (C/C++)
    "120": VulnerabilityCategory.BUFFER_OVERFLOW,
    "121": VulnerabilityCategory.BUFFER_OVERFLOW,  # Stack overflow
    "122": VulnerabilityCategory.BUFFER_OVERFLOW,  # Heap overflow
    "125": VulnerabilityCategory.BUFFER_OVERFLOW,  # Out of bounds read
    "787": VulnerabilityCategory.BUFFER_OVERFLOW,  # Out of bounds write
    "416": VulnerabilityCategory.USE_AFTER_FREE,
    "476": VulnerabilityCategory.NULL_DEREF,
    "190": VulnerabilityCategory.INTEGER_OVERFLOW,
    "191": VulnerabilityCategory.INTEGER_OVERFLOW,  # Underflow
    "134": VulnerabilityCategory.FORMAT_STRING,
    "362": VulnerabilityCategory.RACE_CONDITION,

    # Auth
    "287": VulnerabilityCategory.BROKEN_AUTH,
    "639": VulnerabilityCategory.IDOR,
}


def cwe_to_category(cwe_id: str) -> VulnerabilityCategory:
    """Convert CWE ID to vulnerability category"""
    # Normalize: "CWE-89" -> "89"
    normalized = cwe_id.upper().replace("CWE-", "").replace("CWE", "").strip()
    return CWE_TO_CATEGORY.get(normalized, VulnerabilityCategory.OTHER)


def run_frame_scanner(
    filepath: str,
    language: str = "python",
    timeout_ms: int = 30000,
    verify: bool = True
) -> Tuple[List[DetectedVulnerability], Optional[str]]:
    """
    Run Frame's security scanner on a file.

    Returns:
        Tuple of (detected vulnerabilities, error message or None)
    """
    try:
        from frame.sil import FrameScanner

        scanner = FrameScanner(language=language, verify=verify)
        result = scanner.scan_file(filepath)

        detected = []
        for vuln in result.vulnerabilities:
            detected.append(DetectedVulnerability(
                vuln_type=vuln.type,
                cwe_id=vuln.cwe_id,
                line_number=vuln.line if hasattr(vuln, 'line') else None,
                function_name=vuln.procedure if hasattr(vuln, 'procedure') else None,
                confidence=vuln.confidence if hasattr(vuln, 'confidence') else None,
                description=vuln.description,
            ))

        return detected, None

    except ImportError as e:
        return [], f"Frame scanner not available: {e}"
    except Exception as e:
        return [], f"Scanner error: {e}"


def run_sast_benchmark(
    filepath: str,
    expected_vulns: List[ExpectedVulnerability],
    suite: str,
    division: str,
    language: str,
    timeout_ms: int = 30000,
) -> SASTBenchmarkResult:
    """
    Run a single SAST benchmark test case.

    Args:
        filepath: Path to the source file to scan
        expected_vulns: List of expected vulnerabilities (ground truth)
        suite: Benchmark suite name (e.g., 'owasp_python')
        division: Specific division/category
        language: Programming language
        timeout_ms: Scanner timeout

    Returns:
        SASTBenchmarkResult with metrics computed
    """
    filename = os.path.basename(filepath)
    start_time = time.time()

    detected, error = run_frame_scanner(filepath, language, timeout_ms)

    elapsed_ms = (time.time() - start_time) * 1000

    result = SASTBenchmarkResult(
        filename=filename,
        suite=suite,
        division=division,
        language=language,
        expected_vulns=expected_vulns,
        detected_vulns=detected,
        time_ms=elapsed_ms,
        error=error,
    )

    # Compute TP/FP/FN
    result.compute_metrics(match_by_cwe=True, match_by_line=False)

    return result


def parse_owasp_expected(content: str, filename: str) -> List[ExpectedVulnerability]:
    """
    Parse expected vulnerabilities from OWASP Benchmark file.

    OWASP Benchmark uses comments or annotations to mark vulnerabilities.
    Format varies by language but typically includes CWE and test case metadata.
    """
    expected = []

    # Look for BenchmarkTest metadata in comments
    # Format: @BenchmarkTest(..., cwe=89, ...)
    import re

    # Java/Python: Look for @BenchmarkTest or similar annotations
    cwe_pattern = r'(?:cwe|CWE)[=:\s]*(\d+)'
    vuln_pattern = r'(?:vulnerability|vuln|VULNERABILITY)[=:\s]*["\']?(\w+)["\']?'

    for match in re.finditer(cwe_pattern, content):
        cwe_id = match.group(1)
        expected.append(ExpectedVulnerability(
            cwe_id=f"CWE-{cwe_id}",
            category=cwe_to_category(cwe_id),
        ))

    # Also check filename for test type
    # OWASP naming: BenchmarkTest00001.java, BenchmarkTest00001.py
    # With accompanying expectedresults CSV

    return expected


def parse_juliet_expected(filepath: str, content: str) -> List[ExpectedVulnerability]:
    """
    Parse expected vulnerabilities from Juliet test case.

    Juliet uses directory structure and filename conventions:
    - CWE###_<name>/s01/CWE###_..._bad.c (vulnerable)
    - CWE###_<name>/s01/CWE###_..._good.c (not vulnerable)
    """
    import re

    expected = []
    filename = os.path.basename(filepath)
    dirname = os.path.dirname(filepath)

    # Extract CWE from path (e.g., CWE121_Stack_Based_Buffer_Overflow)
    cwe_match = re.search(r'CWE(\d+)', filepath)
    if cwe_match:
        cwe_id = cwe_match.group(1)

        # Only 'bad' files have vulnerabilities
        is_bad = '_bad' in filename.lower() or filename.endswith('_bad.c') or filename.endswith('_bad.cpp')

        if is_bad:
            expected.append(ExpectedVulnerability(
                cwe_id=f"CWE-{cwe_id}",
                category=cwe_to_category(cwe_id),
            ))

    return expected


def parse_secbench_expected(filepath: str, manifest: Optional[Dict] = None) -> List[ExpectedVulnerability]:
    """
    Parse expected vulnerabilities from SecBench.js test case.

    SecBench.js provides a manifest with vulnerability metadata per package/version.
    """
    expected = []

    if manifest:
        # Look up vulnerability info from manifest
        package_name = os.path.basename(os.path.dirname(filepath))
        if package_name in manifest:
            for vuln_info in manifest[package_name].get('vulnerabilities', []):
                cwe_id = vuln_info.get('cwe', 'unknown')
                expected.append(ExpectedVulnerability(
                    cwe_id=cwe_id,
                    category=cwe_to_category(cwe_id.replace('CWE-', '')),
                    description=vuln_info.get('description'),
                ))

    return expected


def discover_test_files(
    directory: str,
    extensions: List[str],
    pattern: Optional[str] = None
) -> List[str]:
    """
    Discover test files in a directory.

    Args:
        directory: Root directory to search
        extensions: File extensions to include (e.g., ['.py', '.java'])
        pattern: Optional glob pattern filter

    Returns:
        List of file paths
    """
    files = []
    for root, dirs, filenames in os.walk(directory):
        for filename in filenames:
            if any(filename.endswith(ext) for ext in extensions):
                if pattern is None or pattern in filename:
                    files.append(os.path.join(root, filename))
    return sorted(files)
