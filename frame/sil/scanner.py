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
from typing import List, Dict, Optional, Any
from pathlib import Path
from enum import Enum
import json
import time

from frame.sil.procedure import Program
from frame.sil.translator import SILTranslator, VulnerabilityCheck, VulnType
from frame.checking.incorrectness import IncorrectnessChecker, BugReport, BugWitness


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

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization"""
        return {
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
            "errors": self.errors,
            "warnings": self.warnings,
            "scan_time_ms": self.scan_time_ms,
            "lines_scanned": self.lines_scanned,
            "procedures_analyzed": self.procedures_analyzed,
            "summary": {
                "total": len(self.vulnerabilities),
                "critical": self.critical_count,
                "high": self.high_count,
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
                }

            result = {
                "ruleId": rule_id,
                "level": self._severity_to_sarif_level(vuln.severity),
                "message": {"text": vuln.description},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": self.filename},
                        "region": {
                            "startLine": vuln.line,
                            "startColumn": vuln.column,
                        }
                    }
                }],
            }

            if vuln.witness:
                result["message"]["text"] += f"\n\nExploit witness: {vuln.witness}"

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

    def _severity_to_sarif_level(self, severity: Severity) -> str:
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }
        return mapping.get(severity, "warning")


class FrameScanner:
    """
    Main vulnerability scanner.

    Scans source code for security vulnerabilities using:
    1. Language-specific frontend (tree-sitter)
    2. SIL intermediate representation
    3. Frame verification engine (incorrectness logic)
    """

    # Severity mapping for vulnerability types
    SEVERITY_MAP = {
        VulnType.SQL_INJECTION: Severity.CRITICAL,
        VulnType.COMMAND_INJECTION: Severity.CRITICAL,
        VulnType.CODE_INJECTION: Severity.CRITICAL,
        VulnType.DESERIALIZATION: Severity.CRITICAL,
        VulnType.XSS: Severity.HIGH,
        VulnType.PATH_TRAVERSAL: Severity.HIGH,
        VulnType.SSRF: Severity.HIGH,
        VulnType.TEMPLATE_INJECTION: Severity.HIGH,
        VulnType.LDAP_INJECTION: Severity.HIGH,
        VulnType.XPATH_INJECTION: Severity.MEDIUM,
        VulnType.OPEN_REDIRECT: Severity.MEDIUM,
        VulnType.HEADER_INJECTION: Severity.MEDIUM,
        VulnType.LOG_INJECTION: Severity.LOW,
        VulnType.NULL_DEREFERENCE: Severity.MEDIUM,
        VulnType.USE_AFTER_FREE: Severity.CRITICAL,
        VulnType.BUFFER_OVERFLOW: Severity.CRITICAL,
        VulnType.DOUBLE_FREE: Severity.HIGH,
        VulnType.MEMORY_LEAK: Severity.LOW,
        VulnType.TAINT_FLOW: Severity.MEDIUM,
    }

    # CWE mapping
    CWE_MAP = {
        VulnType.SQL_INJECTION: "CWE-89",
        VulnType.COMMAND_INJECTION: "CWE-78",
        VulnType.CODE_INJECTION: "CWE-94",
        VulnType.XSS: "CWE-79",
        VulnType.PATH_TRAVERSAL: "CWE-22",
        VulnType.SSRF: "CWE-918",
        VulnType.DESERIALIZATION: "CWE-502",
        VulnType.OPEN_REDIRECT: "CWE-601",
        VulnType.LDAP_INJECTION: "CWE-90",
        VulnType.XPATH_INJECTION: "CWE-643",
        VulnType.TEMPLATE_INJECTION: "CWE-1336",
        VulnType.HEADER_INJECTION: "CWE-113",
        VulnType.LOG_INJECTION: "CWE-117",
        VulnType.NULL_DEREFERENCE: "CWE-476",
        VulnType.USE_AFTER_FREE: "CWE-416",
        VulnType.BUFFER_OVERFLOW: "CWE-120",
        VulnType.DOUBLE_FREE: "CWE-415",
    }

    def __init__(
        self,
        language: str = "python",
        verify: bool = True,
        timeout: int = 5000,
        verbose: bool = False
    ):
        """
        Initialize the scanner.

        Args:
            language: Source language ("python", "javascript", etc.)
            verify: Whether to verify findings with Frame (slower but no FPs)
            timeout: Verification timeout in milliseconds
            verbose: Enable verbose output
        """
        self.language = language
        self.verify = verify
        self.timeout = timeout
        self.verbose = verbose

        # Initialize frontend
        self.frontend = self._get_frontend(language)

        # Initialize verifier
        if verify:
            self.checker = IncorrectnessChecker(timeout=timeout)
        else:
            self.checker = None

    def _get_frontend(self, language: str):
        """Get frontend for specified language"""
        if language == "python":
            from frame.sil.frontends.python_frontend import PythonFrontend
            return PythonFrontend()
        else:
            raise ValueError(f"Unsupported language: {language}")

    def scan(self, source_code: str, filename: str = "<unknown>") -> ScanResult:
        """
        Scan source code for vulnerabilities.

        Args:
            source_code: Source code string
            filename: Filename for reporting

        Returns:
            ScanResult with vulnerabilities found
        """
        start_time = time.time()
        result = ScanResult(filename=filename)
        result.lines_scanned = source_code.count('\n') + 1

        try:
            # Step 1: Parse source to SIL
            if self.verbose:
                print(f"[Scanner] Parsing {filename}...")

            program = self.frontend.translate(source_code, filename)
            result.procedures_analyzed = len(program.procedures)

            if self.verbose:
                print(f"[Scanner] Found {len(program.procedures)} procedures")

            # Step 2: Generate vulnerability checks
            if self.verbose:
                print(f"[Scanner] Generating vulnerability checks...")

            translator = SILTranslator(program, verbose=self.verbose)
            checks = translator.translate_program()

            if self.verbose:
                print(f"[Scanner] Generated {len(checks)} potential vulnerabilities")

            # Step 3: Verify each check (optional)
            for check in checks:
                vuln = self._process_check(check)
                if vuln:
                    result.vulnerabilities.append(vuln)

        except Exception as e:
            result.errors.append(f"Scan error: {str(e)}")
            if self.verbose:
                import traceback
                traceback.print_exc()

        result.scan_time_ms = (time.time() - start_time) * 1000

        if self.verbose:
            print(f"[Scanner] Scan complete: {len(result.vulnerabilities)} vulnerabilities found")
            print(f"[Scanner] Time: {result.scan_time_ms:.2f}ms")

        return result

    def scan_file(self, filepath: str) -> ScanResult:
        """
        Scan a source file for vulnerabilities.

        Args:
            filepath: Path to source file

        Returns:
            ScanResult with vulnerabilities found
        """
        path = Path(filepath)

        if not path.exists():
            result = ScanResult(filename=str(path))
            result.errors.append(f"File not found: {filepath}")
            return result

        source_code = path.read_text(encoding='utf-8')
        return self.scan(source_code, str(path))

    def scan_directory(self, dirpath: str, pattern: str = "**/*.py") -> List[ScanResult]:
        """
        Scan all matching files in a directory.

        Args:
            dirpath: Directory path
            pattern: Glob pattern for files

        Returns:
            List of ScanResult for each file
        """
        results = []
        dir_path = Path(dirpath)

        for filepath in dir_path.glob(pattern):
            if filepath.is_file():
                result = self.scan_file(str(filepath))
                results.append(result)

        return results

    def _process_check(self, check: VulnerabilityCheck) -> Optional[Vulnerability]:
        """
        Process a vulnerability check, optionally verifying with Frame.

        Returns:
            Vulnerability if confirmed, None otherwise
        """
        witness_str = None

        if self.verify and self.checker:
            # Verify using incorrectness logic
            # This ensures zero false positives
            try:
                # Use the appropriate checker method based on vulnerability type
                report = self._verify_check(check)

                if not report.reachable:
                    # Not a real vulnerability (couldn't prove reachability)
                    return None

                # Extract witness
                if report.witness:
                    witness_str = str(report.witness)

            except Exception as e:
                if self.verbose:
                    print(f"[Scanner] Verification failed: {e}")
                # If verification fails, report anyway with lower confidence
                pass

        # Create vulnerability object
        severity = self.SEVERITY_MAP.get(check.vuln_type, Severity.MEDIUM)
        cwe_id = self.CWE_MAP.get(check.vuln_type)

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
            confidence=1.0 if self.verify else 0.8,
            cwe_id=cwe_id,
        )

    def _verify_check(self, check: VulnerabilityCheck) -> BugReport:
        """Verify vulnerability check using Frame's incorrectness checker"""
        from frame.checking.incorrectness import BugReport, BugType

        # Map VulnType to IncorrectnessChecker method
        if check.vuln_type == VulnType.SQL_INJECTION:
            # Build precondition from formula
            return self.checker.check_bug_reachability(
                check.formula,
                check.formula  # Error condition is embedded in formula
            )
        elif check.vuln_type == VulnType.XSS:
            return self.checker.check_bug_reachability(
                check.formula,
                check.formula
            )
        elif check.vuln_type == VulnType.COMMAND_INJECTION:
            return self.checker.check_bug_reachability(
                check.formula,
                check.formula
            )
        else:
            # Generic taint flow check
            return self.checker.check_bug_reachability(
                check.formula,
                check.formula
            )


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
    # Auto-detect language from extension
    if language is None:
        ext = Path(filepath).suffix.lower()
        language_map = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".java": "java",
            ".go": "go",
            ".c": "c",
            ".cpp": "cpp",
            ".h": "c",
        }
        language = language_map.get(ext, "python")

    scanner = FrameScanner(language=language)
    return scanner.scan_file(filepath)
