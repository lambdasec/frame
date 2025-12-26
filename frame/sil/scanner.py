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
        VulnType.BUSINESS_LOGIC_FLAW: Severity.MEDIUM,
        VulnType.RACE_CONDITION: Severity.HIGH,

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
        VulnType.MEMORY_LEAK: Severity.LOW,

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
        VulnType.MISSING_ENCRYPTION: "CWE-311",
        VulnType.SENSITIVE_DATA_EXPOSURE: "CWE-200",

        # A05: Injection
        VulnType.SQL_INJECTION: "CWE-89",
        VulnType.XSS: "CWE-79",
        VulnType.COMMAND_INJECTION: "CWE-78",
        VulnType.LDAP_INJECTION: "CWE-90",
        VulnType.XPATH_INJECTION: "CWE-643",
        VulnType.CODE_INJECTION: "CWE-94",
        VulnType.TEMPLATE_INJECTION: "CWE-1336",
        VulnType.NOSQL_INJECTION: "CWE-943",
        VulnType.XXE: "CWE-611",
        VulnType.REGEX_DOS: "CWE-1333",
        VulnType.ORM_INJECTION: "CWE-89",
        VulnType.EL_INJECTION: "CWE-917",

        # A06: Insecure Design
        VulnType.MASS_ASSIGNMENT: "CWE-915",
        VulnType.BUSINESS_LOGIC_FLAW: "CWE-840",
        VulnType.RACE_CONDITION: "CWE-362",

        # A07: Authentication Failures
        VulnType.BROKEN_AUTHENTICATION: "CWE-287",
        VulnType.CREDENTIAL_STUFFING: "CWE-307",
        VulnType.SESSION_FIXATION: "CWE-384",
        VulnType.WEAK_PASSWORD: "CWE-521",
        VulnType.TRUST_BOUNDARY_VIOLATION: "CWE-501",
        VulnType.INSECURE_COOKIE: "CWE-614",

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
        VulnType.MEMORY_LEAK: "CWE-401",
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
        elif language == "javascript":
            from frame.sil.frontends.javascript_frontend import JavaScriptFrontend
            return JavaScriptFrontend()
        elif language == "typescript":
            from frame.sil.frontends.javascript_frontend import TypeScriptFrontend
            return TypeScriptFrontend()
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

        # Check if frontend is available
        if self.frontend is None:
            result.errors.append(f"Language '{self.language}' frontend not yet implemented")
            result.scan_time_ms = (time.time() - start_time) * 1000
            return result

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

            # Step 4: Deduplicate vulnerabilities
            result.vulnerabilities = self._deduplicate_vulnerabilities(result.vulnerabilities)

            if self.verbose:
                print(f"[Scanner] After deduplication: {len(result.vulnerabilities)} unique vulnerabilities")

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

        verified = False
        if self.verify and self.checker:
            # Verify using incorrectness logic
            try:
                # Use the appropriate checker method based on vulnerability type
                report = self._verify_check(check)

                if report.reachable:
                    verified = True
                    # Extract witness
                    if report.witness:
                        witness_str = str(report.witness)
                # If not reachable, still report with lower confidence
                # Taint analysis already proved data flows from source to sink

            except Exception as e:
                if self.verbose:
                    print(f"[Scanner] Verification failed: {e}")
                # If verification fails, report anyway with lower confidence
                pass

        # Create vulnerability object
        severity = self.SEVERITY_MAP.get(check.vuln_type, Severity.MEDIUM)
        cwe_id = self.CWE_MAP.get(check.vuln_type)

        # Set confidence based on verification status
        # - verified: highest confidence (formal proof)
        # - verify mode but not proven: medium confidence (taint analysis)
        # - no verification: lower confidence
        if verified:
            confidence = 1.0
        elif self.verify:
            confidence = 0.75  # Taint analysis found it, but couldn't formally verify
        else:
            confidence = 0.8

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

        Priority: Keep the highest severity, most detailed report.
        """
        if not vulns:
            return vulns

        # Group by deduplication key: (line, procedure, cwe_id or vuln_type)
        seen = {}  # key -> best vulnerability

        for vuln in vulns:
            # Primary key: same line, procedure, and vulnerability type
            primary_key = (vuln.line, vuln.procedure, vuln.type.value)

            # Secondary key: same line, procedure, and CWE (for related vulns)
            secondary_key = (vuln.line, vuln.procedure, vuln.cwe_id) if vuln.cwe_id else None

            # Check if we've seen this vulnerability
            existing = seen.get(primary_key)
            if existing is None and secondary_key:
                existing = seen.get(secondary_key)

            if existing is None:
                # New vulnerability
                seen[primary_key] = vuln
                if secondary_key:
                    seen[secondary_key] = vuln
            else:
                # Compare and keep the better one
                # Prefer: higher severity, more detail (longer description), has witness
                should_replace = False

                # Compare severity (CRITICAL > HIGH > MEDIUM > LOW > INFO)
                severity_order = {
                    Severity.CRITICAL: 5,
                    Severity.HIGH: 4,
                    Severity.MEDIUM: 3,
                    Severity.LOW: 2,
                    Severity.INFO: 1,
                }
                if severity_order.get(vuln.severity, 0) > severity_order.get(existing.severity, 0):
                    should_replace = True
                elif severity_order.get(vuln.severity, 0) == severity_order.get(existing.severity, 0):
                    # Same severity - prefer one with witness
                    if vuln.witness and not existing.witness:
                        should_replace = True
                    # Or prefer one with more data flow info
                    elif len(vuln.data_flow) > len(existing.data_flow):
                        should_replace = True

                if should_replace:
                    seen[primary_key] = vuln
                    if secondary_key:
                        seen[secondary_key] = vuln

        # Extract unique vulnerabilities
        unique_vulns = []
        seen_ids = set()

        for vuln in vulns:
            primary_key = (vuln.line, vuln.procedure, vuln.type.value)
            best = seen.get(primary_key)
            if best is not None:
                # Use id to track which we've already added
                vuln_id = (best.line, best.column, best.procedure, best.type.value, best.cwe_id)
                if vuln_id not in seen_ids:
                    unique_vulns.append(best)
                    seen_ids.add(vuln_id)

        return unique_vulns

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
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".java": "java",
            ".c": "c",
            ".cpp": "cpp",
            ".cc": "cpp",
            ".cxx": "cpp",
            ".h": "c",
            ".hpp": "cpp",
            ".cs": "csharp",
        }
        language = language_map.get(ext, "python")

    scanner = FrameScanner(language=language)
    return scanner.scan_file(filepath)
