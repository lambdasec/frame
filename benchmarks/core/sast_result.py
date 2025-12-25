"""SAST Benchmark result data structures for security scanner benchmarks"""

from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Set
from enum import Enum


class VulnerabilityCategory(Enum):
    """Common vulnerability categories across benchmarks"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    CODE_INJECTION = "code_injection"
    DESERIALIZATION = "deserialization"
    SSRF = "ssrf"
    XXE = "xxe"
    LDAP_INJECTION = "ldap_injection"
    XPATH_INJECTION = "xpath_injection"
    WEAK_CRYPTO = "weak_crypto"
    WEAK_HASH = "weak_hash"
    HARDCODED_SECRET = "hardcoded_secret"
    BUFFER_OVERFLOW = "buffer_overflow"
    USE_AFTER_FREE = "use_after_free"
    NULL_DEREF = "null_deref"
    INTEGER_OVERFLOW = "integer_overflow"
    FORMAT_STRING = "format_string"
    RACE_CONDITION = "race_condition"
    BROKEN_AUTH = "broken_auth"
    IDOR = "idor"
    OTHER = "other"


@dataclass
class ExpectedVulnerability:
    """A single expected vulnerability in the ground truth"""
    cwe_id: str  # e.g., "CWE-89"
    category: VulnerabilityCategory
    line_number: Optional[int] = None
    function_name: Optional[str] = None
    description: Optional[str] = None


@dataclass
class DetectedVulnerability:
    """A vulnerability detected by the scanner"""
    vuln_type: str
    cwe_id: Optional[str] = None
    line_number: Optional[int] = None
    function_name: Optional[str] = None
    confidence: Optional[float] = None
    description: Optional[str] = None


@dataclass
class SASTBenchmarkResult:
    """Result of running a SAST benchmark on a single file/test case"""
    filename: str
    suite: str  # 'owasp_python', 'owasp_java', 'juliet', 'issueblot', 'secbench_js'
    division: str  # Specific benchmark category
    language: str  # 'python', 'java', 'c', 'cpp', 'csharp', 'javascript', 'typescript'

    # Ground truth
    expected_vulns: List[ExpectedVulnerability] = field(default_factory=list)

    # Scanner output
    detected_vulns: List[DetectedVulnerability] = field(default_factory=list)

    # Timing
    time_ms: float = 0.0

    # Error handling
    error: Optional[str] = None

    # Computed metrics (set after matching)
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0

    @property
    def has_expected_vulns(self) -> bool:
        """Check if this test case has expected vulnerabilities (is a 'bad' case)"""
        return len(self.expected_vulns) > 0

    @property
    def precision(self) -> float:
        """Precision = TP / (TP + FP)"""
        if self.true_positives + self.false_positives == 0:
            return 1.0 if self.false_negatives == 0 else 0.0
        return self.true_positives / (self.true_positives + self.false_positives)

    @property
    def recall(self) -> float:
        """Recall = TP / (TP + FN)"""
        if self.true_positives + self.false_negatives == 0:
            return 1.0  # No expected vulns and none found = perfect recall
        return self.true_positives / (self.true_positives + self.false_negatives)

    @property
    def f1_score(self) -> float:
        """F1 = 2 * (precision * recall) / (precision + recall)"""
        p, r = self.precision, self.recall
        if p + r == 0:
            return 0.0
        return 2 * (p * r) / (p + r)

    @property
    def correct(self) -> bool:
        """A result is correct if all expected vulns are found and no FPs"""
        if self.error:
            return False
        return self.false_positives == 0 and self.false_negatives == 0

    def compute_metrics(self, match_by_cwe: bool = True, match_by_line: bool = False):
        """
        Compute TP, FP, FN by matching detected vulns against expected.

        Args:
            match_by_cwe: Match by CWE ID (default)
            match_by_line: Also require line number match (stricter)
        """
        if self.error:
            self.false_negatives = len(self.expected_vulns)
            return

        matched_expected: Set[int] = set()
        matched_detected: Set[int] = set()

        for i, expected in enumerate(self.expected_vulns):
            for j, detected in enumerate(self.detected_vulns):
                if j in matched_detected:
                    continue

                # CWE match
                cwe_match = False
                if match_by_cwe and expected.cwe_id and detected.cwe_id:
                    # Normalize CWE IDs (e.g., "CWE-89" == "89" == "cwe89")
                    exp_cwe = expected.cwe_id.upper().replace("CWE-", "").replace("CWE", "")
                    det_cwe = detected.cwe_id.upper().replace("CWE-", "").replace("CWE", "")
                    cwe_match = exp_cwe == det_cwe

                # Category match (fallback if no CWE)
                category_match = False
                if not cwe_match and detected.vuln_type:
                    category_match = expected.category.value in detected.vuln_type.lower()

                # Line match (optional, stricter)
                line_match = True
                if match_by_line and expected.line_number and detected.line_number:
                    # Allow +/- 2 lines for flexibility
                    line_match = abs(expected.line_number - detected.line_number) <= 2

                if (cwe_match or category_match) and line_match:
                    matched_expected.add(i)
                    matched_detected.add(j)
                    break

        self.true_positives = len(matched_expected)
        self.false_negatives = len(self.expected_vulns) - len(matched_expected)
        self.false_positives = len(self.detected_vulns) - len(matched_detected)

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        result = {
            'filename': self.filename,
            'suite': self.suite,
            'division': self.division,
            'language': self.language,
            'expected_vulns': [
                {
                    'cwe_id': v.cwe_id,
                    'category': v.category.value,
                    'line_number': v.line_number,
                    'function_name': v.function_name,
                }
                for v in self.expected_vulns
            ],
            'detected_vulns': [
                {
                    'vuln_type': v.vuln_type,
                    'cwe_id': v.cwe_id,
                    'line_number': v.line_number,
                    'confidence': v.confidence,
                }
                for v in self.detected_vulns
            ],
            'time_ms': self.time_ms,
            'error': self.error,
            'true_positives': self.true_positives,
            'false_positives': self.false_positives,
            'false_negatives': self.false_negatives,
            'precision': self.precision,
            'recall': self.recall,
            'f1_score': self.f1_score,
        }
        return result


def analyze_sast_results(results: List[SASTBenchmarkResult]) -> Dict:
    """Analyze a collection of SAST benchmark results"""
    if not results:
        return {'total': 0}

    total_tp = sum(r.true_positives for r in results)
    total_fp = sum(r.false_positives for r in results)
    total_fn = sum(r.false_negatives for r in results)
    total_expected = sum(len(r.expected_vulns) for r in results)
    total_detected = sum(len(r.detected_vulns) for r in results)

    # Aggregate precision/recall
    if total_tp + total_fp > 0:
        precision = total_tp / (total_tp + total_fp)
    else:
        precision = 1.0 if total_fn == 0 else 0.0

    if total_tp + total_fn > 0:
        recall = total_tp / (total_tp + total_fn)
    else:
        recall = 1.0

    if precision + recall > 0:
        f1 = 2 * (precision * recall) / (precision + recall)
    else:
        f1 = 0.0

    # Group by suite/division/language
    by_suite: Dict[str, Dict] = {}
    by_division: Dict[str, Dict] = {}
    by_language: Dict[str, Dict] = {}

    for r in results:
        for grouping, key in [(by_suite, r.suite), (by_division, r.division), (by_language, r.language)]:
            if key not in grouping:
                grouping[key] = {'total': 0, 'tp': 0, 'fp': 0, 'fn': 0, 'errors': 0}
            grouping[key]['total'] += 1
            grouping[key]['tp'] += r.true_positives
            grouping[key]['fp'] += r.false_positives
            grouping[key]['fn'] += r.false_negatives
            if r.error:
                grouping[key]['errors'] += 1

    # Compute precision/recall for each group
    for grouping in [by_suite, by_division, by_language]:
        for key, stats in grouping.items():
            tp, fp, fn = stats['tp'], stats['fp'], stats['fn']
            stats['precision'] = tp / (tp + fp) if (tp + fp) > 0 else (1.0 if fn == 0 else 0.0)
            stats['recall'] = tp / (tp + fn) if (tp + fn) > 0 else 1.0
            p, r = stats['precision'], stats['recall']
            stats['f1'] = 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    errors = [r for r in results if r.error]

    return {
        'total': len(results),
        'total_expected_vulns': total_expected,
        'total_detected_vulns': total_detected,
        'true_positives': total_tp,
        'false_positives': total_fp,
        'false_negatives': total_fn,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'avg_time_ms': sum(r.time_ms for r in results) / len(results),
        'by_suite': by_suite,
        'by_division': by_division,
        'by_language': by_language,
        'errors': [{'file': e.filename, 'error': e.error} for e in errors],
    }


def print_sast_summary(results: List[SASTBenchmarkResult]):
    """Print a summary of SAST benchmark results"""
    analysis = analyze_sast_results(results)

    print("\n" + "=" * 80)
    print("SAST BENCHMARK RESULTS")
    print("=" * 80)

    print(f"\nTotal test cases: {analysis['total']}")
    print(f"Expected vulnerabilities: {analysis['total_expected_vulns']}")
    print(f"Detected vulnerabilities: {analysis['total_detected_vulns']}")

    print(f"\n--- Aggregate Metrics ---")
    print(f"True Positives:  {analysis['true_positives']}")
    print(f"False Positives: {analysis['false_positives']}")
    print(f"False Negatives: {analysis['false_negatives']}")
    print(f"Precision: {analysis['precision']:.1%}")
    print(f"Recall:    {analysis['recall']:.1%}")
    print(f"F1 Score:  {analysis['f1_score']:.1%}")
    print(f"Avg Time:  {analysis['avg_time_ms']:.1f}ms")

    if analysis['by_suite']:
        print(f"\n--- By Suite ---")
        for suite, stats in sorted(analysis['by_suite'].items()):
            print(f"  {suite}: {stats['total']} tests, "
                  f"P={stats['precision']:.1%}, R={stats['recall']:.1%}, F1={stats['f1']:.1%}")

    if analysis['by_language']:
        print(f"\n--- By Language ---")
        for lang, stats in sorted(analysis['by_language'].items()):
            print(f"  {lang}: {stats['total']} tests, "
                  f"P={stats['precision']:.1%}, R={stats['recall']:.1%}, F1={stats['f1']:.1%}")

    if analysis['errors']:
        print(f"\n--- Errors ({len(analysis['errors'])}) ---")
        for err in analysis['errors'][:5]:
            print(f"  {err['file']}: {err['error'][:50]}...")

    print("=" * 80)
