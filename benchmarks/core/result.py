"""Benchmark result data structures"""

from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class BenchmarkResult:
    """Result of running a single benchmark"""
    filename: str
    suite: str
    division: str
    expected: str
    actual: str
    time_ms: float
    error: Optional[str] = None

    @property
    def correct(self) -> bool:
        """Check if the benchmark result matches expected output

        For SMT benchmarks with expected='unknown':
        - sat/unsat/unknown are all considered correct (solver either proved it or couldn't)
        - Only errors and timeouts are considered incorrect

        For benchmarks with expected='sat' or 'unsat':
        - Must exactly match
        """
        if self.error:
            return False

        # Exact match is always correct
        if self.expected == self.actual:
            return True

        # For 'unknown' expected, any definitive answer (sat/unsat) is also correct
        # This handles cases where Z3 can prove something that was previously unknown
        if self.expected == 'unknown' and self.actual in ('sat', 'unsat'):
            return True

        return False

    def to_dict(self):
        """Convert to dictionary"""
        return asdict(self)
