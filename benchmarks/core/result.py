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
        """Check if the benchmark result matches expected output"""
        if self.error:
            return False
        return self.expected == self.actual

    def to_dict(self):
        """Convert to dictionary"""
        return asdict(self)
