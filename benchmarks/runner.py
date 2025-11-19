#!/usr/bin/env python3
"""
Frame Benchmark Suite - Backward Compatibility Module

This module provides backward compatibility with the old unified runner.
New code should import from benchmarks.orchestrator instead.
"""

# Re-export orchestrator for backward compatibility
from benchmarks.orchestrator import (
    BenchmarkOrchestrator,
    UnifiedBenchmarkRunner,  # Alias for BenchmarkOrchestrator
)

# Re-export main function
from benchmarks.__main__ import main

__all__ = [
    'BenchmarkOrchestrator',
    'UnifiedBenchmarkRunner',
    'main',
]


# Allow running as script
if __name__ == '__main__':
    main()
