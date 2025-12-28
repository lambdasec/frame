"""
Code analyzers for Frame SIL.

This module provides specialized analyzers for different types of
vulnerability detection:

- memory_safety: Memory safety analysis (UAF, double-free, buffer overflow)
"""

from frame.sil.analyzers.memory_safety import (
    MemorySafetyAnalyzer,
    MemoryVulnerability,
    analyze_c_memory_safety,
)

__all__ = [
    "MemorySafetyAnalyzer",
    "MemoryVulnerability",
    "analyze_c_memory_safety",
]
