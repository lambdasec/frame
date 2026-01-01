"""
Code analyzers for Frame SIL.

This module provides specialized analyzers for different types of
vulnerability detection:

- memory_safety: Memory safety analysis (UAF, double-free, buffer overflow)
- sl_semantic_analyzer: Tree-sitter based separation logic analyzer
- interprocedural_analyzer: Cross-function analysis
- ts_function_summarizer: Tree-sitter based function summary extraction
- function_summary: Enhanced function/class summary data structures
"""

from frame.sil.analyzers.memory_safety import (
    MemorySafetyAnalyzer,
    MemoryVulnerability,
    analyze_c_memory_safety,
)

from frame.sil.analyzers.function_summary import (
    FunctionSummary,
    ClassSummary,
    ParameterInfo,
    ParameterEffect,
    MemberEffect,
    ReturnSource,
)

from frame.sil.analyzers.ts_function_summarizer import (
    TreeSitterFunctionSummarizer,
)

__all__ = [
    "MemorySafetyAnalyzer",
    "MemoryVulnerability",
    "analyze_c_memory_safety",
    "FunctionSummary",
    "ClassSummary",
    "ParameterInfo",
    "ParameterEffect",
    "MemberEffect",
    "ReturnSource",
    "TreeSitterFunctionSummarizer",
]
