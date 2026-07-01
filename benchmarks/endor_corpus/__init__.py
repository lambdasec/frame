"""Endor Labs AI-SAST public corpus evaluation harness for Frame.

This package runs Frame over the 8 public repositories that Endor Labs named as
their AI-SAST benchmark corpus. It is an *evaluation harness*, NOT a reproduction
of Endor's benchmark: Endor published the corpus list but not commit SHAs,
ground-truth labels, scanner configs, prompts, or their verified findings
database. See README.md for details and honest limitations.

Reference article (context only):
    https://www.endorlabs.com/learn/ai-sast-benchmark-2x-more-real-vulnerabilities
"""
