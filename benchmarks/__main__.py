#!/usr/bin/env python3
"""
Benchmarks entry point - delegates to benchmarks.runner module.

This wrapper maintains backward compatibility while keeping the
implementation in the benchmarks/ package.
"""

if __name__ == '__main__':
    from benchmarks.runner import main
    main()
