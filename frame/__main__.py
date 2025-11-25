#!/usr/bin/env python3
"""
Frame CLI entry point for `python -m frame`.

Usage:
    python -m frame scan app.py
    python -m frame solve "x |-> 5 |- x |-> 5"
    python -m frame check entailments.txt
    python -m frame parse "x |-> 5 * y |-> 3"
    python -m frame repl
"""

import sys
from frame.cli import main

if __name__ == "__main__":
    sys.exit(main())
