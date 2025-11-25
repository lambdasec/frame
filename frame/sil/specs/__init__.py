"""
Library specifications for common frameworks and APIs.

This module provides ProcSpec definitions for:
- Python: Flask, Django, SQLAlchemy, subprocess, etc.
- JavaScript: Express, Node.js APIs (future)
- Java: Spring, JDBC (future)
- C: libc, POSIX (future)

Specifications include:
- Taint sources (user input, files, network)
- Taint sinks (SQL, shell, HTML, filesystem)
- Sanitizers (escape functions, validators)
- Taint propagation rules
"""

from frame.sil.specs.python_specs import PYTHON_SPECS, get_python_specs

__all__ = [
    "PYTHON_SPECS",
    "get_python_specs",
]
