"""
Library specifications for common frameworks and APIs.

This module provides ProcSpec definitions for:
- Python: Flask, Django, SQLAlchemy, subprocess, etc.
- JavaScript: Express, Node.js, MongoDB, DOM APIs
- Java: Spring, Servlet, JDBC, JPA
- C/C++: stdio, string, stdlib, POSIX, sockets

Specifications include:
- Taint sources (user input, files, network)
- Taint sinks (SQL, shell, HTML, filesystem)
- Sanitizers (escape functions, validators)
- Taint propagation rules
"""

from frame.sil.specs.python_specs import PYTHON_SPECS, get_python_specs

# JavaScript/TypeScript specs
try:
    from frame.sil.specs.javascript_specs import (
        JAVASCRIPT_SPECS,
        TYPESCRIPT_SPECS,
    )
except ImportError:
    JAVASCRIPT_SPECS = {}
    TYPESCRIPT_SPECS = {}

# Java specs
try:
    from frame.sil.specs.java_specs import JAVA_SPECS
except ImportError:
    JAVA_SPECS = {}

# C/C++ specs
try:
    from frame.sil.specs.c_specs import C_SPECS, CPP_SPECS
except ImportError:
    C_SPECS = {}
    CPP_SPECS = {}

# C# specs
try:
    from frame.sil.specs.csharp_specs import CSHARP_SPECS
except ImportError:
    CSHARP_SPECS = {}

__all__ = [
    "PYTHON_SPECS",
    "get_python_specs",
    "JAVASCRIPT_SPECS",
    "TYPESCRIPT_SPECS",
    "JAVA_SPECS",
    "C_SPECS",
    "CPP_SPECS",
    "CSHARP_SPECS",
]
