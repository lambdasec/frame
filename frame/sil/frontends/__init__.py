"""
Language frontends for Frame SIL.

Each frontend translates source code from a specific language to SIL.
Frontends use tree-sitter for parsing and produce a SIL Program.

Available frontends:
- PythonFrontend: Python source code
- JavaScriptFrontend: JavaScript source code
- TypeScriptFrontend: TypeScript source code
- JavaFrontend: Java source code
- CFrontend: C source code
- CppFrontend: C++ source code
- CSharpFrontend: C# source code (planned)
"""

from frame.sil.frontends.python_frontend import PythonFrontend

# JavaScript/TypeScript frontend
try:
    from frame.sil.frontends.javascript_frontend import (
        JavaScriptFrontend,
        TypeScriptFrontend,
    )
    JS_FRONTEND_AVAILABLE = True
except ImportError:
    JS_FRONTEND_AVAILABLE = False
    JavaScriptFrontend = None
    TypeScriptFrontend = None

# Java frontend
try:
    from frame.sil.frontends.java_frontend import JavaFrontend
    JAVA_FRONTEND_AVAILABLE = True
except ImportError:
    JAVA_FRONTEND_AVAILABLE = False
    JavaFrontend = None

# C/C++ frontend
try:
    from frame.sil.frontends.c_frontend import CFrontend, CppFrontend
    C_FRONTEND_AVAILABLE = True
except ImportError:
    C_FRONTEND_AVAILABLE = False
    CFrontend = None
    CppFrontend = None

# C# frontend
try:
    from frame.sil.frontends.csharp_frontend import CSharpFrontend
    CSHARP_FRONTEND_AVAILABLE = True
except ImportError:
    CSHARP_FRONTEND_AVAILABLE = False
    CSharpFrontend = None

__all__ = [
    "PythonFrontend",
    "JavaScriptFrontend",
    "TypeScriptFrontend",
    "JavaFrontend",
    "CFrontend",
    "CppFrontend",
    "CSharpFrontend",
    "JS_FRONTEND_AVAILABLE",
    "JAVA_FRONTEND_AVAILABLE",
    "C_FRONTEND_AVAILABLE",
    "CSHARP_FRONTEND_AVAILABLE",
]
