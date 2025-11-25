"""
Language frontends for Frame SIL.

Each frontend translates source code from a specific language to SIL.
Frontends use tree-sitter for parsing and produce a SIL Program.

Available frontends:
- PythonFrontend: Python source code
- (Future) JavaScriptFrontend: JavaScript/TypeScript
- (Future) JavaFrontend: Java
- (Future) GoFrontend: Go
- (Future) CFrontend: C/C++
"""

from frame.sil.frontends.python_frontend import PythonFrontend

__all__ = [
    "PythonFrontend",
]
