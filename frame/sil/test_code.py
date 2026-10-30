"""Is a file test code? Read from its program model, never from its name.

A file is test code when the program says so: it imports a test framework (pytest, unittest,
JUnit, TestNG, Mockito, jest / vitest / mocha, gtest, Catch2, ...), declares tests the way its
framework discovers them (a C# `[Fact]` / `[Test]` / `[TestMethod]`, a Java `@Test` resolved to
JUnit or TestNG, a module-level pytest `test_*` function), or registers callbacks with the test
runner's globals (`describe(...)`, `it(...)`, `test(...)` in jest and mocha). A file called
`test_utils.py` that defines production helpers is not test code; a `checks.py` full of pytest
tests is.

Findings in test code are tagged (`context: "test"`), never dropped: a real credential in a test
is still leaked. Only a credential found by its variable's name (`password = "hunter2"`), which
in a test is conventionally a fixture value, is lowered to low severity; a value in a provider's
own format keeps its severity.
"""

from __future__ import annotations

from typing import Optional

from frame.sil.specs.test_frameworks import load as _frameworks

# The catalog (imports, annotation packages, attributes, runner globals, pytest's prefix) is
# data: specs/data/test-frameworks.toml.
_LANGUAGE_FAMILY = {"typescript": "javascript", "cpp": "c", "c++": "c"}


def _matches(module: str, prefixes) -> bool:
    for p in prefixes:
        if p.endswith((".", "/")):
            if module.startswith(p):
                return True
        elif module == p or module.startswith(p + ".") or module.startswith(p + "/"):
            return True
    return False


def test_framework(program, language: str) -> Optional[str]:
    """The evidence that the file is test code (e.g. "imports pytest"), or None."""
    family = _LANGUAGE_FAMILY.get(language, language)
    catalog = _frameworks()
    for module in sorted(set((program.imports or {}).values())):
        if _matches(str(module), catalog.imports.get(family, ())):
            return f"imports {module}"
    procs = list(program.procedures.values())
    if family == "java":
        for proc in procs:
            for a in getattr(proc, "annotations", ()) or ():
                qualified = a.canonical or a.name           # `@org.testng.annotations.Test` is written whole
                if qualified.startswith(catalog.java_annotation_packages):
                    return f"@{a.name} ({qualified})"
    if family == "csharp":
        for proc in procs:
            for a in getattr(proc, "annotations", ()) or ():
                if a.name.split(".")[-1].removesuffix("Attribute") in catalog.csharp_attributes:
                    return f"[{a.name}]"
    if family == "javascript":
        for proc in procs:
            for callee, _ in getattr(proc, "passed_as", ()) or ():
                if callee in catalog.js_runner_globals:
                    return f"a callback passed to {callee}()"
    if family == "python":
        # pytest's own discovery: a module-level `test_*` function, which asserts (a production
        # `test_connection()` helper does not); methods are `Class.test_*` and do not count
        for name, proc in program.procedures.items():
            if name.startswith(catalog.python_test_prefix) and "." not in name and getattr(proc, "asserts", False):
                return f"pytest test function {name}()"
    return None


__all__ = ["test_framework"]
