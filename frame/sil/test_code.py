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

# imported module (or prefix, ending in `.` or `/`) -> framework
_IMPORTS = {
    "python": ("pytest", "unittest", "hypothesis", "nose", "nose2", "testtools", "pytest_asyncio", "freezegun"),
    "java": ("org.junit.", "junit.framework.", "org.testng.", "org.mockito.", "org.assertj."),
    "javascript": ("vitest", "@jest/globals", "jest", "mocha", "chai", "node:test", "ava", "jasmine",
                   "@playwright/test", "sinon", "supertest", "@testing-library/"),
    "c": ("gtest/", "gmock/", "catch2/", "catch.hpp", "boost/test/", "CUnit/", "cmocka.h", "doctest/", "doctest.h"),
}
_LANGUAGE_FAMILY = {"typescript": "javascript", "cpp": "c", "c++": "c"}

# test-runner globals a JS test file passes its callbacks to (jest, mocha, jasmine)
_JS_RUNNER_GLOBALS = frozenset({"describe", "it", "test", "suite", "beforeEach", "afterEach", "beforeAll",
                                "afterAll", "before", "after", "context"})
# C# test attributes (xUnit, NUnit, MSTest)
_CSHARP_ATTRIBUTES = frozenset({"Fact", "Theory", "Test", "TestCase", "TestCaseSource", "TestMethod", "DataTestMethod",
                                "TestClass", "TestFixture", "SetUp", "TearDown", "OneTimeSetUp", "TestInitialize"})


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
    for module in sorted(set((program.imports or {}).values())):
        if _matches(str(module), _IMPORTS.get(family, ())):
            return f"imports {module}"
    procs = list(program.procedures.values())
    if family == "java":
        for proc in procs:
            for a in getattr(proc, "annotations", ()) or ():
                qualified = a.canonical or a.name           # `@org.testng.annotations.Test` is written whole
                if qualified.startswith(("org.junit.", "org.testng.")):
                    return f"@{a.name} ({qualified})"
    if family == "csharp":
        for proc in procs:
            for a in getattr(proc, "annotations", ()) or ():
                if a.name.split(".")[-1].removesuffix("Attribute") in _CSHARP_ATTRIBUTES:
                    return f"[{a.name}]"
    if family == "javascript":
        for proc in procs:
            for callee, _ in getattr(proc, "passed_as", ()) or ():
                if callee in _JS_RUNNER_GLOBALS:
                    return f"a callback passed to {callee}()"
    if family == "python":
        # pytest's own discovery: a module-level `test_*` function, which asserts (a production
        # `test_connection()` helper does not); methods are `Class.test_*` and do not count
        for name, proc in program.procedures.items():
            if name.startswith("test_") and "." not in name and getattr(proc, "asserts", False):
                return f"pytest test function {name}()"
    return None


__all__ = ["test_framework"]
