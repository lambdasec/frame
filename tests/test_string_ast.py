"""
Unit tests for string expressions and security predicates in AST

Tests the new AST nodes for:
- String expressions (StrLiteral, StrConcat, StrLen, StrSubstr)
- String formulas (StrContains, StrMatches)
- Security predicates (Taint, Sanitized, Source, Sink)
- Error states (Error, NullDeref, UseAfterFree, BufferOverflow)
"""

import pytest
from frame.core.ast import (
    # Basic types
    Var, Const,
    # String expressions
    StrLiteral, StrConcat, StrLen, StrSubstr,
    # String formulas
    StrContains, StrMatches,
    # Security predicates
    Taint, Sanitized, Source, Sink,
    # Error states
    Error, NullDeref, UseAfterFree, BufferOverflow
)


class TestStringExpressions:
    """Test string expression AST nodes"""

    def test_str_literal_basic(self):
        """Test basic string literal"""
        s = StrLiteral("hello")
        assert str(s) == '"hello"'
        assert s.free_vars() == set()

    def test_str_literal_empty(self):
        """Test empty string literal"""
        s = StrLiteral("")
        assert str(s) == '""'
        assert s.free_vars() == set()

    def test_str_literal_equality(self):
        """Test string literal equality"""
        s1 = StrLiteral("hello")
        s2 = StrLiteral("hello")
        s3 = StrLiteral("world")
        assert s1 == s2
        assert s1 != s3
        assert hash(s1) == hash(s2)
        assert hash(s1) != hash(s3)

    def test_str_concat_basic(self):
        """Test string concatenation"""
        s1 = StrLiteral("hello")
        s2 = StrLiteral("world")
        concat = StrConcat(s1, s2)
        assert str(concat) == '("hello" ++ "world")'
        assert concat.free_vars() == set()

    def test_str_concat_with_vars(self):
        """Test string concatenation with variables"""
        var = Var("x")
        s = StrLiteral("hello")
        concat = StrConcat(var, s)
        assert str(concat) == '(x ++ "hello")'
        assert concat.free_vars() == {"x"}

    def test_str_concat_nested(self):
        """Test nested string concatenation"""
        s1 = StrLiteral("a")
        s2 = StrLiteral("b")
        s3 = StrLiteral("c")
        concat1 = StrConcat(s1, s2)
        concat2 = StrConcat(concat1, s3)
        assert str(concat2) == '(("a" ++ "b") ++ "c")'

    def test_str_concat_equality(self):
        """Test string concatenation equality"""
        s1 = StrLiteral("a")
        s2 = StrLiteral("b")
        concat1 = StrConcat(s1, s2)
        concat2 = StrConcat(s1, s2)
        concat3 = StrConcat(s2, s1)
        assert concat1 == concat2
        assert concat1 != concat3

    def test_str_len_basic(self):
        """Test string length"""
        s = StrLiteral("hello")
        length = StrLen(s)
        assert str(length) == 'len("hello")'
        assert length.free_vars() == set()

    def test_str_len_with_var(self):
        """Test string length with variable"""
        var = Var("s")
        length = StrLen(var)
        assert str(length) == "len(s)"
        assert length.free_vars() == {"s"}

    def test_str_len_equality(self):
        """Test string length equality"""
        s = StrLiteral("hello")
        len1 = StrLen(s)
        len2 = StrLen(s)
        len3 = StrLen(StrLiteral("world"))
        assert len1 == len2
        assert len1 != len3

    def test_str_substr_basic(self):
        """Test substring extraction"""
        s = StrLiteral("hello")
        start = Const(0)
        end = Const(2)
        substr = StrSubstr(s, start, end)
        assert str(substr) == 'substr("hello", 0, 2)'
        assert substr.free_vars() == set()

    def test_str_substr_with_vars(self):
        """Test substring with variables"""
        s = Var("str")
        start = Var("i")
        end = Var("j")
        substr = StrSubstr(s, start, end)
        assert str(substr) == "substr(str, i, j)"
        assert substr.free_vars() == {"str", "i", "j"}

    def test_str_substr_equality(self):
        """Test substring equality"""
        s = StrLiteral("hello")
        substr1 = StrSubstr(s, Const(0), Const(2))
        substr2 = StrSubstr(s, Const(0), Const(2))
        substr3 = StrSubstr(s, Const(1), Const(3))
        assert substr1 == substr2
        assert substr1 != substr3


class TestStringFormulas:
    """Test string formula AST nodes"""

    def test_str_contains_basic(self):
        """Test string containment"""
        haystack = StrLiteral("hello world")
        needle = StrLiteral("world")
        contains = StrContains(haystack, needle)
        assert str(contains) == '("hello world" contains "world")'
        assert contains.free_vars() == set()
        assert not contains.is_spatial()

    def test_str_contains_with_vars(self):
        """Test string containment with variables"""
        haystack = Var("s1")
        needle = Var("s2")
        contains = StrContains(haystack, needle)
        assert str(contains) == "(s1 contains s2)"
        assert contains.free_vars() == {"s1", "s2"}

    def test_str_matches_basic(self):
        """Test regex matching"""
        s = StrLiteral("hello123")
        matches = StrMatches(s, "[a-z]+[0-9]+")
        assert str(matches) == '("hello123" matches /[a-z]+[0-9]+/)'
        assert matches.free_vars() == set()
        assert not matches.is_spatial()

    def test_str_matches_with_var(self):
        """Test regex matching with variable"""
        s = Var("input")
        matches = StrMatches(s, "^[0-9]+$")
        assert str(matches) == "(input matches /^[0-9]+$/)"
        assert matches.free_vars() == {"input"}


class TestSecurityPredicates:
    """Test security and taint tracking predicates"""

    def test_taint_basic(self):
        """Test taint predicate"""
        var = Var("x")
        taint = Taint(var)
        assert str(taint) == "taint(x)"
        assert taint.free_vars() == {"x"}
        assert not taint.is_spatial()

    def test_taint_with_expr(self):
        """Test taint with complex expression"""
        concat = StrConcat(Var("s1"), Var("s2"))
        taint = Taint(concat)
        assert str(taint) == "taint((s1 ++ s2))"
        assert taint.free_vars() == {"s1", "s2"}

    def test_sanitized_basic(self):
        """Test sanitized predicate"""
        var = Var("clean")
        sanitized = Sanitized(var)
        assert str(sanitized) == "sanitized(clean)"
        assert sanitized.free_vars() == {"clean"}
        assert not sanitized.is_spatial()

    def test_source_basic(self):
        """Test taint source predicate"""
        var = Var("user_input")
        source = Source(var, "user")
        assert str(source) == 'source(user_input, "user")'
        assert source.free_vars() == {"user_input"}
        assert not source.is_spatial()

    def test_source_types(self):
        """Test different source types"""
        types = ["user", "network", "file", "env", "database"]
        for source_type in types:
            var = Var("data")
            source = Source(var, source_type)
            assert str(source) == f'source(data, "{source_type}")'

    def test_sink_basic(self):
        """Test taint sink predicate"""
        var = Var("query")
        sink = Sink(var, "sql")
        assert str(sink) == 'sink(query, "sql")'
        assert sink.free_vars() == {"query"}
        assert not sink.is_spatial()

    def test_sink_types(self):
        """Test different sink types"""
        types = ["sql", "shell", "html", "filesystem", "network"]
        for sink_type in types:
            var = Var("output")
            sink = Sink(var, sink_type)
            assert str(sink) == f'sink(output, "{sink_type}")'


class TestErrorStates:
    """Test error state predicates for incorrectness logic"""

    def test_error_basic(self):
        """Test generic error"""
        err = Error()
        assert str(err) == "error()"
        assert err.free_vars() == set()
        assert not err.is_spatial()

    def test_error_with_kind(self):
        """Test error with specific kind"""
        err = Error(kind="division_by_zero")
        assert str(err) == 'error("division_by_zero")'
        assert err.free_vars() == set()

    def test_error_with_message(self):
        """Test error with message"""
        err = Error(kind="overflow", message="Integer overflow detected")
        assert str(err) == 'error("overflow")'
        assert err.message == "Integer overflow detected"

    def test_null_deref_basic(self):
        """Test null dereference error"""
        var = Var("ptr")
        null_deref = NullDeref(var)
        assert str(null_deref) == "null_deref(ptr)"
        assert null_deref.free_vars() == {"ptr"}
        assert not null_deref.is_spatial()

    def test_use_after_free_basic(self):
        """Test use-after-free error"""
        var = Var("buf")
        uaf = UseAfterFree(var)
        assert str(uaf) == "use_after_free(buf)"
        assert uaf.free_vars() == {"buf"}
        assert not uaf.is_spatial()

    def test_buffer_overflow_basic(self):
        """Test buffer overflow error"""
        array = Var("arr")
        index = Var("i")
        size = Const(10)
        overflow = BufferOverflow(array, index, size)
        assert str(overflow) == "buffer_overflow(arr, i, 10)"
        assert overflow.free_vars() == {"arr", "i"}
        assert not overflow.is_spatial()


class TestComplexExamples:
    """Test complex combinations of new AST nodes"""

    def test_tainted_string_concat(self):
        """Test taint on concatenated strings"""
        user_input = Var("user_input")
        prefix = StrLiteral("SELECT * FROM users WHERE id=")
        query = StrConcat(prefix, user_input)
        taint = Taint(query)
        assert str(taint) == 'taint(("SELECT * FROM users WHERE id=" ++ user_input))'
        assert taint.free_vars() == {"user_input"}

    def test_sql_injection_pattern(self):
        """Test SQL injection vulnerability pattern"""
        user_input = Var("input")
        source = Source(user_input, "user")
        taint = Taint(user_input)
        query = Var("query")
        sink = Sink(query, "sql")

        # Verify all predicates work together
        assert str(source) == 'source(input, "user")'
        assert str(taint) == "taint(input)"
        assert str(sink) == 'sink(query, "sql")'

    def test_string_length_constraint(self):
        """Test string length in constraints"""
        password = Var("pwd")
        min_len = Const(8)
        length = StrLen(password)

        # Can be used in formulas (though we'd need to parse this)
        assert str(length) == "len(pwd)"
        assert length.free_vars() == {"pwd"}

    def test_substring_sanitization(self):
        """Test substring extraction with sanitization"""
        user_input = Var("input")
        clean = StrSubstr(user_input, Const(0), Const(10))  # Take first 10 chars
        sanitized = Sanitized(clean)
        assert str(sanitized) == "sanitized(substr(input, 0, 10))"
        assert sanitized.free_vars() == {"input"}

    def test_null_deref_from_heap(self):
        """Test null dereference error state"""
        ptr = Var("x")
        null_deref = NullDeref(ptr)
        # Would be used with: x = nil * null_deref(x)
        assert str(null_deref) == "null_deref(x)"
        assert not null_deref.is_spatial()

    def test_buffer_overflow_scenario(self):
        """Test buffer overflow with array bounds"""
        array = Var("buffer")
        index = Var("i")
        size = Const(100)
        overflow = BufferOverflow(array, index, size)
        # Would be used with: i >= 100 * buffer_overflow(buffer, i, 100)
        assert str(overflow) == "buffer_overflow(buffer, i, 100)"
        assert overflow.free_vars() == {"buffer", "i"}


class TestFreeVariables:
    """Test free variable computation for all new nodes"""

    def test_string_expr_free_vars(self):
        """Test free variables in string expressions"""
        # Literal has no free vars
        assert StrLiteral("hello").free_vars() == set()

        # Variables contribute free vars
        assert StrConcat(Var("x"), Var("y")).free_vars() == {"x", "y"}

        # Length propagates free vars
        assert StrLen(Var("s")).free_vars() == {"s"}

        # Substring collects all free vars
        assert StrSubstr(Var("s"), Var("i"), Var("j")).free_vars() == {"s", "i", "j"}

    def test_string_formula_free_vars(self):
        """Test free variables in string formulas"""
        # Contains collects from both operands
        assert StrContains(Var("s1"), Var("s2")).free_vars() == {"s1", "s2"}

        # Matches from string expr
        assert StrMatches(Var("input"), ".*").free_vars() == {"input"}

    def test_security_predicate_free_vars(self):
        """Test free variables in security predicates"""
        # All security predicates propagate from their variable
        assert Taint(Var("x")).free_vars() == {"x"}
        assert Sanitized(Var("y")).free_vars() == {"y"}
        assert Source(Var("z"), "user").free_vars() == {"z"}
        assert Sink(Var("w"), "sql").free_vars() == {"w"}

    def test_error_state_free_vars(self):
        """Test free variables in error states"""
        # Generic error has no free vars
        assert Error().free_vars() == set()
        assert Error("kind").free_vars() == set()

        # Specific errors propagate from their variables
        assert NullDeref(Var("p")).free_vars() == {"p"}
        assert UseAfterFree(Var("q")).free_vars() == {"q"}
        assert BufferOverflow(Var("a"), Var("i"), Const(10)).free_vars() == {"a", "i"}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
