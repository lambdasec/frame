"""
Unit tests for parsing string expressions and security predicates

Tests parsing support for:
- String literals
- String concatenation
- String functions (len, substr)
- String formulas (contains, matches)
- Security predicates (taint, sanitized, source, sink)
- Error states (error, null_deref, use_after_free, buffer_overflow)
"""

import pytest
from frame.core.parser import parse, ParseError
from frame.core.ast import (
    # String expressions
    StrLiteral, StrConcat, StrLen, StrSubstr,
    # String formulas
    StrContains, StrMatches,
    # Security predicates
    Taint, Sanitized, Source, Sink,
    # Error states
    Error, NullDeref, UseAfterFree, BufferOverflow,
    # Basic types
    Var, Const
)


class TestStringLiterals:
    """Test parsing string literals"""

    def test_simple_string_literal(self):
        """Test parsing simple string literal"""
        result = parse('"hello" = "world"')
        assert isinstance(result, type(parse("x = y")))  # Eq type
        assert isinstance(result.left, StrLiteral)
        assert isinstance(result.right, StrLiteral)
        assert result.left.value == "hello"
        assert result.right.value == "world"

    def test_empty_string_literal(self):
        """Test parsing empty string"""
        result = parse('x = ""')
        assert isinstance(result.right, StrLiteral)
        assert result.right.value == ""

    def test_string_with_spaces(self):
        """Test parsing string with spaces"""
        result = parse('s = "hello world"')
        assert isinstance(result.right, StrLiteral)
        assert result.right.value == "hello world"

    def test_string_with_escapes(self):
        """Test parsing string with escape sequences"""
        result = parse('s = "hello\\nworld"')
        assert isinstance(result.right, StrLiteral)
        assert result.right.value == "hello\nworld"

    def test_string_with_quotes(self):
        """Test parsing string with escaped quotes"""
        result = parse('s = "say \\"hello\\""')
        assert isinstance(result.right, StrLiteral)
        assert result.right.value == 'say "hello"'


class TestStringConcatenation:
    """Test parsing string concatenation"""

    def test_simple_concat(self):
        """Test simple string concatenation"""
        result = parse('x = "hello" ++ "world"')
        assert isinstance(result.right, StrConcat)
        assert isinstance(result.right.left, StrLiteral)
        assert isinstance(result.right.right, StrLiteral)
        assert result.right.left.value == "hello"
        assert result.right.right.value == "world"

    def test_concat_with_vars(self):
        """Test concatenation with variables"""
        result = parse('z = x ++ y')
        assert isinstance(result.right, StrConcat)
        assert isinstance(result.right.left, Var)
        assert isinstance(result.right.right, Var)
        assert result.right.left.name == "x"
        assert result.right.right.name == "y"

    def test_concat_mixed(self):
        """Test concatenation of literal and variable"""
        result = parse('query = "SELECT * FROM users WHERE id=" ++ user_input')
        assert isinstance(result.right, StrConcat)
        assert isinstance(result.right.left, StrLiteral)
        assert isinstance(result.right.right, Var)
        assert result.right.left.value == "SELECT * FROM users WHERE id="
        assert result.right.right.name == "user_input"

    def test_concat_chained(self):
        """Test chained concatenation"""
        result = parse('s = "a" ++ "b" ++ "c"')
        assert isinstance(result.right, StrConcat)
        # Should be left-associative: ("a" ++ "b") ++ "c"
        assert isinstance(result.right.left, StrConcat)
        assert isinstance(result.right.right, StrLiteral)


class TestStringFunctions:
    """Test parsing string functions"""

    def test_len_literal(self):
        """Test len() with string literal"""
        result = parse('n = len("hello")')
        assert isinstance(result.right, StrLen)
        assert isinstance(result.right.string, StrLiteral)
        assert result.right.string.value == "hello"

    def test_len_var(self):
        """Test len() with variable"""
        result = parse('n = len(password)')
        assert isinstance(result.right, StrLen)
        assert isinstance(result.right.string, Var)
        assert result.right.string.name == "password"

    def test_len_concat(self):
        """Test len() with concatenation"""
        result = parse('n = len(x ++ y)')
        assert isinstance(result.right, StrLen)
        assert isinstance(result.right.string, StrConcat)

    def test_substr_basic(self):
        """Test substr() with basic arguments"""
        result = parse('s = substr("hello", 0, 3)')
        assert isinstance(result.right, StrSubstr)
        assert isinstance(result.right.string, StrLiteral)
        assert isinstance(result.right.start, Const)
        assert isinstance(result.right.end, Const)
        assert result.right.string.value == "hello"
        assert result.right.start.value == 0
        assert result.right.end.value == 3

    def test_substr_with_vars(self):
        """Test substr() with variable arguments"""
        result = parse('s2 = substr(s1, i, j)')
        assert isinstance(result.right, StrSubstr)
        assert isinstance(result.right.string, Var)
        assert isinstance(result.right.start, Var)
        assert isinstance(result.right.end, Var)
        assert result.right.string.name == "s1"
        assert result.right.start.name == "i"
        assert result.right.end.name == "j"


class TestStringFormulas:
    """Test parsing string formulas"""

    def test_contains_basic(self):
        """Test string contains"""
        result = parse('s1 contains "world"')
        assert isinstance(result, StrContains)
        assert isinstance(result.haystack, Var)
        assert isinstance(result.needle, StrLiteral)
        assert result.haystack.name == "s1"
        assert result.needle.value == "world"

    def test_contains_both_vars(self):
        """Test contains with both variables"""
        result = parse('haystack contains needle')
        assert isinstance(result, StrContains)
        assert isinstance(result.haystack, Var)
        assert isinstance(result.needle, Var)

    def test_matches_basic(self):
        """Test regex matching"""
        result = parse('input matches /[0-9]+/')
        assert isinstance(result, StrMatches)
        assert isinstance(result.string, Var)
        assert result.string.name == "input"
        assert result.regex == "[0-9]+"

    def test_matches_complex_regex(self):
        """Test matches with complex regex"""
        result = parse('email matches /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$/')
        assert isinstance(result, StrMatches)
        assert "+" in result.regex
        assert "@" in result.regex


class TestSecurityPredicates:
    """Test parsing security predicates"""

    def test_taint_basic(self):
        """Test taint predicate"""
        result = parse('taint(user_input)')
        assert isinstance(result, Taint)
        assert isinstance(result.var, Var)
        assert result.var.name == "user_input"

    def test_taint_with_expr(self):
        """Test taint with complex expression"""
        result = parse('taint(x ++ y)')
        assert isinstance(result, Taint)
        assert isinstance(result.var, StrConcat)

    def test_sanitized_basic(self):
        """Test sanitized predicate"""
        result = parse('sanitized(clean_data)')
        assert isinstance(result, Sanitized)
        assert isinstance(result.var, Var)
        assert result.var.name == "clean_data"

    def test_source_basic(self):
        """Test source predicate"""
        result = parse('source(input, "user")')
        assert isinstance(result, Source)
        assert isinstance(result.var, Var)
        assert result.var.name == "input"
        assert result.source_type == "user"

    def test_source_types(self):
        """Test different source types"""
        types = ["user", "network", "file", "env", "database"]
        for source_type in types:
            result = parse(f'source(data, "{source_type}")')
            assert isinstance(result, Source)
            assert result.source_type == source_type

    def test_sink_basic(self):
        """Test sink predicate"""
        result = parse('sink(query, "sql")')
        assert isinstance(result, Sink)
        assert isinstance(result.var, Var)
        assert result.var.name == "query"
        assert result.sink_type == "sql"

    def test_sink_types(self):
        """Test different sink types"""
        types = ["sql", "shell", "html", "filesystem"]
        for sink_type in types:
            result = parse(f'sink(output, "{sink_type}")')
            assert isinstance(result, Sink)
            assert result.sink_type == sink_type


class TestErrorStates:
    """Test parsing error state predicates"""

    def test_error_basic(self):
        """Test generic error"""
        result = parse('error()')
        assert isinstance(result, Error)
        assert result.kind is None

    def test_error_with_kind(self):
        """Test error with kind"""
        result = parse('error("division_by_zero")')
        assert isinstance(result, Error)
        assert result.kind == "division_by_zero"

    def test_null_deref_basic(self):
        """Test null dereference"""
        result = parse('null_deref(ptr)')
        assert isinstance(result, NullDeref)
        assert isinstance(result.var, Var)
        assert result.var.name == "ptr"

    def test_use_after_free_basic(self):
        """Test use-after-free"""
        result = parse('use_after_free(buffer)')
        assert isinstance(result, UseAfterFree)
        assert isinstance(result.var, Var)
        assert result.var.name == "buffer"

    def test_buffer_overflow_basic(self):
        """Test buffer overflow"""
        result = parse('buffer_overflow(arr, i, 100)')
        assert isinstance(result, BufferOverflow)
        assert isinstance(result.array, Var)
        assert isinstance(result.index, Var)
        assert isinstance(result.size, Const)
        assert result.array.name == "arr"
        assert result.index.name == "i"
        assert result.size.value == 100


class TestComplexFormulas:
    """Test parsing complex formulas with strings and security"""

    def test_sql_injection_pattern(self):
        """Test SQL injection vulnerability pattern"""
        result = parse('source(input, "user") * taint(input) * sink(query, "sql")')
        # Should be SepConj of SepConj of Source, Taint, and Sink
        assert result.free_vars() == {"input", "query"}

    def test_tainted_concat_to_sink(self):
        """Test tainted concatenation flowing to sink"""
        result = parse('taint(user_input) * query = "SELECT * FROM t WHERE id=" ++ user_input * sink(query, "sql")')
        assert result.free_vars() == {"user_input", "query"}

    def test_sanitization_flow(self):
        """Test sanitization flow"""
        result = parse('taint(dirty) * clean = substr(dirty, 0, 10) * sanitized(clean)')
        assert result.free_vars() == {"dirty", "clean"}

    def test_heap_with_strings(self):
        """Test heap formulas with strings"""
        result = parse('x |-> "tainted data" * taint(x)')
        assert result.free_vars() == {"x"}

    def test_complex_security_flow(self):
        """Test complex security data flow"""
        formula = '''
            source(request, "network") *
            taint(request) *
            data = substr(request, 0, len(request)) *
            output = "Response: " ++ data *
            sink(output, "html")
        '''
        result = parse(formula)
        assert "request" in result.free_vars()
        assert "output" in result.free_vars()

    def test_error_with_precondition(self):
        """Test error state with precondition"""
        result = parse('x = nil * null_deref(x)')
        assert result.free_vars() == {"x"}

    def test_buffer_overflow_with_constraint(self):
        """Test buffer overflow with size constraint"""
        result = parse('i >= 10 * buffer_overflow(arr, i, 10)')
        assert "arr" in result.free_vars()
        assert "i" in result.free_vars()


class TestOperatorPrecedence:
    """Test operator precedence with strings"""

    def test_concat_vs_sepconj(self):
        """Test ++ binds tighter than *"""
        result = parse('x = "a" ++ "b" * y = "c"')
        # Should parse as: (x = ("a" ++ "b")) * (y = "c")
        assert result.free_vars() == {"x", "y"}

    def test_arithmetic_vs_concat(self):
        """Test arithmetic vs string concat precedence"""
        result = parse('n = len(s) + 1')
        # Should parse as: n = (len(s) + 1)
        assert result.free_vars() == {"n", "s"}


class TestParsingErrors:
    """Test error handling in parser"""

    def test_unterminated_string(self):
        """Test error on unterminated string"""
        with pytest.raises(ParseError):
            parse('x = "hello')

    def test_missing_comma_in_source(self):
        """Test error on missing comma"""
        with pytest.raises(ParseError):
            parse('source(x "user")')

    def test_missing_parenthesis_in_taint(self):
        """Test error on missing parenthesis"""
        with pytest.raises(ParseError):
            parse('taint(x')

    def test_invalid_regex_syntax(self):
        """Test matches without proper regex delimiters"""
        with pytest.raises(ParseError):
            parse('x matches "pattern"')  # Should use /pattern/


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
