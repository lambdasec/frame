"""
Unit tests for Z3 encoding of string expressions and security predicates

Tests encoding of:
- String literals and operations
- String formulas (contains, matches)
- Taint tracking
- Security predicates (source, sink)
- Error states
"""

import pytest
import z3
from frame.encoding.encoder import Z3Encoder
from frame.core.parser import parse
from frame.core.ast import *


class TestStringExpressionEncoding:
    """Test encoding of string expressions to Z3"""

    def test_string_literal_encoding(self):
        """Test encoding string literals"""
        encoder = Z3Encoder()
        literal = StrLiteral("hello")
        z3_expr = encoder.encode_expr(literal)

        assert isinstance(z3_expr, z3.SeqRef)
        # Check that it's a string value
        solver = z3.Solver()
        solver.add(z3_expr == z3.StringVal("hello"))
        assert solver.check() == z3.sat

    def test_string_concat_encoding(self):
        """Test encoding string concatenation"""
        encoder = Z3Encoder()
        concat = StrConcat(StrLiteral("hello"), StrLiteral("world"))
        z3_expr = encoder.encode_expr(concat)

        solver = z3.Solver()
        solver.add(z3_expr == z3.StringVal("helloworld"))
        assert solver.check() == z3.sat

    def test_string_len_encoding(self):
        """Test encoding string length"""
        encoder = Z3Encoder()
        length = StrLen(StrLiteral("hello"))
        z3_expr = encoder.encode_expr(length)

        solver = z3.Solver()
        solver.add(z3_expr == 5)
        assert solver.check() == z3.sat

    def test_string_substr_encoding(self):
        """Test encoding substring"""
        encoder = Z3Encoder()
        substr = StrSubstr(StrLiteral("hello"), Const(0), Const(2))
        z3_expr = encoder.encode_expr(substr)

        solver = z3.Solver()
        solver.add(z3_expr == z3.StringVal("he"))
        assert solver.check() == z3.sat

    def test_string_variable_concat(self):
        """Test encoding concatenation with variables"""
        encoder = Z3Encoder()
        # s = "hello" ++ x
        concat = StrConcat(StrLiteral("hello"), Var("x"))
        z3_expr = encoder.encode_expr(concat)

        solver = z3.Solver()
        x = z3.String('x')
        solver.add(z3_expr == z3.Concat(z3.StringVal("hello"), x))
        solver.add(x == z3.StringVal("world"))
        assert solver.check() == z3.sat
        model = solver.model()
        assert str(model.eval(z3_expr)) == '"helloworld"'


class TestStringFormulaEncoding:
    """Test encoding of string formulas"""

    def test_str_contains_encoding(self):
        """Test encoding string contains"""
        encoder = Z3Encoder()
        contains = StrContains(StrLiteral("hello world"), StrLiteral("world"))
        z3_formula = encoder.encode_pure(contains)

        solver = z3.Solver()
        solver.add(z3_formula)
        assert solver.check() == z3.sat

    def test_str_contains_negative(self):
        """Test string contains when substring not present"""
        encoder = Z3Encoder()
        contains = StrContains(StrLiteral("hello"), StrLiteral("world"))
        z3_formula = encoder.encode_pure(contains)

        solver = z3.Solver()
        solver.add(z3_formula)
        assert solver.check() == z3.unsat

    def test_str_matches_simple(self):
        """Test encoding regex matching"""
        encoder = Z3Encoder()
        # Simple pattern that should work
        matches = StrMatches(StrLiteral("123"), "[0-9]+")
        z3_formula = encoder.encode_pure(matches)

        solver = z3.Solver()
        solver.add(z3_formula)
        # With proper regex parser, this should be SAT
        result = solver.check()
        assert result == z3.sat


class TestTaintTrackingEncoding:
    """Test encoding of taint tracking predicates"""

    def test_taint_encoding(self):
        """Test encoding taint predicate"""
        encoder = Z3Encoder()
        taint = Taint(Var("user_input"))
        z3_formula = encoder.encode_pure(taint)

        # Taint should encode to IsMember check
        assert isinstance(z3_formula, z3.BoolRef)

    def test_sanitized_encoding(self):
        """Test encoding sanitized predicate"""
        encoder = Z3Encoder()
        sanitized = Sanitized(Var("clean_data"))
        z3_formula = encoder.encode_pure(sanitized)

        assert isinstance(z3_formula, z3.BoolRef)

    def test_source_encoding(self):
        """Test encoding source predicate"""
        encoder = Z3Encoder()
        source = Source(Var("input"), "user")
        z3_formula = encoder.encode_pure(source)

        # Source should mark the variable as tainted
        assert encoder.sources.get("input") == "user"
        assert isinstance(z3_formula, z3.BoolRef)

    def test_sink_encoding(self):
        """Test encoding sink predicate"""
        encoder = Z3Encoder()
        sink = Sink(Var("query"), "sql")
        z3_formula = encoder.encode_pure(sink)

        # Sink should track the variable
        assert encoder.sinks.get("query") == "sql"
        assert isinstance(z3_formula, z3.BoolRef)

    def test_taint_flow_detection(self):
        """Test detecting taint flow"""
        encoder = Z3Encoder()

        # Create a formula: source(x, "user") * taint(x) * sink(y, "sql") * x = y
        formula = parse('source(x, "user") * taint(x) * sink(y, "sql") * x = y')
        z3_formula = encoder.encode_pure(formula)

        solver = z3.Solver()
        solver.add(z3_formula)
        result = solver.check()

        # Should be satisfiable - taint can flow from x to y
        assert result == z3.sat


class TestErrorStateEncoding:
    """Test encoding of error states for incorrectness logic"""

    def test_error_encoding(self):
        """Test encoding generic error"""
        encoder = Z3Encoder()
        error = Error("division_by_zero")
        z3_formula = encoder.encode_pure(error)

        # Error is just a marker, should be true
        assert isinstance(z3_formula, z3.BoolRef)

    def test_null_deref_encoding(self):
        """Test encoding null dereference"""
        encoder = Z3Encoder()
        null_deref = NullDeref(Var("ptr"))
        z3_formula = encoder.encode_pure(null_deref)

        solver = z3.Solver()
        ptr = z3.Int('ptr')
        solver.add(z3_formula)
        solver.add(ptr == 0)  # ptr is nil
        assert solver.check() == z3.sat

        # If ptr is not nil, null_deref should be false
        solver2 = z3.Solver()
        solver2.add(z3_formula)
        solver2.add(ptr != 0)
        assert solver2.check() == z3.unsat

    def test_buffer_overflow_encoding(self):
        """Test encoding buffer overflow"""
        encoder = Z3Encoder()
        overflow = BufferOverflow(Var("arr"), Var("i"), Const(10))
        z3_formula = encoder.encode_pure(overflow)

        solver = z3.Solver()
        i = z3.Int('i')
        solver.add(z3_formula)
        solver.add(i >= 10)  # Overflow condition
        assert solver.check() == z3.sat

        # If i < 10, no overflow
        solver2 = z3.Solver()
        solver2.add(z3_formula)
        solver2.add(i < 10)
        assert solver2.check() == z3.unsat


class TestComplexFormulas:
    """Test encoding of complex formulas combining multiple features"""

    def test_string_equality_check(self):
        """Test string equality in formulas"""
        encoder = Z3Encoder()
        # "hello" = "hello"
        formula = Eq(StrLiteral("hello"), StrLiteral("hello"))
        z3_formula = encoder.encode_pure(formula)

        solver = z3.Solver()
        solver.add(z3_formula)
        assert solver.check() == z3.sat

    def test_string_length_constraint(self):
        """Test string length constraints"""
        encoder = Z3Encoder()
        # len("hello") = 5
        formula = Eq(StrLen(StrLiteral("hello")), Const(5))
        z3_formula = encoder.encode_pure(formula)

        solver = z3.Solver()
        solver.add(z3_formula)
        assert solver.check() == z3.sat

    def test_tainted_string_concat(self):
        """Test taint on concatenated strings"""
        encoder = Z3Encoder()
        # taint(x) * y = "prefix" ++ x
        formula = parse('taint(x)')
        z3_formula = encoder.encode_pure(formula)

        assert isinstance(z3_formula, z3.BoolRef)

    def test_sql_injection_pattern(self):
        """Test SQL injection vulnerability pattern"""
        encoder = Z3Encoder()
        # source(input, "user") * taint(input) * sink(query, "sql")
        formula = parse('source(input, "user") * taint(input) * sink(query, "sql")')

        # Extract pure constraints (this is a non-spatial formula)
        z3_formula = encoder.encode_pure(formula)

        # Check that sources and sinks are tracked
        assert "input" in encoder.sources
        assert encoder.sources["input"] == "user"
        assert "query" in encoder.sinks
        assert encoder.sinks["query"] == "sql"


class TestRegressions:
    """Ensure no regressions in existing functionality"""

    def test_integer_arithmetic_still_works(self):
        """Ensure integer arithmetic still works"""
        encoder = Z3Encoder()
        # x + 5 = 10
        from frame.core.ast import ArithExpr
        formula = Eq(ArithExpr('+', Var('x'), Const(5)), Const(10))
        z3_formula = encoder.encode_pure(formula)

        solver = z3.Solver()
        x = z3.Int('x')
        solver.add(z3_formula)
        assert solver.check() == z3.sat
        model = solver.model()
        assert model.eval(x).as_long() == 5

    def test_basic_entailment_still_works(self):
        """Ensure basic separation logic still works"""
        encoder = Z3Encoder()
        # x |-> 5 (basic points-to)
        from frame import EntailmentChecker
        checker = EntailmentChecker()
        result = checker.check_entailment("x |-> 5 |- x |-> 5")
        assert result.valid


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
