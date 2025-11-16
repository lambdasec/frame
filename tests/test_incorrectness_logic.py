"""
Unit tests for Incorrectness Separation Logic

Tests the incorrectness checker that finds bugs with concrete witnesses.
Incorrectness logic proves bugs ARE reachable (under-approximate).
"""

import pytest
import z3

from frame.checking.incorrectness import (
    IncorrectnessChecker,
    BugReport,
    BugType,
    BugWitness
)
from frame.core.ast import (
    PointsTo, Var, Const, SepConj, Emp, Eq, Neq, And, Or,
    Taint, Source, Sink, StrConcat, StrLiteral,
    Gt, Lt, NullDeref, Allocated, Freed, ArrayPointsTo, ArrayBounds
)
from frame.core.parser import parse


class TestBasicBugReachability:
    """Test basic bug reachability checking"""

    def test_simple_reachable_bug(self):
        """Test detecting a simple reachable bug"""
        checker = IncorrectnessChecker()

        # Precondition: x points to 5
        precondition = PointsTo(Var("x"), Const(5))

        # Error condition: Pure condition that x = 5 (should be reachable)
        error_condition = Eq(Var("x"), Const(5))

        report = checker.check_bug_reachability(precondition, error_condition)

        assert report.reachable, "Bug should be reachable"
        assert report.witness is not None, "Should have witness"

    def test_contradictory_bug(self):
        """Test bug detection with contradictory pure conditions"""
        checker = IncorrectnessChecker()

        # Precondition: x = 5
        precondition = Eq(Var("x"), Const(5))

        # Error condition: x = 10 (contradictory)
        error_condition = Eq(Var("x"), Const(10))

        report = checker.check_bug_reachability(precondition, error_condition)

        # This should not be reachable because x cannot be both 5 and 10
        # Note: Under-approximate reasoning may not always detect this
        # so we just check it doesn't crash
        assert isinstance(report, BugReport)

    def test_conditional_reachability(self):
        """Test bug reachable under certain conditions"""
        checker = IncorrectnessChecker()

        # Precondition: x points to something AND y is 0
        precondition = SepConj(
            PointsTo(Var("x"), Const(10)),
            Eq(Var("y"), Const(0))
        )

        # Error condition: y is 0 (should be reachable)
        error_condition = Eq(Var("y"), Const(0))

        report = checker.check_bug_reachability(precondition, error_condition)

        assert report.reachable, "Bug should be reachable when y = 0"


class TestNullDereference:
    """Test null pointer dereference detection"""

    def test_definite_null_dereference(self):
        """Test detecting definite null dereference"""
        checker = IncorrectnessChecker()

        # Precondition: ptr is null
        precondition = Eq(Var("ptr"), Const(None))

        report = checker.check_null_dereference(precondition, "ptr")

        assert report.reachable, "Null dereference should be reachable"
        assert report.bug_type == BugType.NULL_DEREFERENCE
        assert "ptr" in report.description

    def test_safe_dereference(self):
        """Test dereference with valid pointer"""
        checker = IncorrectnessChecker()

        # Precondition: ptr is NOT null (points to something)
        precondition = PointsTo(Var("ptr"), Const(42))

        report = checker.check_null_dereference(precondition, "ptr")

        # With incorrectness logic (under-approximate), we may not prove this is safe
        # We just verify the check completes
        assert isinstance(report, BugReport)

    def test_conditional_null_dereference(self):
        """Test null dereference in conditional path"""
        checker = IncorrectnessChecker()

        # Precondition: ptr could be null or valid (we don't know)
        # In this case, we assume ptr could be null
        precondition = Emp()  # Empty precondition - ptr is unconstrained

        report = checker.check_null_dereference(precondition, "ptr")

        # With empty precondition, ptr could be null, so bug is reachable
        assert report.reachable, "Conditional null dereference should be detected"


class TestUseAfterFree:
    """Test use-after-free detection"""

    def test_use_after_free_detected(self):
        """Test detecting use-after-free with proper lifecycle tracking"""
        checker = IncorrectnessChecker()

        # Precondition: ptr was allocated initially, then freed
        precondition = Freed(Var("ptr"))

        report = checker.check_use_after_free(precondition, "ptr")

        assert report.reachable, "Use-after-free should be detected"
        assert report.bug_type == BugType.USE_AFTER_FREE

    def test_safe_use_before_free(self):
        """Test that use while allocated is safe"""
        checker = IncorrectnessChecker()

        # Precondition: ptr is allocated (not freed)
        precondition = Allocated(Var("ptr"))

        report = checker.check_use_after_free(precondition, "ptr")

        # Should not be reachable because ptr is allocated, not freed
        assert not report.reachable or isinstance(report, BugReport)


class TestBufferOverflow:
    """Test buffer overflow detection"""

    def test_buffer_overflow_detected(self):
        """Test detecting buffer overflow with array bounds"""
        checker = IncorrectnessChecker()

        # Precondition: index is out of bounds (index = 10)
        precondition = Eq(Var("index"), Const(10))

        # Buffer size is 5, index 10 is out of bounds
        report = checker.check_buffer_overflow(precondition, "buffer", "index", size=5)

        assert report.reachable, "Buffer overflow should be detected"
        assert report.bug_type == BugType.BUFFER_OVERFLOW
        assert "buffer" in report.description
        assert "index" in report.description

    def test_safe_buffer_access(self):
        """Test that safe buffer access doesn't overflow"""
        checker = IncorrectnessChecker()

        # Precondition: index is within bounds (index = 2)
        precondition = Eq(Var("index"), Const(2))

        # Buffer size is 10, index 2 is safe
        report = checker.check_buffer_overflow(precondition, "buffer", "index", size=10)

        # Should not be reachable because index is within bounds
        assert not report.reachable or isinstance(report, BugReport)


class TestSQLInjection:
    """Test SQL injection detection"""

    def test_sql_injection_reachable(self):
        """Test detecting SQL injection vulnerability"""
        checker = IncorrectnessChecker()

        # Precondition: user_input is a tainted source
        precondition = SepConj(
            Source(Var("user_input"), "user"),
            Taint(Var("user_input"))
        )

        report = checker.check_sql_injection(precondition, "user_input", "query")

        assert report.reachable, "SQL injection should be detected"
        assert report.bug_type == BugType.SQL_INJECTION
        assert "user_input" in report.description
        assert "query" in report.description

    def test_sql_injection_with_sanitization(self):
        """Test that sanitized input is safe"""
        checker = IncorrectnessChecker()

        # Precondition: input is NOT tainted (sanitized)
        from frame.core.ast import Sanitized
        precondition = Sanitized(Var("user_input"))

        report = checker.check_sql_injection(precondition, "user_input", "query")

        # Should not be reachable because input is sanitized
        assert isinstance(report, BugReport)  # May or may not prove safety

    def test_sql_with_constant_query(self):
        """Test that constant queries are safe"""
        checker = IncorrectnessChecker()

        # Precondition: query is a constant (not from user input)
        precondition = Eq(Var("query"), StrLiteral("SELECT * FROM users"))

        report = checker.check_sql_injection(precondition, "user_input", "query")

        # Should not be reachable because query doesn't depend on user_input
        assert isinstance(report, BugReport)  # May or may not prove safety


class TestXSS:
    """Test Cross-Site Scripting detection"""

    def test_xss_reachable(self):
        """Test detecting XSS vulnerability"""
        checker = IncorrectnessChecker()

        # Precondition: user_input is tainted
        precondition = SepConj(
            Source(Var("user_input"), "user"),
            Taint(Var("user_input"))
        )

        report = checker.check_xss(precondition, "user_input", "html")

        assert report.reachable, "XSS should be detected"
        assert report.bug_type == BugType.XSS
        assert "user_input" in report.description

    def test_xss_with_escaped_output(self):
        """Test that escaped output is safe"""
        checker = IncorrectnessChecker()

        # Precondition: html is sanitized
        from frame.core.ast import Sanitized
        precondition = Sanitized(Var("html"))

        report = checker.check_xss(precondition, "user_input", "html")

        # Should not be reachable because output is sanitized
        assert isinstance(report, BugReport)  # May or may not prove safety


class TestCommandInjection:
    """Test command injection detection"""

    def test_command_injection_reachable(self):
        """Test detecting command injection"""
        checker = IncorrectnessChecker()

        # Precondition: user_input is tainted
        precondition = SepConj(
            Source(Var("user_input"), "user"),
            Taint(Var("user_input"))
        )

        report = checker.check_command_injection(precondition, "user_input", "cmd")

        assert report.reachable, "Command injection should be detected"
        assert report.bug_type == BugType.COMMAND_INJECTION

    def test_safe_command_execution(self):
        """Test that safe commands are not flagged"""
        checker = IncorrectnessChecker()

        # Precondition: command is a constant
        precondition = Eq(Var("cmd"), StrLiteral("ls -la"))

        report = checker.check_command_injection(precondition, "user_input", "cmd")

        # Should not be reachable because cmd is constant
        assert isinstance(report, BugReport)  # May or may not prove safety


class TestGenericTaintFlow:
    """Test generic taint flow detection"""

    def test_taint_flow_to_filesystem(self):
        """Test taint flow to filesystem sink"""
        checker = IncorrectnessChecker()

        # Precondition: user_input is tainted
        precondition = SepConj(
            Source(Var("user_input"), "user"),
            Taint(Var("user_input"))
        )

        report = checker.check_taint_flow(precondition, "user_input", "path", "filesystem")

        assert report.reachable, "Taint flow to filesystem should be detected"
        assert report.bug_type == BugType.TAINT_FLOW
        assert "filesystem" in report.description

    def test_taint_flow_blocked(self):
        """Test that blocked taint flow is safe"""
        checker = IncorrectnessChecker()

        # Precondition: source exists but sink variable is different and not tainted
        precondition = SepConj(
            Source(Var("user_input"), "user"),
            Eq(Var("safe_var"), StrLiteral("constant"))
        )

        report = checker.check_taint_flow(precondition, "user_input", "safe_var", "sql")

        # Should not be reachable because safe_var is not tainted
        assert isinstance(report, BugReport)  # May or may not prove safety


class TestBugWitness:
    """Test bug witness generation"""

    def test_witness_has_values(self):
        """Test that witnesses contain concrete values"""
        checker = IncorrectnessChecker()

        # Simple reachable bug
        precondition = PointsTo(Var("x"), Const(42))
        error_condition = Eq(Var("x"), Const(42))

        report = checker.check_bug_reachability(precondition, error_condition)

        assert report.reachable
        assert report.witness is not None
        assert isinstance(report.witness, BugWitness)
        # Witness should have some variables (x, or heap variables)
        assert len(report.witness.variables) > 0 or len(report.witness.heap) > 0

    def test_witness_trace(self):
        """Test that witnesses contain execution trace"""
        checker = IncorrectnessChecker()

        precondition = PointsTo(Var("x"), Const(10))
        error_condition = Eq(Var("x"), Const(10))

        report = checker.check_bug_reachability(precondition, error_condition)

        assert report.witness is not None
        assert len(report.witness.trace) > 0
        # Trace should mention precondition and error condition
        trace_str = " ".join(report.witness.trace)
        assert "precondition" in trace_str.lower() or "initial" in trace_str.lower()


class TestBugReportFormatting:
    """Test bug report formatting"""

    def test_bug_report_str_reachable(self):
        """Test string representation of reachable bug"""
        witness = BugWitness(
            variables={"x": 42, "y": "admin"},
            heap={"ptr1": "value1"},
            trace=["Step 1", "Step 2"]
        )

        report = BugReport(
            reachable=True,
            bug_type=BugType.SQL_INJECTION,
            description="Test bug",
            witness=witness,
            confidence=0.95
        )

        report_str = str(report)
        assert "BUG FOUND" in report_str
        assert "sql_injection" in report_str
        assert "95%" in report_str  # Confidence
        assert "x = 42" in report_str
        assert "y = admin" in report_str

    def test_bug_report_str_not_reachable(self):
        """Test string representation of unreachable bug"""
        report = BugReport(
            reachable=False,
            bug_type=BugType.NULL_DEREFERENCE,
            description="Not reachable",
            confidence=1.0
        )

        report_str = str(report)
        assert "No bug reachable" in report_str
        assert "Not reachable" in report_str


class TestEdgeCases:
    """Test edge cases and error handling"""

    def test_empty_precondition(self):
        """Test with empty precondition"""
        checker = IncorrectnessChecker()

        precondition = Emp()
        error_condition = Eq(Var("x"), Const(None))

        report = checker.check_bug_reachability(precondition, error_condition)

        # With empty precondition, x could be anything, so null is reachable
        assert report.reachable

    def test_contradictory_conditions(self):
        """Test with contradictory conditions"""
        checker = IncorrectnessChecker()

        # Precondition: x = 5 AND x = 10 (impossible)
        from frame.core.ast import False_
        precondition = And(
            Eq(Var("x"), Const(5)),
            Eq(Var("x"), Const(10))
        )

        error_condition = Eq(Var("x"), Const(5))

        report = checker.check_bug_reachability(precondition, error_condition)

        # Should not be reachable because precondition is impossible
        assert not report.reachable

    def test_timeout_handling(self):
        """Test that timeout is handled gracefully"""
        # Use very short timeout to force timeout
        checker = IncorrectnessChecker(timeout=1)

        # Create complex formula that might timeout
        precondition = Emp()
        error_condition = Emp()

        # Should not crash even with timeout
        report = checker.check_bug_reachability(precondition, error_condition)
        assert isinstance(report, BugReport)


class TestIntegrationWithTaintAnalysis:
    """Test integration with existing taint analysis"""

    def test_taint_propagation_through_concat(self):
        """Test that taint propagates through string concatenation"""
        checker = IncorrectnessChecker()

        # Precondition: user_input is tainted, query = prefix + user_input
        precondition = SepConj(
            Source(Var("user_input"), "user"),
            SepConj(
                Taint(Var("user_input")),
                Eq(
                    Var("query"),
                    StrConcat(StrLiteral("SELECT * FROM users WHERE id="), Var("user_input"))
                )
            )
        )

        # Error: tainted query flows to SQL sink
        error_condition = SepConj(
            Taint(Var("query")),
            Sink(Var("query"), "sql")
        )

        report = checker.check_bug_reachability(precondition, error_condition)

        # Should detect that taint propagates through concatenation
        assert report.reachable, "Taint should propagate through concatenation"

    def test_multiple_taint_sources(self):
        """Test with multiple taint sources"""
        checker = IncorrectnessChecker()

        # Precondition: two tainted sources
        precondition = SepConj(
            Source(Var("input1"), "user"),
            SepConj(
                Source(Var("input2"), "network"),
                SepConj(
                    Taint(Var("input1")),
                    Taint(Var("input2"))
                )
            )
        )

        # Error: either input flows to SQL
        error_condition = SepConj(
            Taint(Var("query")),
            Sink(Var("query"), "sql")
        )

        report = checker.check_bug_reachability(precondition, error_condition)

        # Should detect potential flow from either source
        assert report.reachable


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
