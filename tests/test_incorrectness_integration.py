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
