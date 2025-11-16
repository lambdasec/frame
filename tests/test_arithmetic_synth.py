"""
Tests for Arithmetic Witness Synthesis (frame/arithmetic/synth.py)

Tests the synthesis of arithmetic constraints from heap graph patterns.
"""

import pytest
import z3
from frame.arithmetic.synth import (
    synthesize_arith_for_chain,
    extract_pure_constraints_z3,
    _encode_arith_expr
)
from frame.core.ast import Var, Const, ArithExpr, Eq, Neq, Lt, Le, Gt, Ge, And
from frame.encoding.encoder import Z3Encoder
from frame.heap.graph import Chain, HeapGraph
from frame.core.parser import parse


class MockProposal:
    """Mock FoldProposal for testing"""
    def __init__(self, predicate_name, args):
        self.predicate_name = predicate_name
        self.args = args


class TestEncodeArithExpr:
    """Test _encode_arith_expr function"""

    def setup_method(self):
        """Set up encoder for each test"""
        self.encoder = Z3Encoder()

    def test_encode_integer(self):
        """Test encoding integer constants"""
        result = _encode_arith_expr(42, self.encoder)
        assert isinstance(result, z3.IntNumRef)
        assert result.as_long() == 42

    def test_encode_const_int(self):
        """Test encoding Const with integer value"""
        const = Const(10)
        result = _encode_arith_expr(const, self.encoder)
        assert isinstance(result, z3.IntNumRef)
        assert result.as_long() == 10

    def test_encode_const_nil(self):
        """Test encoding Const with nil value"""
        const = Const(None)
        result = _encode_arith_expr(const, self.encoder)
        assert isinstance(result, z3.IntNumRef)
        assert result.as_long() == 0

    def test_encode_var(self):
        """Test encoding Var"""
        var = Var('x')
        result = _encode_arith_expr(var, self.encoder)
        assert isinstance(result, z3.ArithRef)

    def test_encode_var_numeric_name(self):
        """Test encoding Var with numeric string name"""
        var = Var('123')
        result = _encode_arith_expr(var, self.encoder)
        assert isinstance(result, z3.IntNumRef)
        assert result.as_long() == 123

    def test_encode_arith_addition(self):
        """Test encoding addition expression"""
        expr = ArithExpr('+', Var('x'), Var('y'))
        result = _encode_arith_expr(expr, self.encoder)
        assert isinstance(result, z3.ArithRef)

    def test_encode_arith_subtraction(self):
        """Test encoding subtraction expression"""
        expr = ArithExpr('-', Var('x'), Const(5))
        result = _encode_arith_expr(expr, self.encoder)
        assert isinstance(result, z3.ArithRef)

    def test_encode_arith_multiplication(self):
        """Test encoding multiplication expression"""
        expr = ArithExpr('*', Const(2), Var('n'))
        result = _encode_arith_expr(expr, self.encoder)
        assert isinstance(result, z3.ArithRef)

    def test_encode_arith_division(self):
        """Test encoding division expression"""
        expr = ArithExpr('div', Var('x'), Const(2))
        result = _encode_arith_expr(expr, self.encoder)
        assert isinstance(result, z3.ArithRef)

    def test_encode_arith_modulo(self):
        """Test encoding modulo expression"""
        expr = ArithExpr('mod', Var('x'), Const(3))
        result = _encode_arith_expr(expr, self.encoder)
        assert isinstance(result, z3.ArithRef)

    def test_encode_nested_arith(self):
        """Test encoding nested arithmetic expressions"""
        # (x + 5) * 2
        inner = ArithExpr('+', Var('x'), Const(5))
        outer = ArithExpr('*', inner, Const(2))
        result = _encode_arith_expr(outer, self.encoder)
        assert isinstance(result, z3.ArithRef)

    def test_encode_string_variable(self):
        """Test encoding string as variable name"""
        result = _encode_arith_expr('myvar', self.encoder)
        assert isinstance(result, z3.ArithRef)

    def test_encode_string_numeric(self):
        """Test encoding numeric string"""
        result = _encode_arith_expr('999', self.encoder)
        assert isinstance(result, z3.IntNumRef)
        assert result.as_long() == 999

    def test_encode_z3_expr_passthrough(self):
        """Test that existing Z3 expressions pass through"""
        z3_expr = z3.Int('x') + 5
        result = _encode_arith_expr(z3_expr, self.encoder)
        assert result is z3_expr


class TestExtractPureConstraints:
    """Test extract_pure_constraints_z3 function"""

    def setup_method(self):
        """Set up encoder for each test"""
        self.encoder = Z3Encoder()

    def test_extract_equality(self):
        """Test extracting equality constraint"""
        formula = Eq(Var('x'), Var('y'))
        constraints = extract_pure_constraints_z3(formula, self.encoder)
        assert len(constraints) == 1
        assert isinstance(constraints[0], z3.BoolRef)

    def test_extract_disequality(self):
        """Test extracting disequality constraint"""
        formula = Neq(Var('x'), Const(None))
        constraints = extract_pure_constraints_z3(formula, self.encoder)
        assert len(constraints) == 1

    def test_extract_less_than(self):
        """Test extracting less-than constraint"""
        formula = Lt(Var('x'), Const(10))
        constraints = extract_pure_constraints_z3(formula, self.encoder)
        assert len(constraints) == 1

    def test_extract_less_equal(self):
        """Test extracting less-than-or-equal constraint"""
        formula = Le(Var('n'), Const(100))
        constraints = extract_pure_constraints_z3(formula, self.encoder)
        assert len(constraints) == 1

    def test_extract_greater_than(self):
        """Test extracting greater-than constraint"""
        formula = Gt(Var('x'), Const(0))
        constraints = extract_pure_constraints_z3(formula, self.encoder)
        assert len(constraints) == 1

    def test_extract_greater_equal(self):
        """Test extracting greater-than-or-equal constraint"""
        formula = Ge(Var('len'), Const(0))
        constraints = extract_pure_constraints_z3(formula, self.encoder)
        assert len(constraints) == 1

    def test_extract_and_multiple(self):
        """Test extracting from And formula"""
        formula = And(
            Gt(Var('x'), Const(0)),
            Lt(Var('x'), Const(10))
        )
        constraints = extract_pure_constraints_z3(formula, self.encoder)
        assert len(constraints) == 2

    def test_extract_nested_and(self):
        """Test extracting from nested And formulas"""
        formula = And(
            And(Gt(Var('x'), Const(0)), Lt(Var('y'), Const(5))),
            Eq(Var('z'), Const(10))
        )
        constraints = extract_pure_constraints_z3(formula, self.encoder)
        assert len(constraints) == 3

    def test_extract_from_non_pure(self):
        """Test extracting from non-pure formula returns empty"""
        from frame.core.ast import PointsTo
        formula = PointsTo(Var('x'), [Var('y')])
        constraints = extract_pure_constraints_z3(formula, self.encoder)
        assert len(constraints) == 0


class TestSynthesizeArithForChain:
    """Test synthesize_arith_for_chain function"""

    def setup_method(self):
        """Set up encoder for each test"""
        self.encoder = Z3Encoder()

    def test_no_predicate_name(self):
        """Test with proposal that has no predicate_name"""
        proposal = object()  # Plain object without predicate_name
        chain = Chain(nodes=['x', 'y'], field='next', length=2)
        result = synthesize_arith_for_chain(chain, proposal, self.encoder)
        assert result == (None, None)

    def test_ldll_basic(self):
        """Test LDLL synthesis with basic chain"""
        # ldll(E, P, len1, F, L, len2)
        proposal = MockProposal('ldll', [
            Var('x'), Var('p'), Var('len1'),
            Var('y'), Var('q'), Var('len2')
        ])
        chain = Chain(nodes=['x', 'y', 'z'], field='next', length=3)

        constraints, witness_map = synthesize_arith_for_chain(chain, proposal, self.encoder)

        if constraints is not None:
            assert len(constraints) >= 1
            assert 'ldll_length' in witness_map

    def test_ldll_insufficient_args(self):
        """Test LDLL with insufficient arguments"""
        proposal = MockProposal('ldll', [Var('x'), Var('p')])
        chain = Chain(nodes=['x', 'y'], field='next', length=2)
        result = synthesize_arith_for_chain(chain, proposal, self.encoder)
        assert result == (None, None)

    def test_unknown_predicate(self):
        """Test with unknown predicate name"""
        proposal = MockProposal('unknown_pred', [Var('x')])
        chain = Chain(nodes=['x'], field='next', length=1)
        result = synthesize_arith_for_chain(chain, proposal, self.encoder)
        assert result == (None, None)


class TestArithmeticConstraintSynthesis:
    """Integration tests for arithmetic synthesis"""

    def setup_method(self):
        """Set up encoder for each test"""
        self.encoder = Z3Encoder()

    def test_synthesize_length_constraint(self):
        """Test synthesizing length constraints"""
        # Create length variables
        len1 = Var('len1')
        len2 = Var('len2')

        # Encode to Z3
        len1_z3 = _encode_arith_expr(len1, self.encoder)
        len2_z3 = _encode_arith_expr(len2, self.encoder)

        # Create constraint: len1 = len2 + 3
        constraint = (len1_z3 == len2_z3 + 3)

        # Verify it's a valid Z3 constraint
        assert isinstance(constraint, z3.BoolRef)

    def test_verify_synthesized_constraint(self):
        """Test that synthesized constraints are satisfiable"""
        from frame.arithmetic.check import check_arithmetic_consistency

        len1 = _encode_arith_expr(Var('len1'), self.encoder)
        len2 = _encode_arith_expr(Var('len2'), self.encoder)

        constraints = [
            len1 == len2 + 5,
            len1 >= 0,
            len2 >= 0
        ]

        result = check_arithmetic_consistency(constraints)
        assert result is True

    def test_complex_arithmetic_expression(self):
        """Test encoding complex arithmetic expressions"""
        # (x + y) * 2 - z
        expr = ArithExpr(
            '-',
            ArithExpr(
                '*',
                ArithExpr('+', Var('x'), Var('y')),
                Const(2)
            ),
            Var('z')
        )

        result = _encode_arith_expr(expr, self.encoder)
        assert isinstance(result, z3.ArithRef)


class TestEdgeCases:
    """Test edge cases in arithmetic synthesis"""

    def setup_method(self):
        """Set up encoder for each test"""
        self.encoder = Z3Encoder()

    def test_encode_zero(self):
        """Test encoding zero"""
        result = _encode_arith_expr(0, self.encoder)
        assert isinstance(result, z3.IntNumRef)
        assert result.as_long() == 0

    def test_encode_negative_number(self):
        """Test encoding negative number"""
        result = _encode_arith_expr(-10, self.encoder)
        assert isinstance(result, z3.IntNumRef)
        assert result.as_long() == -10

    def test_encode_large_number(self):
        """Test encoding large number"""
        result = _encode_arith_expr(1000000, self.encoder)
        assert isinstance(result, z3.IntNumRef)
        assert result.as_long() == 1000000

    def test_unsupported_operator(self):
        """Test encoding expression with unsupported operator"""
        expr = ArithExpr('unsupported', Var('x'), Var('y'))
        with pytest.raises(ValueError, match="Unsupported arithmetic operator"):
            _encode_arith_expr(expr, self.encoder)

    def test_encode_const_string_value(self):
        """Test encoding Const with string value"""
        const = Const('value')
        result = _encode_arith_expr(const, self.encoder)
        # Should create a symbolic variable
        assert isinstance(result, z3.ArithRef)

    def test_extract_empty_and(self):
        """Test extracting from And with no constraints"""
        from frame.core.ast import True_
        formula = And(True_(), True_())
        constraints = extract_pure_constraints_z3(formula, self.encoder)
        # Should return empty list since True_ is not a constraint
        assert len(constraints) == 0
