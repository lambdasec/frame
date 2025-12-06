"""
Formula inspection helper functions

Provides utility functions for inspecting formula structure and contents.
These are extracted from EntailmentChecker to reduce its size and improve modularity.
"""

from frame.core.ast import Formula


def has_predicate_calls(formula: Formula) -> bool:
    """
    Check if a formula contains any predicate calls.
    This is used to determine if the UNSAT antecedent check should be applied.
    """
    from frame.core.ast import PredicateCall, SepConj, And, Or, Not, Exists, Forall

    if isinstance(formula, PredicateCall):
        return True
    elif isinstance(formula, (SepConj, And, Or)):
        return has_predicate_calls(formula.left) or has_predicate_calls(formula.right)
    elif isinstance(formula, Not):
        return has_predicate_calls(formula.formula)
    elif isinstance(formula, (Exists, Forall)):
        return has_predicate_calls(formula.formula)
    else:
        return False


def has_concrete_spatial(formula: Formula) -> bool:
    """
    Check if a formula contains concrete spatial assertions (points-to, emp).
    This is used to distinguish concrete heaps from pure predicate formulas.
    """
    from frame.core.ast import PointsTo, Emp, SepConj, And, Or, Not, Exists, Forall

    if isinstance(formula, (PointsTo, Emp)):
        return True
    elif isinstance(formula, (SepConj, And, Or)):
        return has_concrete_spatial(formula.left) or has_concrete_spatial(formula.right)
    elif isinstance(formula, Not):
        return has_concrete_spatial(formula.formula)
    elif isinstance(formula, (Exists, Forall)):
        return has_concrete_spatial(formula.formula)
    else:
        return False


def count_formulas_by_type(formula: Formula, formula_type) -> int:
    """Count how many subformulas of given type appear in formula"""
    from frame.core.ast import SepConj, And, Or, Not, Exists, Forall

    if isinstance(formula, formula_type):
        return 1
    elif isinstance(formula, (SepConj, And, Or)):
        return (count_formulas_by_type(formula.left, formula_type) +
                count_formulas_by_type(formula.right, formula_type))
    elif isinstance(formula, (Not, Exists, Forall)):
        return count_formulas_by_type(formula.formula, formula_type)
    else:
        return 0


def contains_formula_type(formula: Formula, formula_type) -> bool:
    """Check if formula contains any subformula of given type"""
    return count_formulas_by_type(formula, formula_type) > 0


def collect_variables(formula: Formula) -> set:
    """Collect all variable names from a formula"""
    from frame.core.ast import (
        Var, Const, PointsTo, SepConj, And, Or, Not, Exists, Forall,
        PredicateCall, Emp, Eq, Neq, True_, False_, Wand, ArithExpr
    )

    vars_found = set()

    if isinstance(formula, Var):
        vars_found.add(formula.name)
    elif isinstance(formula, Const):
        pass  # Constants don't have variables
    elif isinstance(formula, PointsTo):
        if isinstance(formula.location, Var):
            vars_found.add(formula.location.name)
        for val in formula.values:
            if isinstance(val, Var):
                vars_found.add(val.name)
    elif isinstance(formula, (SepConj, And, Or)):
        vars_found.update(collect_variables(formula.left))
        vars_found.update(collect_variables(formula.right))
    elif isinstance(formula, Wand):
        vars_found.update(collect_variables(formula.left))
        vars_found.update(collect_variables(formula.right))
    elif isinstance(formula, Not):
        vars_found.update(collect_variables(formula.formula))
    elif isinstance(formula, (Exists, Forall)):
        # Don't include bound variables
        inner_vars = collect_variables(formula.formula)
        inner_vars.discard(formula.var)
        vars_found.update(inner_vars)
    elif isinstance(formula, PredicateCall):
        for arg in formula.args:
            if isinstance(arg, Var):
                vars_found.add(arg.name)
    elif isinstance(formula, (Eq, Neq)):
        if isinstance(formula.left, Var):
            vars_found.add(formula.left.name)
        if isinstance(formula.right, Var):
            vars_found.add(formula.right.name)
    elif isinstance(formula, ArithExpr):
        if isinstance(formula.left, Var):
            vars_found.add(formula.left.name)
        if isinstance(formula.right, Var):
            vars_found.add(formula.right.name)

    return vars_found


def substitute_var_in_formula(formula: Formula, old_var: str, new_expr) -> Formula:
    """Substitute all occurrences of old_var with new_expr in formula"""
    from frame.core.ast import (
        Var, Const, PointsTo, SepConj, And, Or, Not, Exists, Forall,
        PredicateCall, Emp, Eq, Neq, True_, False_, Wand, ArithExpr
    )
    from frame.core._ast_pure import Lt, Le  # Comparison operators

    def sub_expr(expr):
        if isinstance(expr, Var) and expr.name == old_var:
            return new_expr
        elif isinstance(expr, ArithExpr):
            return ArithExpr(expr.op, sub_expr(expr.left), sub_expr(expr.right))
        return expr

    if isinstance(formula, Var):
        return new_expr if formula.name == old_var else formula
    elif isinstance(formula, (Const, Emp, True_, False_)):
        return formula
    elif isinstance(formula, PointsTo):
        new_loc = sub_expr(formula.location)
        new_vals = [sub_expr(v) for v in formula.values]
        return PointsTo(new_loc, new_vals)
    elif isinstance(formula, SepConj):
        return SepConj(
            substitute_var_in_formula(formula.left, old_var, new_expr),
            substitute_var_in_formula(formula.right, old_var, new_expr)
        )
    elif isinstance(formula, And):
        return And(
            substitute_var_in_formula(formula.left, old_var, new_expr),
            substitute_var_in_formula(formula.right, old_var, new_expr)
        )
    elif isinstance(formula, Or):
        return Or(
            substitute_var_in_formula(formula.left, old_var, new_expr),
            substitute_var_in_formula(formula.right, old_var, new_expr)
        )
    elif isinstance(formula, Wand):
        return Wand(
            substitute_var_in_formula(formula.left, old_var, new_expr),
            substitute_var_in_formula(formula.right, old_var, new_expr)
        )
    elif isinstance(formula, Not):
        return Not(substitute_var_in_formula(formula.formula, old_var, new_expr))
    elif isinstance(formula, Exists):
        if formula.var == old_var:
            return formula  # Don't substitute bound variable
        return Exists(formula.var, substitute_var_in_formula(formula.formula, old_var, new_expr))
    elif isinstance(formula, Forall):
        if formula.var == old_var:
            return formula  # Don't substitute bound variable
        return Forall(formula.var, substitute_var_in_formula(formula.formula, old_var, new_expr))
    elif isinstance(formula, PredicateCall):
        new_args = [sub_expr(arg) for arg in formula.args]
        return PredicateCall(formula.name, new_args)
    elif isinstance(formula, Eq):
        return Eq(sub_expr(formula.left), sub_expr(formula.right))
    elif isinstance(formula, Neq):
        return Neq(sub_expr(formula.left), sub_expr(formula.right))
    # Handle comparison operators (Lt, Le, etc.)
    elif isinstance(formula, Lt):
        return Lt(sub_expr(formula.left), sub_expr(formula.right))
    elif isinstance(formula, Le):
        return Le(sub_expr(formula.left), sub_expr(formula.right))
    else:
        return formula


def try_instantiate_existential(antecedent: Formula, consequent: Formula) -> list:
    """
    Try to instantiate existential quantifiers in consequent with witnesses from antecedent.

    For consequent of the form `exists x. P(x)`, try each variable from antecedent as witness.
    Returns a list of (witness, instantiated_consequent) pairs to try.

    This is a key technique for handling shid_entl and shidlia_entl benchmarks
    which have existential quantifiers in the consequent.

    Enhanced for SHIDLIA benchmarks: Also generates arithmetic witnesses like n+1
    when the existential appears to be a length parameter.
    """
    from frame.core.ast import Exists, Var, Const, ArithExpr, PredicateCall

    if not isinstance(consequent, Exists):
        return []

    # Collect variables from antecedent
    ant_vars = collect_variables(antecedent)

    # Get the bound variable and body
    bound_var = consequent.var
    body = consequent.formula

    # Generate instantiations for each antecedent variable
    instantiations = []
    for var_name in ant_vars:
        # Substitute bound variable with the antecedent variable
        witness = Var(var_name)
        instantiated = substitute_var_in_formula(body, bound_var, witness)
        instantiations.append((var_name, instantiated))

    # Also try nil as a witness (common in DLL benchmarks)
    nil_witness = Const(None)
    instantiated_nil = substitute_var_in_formula(body, bound_var, nil_witness)
    instantiations.append(("nil", instantiated_nil))

    # SHIDLIA enhancement: Try arithmetic witnesses
    # For DLL/list length composition patterns, try n+1 and n-1 as witnesses
    length_vars = _extract_length_vars_from_predicates(antecedent)
    for len_var in length_vars:
        # Try len_var + 1 (for append operations)
        plus_one = ArithExpr('+', Var(len_var), Const(1))
        instantiated_plus = substitute_var_in_formula(body, bound_var, plus_one)
        instantiations.append((f"{len_var}+1", instantiated_plus))

        # Try len_var - 1 (for remove/pop operations)
        minus_one = ArithExpr('-', Var(len_var), Const(1))
        instantiated_minus = substitute_var_in_formula(body, bound_var, minus_one)
        instantiations.append((f"{len_var}-1", instantiated_minus))

    # For length composition, try sum of length vars
    if len(length_vars) >= 2:
        length_var_list = list(length_vars)
        for i, lv1 in enumerate(length_var_list):
            for lv2 in length_var_list[i+1:]:
                # Try lv1 + lv2 (for concatenation)
                sum_expr = ArithExpr('+', Var(lv1), Var(lv2))
                instantiated_sum = substitute_var_in_formula(body, bound_var, sum_expr)
                instantiations.append((f"{lv1}+{lv2}", instantiated_sum))

                # Try lv1 + lv2 + 1 (for concat with extra node)
                sum_plus_one = ArithExpr('+', sum_expr, Const(1))
                instantiated_sum_plus = substitute_var_in_formula(body, bound_var, sum_plus_one)
                instantiations.append((f"{lv1}+{lv2}+1", instantiated_sum_plus))

                # Try lv1 + lv2 - 1 (for concat minus overlap)
                sum_minus_one = ArithExpr('-', sum_expr, Const(1))
                instantiated_sum_minus = substitute_var_in_formula(body, bound_var, sum_minus_one)
                instantiations.append((f"{lv1}+{lv2}-1", instantiated_sum_minus))

    return instantiations


def _extract_length_vars_from_predicates(formula: Formula) -> set:
    """
    Extract variable names that appear to be length parameters in predicates.

    Length parameters are typically the last integer argument in DLL/list predicates.
    Common patterns:
    - dll(head, prev, tail, next, LENGTH)
    - dllnull(head, prev, LENGTH)
    - ls(start, end, LENGTH)
    """
    from frame.core.ast import PredicateCall, Var, SepConj, And, Or, Exists, Forall

    length_vars = set()

    def extract(f: Formula):
        if isinstance(f, PredicateCall):
            # Check for DLL-like predicates with length parameter
            name_lower = f.name.lower()
            if any(x in name_lower for x in ['dll', 'ls', 'list', 'len']):
                # The last argument is often the length
                if f.args and isinstance(f.args[-1], Var):
                    length_vars.add(f.args[-1].name)
                # For 5-arg DLL predicates, the 5th arg is length
                if len(f.args) >= 5 and isinstance(f.args[4], Var):
                    length_vars.add(f.args[4].name)
        elif isinstance(f, (SepConj, And, Or)):
            extract(f.left)
            extract(f.right)
        elif isinstance(f, (Exists, Forall)):
            extract(f.formula)

    extract(formula)
    return length_vars


def try_instantiate_nested_existentials(antecedent: Formula, consequent: Formula) -> list:
    """
    Try to instantiate TWO nested existential quantifiers in consequent.

    For SHIDLIA benchmarks, consequent often has form:
        exists u. exists k. (z |-> (t, u) * ls(x, z, k)) & k = n-1

    Where:
    - u is a pointer variable (appears in PointsTo)
    - k is a length variable (appears in arithmetic constraint like k = n-1)

    This function analyzes the structure and generates smart instantiations.
    Returns list of (description, instantiated_formula) pairs.
    """
    from frame.core.ast import Exists, Var, Const, ArithExpr, And, Eq, PointsTo, PredicateCall, SepConj

    # Must be exactly 2 nested existentials
    if not isinstance(consequent, Exists):
        return []
    if not isinstance(consequent.formula, Exists):
        return []
    if isinstance(consequent.formula.formula, Exists):
        return []  # More than 2 nested - too complex

    outer_var = consequent.var  # First existential variable
    inner_var = consequent.formula.var  # Second existential variable
    body = consequent.formula.formula  # The actual formula

    # Analyze which variable is length vs pointer
    length_var = None
    pointer_var = None
    length_expr = None  # The expression to use for length (e.g., n-1)

    def find_arith_constraint(f):
        """Find arithmetic equality constraint like k = n-1"""
        nonlocal length_var, length_expr
        if isinstance(f, And):
            find_arith_constraint(f.left)
            find_arith_constraint(f.right)
        elif isinstance(f, Eq):
            # Check if left is one of our bound vars and right is arithmetic
            if isinstance(f.left, Var):
                if f.left.name == outer_var or f.left.name == inner_var:
                    if isinstance(f.right, ArithExpr) or isinstance(f.right, Var):
                        length_var = f.left.name
                        length_expr = f.right
            # Check other direction
            if isinstance(f.right, Var):
                if f.right.name == outer_var or f.right.name == inner_var:
                    if isinstance(f.left, ArithExpr) or isinstance(f.left, Var):
                        length_var = f.right.name
                        length_expr = f.left

    def find_pointer_in_pto(f):
        """Find if a variable appears as pointer value in PointsTo"""
        nonlocal pointer_var
        if isinstance(f, PointsTo):
            for val in f.values:
                if isinstance(val, Var):
                    if val.name == outer_var or val.name == inner_var:
                        pointer_var = val.name
        elif isinstance(f, And):
            find_pointer_in_pto(f.left)
            find_pointer_in_pto(f.right)
        elif isinstance(f, SepConj):
            find_pointer_in_pto(f.left)
            find_pointer_in_pto(f.right)

    find_arith_constraint(body)
    find_pointer_in_pto(body)

    # Determine which is length and which is pointer
    if length_var is None and pointer_var is None:
        return []  # Can't determine types

    # If only one identified, the other is the opposite type
    if length_var and not pointer_var:
        pointer_var = inner_var if length_var == outer_var else outer_var
    elif pointer_var and not length_var:
        length_var = inner_var if pointer_var == outer_var else outer_var

    # Collect antecedent variables for pointer witnesses
    ant_vars = collect_variables(antecedent)

    # Collect length-related variables from antecedent
    length_vars_from_ant = _extract_length_vars_from_predicates(antecedent)

    instantiations = []

    # Generate combinations of pointer and length witnesses
    # IMPORTANT: Filter out length variables from pointer witnesses
    # Length variables (like 'n', 'm') should not be used as pointer witnesses
    pointer_witnesses = [v for v in ant_vars if v not in length_vars_from_ant and not v.isdigit()]
    pointer_witnesses = pointer_witnesses[:4]  # Limit pointer witnesses
    pointer_witnesses.append(None)  # nil

    # Generate length witnesses
    length_witnesses = []
    if length_expr:
        # Use the constraint expression directly (e.g., n-1)
        length_witnesses.append(("expr", length_expr))

    # Also try arithmetic on antecedent length vars
    for lv in list(length_vars_from_ant)[:2]:
        length_witnesses.append((f"{lv}", Var(lv)))
        length_witnesses.append((f"{lv}-1", ArithExpr('-', Var(lv), Const(1))))
        length_witnesses.append((f"{lv}+1", ArithExpr('+', Var(lv), Const(1))))

    # Combine witnesses (limited to avoid explosion)
    MAX_COMBINATIONS = 8
    count = 0

    for pw in pointer_witnesses:
        if count >= MAX_COMBINATIONS:
            break
        for lw_name, lw_expr in length_witnesses:
            if count >= MAX_COMBINATIONS:
                break

            # Create instantiation
            pw_expr = Const(None) if pw is None else Var(pw)
            pw_name = "nil" if pw is None else pw

            # Substitute both variables
            instantiated = substitute_var_in_formula(body, pointer_var, pw_expr)
            instantiated = substitute_var_in_formula(instantiated, length_var, lw_expr)

            desc = f"({pointer_var}={pw_name}, {length_var}={lw_name})"
            instantiations.append((desc, instantiated))
            count += 1

    return instantiations
