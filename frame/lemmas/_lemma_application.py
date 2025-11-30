"""
Lemma Application Helper Functions

Internal helper module for applying lemmas to prove entailments.
Handles both single-step and multi-step lemma application.
"""

from typing import Optional, Dict, List, Tuple
from frame.core.ast import Formula, Expr, Emp, SepConj, And
from itertools import combinations


def try_apply_lemma(
    library,  # LemmaLibrary instance
    antecedent: Formula,
    consequent: Formula
) -> Optional[str]:
    """
    Try to apply a lemma to prove the entailment.

    Two-phase matching strategy:
    1. Direct matching (fast path): syntactic pattern matching
    2. Constraint-aware matching: normalize with equality constraints

    Note: Graph-based folding (synthesis) has been moved to frame/folding/goal_directed.py
    where it belongs. Lemmas are ONLY for proven facts about predicates.

    Lemmas are validated against predicate definitions to ensure soundness.

    Returns the name of the applied lemma if successful, None otherwise.
    """
    # Normalize SepConj order for consistent matching (P * Q = Q * P)
    from frame.analysis.formula import FormulaAnalyzer
    from frame.utils.formula_utils import extract_spatial_part
    from frame.core.ast import PredicateCall, Var, Const

    analyzer = FormulaAnalyzer()
    antecedent = analyzer.normalize_sepconj(antecedent)
    consequent = analyzer.normalize_sepconj(consequent)

    # Extract disequality and structural info for transitivity soundness check
    disequalities = _extract_disequalities(antecedent)
    cells_at = _extract_cell_locations(antecedent)

    # Phase 1: Direct matching (fast path)
    for lemma in library.lemmas:
        # Validate lemma before applying
        if not library._is_lemma_sound(lemma):
            continue

        bindings = library.match_formula(lemma.antecedent, antecedent)
        if bindings is not None:
            # SOUNDNESS CHECK: For transitivity lemmas, verify endpoints are provably different
            if lemma.name in ('ls_transitivity', 'ls_triple_transitivity', 'ls_snoc'):
                if not _can_apply_transitivity(lemma, bindings, disequalities, cells_at):
                    continue  # Skip - endpoints might be aliased

            instantiated_consequent = library.substitute_bindings(lemma.consequent, bindings)
            if library._formulas_equal(instantiated_consequent, consequent):
                return lemma.name

    # Phase 2: Constraint-aware matching
    # Extract equality constraints from antecedent
    substitution = library._extract_equality_constraints(antecedent)

    if substitution:
        # Apply substitutions to get normalized antecedent
        normalized_antecedent = library._apply_substitution_to_formula(antecedent, substitution)

        # Extract spatial part from normalized antecedent
        spatial_part = extract_spatial_part(normalized_antecedent)

        if spatial_part:
            # Try to match lemmas against the normalized spatial part
            for lemma in library.lemmas:
                # Validate lemma before applying
                if not library._is_lemma_sound(lemma):
                    continue

                bindings = library.match_formula(lemma.antecedent, spatial_part)
                if bindings is not None:
                    # SOUNDNESS CHECK: For transitivity lemmas, verify endpoints are provably different
                    if lemma.name in ('ls_transitivity', 'ls_triple_transitivity', 'ls_snoc'):
                        if not _can_apply_transitivity(lemma, bindings, disequalities, cells_at):
                            continue  # Skip - endpoints might be aliased

                    instantiated_consequent = library.substitute_bindings(lemma.consequent, bindings)

                    # Check if instantiated consequent matches the consequent's spatial part
                    consequent_spatial = extract_spatial_part(consequent)
                    if consequent_spatial and library._formulas_equal(instantiated_consequent, consequent_spatial):
                        return lemma.name

    # Phase 3 (graph-based folding) has been REMOVED and moved to:
    # frame/folding/goal_directed.py - fold_towards_goal()
    #
    # This keeps concerns properly separated:
    #   - Lemmas: proven facts about predicates
    #   - Folding: synthesis of predicates from concrete heaps
    #
    # The checker now calls goal-directed folding BEFORE lemma application.

    return None


def _extract_disequalities(formula: Formula) -> set:
    """
    Extract explicit disequality constraints (x != y) from formula.

    Returns set of (name1, name2) tuples (sorted for canonical form).
    """
    from frame.core.ast import Neq, And, Var, Const

    diseqs = set()

    def extract(f):
        if isinstance(f, Neq):
            left = f.left
            right = f.right
            name1 = left.name if isinstance(left, Var) else str(left)
            name2 = right.name if isinstance(right, Var) else str(right)
            # Canonical form: sorted tuple
            diseqs.add(tuple(sorted([name1, name2])))
        elif isinstance(f, And):
            extract(f.left)
            extract(f.right)
        elif isinstance(f, SepConj):
            extract(f.left)
            extract(f.right)

    extract(formula)
    return diseqs


def _extract_cell_locations(formula: Formula) -> set:
    """
    Extract locations that have concrete cells (PointsTo).

    If two different locations both have cells, they MUST be different
    due to separation (disjoint domains).

    Returns set of location names.
    """
    from frame.core.ast import PointsTo, Var, SepConj, And

    locations = set()

    def extract(f):
        if isinstance(f, PointsTo):
            loc = f.location
            name = loc.name if isinstance(loc, Var) else str(loc)
            locations.add(name)
        elif isinstance(f, SepConj):
            extract(f.left)
            extract(f.right)
        elif isinstance(f, And):
            extract(f.left)
            extract(f.right)

    extract(formula)
    return locations


def _can_apply_transitivity(lemma, bindings: Dict, disequalities: set, cells_at: set) -> bool:
    """
    Check if transitivity lemma can be soundly applied.

    Transitivity ls(x,y) * ls(y,z) |- ls(x,z) is ONLY sound when x != z.

    We can prove x != z if:
    1. Explicit disequality (x != z) in antecedent
    2. Both x and z have concrete cells (separation implies difference)
    3. x and z are syntactically different AND one is a special constant (nil, null)

    Returns True if transitivity can be safely applied, False otherwise.
    """
    from frame.core.ast import PredicateCall, Var, Const

    if not isinstance(lemma.consequent, PredicateCall) or len(lemma.consequent.args) < 2:
        return True  # Not a transitivity-style lemma

    # Get the instantiated start and end variables
    start_var = lemma.consequent.args[0]
    end_var = lemma.consequent.args[1]

    start_val = bindings.get(start_var.name if isinstance(start_var, Var) else str(start_var), start_var)
    end_val = bindings.get(end_var.name if isinstance(end_var, Var) else str(end_var), end_var)

    # Get names for comparison
    start_name = start_val.name if isinstance(start_val, Var) else str(start_val)
    end_name = end_val.name if isinstance(end_val, Var) else str(end_val)

    # Check 1: If syntactically the same, definitely aliased - REJECT
    if start_name == end_name:
        return False

    # Check 2: Explicit disequality in antecedent - ACCEPT
    canonical = tuple(sorted([start_name, end_name]))
    if canonical in disequalities:
        return True

    # Check 3: Both have concrete cells - ACCEPT (separation implies difference)
    if start_name in cells_at and end_name in cells_at:
        return True

    # Check 4: One is a special constant (nil, null, None) - these are special
    special_constants = {'nil', 'null', 'None', '(as nil RefSll_t)'}
    if start_name in special_constants or end_name in special_constants:
        # If one is nil and they're syntactically different, they're different
        return True

    # Default: Cannot prove disequality - REJECT (conservative)
    return False


def try_apply_lemma_multistep(
    library,  # LemmaLibrary instance
    antecedent: Formula,
    consequent: Formula,
    max_iterations: int = 5,
    verbose: bool = False
) -> Optional[Tuple[str, int]]:
    """
    Try to apply lemmas iteratively to prove the entailment.

    This enables proving entailments that require multiple lemma applications,
    such as: ls(x,y) * ls(y,z) * ls(z,w) |- ls(x,w)
    which needs transitivity applied twice.

    Algorithm:
    1. Start with current = antecedent
    2. For each iteration:
       a. Try to find a lemma L where L.antecedent matches part of current
       b. If found, replace that part with L.consequent
       c. Check if result matches consequent (success!)
       d. Otherwise, continue with transformed formula
    3. Stop when consequent is reached or no more lemmas apply

    Args:
        library: LemmaLibrary instance
        antecedent: The formula to transform
        consequent: The goal formula to prove
        max_iterations: Maximum number of lemma applications
        verbose: Enable debug output

    Returns:
        (lemma_description, num_applications) if successful, None otherwise
    """
    from frame.analysis.formula import FormulaAnalyzer

    analyzer = FormulaAnalyzer()
    current = antecedent
    applications = []

    if verbose:
        print(f"[Multi-Step Lemma] Starting: {antecedent} |- {consequent}")

    for iteration in range(max_iterations):
        if verbose:
            print(f"\n[Multi-Step Lemma] Iteration {iteration + 1}/{max_iterations}")
            print(f"[Multi-Step Lemma] Current: {current}")

        # Check if we've reached the goal (normalize by removing emp first)
        current_normalized = remove_emp_parts(current, analyzer)
        consequent_normalized = remove_emp_parts(consequent, analyzer)

        if library._formulas_equal(current_normalized, consequent_normalized):
            if verbose:
                print(f"[Multi-Step Lemma] ✓ Goal reached after {len(applications)} applications!")
            return (f"multi_step_lemma ({'+'.join(applications)})", len(applications))

        # Extract parts from current formula
        current_parts = analyzer._extract_sepconj_parts(current)

        # Try to find a lemma that applies to some subset of parts
        lemma_applied = False

        for lemma in library.lemmas:
            # Validate lemma before applying
            if not library._is_lemma_sound(lemma):
                continue

            # Get lemma antecedent parts
            lemma_ante_parts = analyzer._extract_sepconj_parts(lemma.antecedent)

            # Try to match lemma antecedent against subset of current parts
            # This allows matching ls(x,y) * ls(y,z) within larger formula
            bindings = try_match_subset(library, current_parts, lemma_ante_parts)

            if bindings is not None:
                # SOUNDNESS CHECK: Detect aliasing in transitivity lemma
                # If applying ls_transitivity would create ls(x,x) where x=z,
                # skip this application as it leads to unsound conclusions.
                # Example: ls(x,y) * ls(y,x) should NOT become ls(x,x) = emp
                # because the antecedent has non-empty heap.
                if lemma.name in ('ls_transitivity', 'ls_triple_transitivity', 'ls_snoc'):
                    # Check if result would have aliased endpoints
                    from frame.core.ast import PredicateCall, Var, Const
                    if isinstance(lemma.consequent, PredicateCall) and len(lemma.consequent.args) >= 2:
                        # Get the instantiated start and end variables
                        start_var = lemma.consequent.args[0]
                        end_var = lemma.consequent.args[1]

                        # Substitute bindings
                        start_val = bindings.get(start_var.name if isinstance(start_var, Var) else str(start_var), start_var)
                        end_val = bindings.get(end_var.name if isinstance(end_var, Var) else str(end_var), end_var)

                        # Check if they alias (same variable or value)
                        def exprs_equal(e1, e2):
                            if isinstance(e1, Var) and isinstance(e2, Var):
                                return e1.name == e2.name
                            if isinstance(e1, Const) and isinstance(e2, Const):
                                return e1.value == e2.value
                            return str(e1) == str(e2)

                        if exprs_equal(start_val, end_val):
                            if verbose:
                                print(f"[Multi-Step Lemma] ✗ Skipping {lemma.name}: would create aliased endpoints {start_val}")
                            continue  # Skip this lemma, try another

                # Found a match! Apply the lemma
                instantiated_consequent = library.substitute_bindings(lemma.consequent, bindings)

                # Build new formula: remove matched parts, add consequent
                matched_parts_set = set()
                for lemma_part in lemma_ante_parts:
                    for i, current_part in enumerate(current_parts):
                        if i not in matched_parts_set:
                            part_bindings = library.match_formula(lemma_part, current_part)
                            if part_bindings is not None:
                                matched_parts_set.add(i)
                                break

                # Build new formula with unmatched parts + instantiated consequent
                new_parts = [p for i, p in enumerate(current_parts) if i not in matched_parts_set]
                new_parts.append(instantiated_consequent)

                current = analyzer._build_sepconj(new_parts)
                applications.append(lemma.name)
                lemma_applied = True

                if verbose:
                    print(f"[Multi-Step Lemma] ✓ Applied {lemma.name}")
                    print(f"[Multi-Step Lemma] New formula: {current}")

                break  # Apply one lemma per iteration

        if not lemma_applied:
            if verbose:
                print(f"[Multi-Step Lemma] ✗ No lemma applicable")
            break

    # Check final result (normalize by removing emp)
    current_normalized = remove_emp_parts(current, analyzer)
    consequent_normalized = remove_emp_parts(consequent, analyzer)

    if library._formulas_equal(current_normalized, consequent_normalized):
        if verbose:
            print(f"[Multi-Step Lemma] ✓ Success after {len(applications)} applications!")
        return (f"multi_step_lemma ({'+'.join(applications)})", len(applications))

    if verbose:
        print(f"[Multi-Step Lemma] ✗ Failed after {len(applications)} applications")
        print(f"[Multi-Step Lemma]   Final: {current_normalized}")
        print(f"[Multi-Step Lemma]   Goal:  {consequent_normalized}")

    return None


def remove_emp_parts(formula: Formula, analyzer) -> Formula:
    """
    Remove vacuous emp conjuncts from formula for normalization.

    Only removes emp from SPATIAL conjunctions (SepConj), not from pure conjunctions (And).
    This preserves pure constraints while normalizing spatial formulas.
    """
    def normalize(f: Formula) -> Formula:
        # Remove emp from SepConj
        if isinstance(f, SepConj):
            left = normalize(f.left)
            right = normalize(f.right)

            if isinstance(left, Emp):
                return right
            if isinstance(right, Emp):
                return left

            # If both sides changed, create new SepConj
            if left != f.left or right != f.right:
                return SepConj(left, right)

            return f

        # Keep And unchanged (preserve pure constraints)
        elif isinstance(f, And):
            return f

        return f

    return normalize(formula)


def try_match_subset(
    library,  # LemmaLibrary instance
    formula_parts: List[Formula],
    pattern_parts: List[Formula]
) -> Optional[Dict[str, Expr]]:
    """
    Try to match pattern parts against a subset of formula parts.

    This enables matching ls(x,y) * ls(y,z) within x|->a * ls(x,y) * ls(y,z) * z|->b

    IMPORTANT: We must try all PERMUTATIONS of how pattern parts map to formula parts,
    not just combinations. For example, with pattern [ls(X,Y), ls(Y,Z)] and formula
    parts [ls(a,b), ls(c,a)], we need to try:
      - pattern[0]->formula[0], pattern[1]->formula[1]: ls(X,Y)->ls(a,b), ls(Y,Z)->ls(c,a) - FAIL (Y=b != c)
      - pattern[0]->formula[1], pattern[1]->formula[0]: ls(X,Y)->ls(c,a), ls(Y,Z)->ls(a,b) - OK (X=c, Y=a, Z=b)

    Returns unified bindings if all pattern parts match, None otherwise.
    """
    from itertools import permutations

    if len(pattern_parts) > len(formula_parts):
        return None

    # Try all combinations of formula_parts that match the size of pattern_parts
    # and all permutations of each combination
    for combo in combinations(range(len(formula_parts)), len(pattern_parts)):
        # Try all orderings of this combination
        for perm in permutations(combo):
            # Try to match this permutation
            bindings = {}
            matched = True

            for pattern_part, formula_idx in zip(pattern_parts, perm):
                formula_part = formula_parts[formula_idx]
                part_bindings = library.match_formula(pattern_part, formula_part, bindings)

                if part_bindings is None:
                    matched = False
                    break

                bindings = part_bindings

            if matched:
                return bindings

    return None
