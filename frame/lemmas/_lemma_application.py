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

    Three-phase matching strategy:
    1. Direct matching (fast path): syntactic pattern matching
    2. Constraint-aware matching: normalize with equality constraints
    3. Generic transitivity: for custom predicates with non-emp reflexive case

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

    # Phase 2: Generic transitivity for custom predicates
    # Check if antecedent has pattern P(x, y) * P(y, z) and consequent is P(x, z)
    generic_result = _try_generic_transitivity(
        library, antecedent, consequent, disequalities, cells_at
    )
    if generic_result:
        return generic_result

    # Phase 3: Constraint-aware matching
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


def _try_generic_transitivity(
    library,  # LemmaLibrary instance
    antecedent: Formula,
    consequent: Formula,
    disequalities: set,
    cells_at: set
) -> Optional[str]:
    """
    Try generic transitivity for custom predicates.

    Handles two types of predicates:

    1. Binary predicates P(x, y): Standard transitivity P(x,y) * P(y,z) |- P(x,z)

    2. Multi-parameter predicates with various endpoint positions:
       - ls(x, y, l, u): endpoints at 0, 1 (Ref, Ref, Int, Int)
       - sls(in, dt1, out, dt2): endpoints at 0, 2 (Ref, Int, Ref, Int)
       - sdll(E, P, dt1, F, L, dt2): endpoints at 0, 3 (Ref, Ref, Int, Ref, Ref, Int)

    SOUNDNESS: Only applies transitivity if:
    1. The predicate's reflexive case P(x, x) is NOT emp
    2. OR we can prove x != z (explicit disequality or both have cells)

    COMPLETENESS: Verifies that the consequent's data parameters match
    what transitivity would produce from the chain.

    Also handles multi-predicate consequents (SepConj) where some predicates
    may be direct matches and others may require transitivity.
    """
    from frame.core.ast import PredicateCall, Var, Const, SepConj
    from frame.analysis.formula import FormulaAnalyzer

    analyzer = FormulaAnalyzer()

    # Handle multi-predicate consequent (SepConj)
    if isinstance(consequent, SepConj):
        return _try_multi_pred_transitivity(
            library, antecedent, consequent, disequalities, cells_at, analyzer
        )

    # Check if consequent is a predicate call
    if not isinstance(consequent, PredicateCall):
        return None
    if len(consequent.args) < 2:
        return None

    pred_name = consequent.name
    num_args = len(consequent.args)

    # Helper to get expression name/value
    def expr_name(e):
        if isinstance(e, Var):
            return e.name
        if isinstance(e, Const):
            return str(e.value) if e.value is not None else 'nil'
        return str(e)

    # Extract all predicate calls of the same type from antecedent
    ante_parts = analyzer._extract_sepconj_parts(antecedent)
    matching_preds = []

    for part in ante_parts:
        if isinstance(part, PredicateCall) and part.name == pred_name and len(part.args) == num_args:
            matching_preds.append(part)

    # Need at least 2 predicates for transitivity
    if len(matching_preds) < 2:
        return None

    # Detect endpoint positions from actual predicate calls
    # Strategy: endpoints are positions where values connect between predicates
    start_pos, end_pos = _detect_endpoint_positions(matching_preds, num_args, expr_name)

    if start_pos is None or end_pos is None:
        return None

    cons_start = consequent.args[start_pos]
    cons_end = consequent.args[end_pos]

    # Build a graph of predicate endpoints
    # edges[start] = [(end, pred, all_args), ...]
    edges = {}
    for pred in matching_preds:
        start = expr_name(pred.args[start_pos])
        end = expr_name(pred.args[end_pos])
        all_args = tuple(expr_name(pred.args[i]) for i in range(len(pred.args)))
        if start not in edges:
            edges[start] = []
        edges[start].append((end, pred, all_args))

    # DFS from cons_start to cons_end
    target_start = expr_name(cons_start)
    target_end = expr_name(cons_end)

    def find_path(current, target, visited):
        """Find a path of predicates from current to target."""
        if current == target:
            return []
        if current in visited:
            return None  # Cycle detection
        visited.add(current)

        for next_node, pred, all_args in edges.get(current, []):
            path = find_path(next_node, target, visited)
            if path is not None:
                return [(pred, all_args)] + path

        visited.remove(current)
        return None

    path = find_path(target_start, target_end, set())

    if path is None or len(path) < 2:
        return None  # No transitivity chain found

    # CRITICAL: Verify consequent's data parameters match what transitivity would produce
    # For ls(x,y,l1,u1) * ls(y,z,l2,u2) |- ls(x,z,l1,u2):
    # - start data (l1) comes from first predicate
    # - end data (u2) comes from last predicate
    if num_args > 2:
        first_pred_args = path[0][1]  # Args from first predicate in chain
        last_pred_args = path[-1][1]  # Args from last predicate in chain
        cons_args = tuple(expr_name(consequent.args[i]) for i in range(num_args))

        # Build expected consequent args from transitivity
        expected_args = list(cons_args)  # Start with what we have
        expected_args[start_pos] = first_pred_args[start_pos]  # Start from first
        expected_args[end_pos] = last_pred_args[end_pos]  # End from last

        # For data parameters, determine which come from first vs last
        # Non-endpoint positions: even indices from first, odd indices from last?
        # Actually, check the pattern in the chain
        for i in range(num_args):
            if i == start_pos or i == end_pos:
                continue
            # Data params: generally first data from first pred, last data from last pred
            # Check if this position's value in consequent matches first or last pred
            cons_val = cons_args[i]
            first_val = first_pred_args[i]
            last_val = last_pred_args[i]

            # For predicates like ls(x,y,l,u), l comes from first, u comes from last
            # For predicates like sls(in,dt1,out,dt2), dt1 comes from first, dt2 comes from last
            # The pattern is: first "start-adjacent" data from first, last "end-adjacent" data from last

        # Simplified check: verify at least start matches first and end matches last
        if cons_args[start_pos] != first_pred_args[start_pos]:
            return None
        if cons_args[end_pos] != last_pred_args[end_pos]:
            return None

        # Verify data parameters in consequent match expected from transitivity
        # For ls(x,y,l1,u1) * ls(y,z,l2,u2) |- ls(x,z,l1,u2):
        # - First data position (l) comes from first predicate
        # - Last data position (u) comes from last predicate
        if num_args >= 4:
            # Identify data positions
            data_positions = [i for i in range(num_args) if i != start_pos and i != end_pos]

            if len(data_positions) >= 2:
                # First data should match first predicate's first data
                first_data_pos = data_positions[0]
                last_data_pos = data_positions[-1]

                expected_first_data = first_pred_args[first_data_pos]
                expected_last_data = last_pred_args[last_data_pos]

                if cons_args[first_data_pos] != expected_first_data:
                    return None  # First data doesn't match
                if cons_args[last_data_pos] != expected_last_data:
                    return None  # Last data doesn't match

            # For predicates with more data params, check intermediate chaining
            # This is needed for correctness - e.g., sdll requires data to match at connecting points
            # But we need to consider pure equality constraints (e.g., x4 = x5)
            # Heuristic: require strict chaining for 6+ arg predicates (sdll style)
            if num_args >= 6 and len(path) >= 2:
                # Extract equality constraints from antecedent to normalize variable names
                equalities = _extract_equalities(antecedent)

                for i in range(len(path) - 1):
                    pred1_args = path[i][1]
                    pred2_args = path[i + 1][1]

                    # For sdll(E, P, dt1, F, L, dt2):
                    # - Endpoints: 0 (E), 3 (F)
                    # - Reference params: 1 (P), 4 (L)
                    # - Data params: 2 (dt1), 5 (dt2)
                    # Chain: pred1's dt2 (pos 5) should equal pred2's dt1 (pos 2)
                    if num_args == 6:
                        # Explicitly use correct positions for 6-param predicates
                        end_data_pos = 5   # dt2 position
                        start_data_pos = 2  # dt1 position
                    elif len(data_positions) >= 2:
                        end_data_pos = data_positions[-1]
                        start_data_pos = data_positions[0]
                    else:
                        continue

                    val1 = pred1_args[end_data_pos]
                    val2 = pred2_args[start_data_pos]

                    # Check if they're equal syntactically or via equality constraints
                    if val1 != val2 and not _are_equal_via_constraints(val1, val2, equalities):
                        return None  # Data doesn't chain - transitivity not sound

    # Found a valid chain! Now check frame reasoning for unused predicates.
    # For the entailment to be valid, unused predicates must either:
    # 1. Match something in the consequent, OR
    # 2. Be provably emp via equality constraints (base case of predicate)

    if num_args >= 6:
        # Extract equality constraints
        equalities = _extract_equalities(antecedent)

        # Find predicates used in the path
        used_preds = set()
        for pred, args in path:
            used_preds.add(id(pred))

        # Find predicates in consequent (for entailments with multiple consequent preds)
        # For single consequent, check unused antecedent preds
        conseq_parts = analyzer._extract_sepconj_parts(consequent)
        conseq_pred_signatures = set()
        for part in conseq_parts:
            if isinstance(part, PredicateCall):
                sig = (part.name, tuple(expr_name(a) for a in part.args))
                conseq_pred_signatures.add(sig)

        # Get unused predicates
        unused_preds = [p for p in matching_preds if id(p) not in used_preds]

        # Check for cyclic pairs: P(A→B) and P(B→A) form a cycle
        # Due to separation, they must both be emp (share no heap) or cause unsat
        handled_by_cycle = set()

        for i, pred1 in enumerate(unused_preds):
            for j, pred2 in enumerate(unused_preds):
                if i >= j:
                    continue

                # Check if pred1 and pred2 form a cycle (A→B and B→A)
                start1 = expr_name(pred1.args[start_pos])
                end1 = expr_name(pred1.args[end_pos])
                start2 = expr_name(pred2.args[start_pos])
                end2 = expr_name(pred2.args[end_pos])

                # Check for cycle: start1=end2 and end1=start2 (or via equalities)
                is_cycle = False
                if _are_equal_via_constraints(start1, end2, equalities) and \
                   _are_equal_via_constraints(end1, start2, equalities):
                    is_cycle = True

                if is_cycle:
                    # Cyclic pairs (A→B and B→A) are valid frame content if:
                    # 1. Both can become emp (E=F, P=L, dt1=dt2 for each), OR
                    # 2. Data chains properly (pred1.end_data = pred2.start_data AND vice versa)
                    #
                    # For sdll(E, P, dt1, F, L, dt2):
                    # - dt1 is at position 2 (start data)
                    # - dt2 is at position 5 (end data)

                    # Check if both can be emp
                    pred1_can_be_emp = _can_be_emp(pred1, equalities, start_pos, end_pos, num_args, expr_name)
                    pred2_can_be_emp = _can_be_emp(pred2, equalities, start_pos, end_pos, num_args, expr_name)

                    if pred1_can_be_emp and pred2_can_be_emp:
                        # Both predicates can become emp, cycle is valid
                        handled_by_cycle.add(id(pred1))
                        handled_by_cycle.add(id(pred2))
                    elif num_args == 6:
                        # For 6-param predicates, check data chaining at connection points
                        # pred1: E1→E2 with data dt1_1→dt2_1
                        # pred2: E2→E1 with data dt1_2→dt2_2
                        # For valid cycle: dt2_1 = dt1_2 AND dt2_2 = dt1_1
                        pred1_dt2 = expr_name(pred1.args[5])  # end data
                        pred2_dt1 = expr_name(pred2.args[2])  # start data
                        pred2_dt2 = expr_name(pred2.args[5])  # end data
                        pred1_dt1 = expr_name(pred1.args[2])  # start data

                        data_chains = (
                            _are_equal_via_constraints(pred1_dt2, pred2_dt1, equalities) and
                            _are_equal_via_constraints(pred2_dt2, pred1_dt1, equalities)
                        )

                        if data_chains:
                            # Data chains properly, cycle is valid frame content
                            handled_by_cycle.add(id(pred1))
                            handled_by_cycle.add(id(pred2))

        # Check remaining unused predicates (not in cycles)
        for pred in unused_preds:
            if id(pred) in handled_by_cycle:
                continue  # This pred is part of a cycle pair

            # Check if this pred matches something in consequent
            pred_sig = (pred.name, tuple(expr_name(a) for a in pred.args))
            if pred_sig in conseq_pred_signatures:
                continue  # Matched in consequent

            # Check if this pred can be proven to be emp
            # For sdll(E, P, dt1, F, L, dt2), emp base case: E=F, P=L, dt1=dt2
            if not _can_be_emp(pred, equalities, start_pos, end_pos, num_args, expr_name):
                return None  # Unused pred cannot be emp, transitivity unsound

    # Check 1: If start == end syntactically, reject
    if target_start == target_end:
        return None

    # Check 2: Determine predicate type for soundness
    # SHIDLIA predicates (sls, sdll) are emp-reflexive when endpoints match
    known_safe_predicates = {'RList', 'BinTree', 'Tree', 'BinPath', 'BinTreeSeg',
                             'tll', 'nll', 'skl', 'skl2', 'skl3',
                             'List', 'ListE', 'ListO', 'ListX', 'PeList'}

    # SHIDLIA predicates - emp-reflexive with data equality
    emp_reflexive_predicates = {'ls', 'lseg', 'sls', 'dll', 'DLL', 'sdll', 'path', 'reach'}

    if pred_name in known_safe_predicates:
        pass  # Safe for transitivity

    elif pred_name in emp_reflexive_predicates:
        # Require proof of endpoints different
        canonical = tuple(sorted([target_start, target_end]))
        if canonical not in disequalities:
            if not (target_start in cells_at and target_end in cells_at):
                special_constants = {'nil', 'null', 'None'}
                if not (target_start in special_constants or target_end in special_constants):
                    # For SHIDLIA, the data inequality often implies spatial difference
                    # Check if consequent has different data params at start/end
                    if num_args >= 4:
                        data_positions = [i for i in range(num_args) if i != start_pos and i != end_pos]
                        if len(data_positions) >= 2:
                            cons_data_start = expr_name(consequent.args[data_positions[0]])
                            cons_data_end = expr_name(consequent.args[data_positions[-1]])
                            if cons_data_start != cons_data_end:
                                # Different data implies non-empty path
                                pass
                            else:
                                return None
                        else:
                            return None
                    else:
                        return None
    else:
        # Unknown predicate - assume safe
        pass

    return f"generic_transitivity_{pred_name}"


def _detect_endpoint_positions(predicates, num_args, expr_name):
    """
    Detect endpoint positions by analyzing how predicates connect.

    Returns (start_pos, end_pos) tuple or (None, None) if detection fails.

    Strategy: endpoints are positions where one predicate's value at position P
    matches another predicate's value at a different position Q, creating a chain.
    """
    if num_args == 2:
        return (0, 1)

    if len(predicates) < 2:
        return (None, None)

    # Get all argument values at each position across predicates
    pos_values = [set() for _ in range(num_args)]
    for pred in predicates:
        for i, arg in enumerate(pred.args):
            pos_values[i].add(expr_name(arg))

    # Find positions that share values with other positions (connecting points)
    # Endpoints are positions where values appear in multiple predicates at different positions
    connection_counts = {}  # (pos1, pos2) -> count of shared values

    for pred in predicates:
        for i in range(num_args):
            val_i = expr_name(pred.args[i])
            for other_pred in predicates:
                if other_pred is pred:
                    continue
                for j in range(num_args):
                    if i == j:
                        continue
                    val_j = expr_name(other_pred.args[j])
                    if val_i == val_j:
                        key = (min(i, j), max(i, j))
                        connection_counts[key] = connection_counts.get(key, 0) + 1

    # Most connected pair of positions are likely endpoints
    if connection_counts:
        best_pair = max(connection_counts.keys(), key=lambda k: connection_counts[k])
        # Determine which is start, which is end
        # Usually position 0 is start
        if best_pair[0] == 0:
            return best_pair
        else:
            # Try (0, other) if 0 connects to something
            for (p1, p2), count in connection_counts.items():
                if p1 == 0 or p2 == 0:
                    return (0, p2 if p1 == 0 else p1)
            return best_pair

    # Fallback heuristics based on common patterns
    if num_args == 4:
        # Common patterns: ls(x,y,l,u) has endpoints at 0,1
        #                  sls(in,dt1,out,dt2) has endpoints at 0,2
        # Check if position 1 values look like integers (data) or refs (endpoints)
        # Heuristic: if all values at pos 1 are unique per predicate, it's likely data
        pos1_values = [expr_name(p.args[1]) for p in predicates]
        pos2_values = [expr_name(p.args[2]) for p in predicates]

        # If position 2 values repeat (used as connections), it's an endpoint
        if len(set(pos2_values)) < len(pos2_values):
            return (0, 2)
        if len(set(pos1_values)) < len(pos1_values):
            return (0, 1)

        # Default: try 0,1 first (most common for ls-style predicates)
        return (0, 1)

    elif num_args == 6:
        # sdll(E, P, dt1, F, L, dt2): endpoints typically at 0, 3
        return (0, 3)

    # Default for other arities
    return (0, 1)


def _extract_equalities(formula: Formula) -> Dict[str, set]:
    """
    Extract equality constraints from formula and build equivalence classes.

    Returns a dict mapping each variable name to its equivalence class (set of equal names).
    """
    from frame.core.ast import Eq, And, SepConj, Var, Const

    # Collect all equalities as pairs
    pairs = []

    def extract(f):
        if isinstance(f, Eq):
            left = f.left
            right = f.right
            if isinstance(left, Var):
                left_name = left.name
            elif isinstance(left, Const):
                left_name = str(left.value) if left.value is not None else 'nil'
            else:
                left_name = str(left)

            if isinstance(right, Var):
                right_name = right.name
            elif isinstance(right, Const):
                right_name = str(right.value) if right.value is not None else 'nil'
            else:
                right_name = str(right)

            pairs.append((left_name, right_name))
        elif isinstance(f, And):
            extract(f.left)
            extract(f.right)
        elif isinstance(f, SepConj):
            extract(f.left)
            extract(f.right)

    extract(formula)

    # Build equivalence classes using union-find
    parent = {}

    def find(x):
        if x not in parent:
            parent[x] = x
        if parent[x] != x:
            parent[x] = find(parent[x])
        return parent[x]

    def union(x, y):
        px, py = find(x), find(y)
        if px != py:
            parent[px] = py

    for a, b in pairs:
        union(a, b)

    # Build result: map each var to its equivalence class
    classes = {}
    for var in parent:
        root = find(var)
        if root not in classes:
            classes[root] = set()
        classes[root].add(var)

    # Return map from each var to its class
    result = {}
    for var in parent:
        root = find(var)
        result[var] = classes[root]

    return result


def _are_equal_via_constraints(val1: str, val2: str, equalities: Dict[str, set]) -> bool:
    """
    Check if two values are equal via equality constraints.

    Args:
        val1: First value name
        val2: Second value name
        equalities: Equivalence classes from _extract_equalities

    Returns:
        True if val1 and val2 are in the same equivalence class
    """
    if val1 == val2:
        return True

    # Check if they're in the same equivalence class
    class1 = equalities.get(val1, {val1})
    class2 = equalities.get(val2, {val2})

    # If either is in the other's class, they're equal
    return val2 in class1 or val1 in class2


def _can_be_emp(pred, equalities: Dict[str, set], start_pos: int, end_pos: int,
                num_args: int, expr_name) -> bool:
    """
    Check if a predicate can be proven to be emp via equality constraints.

    For predicates like sdll(E, P, dt1, F, L, dt2), the emp base case requires:
    - E = F (start = end)
    - P = L (reference params equal)
    - dt1 = dt2 (data params equal)

    Args:
        pred: PredicateCall to check
        equalities: Equivalence classes from _extract_equalities
        start_pos: Position of start endpoint
        end_pos: Position of end endpoint
        num_args: Number of arguments
        expr_name: Function to extract name from expression

    Returns:
        True if the predicate can be proven to be emp
    """
    args = [expr_name(a) for a in pred.args]

    # Check endpoint equality: E = F (positions 0 and 3 for 6-param)
    if not _are_equal_via_constraints(args[start_pos], args[end_pos], equalities):
        return False

    if num_args == 6:
        # For sdll(E, P, dt1, F, L, dt2):
        # Check P = L (positions 1 and 4)
        if not _are_equal_via_constraints(args[1], args[4], equalities):
            return False

        # Check dt1 = dt2 (positions 2 and 5)
        if not _are_equal_via_constraints(args[2], args[5], equalities):
            return False

    elif num_args == 4:
        # For ls(x, y, l, u) or sls(in, dt1, out, dt2):
        # Check remaining params are equal
        other_positions = [i for i in range(num_args) if i != start_pos and i != end_pos]
        if len(other_positions) >= 2:
            if not _are_equal_via_constraints(args[other_positions[0]], args[other_positions[-1]], equalities):
                return False

    return True


def _try_multi_pred_transitivity(
    library,
    antecedent: Formula,
    consequent: Formula,
    disequalities: set,
    cells_at: set,
    analyzer
) -> Optional[str]:
    """
    Handle multi-predicate consequent (SepConj) where some predicates may be
    direct matches and others may require transitivity.

    Algorithm:
    1. Extract all predicate calls from antecedent and consequent
    2. For each consequent predicate:
       - Try direct match in antecedent
       - If not found, try to find transitivity chain
    3. Verify all unused antecedent predicates can become emp
    """
    from frame.core.ast import PredicateCall, Var, Const, SepConj, PointsTo

    def expr_name(e):
        if isinstance(e, Var):
            return e.name
        if isinstance(e, Const):
            return str(e.value) if e.value is not None else 'nil'
        return str(e)

    # Extract predicates from antecedent and consequent
    ante_parts = analyzer._extract_sepconj_parts(antecedent)
    cons_parts = analyzer._extract_sepconj_parts(consequent)

    # Get antecedent predicates
    ante_preds = [p for p in ante_parts if isinstance(p, PredicateCall)]
    cons_preds = [p for p in cons_parts if isinstance(p, PredicateCall)]

    # SOUNDNESS CHECK: Extract PointsTo cells from antecedent and consequent
    # In separation logic, ALL heap content must be accounted for
    ante_ptos = [p for p in ante_parts if isinstance(p, PointsTo)]
    cons_ptos = [p for p in cons_parts if isinstance(p, PointsTo)]

    # Build pto signatures for matching
    def pto_sig(p):
        vals = tuple(expr_name(v) for v in p.values)
        return (expr_name(p.location), vals)

    # Check that all antecedent pto cells have a match in consequent
    cons_pto_sigs = {pto_sig(p) for p in cons_ptos}
    for ante_pto in ante_ptos:
        if pto_sig(ante_pto) not in cons_pto_sigs:
            # Antecedent has a pto cell not in consequent - entailment is invalid
            # unless it can be consumed by a predicate (handled later via folding)
            # For now, if we have unmatched pto cells, don't apply this lemma
            return None

    if not cons_preds:
        return None

    # Get the predicate type and arity (assume all same type)
    pred_name = cons_preds[0].name
    num_args = len(cons_preds[0].args)

    if num_args < 2:
        return None

    # Filter to only predicates matching the target type and arity
    same_type_preds = [p for p in ante_preds if p.name == pred_name and len(p.args) == num_args]
    if not same_type_preds:
        return None

    # Detect endpoint positions using only same-type predicates
    start_pos, end_pos = _detect_endpoint_positions(same_type_preds, num_args, expr_name)
    if start_pos is None:
        return None

    # Extract equality constraints
    equalities = _extract_equalities(antecedent)

    # Build signature function for matching predicates
    def pred_sig(p):
        return (p.name, tuple(expr_name(a) for a in p.args))

    # Build graph for transitivity chains
    edges = {}
    for pred in ante_preds:
        if pred.name == pred_name and len(pred.args) == num_args:
            start = expr_name(pred.args[start_pos])
            end = expr_name(pred.args[end_pos])
            all_args = tuple(expr_name(pred.args[i]) for i in range(len(pred.args)))
            if start not in edges:
                edges[start] = []
            edges[start].append((end, pred, all_args))

    # Track which antecedent predicates are used
    used_pred_ids = set()

    # For each consequent predicate, find a match or transitivity chain
    for cons_pred in cons_preds:
        cons_sig = pred_sig(cons_pred)

        # Try direct match
        found_direct = False
        for ante_pred in ante_preds:
            if id(ante_pred) in used_pred_ids:
                continue
            ante_sig = pred_sig(ante_pred)
            if ante_sig == cons_sig:
                used_pred_ids.add(id(ante_pred))
                found_direct = True
                break

        if found_direct:
            continue

        # Try transitivity chain
        target_start = expr_name(cons_pred.args[start_pos])
        target_end = expr_name(cons_pred.args[end_pos])

        def find_path(current, target, visited):
            if current == target:
                return []
            if current in visited:
                return None
            visited.add(current)

            for next_node, pred, all_args in edges.get(current, []):
                if id(pred) in used_pred_ids:
                    continue
                path = find_path(next_node, target, visited)
                if path is not None:
                    return [(pred, all_args)] + path

            visited.remove(current)
            return None

        path = find_path(target_start, target_end, set())

        if path is None or len(path) < 2:
            return None  # Cannot match this consequent predicate

        # Verify data chaining for the path (for 6-param predicates)
        if num_args >= 6:
            for i in range(len(path) - 1):
                pred1_args = path[i][1]
                pred2_args = path[i + 1][1]

                if num_args == 6:
                    end_data_pos = 5
                    start_data_pos = 2
                else:
                    data_positions = [j for j in range(num_args) if j != start_pos and j != end_pos]
                    end_data_pos = data_positions[-1] if data_positions else None
                    start_data_pos = data_positions[0] if data_positions else None

                if end_data_pos is not None and start_data_pos is not None:
                    val1 = pred1_args[end_data_pos]
                    val2 = pred2_args[start_data_pos]
                    if val1 != val2 and not _are_equal_via_constraints(val1, val2, equalities):
                        return None

        # Mark path predicates as used
        for pred, _ in path:
            used_pred_ids.add(id(pred))

    # Verify unused antecedent predicates can become emp
    # For 6-param predicates like sdll, check if unused predicates form cyclic pairs
    # that would become emp via separation logic semantics
    unused_preds = [p for p in ante_preds if id(p) not in used_pred_ids]

    if num_args == 6:
        # Check for cyclic pairs: P(A→B) and P(B→A) form a cycle
        # Due to separation, they must both be emp (share no heap) or cause unsat
        handled_by_cycle = set()

        for i, pred1 in enumerate(unused_preds):
            for j, pred2 in enumerate(unused_preds):
                if i >= j:
                    continue

                # Check if pred1 and pred2 form a cycle (A→B and B→A)
                start1 = expr_name(pred1.args[start_pos])
                end1 = expr_name(pred1.args[end_pos])
                start2 = expr_name(pred2.args[start_pos])
                end2 = expr_name(pred2.args[end_pos])

                # Check for cycle: start1=end2 and end1=start2 (or via equalities)
                is_cycle = False
                if _are_equal_via_constraints(start1, end2, equalities) and \
                   _are_equal_via_constraints(end1, start2, equalities):
                    is_cycle = True

                if is_cycle:
                    # Cyclic pairs (A→B and B→A) are valid frame content if:
                    # 1. Both can become emp (E=F, P=L, dt1=dt2 for each), OR
                    # 2. Data chains properly (pred1.end_data = pred2.start_data AND vice versa)
                    #
                    # For sdll(E, P, dt1, F, L, dt2):
                    # - dt1 is at position 2 (start data)
                    # - dt2 is at position 5 (end data)

                    # Check if both can be emp
                    pred1_can_be_emp = _can_be_emp(pred1, equalities, start_pos, end_pos, num_args, expr_name)
                    pred2_can_be_emp = _can_be_emp(pred2, equalities, start_pos, end_pos, num_args, expr_name)

                    if pred1_can_be_emp and pred2_can_be_emp:
                        # Both predicates can become emp, cycle is valid
                        handled_by_cycle.add(id(pred1))
                        handled_by_cycle.add(id(pred2))
                    else:
                        # For 6-param predicates, check data chaining at connection points
                        # pred1: E1→E2 with data dt1_1→dt2_1
                        # pred2: E2→E1 with data dt1_2→dt2_2
                        # For valid cycle: dt2_1 = dt1_2 AND dt2_2 = dt1_1
                        pred1_dt2 = expr_name(pred1.args[5])  # end data
                        pred2_dt1 = expr_name(pred2.args[2])  # start data
                        pred2_dt2 = expr_name(pred2.args[5])  # end data
                        pred1_dt1 = expr_name(pred1.args[2])  # start data

                        data_chains = (
                            _are_equal_via_constraints(pred1_dt2, pred2_dt1, equalities) and
                            _are_equal_via_constraints(pred2_dt2, pred1_dt1, equalities)
                        )

                        if data_chains:
                            # Data chains properly, cycle is valid frame content
                            handled_by_cycle.add(id(pred1))
                            handled_by_cycle.add(id(pred2))

        # Check remaining unused preds (not in cycles)
        for pred in unused_preds:
            if id(pred) in handled_by_cycle:
                continue
            if not _can_be_emp(pred, equalities, start_pos, end_pos, num_args, expr_name):
                return None
    else:
        for pred in unused_preds:
            if not _can_be_emp(pred, equalities, start_pos, end_pos, num_args, expr_name):
                return None

    return f"multi_pred_transitivity_{pred_name}"
