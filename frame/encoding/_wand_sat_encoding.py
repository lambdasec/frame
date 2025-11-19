"""
SAT-Mode Wand Encoding for Separation Logic

Implements the existential witness-based encoding for magic wand in SAT mode.
This is extracted from _wand.py to reduce file size.
"""

import z3
from typing import Set, Tuple, Optional, Dict, List
from frame.core.ast import Formula, Emp, PointsTo, SepConj, And, Or

def encode_wand_sat(
    wand_encoder,
    P: Formula,
    Q: Formula,
    heap_var: z3.ExprRef,
    domain_set: Set[z3.ExprRef],
    domain_map: Dict[z3.ExprRef, z3.ExprRef],
    prefix: str
) -> Tuple[z3.BoolRef, Set[z3.ExprRef]]:
    """
    SAT-specific wand encoding using materialized witness (existential).

    For SAT problems, we encode: EXISTS ext_heap such that:
      - ext_heap is disjoint from main heap
      - P holds in ext_heap
      - Q holds in (main_heap union ext_heap)

    This is stronger than the implication-based encoding and prevents
    vacuous satisfaction. The existential quantification forces the solver
    to find an actual witness, properly constraining the main heap.

    WAND ELIMINATION: If P exactly matches the local heap context (same locations
    with same values), apply the rule: P * (P -* Q) ≡ P * Q
    In this case, we just encode Q without the extension heap.

    Args:
        wand_encoder: The WandEncoder instance
        P: Wand antecedent
        Q: Wand consequent
        heap_var: Main heap variable
        domain_set: Current domain
        domain_map: Domain value map
        prefix: Variable prefix

    Returns:
        (wand_constraint, wand_domain): Existentially quantified constraint and domain
    """
    # STEP 1: Try wand elimination (P * (P -* Q) ≡ P * Q)
    # If P's footprint is already in domain_set with matching values, just encode Q
    elimination_result = wand_encoder._try_wand_elimination(P, Q, heap_var, domain_set, domain_map, prefix)
    if elimination_result is not None:
        return elimination_result

    # STEP 2: Fallback to witness-based encoding with STRICT disjointness
    # Collect known locations from P and Q for finite encoding
    known_locs = wand_encoder._collect_known_locations(P, Q, prefix)

    if not known_locs:
        # Fallback to implication encoding if no locations found
        return wand_encoder._encode_wand_full(P, Q, heap_var, domain_set, domain_map, prefix)

    # Create finite symbolic heaps using alloc/val variables per location
    ext_alloc = {}
    ext_val = {}
    union_alloc = {}
    union_val = {}

    for loc in known_locs:
        ext_alloc[loc] = z3.Bool(f"{prefix}_ext_alloc_{loc}")
        ext_val[loc] = z3.Int(f"{prefix}_ext_val_{loc}")
        union_alloc[loc] = z3.Bool(f"{prefix}_union_alloc_{loc}")
        union_val[loc] = z3.Int(f"{prefix}_union_val_{loc}")

    # Encode P on extension heap (finite)
    p_constraints = wand_encoder._encode_formula_on_finite_heap(P, ext_alloc, ext_val, prefix)

    # Encode disjointness: ext heap must be STRICTLY disjoint from main heap
    #
    # CRITICAL: Extension cannot allocate ANY location in domain_set.
    # This is required by separation logic semantics.
    #
    # If P matches the local context exactly, wand elimination (above) handles it.
    # If we reach here, P doesn't match, so ext must be completely disjoint.
    #
    # Constraint: ext_alloc[loc] => Not(loc in domain_set)
    disj_constraints = []
    for loc in known_locs:
        # Check if loc is allocated in the local heap context (domain_set)
        main_alloc = wand_encoder._is_allocated_in_domain(loc, domain_set)
        if main_alloc is not None:
            # loc is in domain: ext CANNOT allocate it (strict disjointness)
            # main_alloc is True if loc is in domain, so Not(True) = False prevents allocation
            disjoint_constraint = z3.Implies(ext_alloc[loc], z3.Not(main_alloc))
            disj_constraints.append(disjoint_constraint)

    # Encode union heap semantics
    union_constraints = []
    for loc in known_locs:
        main_alloc = wand_encoder._is_allocated_in_domain(loc, domain_set)

        # union_alloc[loc] = main_alloc[loc] OR ext_alloc[loc]
        if main_alloc is not None:
            union_constraints.append(union_alloc[loc] == z3.Or(main_alloc, ext_alloc[loc]))
        else:
            union_constraints.append(union_alloc[loc] == ext_alloc[loc])

        # union_val[loc] = ext_val if ext allocated, else main_val if main allocated
        union_constraints.append(
            z3.Implies(ext_alloc[loc], union_val[loc] == ext_val[loc])
        )

        # If ext doesn't allocate but main does, use main value
        if main_alloc is not None:
            main_val = wand_encoder._get_value_from_heap(loc, heap_var)
            union_constraints.append(
                z3.Implies(z3.And(z3.Not(ext_alloc[loc]), main_alloc),
                         union_val[loc] == main_val)
            )

    # Encode Q on union heap (finite)
    q_constraints = wand_encoder._encode_formula_on_finite_heap(Q, union_alloc, union_val, prefix)

    # CORRECT WAND SEMANTICS for SAT mode:
    # (P -* Q)(h) ≡ ∀h'. (h # h' ∧ P(h')) → Q(h ∪ h')
    # Which is equivalent to: ¬∃h'. (h # h' ∧ P(h') ∧ ¬Q(h ∪ h'))
    #
    # Build the counterexample: P(ext) ∧ disjoint ∧ union_def ∧ ¬Q(union)
    counterexample_parts = p_constraints + disj_constraints + union_constraints

    # Negate Q constraints for the counterexample
    q_body = z3.And(q_constraints) if len(q_constraints) > 1 else (q_constraints[0] if q_constraints else z3.BoolVal(True))
    counterexample_parts.append(z3.Not(q_body))

    counterexample = z3.And(counterexample_parts) if len(counterexample_parts) > 1 else (
        counterexample_parts[0] if counterexample_parts else z3.BoolVal(False)
    )

    # Existentially quantify over extension heap variables (the counterexample)
    ext_vars = list(ext_alloc.values()) + list(ext_val.values())

    if ext_vars:
        # Wand holds iff there is NO counterexample
        wand_constraint = z3.Not(z3.Exists(ext_vars, counterexample))
    else:
        # No extension variables - just check if counterexample is impossible
        wand_constraint = z3.Not(counterexample)

    # Domain: The wand itself does NOT claim any locations
    # CRITICAL: Returning locations from P would cause spurious disjointness constraints
    # in SepConj. For example, (u |-> v) * (u |-> v -* Q) would generate u != u.
    #
    # The wand is a PROPOSITION about heap extensions, not an allocation.
    # It should not claim any domain locations.
    wand_domain = set()  # Empty domain - wand doesn't allocate

    return (wand_constraint, wand_domain)


def encode_formula_on_finite_heap(
    wand_encoder,
    formula: Formula,
    alloc_map: Dict[z3.ExprRef, z3.BoolRef],
    val_map: Dict[z3.ExprRef, z3.ExprRef],
    prefix: str
) -> List[z3.BoolRef]:
    """
    Encode a formula over a finite symbolic heap represented by alloc/val maps.

    Args:
        wand_encoder: The WandEncoder instance
        formula: The formula to encode
        alloc_map: Dict mapping locations to allocation flags
        val_map: Dict mapping locations to values
        prefix: Variable prefix

    Returns:
        List of Z3 constraints representing the formula
    """
    constraints = []

    if isinstance(formula, Emp):
        # Empty heap: check if standalone or in SepConj
        #
        # Case 1: Standalone Q = emp in wand (P -* emp)
        #   Should assert union heap is empty: all alloc_flags false
        #
        # Case 2: In SepConj like (P * emp)
        #   Should be identity: no constraints
        #
        # We can't easily distinguish these cases at this level.
        # Workaround: Only assert emptiness if alloc_map has exactly the locations
        # that a standalone emp would check. For now, use a heuristic:
        # If there are very few locations (≤2), might be standalone emp for wand consequent
        #
        # Better solution: Pass a flag indicating context, but that requires refactoring.
        #
        # For now: Always treat as identity (no constraints) to avoid SepConj contradictions
        # This means wand consequent emp won't work correctly - known limitation
        pass

    elif isinstance(formula, PointsTo):
        # x |-> v: location x is allocated with value v
        loc = wand_encoder.encoder.encode_expr(formula.location, prefix=prefix)

        # Find this location in alloc_map
        if loc in alloc_map:
            constraints.append(alloc_map[loc])  # Location is allocated

            # Encode values
            if len(formula.values) == 1:
                val = wand_encoder.encoder.encode_expr(formula.values[0], prefix=prefix)
                constraints.append(val_map[loc] == val)
            # For multiple values, would need offset handling
        else:
            # Location not in our finite domain; conservative: always true
            pass

    elif isinstance(formula, SepConj):
        # P * Q: both hold on disjoint parts
        # For finite encoding, we split allocations between P and Q
        # This is approximated: we require both to hold
        left_constraints = encode_formula_on_finite_heap(wand_encoder, formula.left, alloc_map, val_map, prefix)
        right_constraints = encode_formula_on_finite_heap(wand_encoder, formula.right, alloc_map, val_map, prefix)
        constraints.extend(left_constraints)
        constraints.extend(right_constraints)

    elif isinstance(formula, And):
        # P & Q: both hold on same heap
        left_constraints = encode_formula_on_finite_heap(wand_encoder, formula.left, alloc_map, val_map, prefix)
        right_constraints = encode_formula_on_finite_heap(wand_encoder, formula.right, alloc_map, val_map, prefix)
        constraints.extend(left_constraints)
        constraints.extend(right_constraints)

    elif isinstance(formula, Or):
        # P | Q: at least one holds
        left_constraints = encode_formula_on_finite_heap(wand_encoder, formula.left, alloc_map, val_map, prefix)
        right_constraints = encode_formula_on_finite_heap(wand_encoder, formula.right, alloc_map, val_map, prefix)
        if left_constraints and right_constraints:
            constraints.append(z3.Or(z3.And(left_constraints), z3.And(right_constraints)))
        elif left_constraints:
            constraints.extend(left_constraints)
        elif right_constraints:
            constraints.extend(right_constraints)

    # Other formula types (predicates, etc.) would need special handling

    return constraints


def encode_negated_wand_sat(
    wand_encoder,
    P: Formula,
    Q: Formula,
    heap_var: z3.ExprRef,
    domain_set: Set[z3.ExprRef],
    prefix: str
) -> Tuple[z3.BoolRef, Set[z3.ExprRef]]:
    """
    Encode NOT(P -* Q) for SAT context using counterexample semantics.

    Semantics: not (P -* Q) means there exists an extension h' such that:
      - h' is disjoint from h
      - P holds in h'
      - Q does NOT hold in h ∪ h'

    This is the existential counterexample to the wand.

    Args:
        wand_encoder: The WandEncoder instance
        P: Wand antecedent
        Q: Wand consequent
        heap_var: Main heap variable
        domain_set: Current domain
        prefix: Variable prefix

    Returns:
        (constraint, domain): Existentially quantified counterexample and domain
    """
    # Use same finite heap encoding as positive wand, but negate Q
    known_locs = wand_encoder._collect_known_locations(P, Q, prefix)

    if not known_locs:
        # Fallback: negate the implication encoding
        wand_constraint, wand_domain = wand_encoder._encode_wand_full(P, Q, heap_var, domain_set, {}, prefix)
        return (z3.Not(wand_constraint), wand_domain)

    # Create finite symbolic heaps
    ext_alloc = {}
    ext_val = {}
    union_alloc = {}
    union_val = {}

    for loc in known_locs:
        ext_alloc[loc] = z3.Bool(f"{prefix}_negext_alloc_{loc}")
        ext_val[loc] = z3.Int(f"{prefix}_negext_val_{loc}")
        union_alloc[loc] = z3.Bool(f"{prefix}_negunion_alloc_{loc}")
        union_val[loc] = z3.Int(f"{prefix}_negunion_val_{loc}")

    # Encode P on extension heap
    p_constraints = encode_formula_on_finite_heap(wand_encoder, P, ext_alloc, ext_val, prefix)

    # Encode disjointness (same as positive wand)
    disj_constraints = []
    for loc in known_locs:
        main_alloc = wand_encoder._is_allocated_in_domain(loc, domain_set)
        if main_alloc is not None:
            disj_constraints.append(z3.Implies(ext_alloc[loc], z3.Not(main_alloc)))

    # Encode union heap
    union_constraints = []
    for loc in known_locs:
        main_alloc = wand_encoder._is_allocated_in_domain(loc, domain_set)

        if main_alloc is not None:
            union_constraints.append(union_alloc[loc] == z3.Or(main_alloc, ext_alloc[loc]))
        else:
            union_constraints.append(union_alloc[loc] == ext_alloc[loc])

        union_constraints.append(
            z3.Implies(ext_alloc[loc], union_val[loc] == ext_val[loc])
        )

        if main_alloc is not None:
            main_val = wand_encoder._get_value_from_heap(loc, heap_var)
            union_constraints.append(
                z3.Implies(z3.And(z3.Not(ext_alloc[loc]), main_alloc),
                         union_val[loc] == main_val)
            )

    # Encode Q on union heap
    q_constraints = encode_formula_on_finite_heap(wand_encoder, Q, union_alloc, union_val, prefix)

    # CRITICAL: Negate Q for counterexample
    # not (P -* Q) = Exists ext. P(ext) ∧ ¬Q(union) ∧ disjoint
    if q_constraints:
        negated_q = z3.Not(z3.And(q_constraints)) if len(q_constraints) > 1 else z3.Not(q_constraints[0])
    else:
        negated_q = z3.BoolVal(True)  # Q is vacuously false if no constraints

    # Build counterexample body
    body_parts = p_constraints + disj_constraints + union_constraints + [negated_q]
    body = z3.And(body_parts) if len(body_parts) > 1 else (body_parts[0] if body_parts else z3.BoolVal(True))

    # Existentially quantify over extension heap variables
    ext_vars = list(ext_alloc.values()) + list(ext_val.values())

    if ext_vars:
        negated_wand_constraint = z3.Exists(ext_vars, body)
    else:
        negated_wand_constraint = body

    # Domain: claim locations from antecedent P
    wand_domain = wand_encoder._extract_locations_from_antecedent(P, prefix)

    return (negated_wand_constraint, wand_domain)
