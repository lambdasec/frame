"""
Magic Wand Encoding for Separation Logic

Implements semantic encoding of P -* Q (magic wand) using bounded heap extensions.

Theoretical Foundation:
  (P -* Q) holds in heap h if:
  ∀h'. (disjoint(h, h') ∧ P(h')) → Q(h ∪ h')

Practical Encoding:
  - Bound h' size by formula complexity (finite model property)
  - Use existential quantification over bounded extensions
  - Lazy instantiation: only check wand when used in frame inference

References:
  - Reynolds, "Separation Logic: A Logic for Shared Mutable Data Structures" (2002)
  - Piskac et al., "Deciding Separation Logic with Heap Extensions" (2013)
  - CVC4-SL implementation

Implementation Strategy:
  For simple cases like (P -* Q) * P |- Q (wand elimination/modus ponens),
  we can use a direct encoding without complex heap quantification.

  For now, we implement:
  1. Direct wand elimination pattern matching (fast path)
  2. Conservative encoding for other cases (fall back to lemmas)
  3. Future: Full bounded heap extension encoding for complex cases
"""

import z3
from typing import Set, Tuple, Optional, Dict, List
from frame.core.ast import Formula, Wand, Emp, PointsTo, SepConj, And, Or, Not, Eq, Neq, Var, ArithExpr


class WandEncoder:
    """Encodes magic wand (P -* Q) into Z3 constraints"""

    def __init__(self, parent_encoder):
        """
        Args:
            parent_encoder: Reference to Z3Encoder for shared state
        """
        self.encoder = parent_encoder
        self.max_extension_size = 5  # Bound on heap extension size
        self.enable_full_encoding = True  # Enable full bounded heap extension encoding
        self.mode = "SAT"  # Default mode: "SAT" or "ENTAILMENT"

    def encode_wand(self, wand: Wand, heap_var: z3.ExprRef,
                   domain_set: Set[z3.ExprRef],
                   domain_map: Dict[z3.ExprRef, z3.ExprRef],
                   prefix: str = "") -> Tuple[z3.BoolRef, Set[z3.ExprRef]]:
        """
        Encode (P -* Q) using mode-aware semantics.

        Mode selection:
          - SAT: Use materialized witness encoding (existential)
          - ENTAILMENT: Use implication-based encoding (universal)

        Strategy:
          1. Check for simple elimination patterns (P -* Q) * P
          2. For simple emp case: emp -* Q means Q holds
          3. For SAT mode: Use materialized witness encoding
          4. For ENTAILMENT mode: Use bounded heap extension encoding

        Args:
            wand: The wand formula P -* Q
            heap_var: Current heap variable
            domain_set: Current domain
            prefix: Variable prefix for scoping

        Returns:
            (wand_constraint, wand_domain): Z3 constraint and domain
        """
        P = wand.left  # Antecedent
        Q = wand.right  # Consequent

        # Special case 1: emp -* Q means Q (with empty heap)
        if isinstance(P, Emp):
            return self._encode_emp_wand(Q, heap_var, domain_set, prefix)

        # Route to mode-specific encoding
        if self.mode == "SAT" and self.enable_full_encoding:
            return self._encode_wand_sat(P, Q, heap_var, domain_set, domain_map, prefix)
        elif self.mode == "ENTAILMENT" and self.enable_full_encoding:
            return self._encode_wand_full(P, Q, heap_var, domain_set, domain_map, prefix)
        else:
            # Conservative fallback: create boolean variable
            wand_var = z3.Bool(f"wand_{prefix}_{id(wand)}")
            wand_domain = self._extract_locations_from_antecedent(P, prefix)
            return (wand_var, wand_domain)

    def _encode_emp_wand(self, Q: Formula, heap_var: z3.ExprRef,
                        domain_set: Set[z3.ExprRef],
                        prefix: str) -> Tuple[z3.BoolRef, Set[z3.ExprRef]]:
        """
        Encode emp -* Q.

        Semantics: (emp -* Q) holds in h if Q holds in h
        (since emp can be satisfied with empty extension)
        """
        # Q should hold on the current heap
        q_constraints, q_domain = self.encoder._spatial_encoder.encode_heap_assertion(
            Q, heap_var, domain_set, prefix=f"{prefix}_empwand"
        )

        # emp -* Q: Since antecedent is emp, no locations to claim
        # But we return q_domain to indicate this wand requires those locations
        return (q_constraints, q_domain)

    def _encode_pto_wand(self, P: PointsTo, Q: PointsTo, heap_var: z3.ExprRef,
                        domain_set: Set[z3.ExprRef],
                        prefix: str) -> Tuple[z3.BoolRef, Set[z3.ExprRef]]:
        """
        Encode (x |-> v -* y |-> w).

        Semantics: If we extend heap with x |-> v, then y |-> w must hold.
        For disjoint case (x != y), this is a conditional constraint.
        """
        # The wand constraint: if we add P to heap, Q must follow
        # This is a conditional: P_valid → Q_valid
        # For now, encode conservatively
        wand_var = z3.Bool(f"pto_wand_{prefix}_{id(P)}_{id(Q)}")

        # Extract the location from P's antecedent
        wand_domain = self._extract_locations_from_antecedent(P, prefix)

        return (wand_var, wand_domain)

    def _encode_wand_full(self, P: Formula, Q: Formula, heap_var: z3.ExprRef,
                         domain_set: Set[z3.ExprRef],
                         domain_map: Dict[z3.ExprRef, z3.ExprRef],
                         prefix: str) -> Tuple[z3.BoolRef, Set[z3.ExprRef]]:
        """
        Full bounded heap extension encoding for wand.

        Encoding: (P -* Q)(h) = ∀h'. (disjoint(h, h') ∧ P(h')) → Q(h ∪ h')

        With bounded extension size for decidability.
        """
        # Step 1: Compute bound on extension size
        extension_bound = self._compute_extension_bound(P)
        if extension_bound > self.max_extension_size:
            extension_bound = self.max_extension_size

        # Step 2: Create fresh locations for extension heap h'
        extension_locs = [
            self.encoder.fresh_var(f"ext_{prefix}", self.encoder.LocSort)
            for _ in range(extension_bound)
        ]
        extension_domain = set(extension_locs)

        # Step 3: Create extension heap ID (using heap-ID based encoding)
        ext_heap_id = self.encoder.fresh_heap_id(f"ext_{prefix}")

        # Step 4: Encode P on extension heap
        # CRITICAL: Use the SAME prefix as the surrounding context to ensure
        # variables like 'u' in the wand match variables 'u' in the main formula
        p_constraints, p_domain = self.encoder._spatial_encoder.encode_heap_assertion(
            P, ext_heap_id, set(), forbidden_domain=domain_set, prefix=prefix
        )

        # Step 5: Encode disjointness: domain(h) ∩ domain(h') = ∅
        disjointness = self._encode_disjointness(domain_set, p_domain)

        # Step 6: Create union heap ID: h ∪ h'
        union_heap_id = self.encoder.fresh_heap_id(f"union_{prefix}")
        union_domain = domain_set | p_domain

        # Encode heap union semantics: for each location in union domain,
        # the value comes from either h or h' (depending on which owns it)
        union_constraints = []
        for loc in union_domain:
            if loc in domain_set:
                # Location from original heap: alloc(union, loc) <-> alloc(h, loc)
                #                               hval(union, loc) = hval(h, loc)
                union_constraints.append(
                    z3.Implies(self.encoder.alloc(heap_var, loc),
                               z3.And(self.encoder.alloc(union_heap_id, loc),
                                      self.encoder.hval(union_heap_id, loc) == self.encoder.hval(heap_var, loc))))
            else:
                # Location from extension heap: alloc(union, loc) <-> alloc(h', loc)
                #                                hval(union, loc) = hval(h', loc)
                union_constraints.append(
                    z3.Implies(self.encoder.alloc(ext_heap_id, loc),
                               z3.And(self.encoder.alloc(union_heap_id, loc),
                                      self.encoder.hval(union_heap_id, loc) == self.encoder.hval(ext_heap_id, loc))))

        # Step 7: Encode Q on union heap
        # CRITICAL: Use the SAME prefix to ensure variable consistency
        q_constraints, q_domain = self.encoder._spatial_encoder.encode_heap_assertion(
            Q, union_heap_id, union_domain, prefix=prefix
        )

        # Step 8: Encode wand semantics: (disjoint ∧ P(h')) → Q(h ∪ h')
        wand_constraint = z3.Implies(
            z3.And(disjointness, p_constraints, *union_constraints),
            q_constraints
        )

        # CRITICAL FIX: The wand must claim the locations mentioned in its antecedent P
        # to ensure proper disjointness checking in separating conjunction.
        # For example: u |-> 0 * (u |-> 0 -* Q) * u |-> 0
        # All three parts should claim location u, triggering disjointness violation.
        wand_domain = self._extract_locations_from_antecedent(P, prefix)

        return (wand_constraint, wand_domain)

    def _antecedent_matches_context(self, P: Formula, heap_var: z3.ExprRef,
                                    domain_set: Set[z3.ExprRef], prefix: str) -> bool:
        """
        Check if wand antecedent P matches what's already in the local heap context.

        This enables wand elimination: P * (P -* Q) ≡ P * Q

        Returns True if:
        1. All locations in P are in domain_set
        2. All values in P match what's in heap_var

        Currently handles simple cases:
        - Single PointsTo: u |-> v
        - Emp (always matches)
        - SepConj of PointsTo assertions

        Args:
            P: Wand antecedent formula
            heap_var: Heap array
            domain_set: Local heap domain
            prefix: Variable prefix

        Returns:
            True if P matches the local context, False otherwise
        """
        # Handle Emp: always matches (empty heap requirement is satisfied)
        if isinstance(P, Emp):
            return True

        # Handle simple PointsTo: u |-> v
        if isinstance(P, PointsTo):
            loc_z3 = self.encoder.encode_expr(P.location, prefix=prefix)

            # Check if location is in domain
            # If it is, apply wand elimination - the wand will be checked via Q
            # The key insight: if u is in domain_set, then (u |-> v) * (u |-> v' -* Q)
            # can only be SAT if v == v', which will be checked by the rest of the formula
            return self._is_allocated_in_domain(loc_z3, domain_set) is not None

        # Handle SepConj: P1 * P2 (both parts must match)
        if isinstance(P, SepConj):
            return (self._antecedent_matches_context(P.left, heap_var, domain_set, prefix) and
                    self._antecedent_matches_context(P.right, heap_var, domain_set, prefix))

        # Handle And: P1 & P2 (both parts must match)
        if isinstance(P, And):
            # If left is pure and right is spatial, check the spatial part
            if not P.left.is_spatial() and P.right.is_spatial():
                return self._antecedent_matches_context(P.right, heap_var, domain_set, prefix)
            # If right is pure and left is spatial, check the spatial part
            if not P.right.is_spatial() and P.left.is_spatial():
                return self._antecedent_matches_context(P.left, heap_var, domain_set, prefix)
            # Both spatial: check both
            if P.left.is_spatial() and P.right.is_spatial():
                return (self._antecedent_matches_context(P.left, heap_var, domain_set, prefix) and
                        self._antecedent_matches_context(P.right, heap_var, domain_set, prefix))
            # Both pure: matches vacuously (pure constraints don't affect heap)
            return True

        # Conservative: return False for complex patterns
        return False

    def _try_wand_elimination(self, P: Formula, Q: Formula, heap_var: z3.ExprRef,
                             domain_set: Set[z3.ExprRef],
                             domain_map: Dict[z3.ExprRef, z3.ExprRef],
                             prefix: str) -> Optional[Tuple[z3.BoolRef, Set[z3.ExprRef]]]:
        """
        Attempt wand elimination: P * (P -* Q) ≡ P * Q

        Checks if P's footprint is already present in domain_set with matching values.
        If so, encodes Q directly on the existing heap without creating extension.

        Returns:
            (q_constraint, domain) if elimination applies, None otherwise
        """
        # Extract locations and required values from P
        p_footprint = self._extract_footprint_with_values(P, prefix)

        if not p_footprint:
            # No concrete footprint (e.g., emp or complex formula)
            # For emp, always eliminate (emp matches empty footprint)
            if isinstance(P, Emp):
                from frame.encoding._spatial import SpatialEncoder
                spatial_encoder = SpatialEncoder(self.encoder)
                # CRITICAL: Use empty prefix so Q references existing variables from left side
                q_constraint, q_domain = spatial_encoder.encode_heap_assertion(
                    Q, heap_var, domain_set, set(), 0, prefix=""
                )
                return (q_constraint, set())  # Wand doesn't claim domain
            return None

        # Check if all locations in P are in domain_set with matching values using domain_map
        for loc_expr, required_val_expr in p_footprint.items():
            # Check location is in domain
            if not self._is_allocated_in_domain(loc_expr, domain_set):
                return None  # Location not in domain, can't eliminate

            # Check value matches using domain_map
            # domain_map tracks what value was assigned to each location in the left side
            if loc_expr in domain_map:
                actual_val = domain_map[loc_expr]
                # Check if actual value equals required value
                # Use Z3's structural equality (z3.eq for objects, simplify for expressions)
                if not z3.eq(actual_val, required_val_expr):
                    # Try semantic equality check
                    if not z3.simplify(actual_val == required_val_expr):
                        return None  # Values don't match, can't eliminate
            else:
                # Location not in domain_map - shouldn't happen if it's in domain_set
                # Be conservative: don't eliminate
                return None

        # All locations present with matching values - safe to eliminate
        from frame.encoding._spatial import SpatialEncoder
        spatial_encoder = SpatialEncoder(self.encoder)
        # CRITICAL: Use empty prefix so Q references existing variables from left side
        q_constraint, q_domain = spatial_encoder.encode_heap_assertion(
            Q, heap_var, domain_set, set(), 0, prefix=""
        )

        # Return Q's constraint with empty wand domain
        return (q_constraint, set())

    def _extract_footprint_with_values(self, formula: Formula, prefix: str) -> Dict[z3.ExprRef, z3.ExprRef]:
        """
        Extract footprint of formula as mapping from locations to required values.

        Returns:
            Dict mapping location Z3 expressions to value Z3 expressions
        """
        footprint = {}

        if isinstance(formula, Emp):
            return {}  # Empty footprint

        elif isinstance(formula, PointsTo):
            loc_expr = self.encoder.encode_expr(formula.location, prefix=prefix)
            # Add offset to match domain_map keys (which use loc + offset)
            for i, val_expr_ast in enumerate(formula.values):
                val_expr = self.encoder.encode_expr(val_expr_ast, prefix=prefix)
                footprint[loc_expr + i] = val_expr

        elif isinstance(formula, SepConj):
            # Union of footprints from both sides
            left_fp = self._extract_footprint_with_values(formula.left, prefix)
            right_fp = self._extract_footprint_with_values(formula.right, prefix)
            footprint.update(left_fp)
            footprint.update(right_fp)

        elif isinstance(formula, And):
            # Extract from spatial part only
            if formula.left.is_spatial():
                footprint.update(self._extract_footprint_with_values(formula.left, prefix))
            if formula.right.is_spatial():
                footprint.update(self._extract_footprint_with_values(formula.right, prefix))

        # For other formulas, return empty (conservative)
        return footprint

    def _encode_wand_sat(self, P: Formula, Q: Formula, heap_var: z3.ExprRef,
                        domain_set: Set[z3.ExprRef],
                        domain_map: Dict[z3.ExprRef, z3.ExprRef],
                        prefix: str) -> Tuple[z3.BoolRef, Set[z3.ExprRef]]:
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
            P: Wand antecedent
            Q: Wand consequent
            heap_var: Main heap variable
            domain_set: Current domain
            prefix: Variable prefix

        Returns:
            (wand_constraint, wand_domain): Existentially quantified constraint and domain
        """
        # STEP 1: Try wand elimination (P * (P -* Q) ≡ P * Q)
        # If P's footprint is already in domain_set with matching values, just encode Q
        elimination_result = self._try_wand_elimination(P, Q, heap_var, domain_set, domain_map, prefix)
        if elimination_result is not None:
            return elimination_result

        # STEP 2: Fallback to witness-based encoding with STRICT disjointness
        # Collect known locations from P and Q for finite encoding
        known_locs = self._collect_known_locations(P, Q, prefix)

        if not known_locs:
            # Fallback to implication encoding if no locations found
            return self._encode_wand_full(P, Q, heap_var, domain_set, prefix)

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
        p_constraints = self._encode_formula_on_finite_heap(P, ext_alloc, ext_val, prefix)

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
            main_alloc = self._is_allocated_in_domain(loc, domain_set)
            if main_alloc is not None:
                # loc is in domain: ext CANNOT allocate it (strict disjointness)
                # main_alloc is True if loc is in domain, so Not(True) = False prevents allocation
                disjoint_constraint = z3.Implies(ext_alloc[loc], z3.Not(main_alloc))
                disj_constraints.append(disjoint_constraint)

        # Encode union heap semantics
        union_constraints = []
        for loc in known_locs:
            main_alloc = self._is_allocated_in_domain(loc, domain_set)

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
                main_val = self._get_value_from_heap(loc, heap_var)
                union_constraints.append(
                    z3.Implies(z3.And(z3.Not(ext_alloc[loc]), main_alloc),
                             union_val[loc] == main_val)
                )

        # Encode Q on union heap (finite)
        q_constraints = self._encode_formula_on_finite_heap(Q, union_alloc, union_val, prefix)

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

    def _collect_known_locations(self, P: Formula, Q: Formula, prefix: str) -> Set[z3.ExprRef]:
        """
        Collect all known location variables from P and Q.
        These are the locations we'll materialize in the finite heap encoding.

        EXPANDED: Now collects:
        1. All locations from PointsTo assertions
        2. All values pointed to (closure under pto)
        3. All variables mentioned in equalities (closure under equalities)
        """
        locations = set()
        vars_mentioned = set()  # Track all variables for equality closure

        def collect_expr_vars(expr):
            """Collect all variables from an expression"""
            if isinstance(expr, Var):
                vars_mentioned.add(expr.name)
            elif isinstance(expr, ArithExpr):
                if hasattr(expr, 'left'):
                    collect_expr_vars(expr.left)
                if hasattr(expr, 'right'):
                    collect_expr_vars(expr.right)

        def collect(formula: Formula):
            if isinstance(formula, PointsTo):
                # Collect location
                loc_z3 = self.encoder.encode_expr(formula.location, prefix=prefix)
                locations.add(loc_z3)
                # Also collect location variable name for equality closure
                collect_expr_vars(formula.location)
                # NEW: Also collect values for closure
                for val_expr in formula.values:
                    collect_expr_vars(val_expr)
                    # If value is a variable or constant, encode it as potential location
                    try:
                        val_z3 = self.encoder.encode_expr(val_expr, prefix=prefix)
                        locations.add(val_z3)
                    except:
                        pass
            elif isinstance(formula, (Eq, Neq)):
                # Collect variables from both sides of equality
                collect_expr_vars(formula.left)
                collect_expr_vars(formula.right)
            elif isinstance(formula, SepConj):
                collect(formula.left)
                collect(formula.right)
            elif isinstance(formula, And) or isinstance(formula, Or):
                collect(formula.left)
                collect(formula.right)
            elif isinstance(formula, Wand):
                collect(formula.left)
                collect(formula.right)
            elif isinstance(formula, Not):
                collect(formula.formula)
            # Predicates would need unfolding, skip for now

        collect(P)
        collect(Q)

        # NEW: Close under equalities - encode all mentioned variables
        for var_name in vars_mentioned:
            try:
                var_expr = Var(var_name)
                var_z3 = self.encoder.encode_expr(var_expr, prefix=prefix)
                locations.add(var_z3)
            except:
                pass

        return locations

    def _is_allocated_in_domain(self, loc: z3.ExprRef, domain_set: Set[z3.ExprRef]) -> z3.BoolRef:
        """
        Check if a location is allocated in the given domain.
        Returns Z3 constraint or None if location not in domain.
        """
        # Check if loc is in domain_set by comparing simplified string representations
        # z3.eq() returns a Z3 expression, not a Python bool, so we can't use it directly
        loc_str = str(z3.simplify(loc))
        for domain_loc in domain_set:
            domain_loc_str = str(z3.simplify(domain_loc))
            if loc_str == domain_loc_str:
                # Location is in main domain, so it IS allocated in main
                return z3.BoolVal(True)

        # Location not in domain means not allocated
        return None

    def _get_value_from_heap(self, loc: z3.ExprRef, heap_id: z3.ExprRef) -> z3.ExprRef:
        """Get value at location from heap using heap-relative semantics."""
        return self.encoder.hval(heap_id, loc)

    def _encode_formula_on_finite_heap(self, formula: Formula,
                                      alloc_map: Dict[z3.ExprRef, z3.BoolRef],
                                      val_map: Dict[z3.ExprRef, z3.ExprRef],
                                      prefix: str) -> List[z3.BoolRef]:
        """
        Encode a formula over a finite symbolic heap represented by alloc/val maps.

        Args:
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
            loc = self.encoder.encode_expr(formula.location, prefix=prefix)

            # Find this location in alloc_map
            if loc in alloc_map:
                constraints.append(alloc_map[loc])  # Location is allocated

                # Encode values
                if len(formula.values) == 1:
                    val = self.encoder.encode_expr(formula.values[0], prefix=prefix)
                    constraints.append(val_map[loc] == val)
                # For multiple values, would need offset handling
            else:
                # Location not in our finite domain; conservative: always true
                pass

        elif isinstance(formula, SepConj):
            # P * Q: both hold on disjoint parts
            # For finite encoding, we split allocations between P and Q
            # This is approximated: we require both to hold
            left_constraints = self._encode_formula_on_finite_heap(formula.left, alloc_map, val_map, prefix)
            right_constraints = self._encode_formula_on_finite_heap(formula.right, alloc_map, val_map, prefix)
            constraints.extend(left_constraints)
            constraints.extend(right_constraints)

        elif isinstance(formula, And):
            # P & Q: both hold on same heap
            left_constraints = self._encode_formula_on_finite_heap(formula.left, alloc_map, val_map, prefix)
            right_constraints = self._encode_formula_on_finite_heap(formula.right, alloc_map, val_map, prefix)
            constraints.extend(left_constraints)
            constraints.extend(right_constraints)

        elif isinstance(formula, Or):
            # P | Q: at least one holds
            left_constraints = self._encode_formula_on_finite_heap(formula.left, alloc_map, val_map, prefix)
            right_constraints = self._encode_formula_on_finite_heap(formula.right, alloc_map, val_map, prefix)
            if left_constraints and right_constraints:
                constraints.append(z3.Or(z3.And(left_constraints), z3.And(right_constraints)))
            elif left_constraints:
                constraints.extend(left_constraints)
            elif right_constraints:
                constraints.extend(right_constraints)

        # Other formula types (predicates, etc.) would need special handling

        return constraints

    def _encode_negated_wand_sat(self, P: Formula, Q: Formula, heap_var: z3.ExprRef,
                                 domain_set: Set[z3.ExprRef],
                                 prefix: str) -> Tuple[z3.BoolRef, Set[z3.ExprRef]]:
        """
        Encode NOT(P -* Q) for SAT context using counterexample semantics.

        Semantics: not (P -* Q) means there exists an extension h' such that:
          - h' is disjoint from h
          - P holds in h'
          - Q does NOT hold in h ∪ h'

        This is the existential counterexample to the wand.

        Args:
            P: Wand antecedent
            Q: Wand consequent
            heap_var: Main heap variable
            domain_set: Current domain
            prefix: Variable prefix

        Returns:
            (constraint, domain): Existentially quantified counterexample and domain
        """
        # Use same finite heap encoding as positive wand, but negate Q
        known_locs = self._collect_known_locations(P, Q, prefix)

        if not known_locs:
            # Fallback: negate the implication encoding
            wand_constraint, wand_domain = self._encode_wand_full(P, Q, heap_var, domain_set, prefix)
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
        p_constraints = self._encode_formula_on_finite_heap(P, ext_alloc, ext_val, prefix)

        # Encode disjointness (same as positive wand)
        disj_constraints = []
        for loc in known_locs:
            main_alloc = self._is_allocated_in_domain(loc, domain_set)
            if main_alloc is not None:
                disj_constraints.append(z3.Implies(ext_alloc[loc], z3.Not(main_alloc)))

        # Encode union heap
        union_constraints = []
        for loc in known_locs:
            main_alloc = self._is_allocated_in_domain(loc, domain_set)

            if main_alloc is not None:
                union_constraints.append(union_alloc[loc] == z3.Or(main_alloc, ext_alloc[loc]))
            else:
                union_constraints.append(union_alloc[loc] == ext_alloc[loc])

            union_constraints.append(
                z3.Implies(ext_alloc[loc], union_val[loc] == ext_val[loc])
            )

            if main_alloc is not None:
                main_val = self._get_value_from_heap(loc, heap_var)
                union_constraints.append(
                    z3.Implies(z3.And(z3.Not(ext_alloc[loc]), main_alloc),
                             union_val[loc] == main_val)
                )

        # Encode Q on union heap
        q_constraints = self._encode_formula_on_finite_heap(Q, union_alloc, union_val, prefix)

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
        wand_domain = self._extract_locations_from_antecedent(P, prefix)

        return (negated_wand_constraint, wand_domain)

    def _compute_extension_bound(self, formula: Formula) -> int:
        """
        Compute bound on heap extension size needed for formula.

        Strategy: Count points-to assertions (each needs 1+ locations)
        """
        if isinstance(formula, Emp):
            return 0
        elif isinstance(formula, PointsTo):
            # x |-> (v1, ..., vn) needs 1 location (+ field offsets)
            return 1 + len(formula.values)
        elif isinstance(formula, SepConj):
            return self._compute_extension_bound(formula.left) + \
                   self._compute_extension_bound(formula.right)
        elif isinstance(formula, And):
            # And doesn't add more locations
            return max(self._compute_extension_bound(formula.left),
                      self._compute_extension_bound(formula.right))
        elif isinstance(formula, Or):
            # Or: take max of branches
            return max(self._compute_extension_bound(formula.left),
                      self._compute_extension_bound(formula.right))
        else:
            # Conservative: default bound
            return 3

    def _encode_disjointness(self, domain1: Set[z3.ExprRef],
                            domain2: Set[z3.ExprRef]) -> z3.BoolRef:
        """
        Encode: domain1 ∩ domain2 = ∅

        Returns: Z3 constraint asserting all locations are pairwise distinct
        """
        if not domain1 or not domain2:
            return z3.BoolVal(True)

        # All pairs (l1, l2) must be distinct
        constraints = []
        for l1 in domain1:
            for l2 in domain2:
                constraints.append(l1 != l2)

        return z3.And(constraints) if constraints else z3.BoolVal(True)

    def check_wand_elimination(self, formula: Formula, wand: Wand,
                              extension: Formula) -> Optional[Formula]:
        """
        Check if formula matches wand elimination pattern: (P -* Q) * P |- Q

        If so, return Q. Otherwise return None.

        This is a fast path for the most common wand usage.
        """
        # Check if formula is (P -* Q) * P (in either order)
        if not isinstance(formula, SepConj):
            return None

        # Check if one side is the wand and the other is the antecedent
        left, right = formula.left, formula.right

        # Pattern 1: (P -* Q) * P
        if isinstance(left, Wand) and self._formulas_equal(left.left, right):
            return left.right

        # Pattern 2: P * (P -* Q)
        if isinstance(right, Wand) and self._formulas_equal(right.left, left):
            return right.right

        return None

    def _formulas_equal(self, f1: Formula, f2: Formula) -> bool:
        """Check if two formulas are syntactically equal"""
        return str(f1) == str(f2)  # Simple string comparison for now

    def _extract_locations_from_antecedent(self, P: Formula, prefix: str) -> Set[z3.ExprRef]:
        """
        Extract location variables from the wand's antecedent P.

        The wand (P -* Q) should claim these locations in its domain to ensure
        proper disjointness checking when used in separating conjunction.

        For example, (u |-> v -* Q) should claim location u.

        Args:
            P: The wand's antecedent formula
            prefix: Variable prefix for encoding (should match surrounding context)

        Returns:
            Set of Z3 location variables mentioned in P
        """
        locations = set()

        def extract_from_formula(formula: Formula):
            """Recursively extract location variables"""
            if isinstance(formula, PointsTo):
                # PointsTo(loc, values): extract the location
                loc_z3 = self.encoder.encode_expr(formula.location, prefix=prefix)
                locations.add(loc_z3)
            elif isinstance(formula, SepConj):
                # P * Q: extract from both sides
                extract_from_formula(formula.left)
                extract_from_formula(formula.right)
            elif isinstance(formula, And) or isinstance(formula, Or):
                # P & Q or P | Q: extract from both sides
                extract_from_formula(formula.left)
                extract_from_formula(formula.right)
            elif isinstance(formula, Wand):
                # Nested wand: extract from its antecedent
                extract_from_formula(formula.left)
            elif isinstance(formula, Emp):
                # emp: no locations
                pass
            # Other formula types don't directly reference heap locations

        extract_from_formula(P)
        return locations
