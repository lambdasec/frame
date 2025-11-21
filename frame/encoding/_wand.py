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
from frame.encoding._wand_utils import (
    collect_known_locations as _collect_known_locations,
    extract_locations_from_antecedent as _extract_locations_from_antecedent,
    extract_footprint_with_values as _extract_footprint_with_values,
    compute_extension_bound as _compute_extension_bound,
    encode_disjointness as _encode_disjointness,
    is_allocated_in_domain as _is_allocated_in_domain,
    formulas_equal as _formulas_equal
)
from frame.encoding._wand_sat_encoding import (
    encode_wand_sat as _encode_wand_sat_impl,
    encode_formula_on_finite_heap as _encode_formula_on_finite_heap_impl,
    encode_negated_wand_sat as _encode_negated_wand_sat_impl
)


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

    def encode_wand(self, wand: Wand, heap_id: z3.ExprRef,
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
            return self._encode_emp_wand(Q, heap_id, domain_set, prefix)

        # Route to mode-specific encoding
        if self.mode == "SAT" and self.enable_full_encoding:
            return self._encode_wand_sat(P, Q, heap_id, domain_set, domain_map, prefix)
        elif self.mode == "ENTAILMENT" and self.enable_full_encoding:
            return self._encode_wand_full(P, Q, heap_id, domain_set, domain_map, prefix)
        else:
            # Conservative fallback: create boolean variable
            wand_var = z3.Bool(f"wand_{prefix}_{id(wand)}")
            wand_domain = self._extract_locations_from_antecedent(P, prefix)
            return (wand_var, wand_domain)

    def _encode_emp_wand(self, Q: Formula, heap_id: z3.ExprRef,
                        domain_set: Set[z3.ExprRef],
                        prefix: str) -> Tuple[z3.BoolRef, Set[z3.ExprRef]]:
        """
        Encode emp -* Q.

        Semantics: (emp -* Q) holds in h if Q holds in h
        (since emp can be satisfied with empty extension)
        """
        # Q should hold on the current heap
        q_constraints, q_domain = self.encoder._spatial_encoder.encode_heap_assertion(
            Q, heap_id, domain_set, prefix=f"{prefix}_empwand"
        )

        # emp -* Q: Since antecedent is emp, no locations to claim
        # But we return q_domain to indicate this wand requires those locations
        return (q_constraints, q_domain)

    def _encode_pto_wand(self, P: PointsTo, Q: PointsTo, heap_id: z3.ExprRef,
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

    def _encode_wand_full(self, P: Formula, Q: Formula, heap_id: z3.ExprRef,
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
                    z3.Implies(self.encoder.alloc(heap_id, loc),
                               z3.And(self.encoder.alloc(union_heap_id, loc),
                                      self.encoder.hval(union_heap_id, loc) == self.encoder.hval(heap_id, loc))))
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

    def _antecedent_matches_context(self, P: Formula, heap_id: z3.ExprRef,
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
            return (self._antecedent_matches_context(P.left, heap_id, domain_set, prefix) and
                    self._antecedent_matches_context(P.right, heap_id, domain_set, prefix))

        # Handle And: P1 & P2 (both parts must match)
        if isinstance(P, And):
            # If left is pure and right is spatial, check the spatial part
            if not P.left.is_spatial() and P.right.is_spatial():
                return self._antecedent_matches_context(P.right, heap_id, domain_set, prefix)
            # If right is pure and left is spatial, check the spatial part
            if not P.right.is_spatial() and P.left.is_spatial():
                return self._antecedent_matches_context(P.left, heap_id, domain_set, prefix)
            # Both spatial: check both
            if P.left.is_spatial() and P.right.is_spatial():
                return (self._antecedent_matches_context(P.left, heap_id, domain_set, prefix) and
                        self._antecedent_matches_context(P.right, heap_id, domain_set, prefix))
            # Both pure: matches vacuously (pure constraints don't affect heap)
            return True

        # Conservative: return False for complex patterns
        return False

    def _try_wand_elimination(self, P: Formula, Q: Formula, heap_id: z3.ExprRef,
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
                    Q, heap_id, domain_set, set(), 0, prefix=""
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
            Q, heap_id, domain_set, set(), 0, prefix=""
        )

        # Return Q's constraint with empty wand domain
        return (q_constraint, set())

    def _extract_footprint_with_values(self, formula: Formula, prefix: str) -> Dict[z3.ExprRef, z3.ExprRef]:
        """Delegate to wand utils"""
        return _extract_footprint_with_values(self.encoder, formula, prefix)

    def _encode_wand_sat(self, P: Formula, Q: Formula, heap_id: z3.ExprRef,
                        domain_set: Set[z3.ExprRef],
                        domain_map: Dict[z3.ExprRef, z3.ExprRef],
                        prefix: str) -> Tuple[z3.BoolRef, Set[z3.ExprRef]]:
        """Delegate to SAT encoding module"""
        return _encode_wand_sat_impl(self, P, Q, heap_id, domain_set, domain_map, prefix)

    def _collect_known_locations(self, P: Formula, Q: Formula, prefix: str) -> Set[z3.ExprRef]:
        """Delegate to wand utils"""
        return _collect_known_locations(self.encoder, P, Q, prefix)

    def _is_allocated_in_domain(self, loc: z3.ExprRef, domain_set: Set[z3.ExprRef]) -> z3.BoolRef:
        """Delegate to wand utils"""
        return _is_allocated_in_domain(loc, domain_set)

    def _get_value_from_heap(self, loc: z3.ExprRef, heap_id: z3.ExprRef) -> z3.ExprRef:
        """Get value at location from heap using heap-relative semantics."""
        return self.encoder.hval(heap_id, loc)

    def _encode_formula_on_finite_heap(self, formula: Formula,
                                      alloc_map: Dict[z3.ExprRef, z3.BoolRef],
                                      val_map: Dict[z3.ExprRef, z3.ExprRef],
                                      prefix: str) -> List[z3.BoolRef]:
        """Delegate to SAT encoding module"""
        return _encode_formula_on_finite_heap_impl(self, formula, alloc_map, val_map, prefix)

    def _encode_negated_wand_sat(self, P: Formula, Q: Formula, heap_id: z3.ExprRef,
                                 domain_set: Set[z3.ExprRef],
                                 prefix: str) -> Tuple[z3.BoolRef, Set[z3.ExprRef]]:
        """Delegate to SAT encoding module"""
        return _encode_negated_wand_sat_impl(self, P, Q, heap_id, domain_set, prefix)

    def _compute_extension_bound(self, formula: Formula) -> int:
        """Delegate to wand utils"""
        return _compute_extension_bound(formula)

    def _encode_disjointness(self, domain1: Set[z3.ExprRef],
                            domain2: Set[z3.ExprRef]) -> z3.BoolRef:
        """Delegate to wand utils"""
        return _encode_disjointness(domain1, domain2)

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
        """Delegate to wand utils"""
        return _formulas_equal(f1, f2)

    def _extract_locations_from_antecedent(self, P: Formula, prefix: str) -> Set[z3.ExprRef]:
        """Delegate to wand utils"""
        return _extract_locations_from_antecedent(self.encoder, P, prefix)
