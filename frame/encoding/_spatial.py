"""
Spatial formula encoding for Z3

This module handles encoding of spatial formulas (emp, points-to, separating conjunction)
into Z3 constraints. It's extracted from z3_encoder.py to keep that file manageable.
"""

import z3
from typing import Set, Tuple, Optional
from frame.core.ast import *


class SpatialEncoder:
    """Handles encoding of spatial formulas to Z3 constraints"""

    def __init__(self, encoder):
        """
        Args:
            encoder: Reference to parent Z3Encoder for accessing shared state
                    (LocSort, nil, encode_expr, encode_pure)
        """
        self.encoder = encoder
        # Import wand encoder (delayed to avoid circular imports)
        from frame.encoding._wand import WandEncoder
        self.wand_encoder = WandEncoder(encoder)
        # Domain map: tracks location -> value mappings during encoding
        # This is populated during encode_heap_assertion() and used for wand elimination
        self.domain_map = {}
        # Allocation map: tracks canonical alloc(loc) booleans for conditional footprint
        # Key: Z3 location expression (normalized string), Value: Z3 Bool for alloc(loc)
        self.alloc_map: Dict[str, z3.BoolRef] = {}
        # Cache of mentioned locations per formula for finite-location reduction
        self._mentioned_locations_cache = {}

    def normalize_loc(self, loc_expr: z3.ExprRef) -> z3.ExprRef:
        """Normalize a location expression for consistent comparison"""
        return z3.simplify(loc_expr)

    def normalize_domain(self, domain: Set[z3.ExprRef]) -> Set[z3.ExprRef]:
        """Normalize all locations in a domain set"""
        return {self.normalize_loc(loc) for loc in domain}

    def get_alloc_bool(self, loc_expr: z3.ExprRef) -> z3.BoolRef:
        """Get or create canonical alloc(loc) boolean for a location"""
        # Normalize location expression to string for canonical lookup
        loc_str = str(loc_expr).replace(" ", "")  # Remove spaces for normalization
        if loc_str not in self.alloc_map:
            # Create a canonical alloc boolean for this location
            self.alloc_map[loc_str] = z3.Bool(f"alloc_{loc_str}")
        return self.alloc_map[loc_str]

    def collect_mentioned_locations(self, formula: Formula, prefix: str = "") -> Set[z3.ExprRef]:
        """
        Collect all location expressions mentioned in a formula.

        This is used for finite-location reduction to avoid quantifiers.
        We replace forall/exists over all locations with finite conjunctions/disjunctions
        over the small set of locations actually mentioned in the formula.

        Args:
            formula: The formula to analyze
            prefix: Variable prefix for scoping

        Returns:
            Set of Z3 location expressions
        """
        cache_key = (id(formula), prefix)
        if cache_key in self._mentioned_locations_cache:
            return self._mentioned_locations_cache[cache_key]

        locations = set()

        if isinstance(formula, PointsTo):
            loc = self.encoder.encode_expr(formula.location, prefix=prefix)
            # Add base location and field offsets
            for i in range(len(formula.values)):
                locations.add(loc + i)

        elif isinstance(formula, (SepConj, And, Or)):
            locations.update(self.collect_mentioned_locations(formula.left, prefix))
            locations.update(self.collect_mentioned_locations(formula.right, prefix))

        elif isinstance(formula, Not):
            locations.update(self.collect_mentioned_locations(formula.formula, prefix))

        elif isinstance(formula, (Exists, Forall)):
            # Collect from body (quantified vars handled separately)
            locations.update(self.collect_mentioned_locations(formula.formula, prefix))

        # Wand and other formulas don't contribute locations directly

        self._mentioned_locations_cache[cache_key] = locations
        return locations

    def encode_heap_assertion(self, formula: Formula, heap_id: z3.ExprRef,
                             domain_set: Set[z3.ExprRef],
                             forbidden_domain: Optional[Set[z3.ExprRef]] = None,
                             distribution_depth: int = 0,
                             prefix: str = "",
                             in_sepconj: bool = False) -> Tuple[z3.BoolRef, Set[z3.ExprRef]]:
        """
        Encode a spatial formula to Z3 constraints using heap-relative semantics.

        Args:
            formula: The formula to encode
            heap_id: The heap fragment ID (HeapId sort) for this formula
            domain_set: Current domain being built
            forbidden_domain: Locations that should NOT be in this formula's domain (for emp checking)
            distribution_depth: Depth of Or-distribution for precise domain tracking
            prefix: Variable prefix for scoping (e.g., "cons_" for consequent)
            in_sepconj: Whether we're encoding within a SepConj context (for Not(PointsTo) third disjunct)

        Returns:
            (constraints, domain): Z3 constraints and set of domain locations
        """
        if forbidden_domain is None:
            forbidden_domain = set()

        if isinstance(formula, True_):
            # True in spatial context means "any heap" - always satisfiable
            # Return true with empty domain (no specific constraints)
            return (z3.BoolVal(True), set())

        elif isinstance(formula, False_):
            # False is unsatisfiable
            return (z3.BoolVal(False), set())

        elif isinstance(formula, Emp):
            # Empty heap: domain is empty
            # If we have a forbidden domain (locations from antecedent),
            # emp is only valid if there are no conflicts
            # For now, just return true with empty domain
            # The conflict checking will happen at the entailment level
            return (z3.BoolVal(True), set())

        elif isinstance(formula, PointsTo):
            # x |-> (v1, v2, ..., vn) with heap-relative encoding
            # CRITICAL: PointsTo denotes a SINGLETON fragment
            # So we must enforce: alloc(H,x) ∧ hval(H,x)=y ∧ ∀l.(l≠x ⇒ ¬alloc(H,l))

            loc = self.encoder.encode_expr(formula.location, prefix=prefix)
            constraints = []

            # Location must be non-nil
            constraints.append(loc != self.encoder.nil)

            # Encode heap values for each field using heap-relative semantics
            for i, val_expr in enumerate(formula.values):
                val = self.encoder.encode_expr(val_expr, prefix=prefix)
                # Location is allocated in this heap fragment
                constraints.append(self.encoder.alloc(heap_id, loc + i))
                # Value at location in this heap fragment
                constraints.append(self.encoder.hval(heap_id, loc + i) == val)

                # ACYCLICITY CONSTRAINT: Following pointers increases rank
                # x |-> y ∧ y ≠ nil ⇒ rank(x) < rank(y)
                # This prevents cyclic heap structures (e.g., x → y → z → x)
                # NOTE: rank is GLOBAL, not per-heap-fragment, so cycles are detected across separating conjunction
                if self.encoder.use_acyclicity_constraints:
                    # Only enforce rank constraint for non-nil values
                    # If val is not nil, then rank(loc) < rank(val)
                    rank_constraint = z3.Implies(
                        val != self.encoder.nil,
                        self.encoder.rank(loc + i) < self.encoder.rank(val)
                    )
                    constraints.append(rank_constraint)

                # Track in domain_map for wand elimination
                self.domain_map[loc + i] = val

            # Domain includes loc and field offsets (normalized)
            new_domain = self.normalize_domain({loc + i for i in range(len(formula.values))})

            # NOTE: We DON'T add a singleton constraint here because:
            # 1. In SepConj, disjointness is enforced separately
            # 2. In And, multiple allocations on the same heap are allowed
            # 3. The singleton semantics are captured in Not(PointsTo) via the third disjunct

            return (z3.And(constraints), new_domain)

        elif isinstance(formula, ArrayPointsTo):
            # array[index] |-> value with heap-relative encoding
            # This is similar to PointsTo but uses array indexing
            # We use the array_heap function from the encoder

            array_base = self.encoder.encode_expr(formula.array, prefix=prefix)
            index = self.encoder.encode_expr(formula.index, prefix=prefix)
            value = self.encoder.encode_expr(formula.value, prefix=prefix)

            constraints = []

            # Array base must be non-nil
            constraints.append(array_base != self.encoder.nil)

            # Index must be non-negative
            constraints.append(index >= 0)

            # Array element is allocated in this heap fragment
            # We use array_base + index as the effective location
            effective_loc = array_base + index
            constraints.append(self.encoder.alloc(heap_id, effective_loc))

            # Value at array[index] in this heap fragment
            constraints.append(self.encoder.hval(heap_id, effective_loc) == value)

            # Also record in array_heap for array-specific reasoning
            constraints.append(self.encoder.array_heap(array_base, index) == value)

            # Track in domain_map
            self.domain_map[effective_loc] = value

            # Domain includes the effective location
            new_domain = self.normalize_domain({effective_loc})

            return (z3.And(constraints), new_domain)

        elif isinstance(formula, SepConj):
            # P * Q: encode with heap splitting (heap-relative semantics)
            # CORRECT ENCODING: Each operand gets its own heap fragment
            # This is critical for handling patterns like pto(x,y) * not(pto(x,y))

            # Special case: if either side is an Or, distribute to get precise domains
            # This fixes the domain overapproximation bug where Or domains are unioned
            # Limit distribution depth to prevent infinite recursion

            MAX_DISTRIBUTION_DEPTH = 3

            if isinstance(formula.left, Or) and distribution_depth < MAX_DISTRIBUTION_DEPTH:
                # (P1 | P2) * Q  =>  (P1 * Q) | (P2 * Q)
                left_case1 = SepConj(formula.left.left, formula.right)
                left_case2 = SepConj(formula.left.right, formula.right)
                distributed = Or(left_case1, left_case2)
                return self.encode_heap_assertion(distributed, heap_id, domain_set, forbidden_domain, distribution_depth + 1, prefix=prefix, in_sepconj=in_sepconj)

            if isinstance(formula.right, Or) and distribution_depth < MAX_DISTRIBUTION_DEPTH:
                # P * (Q1 | Q2)  =>  (P * Q1) | (P * Q2)
                right_case1 = SepConj(formula.left, formula.right.left)
                right_case2 = SepConj(formula.left, formula.right.right)
                distributed = Or(right_case1, right_case2)
                return self.encode_heap_assertion(distributed, heap_id, domain_set, forbidden_domain, distribution_depth + 1, prefix=prefix, in_sepconj=in_sepconj)

            # CORRECT APPROACH: Create fresh heap IDs for each operand
            # This allows pto(x,y) * not(pto(x,y)) to be SAT with H1={x→y}, H2=∅

            # Generate fresh heap IDs
            import time
            unique_id = int(time.time() * 1000000) % 1000000
            heap1 = z3.Const(f'H1_{unique_id}', self.encoder.HeapIdSort)
            heap2 = z3.Const(f'H2_{unique_id}', self.encoder.HeapIdSort)

            # Collect all locations mentioned in both operands for finite encoding
            left_locs = self.collect_mentioned_locations(formula.left, prefix)
            right_locs = self.collect_mentioned_locations(formula.right, prefix)
            mentioned_locs = self.normalize_domain(left_locs | right_locs)

            # Encode left on H1, right on H2 (both in SepConj context)
            left_constraints, left_domain = self.encode_heap_assertion(
                formula.left, heap1, set(), forbidden_domain, distribution_depth, prefix=prefix, in_sepconj=True
            )
            right_constraints, right_domain = self.encode_heap_assertion(
                formula.right, heap2, set(), forbidden_domain, distribution_depth, prefix=prefix, in_sepconj=True
            )

            # DISJOINT constraint: H1 and H2 have no overlapping allocations
            # Finite version: ∧_{l in mentioned_locs} ¬(alloc(H1,l) ∧ alloc(H2,l))
            disjoint_constraints = []
            for loc in mentioned_locs:
                disjoint_constraints.append(
                    z3.Not(z3.And(self.encoder.alloc(heap1, loc),
                                  self.encoder.alloc(heap2, loc)))
                )

            # MERGE constraint: parent heap H reflects union of H1 and H2
            # Finite version over mentioned_locs:
            # For each l: if alloc(H1,l) then alloc(H,l) ∧ hval(H,l)==hval(H1,l)
            #        else if alloc(H2,l) then alloc(H,l) ∧ hval(H,l)==hval(H2,l)
            #        else ¬alloc(H,l)
            merge_constraints = []
            for loc in mentioned_locs:
                # If allocated in H1, parent has same allocation and value
                merge_h1 = z3.Implies(
                    self.encoder.alloc(heap1, loc),
                    z3.And(self.encoder.alloc(heap_id, loc),
                           self.encoder.hval(heap_id, loc) == self.encoder.hval(heap1, loc))
                )
                # If allocated in H2, parent has same allocation and value
                merge_h2 = z3.Implies(
                    self.encoder.alloc(heap2, loc),
                    z3.And(self.encoder.alloc(heap_id, loc),
                           self.encoder.hval(heap_id, loc) == self.encoder.hval(heap2, loc))
                )
                # If allocated in neither, parent is not allocated
                merge_none = z3.Implies(
                    z3.And(z3.Not(self.encoder.alloc(heap1, loc)),
                           z3.Not(self.encoder.alloc(heap2, loc))),
                    z3.Not(self.encoder.alloc(heap_id, loc))
                )
                merge_constraints.extend([merge_h1, merge_h2, merge_none])

                # NOTE: No rank merge constraints needed because rank is GLOBAL
                # All heap fragments share the same rank function

            # Combine all constraints with existential quantification over H1, H2
            all_constraints = [left_constraints, right_constraints] + disjoint_constraints + merge_constraints
            combined = z3.And(all_constraints)

            # Existentially quantify the fragment heap IDs
            result = z3.Exists([heap1, heap2], combined)

            # Combined domain is union of both sides
            combined_domain = self.normalize_domain(left_domain | right_domain)

            return (result, combined_domain)

        elif isinstance(formula, Or):
            # P | Q: disjunction of spatial formulas
            # Both branches use the same heap ID (they're alternatives on the same heap)
            left_constraints, left_domain = self.encode_heap_assertion(
                formula.left, heap_id, domain_set, forbidden_domain, distribution_depth, prefix=prefix
            )
            right_constraints, right_domain = self.encode_heap_assertion(
                formula.right, heap_id, domain_set, forbidden_domain, distribution_depth, prefix=prefix
            )

            # Union of possible domains (overapproximation)
            combined_domain = left_domain.union(right_domain)
            disjunction = z3.Or(left_constraints, right_constraints)

            return (disjunction, combined_domain)

        elif isinstance(formula, And):
            # P & Q: conjunction - encode both on SAME heap (not disjoint like SepConj)
            # Note: And is different from SepConj!
            # And means both formulas hold on the SAME heap
            # SepConj means they hold on DISJOINT parts
            if formula.left.is_spatial() and formula.right.is_spatial():
                # Both spatial - encode both on same heap ID
                # NOTE: And is different from SepConj!
                # And means both formulas hold on the SAME heap (no disjointness)
                # SepConj means they hold on DISJOINT parts
                left_constraints, left_domain = self.encode_heap_assertion(
                    formula.left, heap_id, domain_set, forbidden_domain, distribution_depth, prefix=prefix
                )
                # For And, we DON'T pass accumulated domain to right side
                # because both sides can reference the same locations
                right_constraints, right_domain = self.encode_heap_assertion(
                    formula.right, heap_id, domain_set, forbidden_domain, distribution_depth, prefix=prefix
                )
                # Combine constraints with AND (no disjointness requirement)
                combined_constraints = z3.And(left_constraints, right_constraints)
                # Domain is the union (both parts must hold)
                combined_domain = left_domain.union(right_domain)
                return (combined_constraints, combined_domain)
            elif formula.left.is_spatial():
                # Only left is spatial
                pure_constraint = self.encoder.encode_pure(formula.right, prefix=prefix)
                spatial_constraint, domain = self.encode_heap_assertion(
                    formula.left, heap_id, domain_set, forbidden_domain, distribution_depth, prefix=prefix
                )
                return (z3.And(pure_constraint, spatial_constraint), domain)
            elif formula.right.is_spatial():
                # Only right is spatial
                pure_constraint = self.encoder.encode_pure(formula.left, prefix=prefix)
                spatial_constraint, domain = self.encode_heap_assertion(
                    formula.right, heap_id, domain_set, forbidden_domain, distribution_depth, prefix=prefix
                )
                return (z3.And(pure_constraint, spatial_constraint), domain)
            else:
                # Neither spatial - just pure
                pure_constraint = self.encoder.encode_pure(formula)
                return (pure_constraint, set())

        elif isinstance(formula, Not):
            # Negation: !P with heap-relative semantics
            # Special handling for NOT(PointsTo) which is common in qf_bsllia_sat
            if isinstance(formula.formula, PointsTo):
                # NOT(x |-> y) with heap-relative semantics:
                # It's NOT the case that (x is allocated in this heap AND points to y)
                # This correctly handles negation relative to a specific heap fragment
                #
                # CRITICAL: In SMT-LIB2 semantics, (sep (not (pto x y)) Q) means negation
                # claims a heap domain. We must return the location domain so disjointness
                # checking will properly detect conflicts like: !(x |-> y) * (x |-> z)
                #
                # CRITICAL FIX: If location is already in domain_set, we have a conflict!
                # Example: (u |-> v * !u |-> w) should be UNSAT because u can't be both
                # allocated pointing to v AND not allocated at the same time in SepConj context.
                pto = formula.formula
                loc = self.encoder.encode_expr(pto.location, prefix=prefix)

                if len(pto.values) == 1:
                    val = self.encoder.encode_expr(pto.values[0], prefix=prefix)

                    # CORRECT ENCODING for negated points-to with THREE disjuncts:
                    # Not(PointsTo(x,y)) means "fragment is NOT exactly {x→y}"
                    # This is true when:
                    # 1. x is not allocated: ¬alloc(H,x)
                    # 2. x points to something else: hval(H,x) ≠ y
                    # 3. Fragment has extra cells: ∃l.(l≠x ∧ alloc(H,l))
                    #
                    # We use finite-location reduction to avoid quantifiers:
                    # ∃l.(l≠x ∧ alloc(H,l)) ≈ ∨_{l in mentioned_locs \ {x}} alloc(H,l)

                    disjuncts = []

                    # Disjunct 1: location not allocated
                    disjuncts.append(z3.Not(self.encoder.alloc(heap_id, loc)))

                    # Disjunct 2: location points to different value
                    disjuncts.append(self.encoder.hval(heap_id, loc) != val)

                    # Disjunct 3: fragment has extra cells (finite-location reduction)
                    # This checks if the fragment contains MORE than just x->y
                    # CRITICAL: Only apply this in SepConj contexts where we have heap fragments!
                    # In And contexts, both sides share the SAME heap, so this doesn't make sense.
                    if in_sepconj:
                        # We check if any location in the current domain (excluding x itself) is allocated
                        # Use domain_set (locations from other SepConj operands)
                        norm_loc = self.normalize_loc(loc)
                        norm_domain_set = self.normalize_domain(domain_set)
                        other_locs = norm_domain_set - {norm_loc}
                        for other_loc in other_locs:
                            disjuncts.append(self.encoder.alloc(heap_id, other_loc))

                    negated_pto = z3.Or(disjuncts) if disjuncts else z3.BoolVal(False)

                    # Return empty domain for negations - BSL semantics require different handling
                    # TODO: Proper BSL support needs semantic check for (pto x y) * (not (pto x y))
                    return (negated_pto, set())
                else:
                    # Multi-field case: NOT(x |-> (y1, y2, ...))
                    # ¬(alloc(heap_id,x) ∧ alloc(heap_id,x+1) ∧ ... ∧ hval(heap_id,x)=y1 ∧ hval(heap_id,x+1)=y2 ∧ ...)
                    alloc_constraints = []
                    value_constraints = []
                    for i, val_expr in enumerate(pto.values):
                        val = self.encoder.encode_expr(val_expr, prefix=prefix)
                        alloc_constraints.append(self.encoder.alloc(heap_id, loc + i))
                        value_constraints.append(self.encoder.hval(heap_id, loc + i) == val)

                    negated_pto = z3.Not(z3.And(alloc_constraints + value_constraints))
                    # Return domain {x, x+1, ...} so disjointness checking works
                    neg_domain = {loc + i for i in range(len(pto.values))}
                    return (negated_pto, neg_domain)

            # Special handling for NOT(Wand) - critical for qf_bsl_sat benchmarks
            if isinstance(formula.formula, Wand):
                # not (P -* Q) means: there exists ext heap where P holds but Q doesn't
                # Encode as: Exists ext. P(ext) ∧ ¬Q(union) ∧ disjoint(main, ext)
                #
                # This is the semantic negation of the wand, not just negating the encoding.
                # It's a counterexample: we can extend the heap with P, but Q fails.
                wand = formula.formula
                P = wand.left
                Q = wand.right

                # Use special negated-wand encoding for SAT mode
                if self.wand_encoder.mode == "SAT":
                    return self.wand_encoder._encode_negated_wand_sat(
                        P, Q, heap_id, domain_set, prefix=f"{prefix}_negwand"
                    )
                else:
                    # For ENTAILMENT mode, just negate the standard encoding
                    wand_constraint, wand_domain = self.wand_encoder.encode_wand(
                        wand, heap_id, domain_set, prefix=f"{prefix}_negwand"
                    )
                    negated_wand = z3.Not(wand_constraint)
                    return (negated_wand, wand_domain)

            # General case: encode inner formula and negate
            inner_constraints, inner_domain = self.encode_heap_assertion(
                formula.formula, heap_id, domain_set, forbidden_domain, distribution_depth, prefix=prefix
            )

            # Negate the constraints
            negated = z3.Not(inner_constraints)

            # For domain: negation doesn't change what locations might be relevant
            # Use empty domain as conservative approximation
            return (negated, set())

        elif isinstance(formula, Exists):
            # Existential quantification
            # Create a fresh Z3 variable for the bound variable
            # Note: Fresh variables are NOT prefixed (they're already unique)
            fresh = self.encoder.fresh_var(formula.var, self.encoder.LocSort)

            # Temporarily add to variable cache
            # CRITICAL: Bind using PREFIXED name so encode_expr can find it
            cache_key = f"{prefix}{formula.var}" if prefix else formula.var
            old_binding = self.encoder.var_cache.get(cache_key)
            self.encoder.var_cache[cache_key] = fresh

            # Encode the body (free variables will be prefixed, bound var won't)
            body_constraints, body_domain = self.encode_heap_assertion(
                formula.formula, heap_id, domain_set, forbidden_domain, distribution_depth, prefix=prefix
            )

            # Restore old binding
            if old_binding is not None:
                self.encoder.var_cache[cache_key] = old_binding
            else:
                del self.encoder.var_cache[cache_key]

            # Create existential quantifier
            result = z3.Exists([fresh], body_constraints)

            return (result, body_domain)

        elif isinstance(formula, Wand):
            # Magic wand: P -* Q
            # Use improved wand encoding from _wand.py
            return self.wand_encoder.encode_wand(
                formula, heap_id, domain_set, self.domain_map, prefix=prefix
            )

        elif isinstance(formula, PredicateCall):
            # Predicate call with conditional footprint facts
            # Generate a fresh boolean variable to represent the predicate holds
            pred_var = z3.Bool(f"pred_{formula.name}_{id(formula)}_{prefix}")

            # Add conditional footprint constraints based on predicate semantics
            constraints = [pred_var]  # Start with the predicate variable itself

            # List segment: ls(x, y) or ls(x, y, len)
            if formula.name == 'ls' and len(formula.args) >= 2:
                x_z3 = self.encoder.encode_expr(formula.args[0], prefix=prefix)
                y_z3 = self.encoder.encode_expr(formula.args[1], prefix=prefix)

                # ls(x,y) is non-empty when x != y
                nonempty = (x_z3 != y_z3)

                # Get canonical alloc boolean for x (legacy approach for predicates)
                alloc_x = self.get_alloc_bool(x_z3)

                # Constraint: pred_var & nonempty => alloc(x)
                # This means: if ls(x,y) holds and x != y, then x must be allocated
                constraints.append(z3.Implies(z3.And(pred_var, nonempty), alloc_x))

                # Also constrain heap value: ls(x,y) with x != y means heap[x] points to some next node
                next_var = self.encoder.fresh_var(f"ls_next_{prefix}")
                constraints.append(z3.Implies(z3.And(pred_var, nonempty),
                                             self.encoder.hval(heap_id, x_z3) == next_var))

            # Doubly-linked list: dll(hd, prev, tail, next, ...)
            elif formula.name == 'dll' and len(formula.args) >= 4:
                hd_z3 = self.encoder.encode_expr(formula.args[0], prefix=prefix)
                tail_z3 = self.encoder.encode_expr(formula.args[2], prefix=prefix)

                # dll is non-empty when hd != tail
                nonempty = (hd_z3 != tail_z3)

                # Get canonical alloc boolean for hd (legacy approach for predicates)
                alloc_hd = self.get_alloc_bool(hd_z3)

                # Constraint: pred_var & nonempty => alloc(hd)
                constraints.append(z3.Implies(z3.And(pred_var, nonempty), alloc_hd))

                # dll with hd != tail means heap[hd] points somewhere
                next_var = self.encoder.fresh_var(f"dll_next_{prefix}")
                constraints.append(z3.Implies(z3.And(pred_var, nonempty),
                                             self.encoder.hval(heap_id, hd_z3) == next_var))

            # List: list(x) (null-terminated list)
            elif formula.name == 'list' and len(formula.args) >= 1:
                x_z3 = self.encoder.encode_expr(formula.args[0], prefix=prefix)

                # list(x) is non-empty when x != nil
                nonempty = (x_z3 != self.encoder.nil)

                # Get canonical alloc boolean for x (legacy approach for predicates)
                alloc_x = self.get_alloc_bool(x_z3)

                # Constraint: pred_var & nonempty => alloc(x)
                constraints.append(z3.Implies(z3.And(pred_var, nonempty), alloc_x))

                # list(x) with x != nil means heap[x] points to next
                next_var = self.encoder.fresh_var(f"list_next_{prefix}")
                constraints.append(z3.Implies(z3.And(pred_var, nonempty),
                                             self.encoder.hval(heap_id, x_z3) == next_var))

            # Tree: tree(x)
            elif formula.name == 'tree' and len(formula.args) >= 1:
                x_z3 = self.encoder.encode_expr(formula.args[0], prefix=prefix)

                # tree(x) is non-empty when x != nil
                nonempty = (x_z3 != self.encoder.nil)

                # Get canonical alloc boolean for x (legacy approach for predicates)
                alloc_x = self.get_alloc_bool(x_z3)

                # Constraint: pred_var & nonempty => alloc(x)
                constraints.append(z3.Implies(z3.And(pred_var, nonempty), alloc_x))

            # For other predicates, we don't add footprint constraints yet
            # This is conservative but sound

            # Domain is still empty (we track allocations via alloc booleans, not domain set)
            domain = set()

            # Combine all constraints
            combined_constraint = z3.And(*constraints) if len(constraints) > 1 else constraints[0]

            return (combined_constraint, domain)

        else:
            # Check if this is a pure formula (non-spatial)
            # Pure formulas should be handled by encode_pure(), not encode_heap_assertion()
            # When mixed with spatial formulas in SepConj, we return empty constraints here
            if not formula.is_spatial():
                # Pure formula in spatial context - return true with empty domain
                # The pure constraints will be handled separately
                return (z3.BoolVal(True), set())
            else:
                raise ValueError(f"Not a spatial formula: {type(formula)}")
