"""
Spatial formula encoding for Z3

This module handles encoding of spatial formulas (emp, points-to, separating conjunction)
into Z3 constraints. It's extracted from z3_encoder.py to keep that file manageable.
"""

import z3
from typing import Set, Tuple, Optional
from frame.core.ast import *

from frame.encoding._spatial_core import encode_heap_assertion as _encode_heap_assertion_impl

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
        """Delegate to spatial encoding helper"""
        return _encode_heap_assertion_impl(self, formula, heap_id, domain_set,
                                          forbidden_domain, distribution_depth,
                                          prefix, in_sepconj)
