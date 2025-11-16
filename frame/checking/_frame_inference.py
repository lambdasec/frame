"""
Frame inference helper methods (internal)

Extracts frame computation and abductive reasoning from the main checker.
Used for finding leftover heap and synthesizing missing specifications.
"""

from typing import Optional
from frame.core.ast import Formula, PredicateCall, PointsTo, Emp, Var, SepConj


def find_frame(checker, antecedent: Formula, consequent: Formula) -> Optional[Formula]:
    """
    Find the frame of an entailment: if P |- Q, find R such that P ≡ Q * R

    This extracts the "leftover" heap from the antecedent after matching
    the consequent. This is the frame R in the frame rule: P * R |- Q * R

    Algorithm:
    1. Check if P |- Q is valid
    2. Apply frame rule to extract common parts
    3. Return the remainder (leftover) from P as the frame R

    Args:
        checker: The EntailmentChecker instance
        antecedent: Formula P (what we have)
        consequent: Formula Q (what we're proving)

    Returns:
        The frame formula R, or None if:
        - Entailment is invalid
        - No frame exists (P and Q are equivalent)
        - Frame cannot be computed

    Example:
        P = x |-> 5 * y |-> 3 * z |-> 7
        Q = x |-> 5
        Frame R = y |-> 3 * z |-> 7
    """
    if checker.verbose:
        print(f"[Frame Extraction] Finding frame for: {antecedent} |- {consequent}")

    # Step 1: Check if entailment is valid
    result = checker.check(antecedent, consequent)
    if not result.valid:
        if checker.verbose:
            print(f"[Frame Extraction] Entailment invalid, no frame exists")
        return None

    # Step 2: Extract spatial parts from both sides
    ante_parts = checker.analyzer._extract_sepconj_parts(antecedent)
    cons_parts = checker.analyzer._extract_sepconj_parts(consequent)

    # Remove emp parts (neutral in separating conjunction)
    ante_parts = [p for p in ante_parts if not isinstance(p, Emp)]
    cons_parts = [p for p in cons_parts if not isinstance(p, Emp)]

    # Step 3: Find matching parts between antecedent and consequent
    # Use both syntactic equality and semantic matching (via lemmas)
    matched_ante_parts = []
    unmatched_cons_parts = list(cons_parts)

    for cons_part in cons_parts:
        # Try to find a matching part in antecedent
        matched = False

        # Strategy 1: Direct syntactic match
        for ante_part in ante_parts:
            if ante_part in matched_ante_parts:
                continue
            if checker.analyzer.formulas_syntactically_equal(ante_part, cons_part):
                matched_ante_parts.append(ante_part)
                if cons_part in unmatched_cons_parts:
                    unmatched_cons_parts.remove(cons_part)
                matched = True
                break

        # Strategy 2: Semantic match via unification (for predicates with variables)
        if not matched:
            for ante_part in ante_parts:
                if ante_part in matched_ante_parts:
                    continue
                # Try unification
                subst = checker.unifier.unify_formulas(ante_part, cons_part)
                if subst is not None:
                    matched_ante_parts.append(ante_part)
                    if cons_part in unmatched_cons_parts:
                        unmatched_cons_parts.remove(cons_part)
                    matched = True
                    break

    # Step 4: Compute frame R = parts of P not matched by Q
    frame_parts = [p for p in ante_parts if p not in matched_ante_parts]

    if not frame_parts:
        # No leftover frame (P and Q are equivalent)
        if checker.verbose:
            print(f"[Frame Extraction] No frame (formulas equivalent)")
        return Emp()

    # Build frame formula from remaining parts
    frame = checker.analyzer._build_sepconj(frame_parts)

    if checker.verbose:
        print(f"[Frame Extraction] Extracted frame: {frame}")
        print(f"[Frame Extraction] Matched {len(matched_ante_parts)} parts, {len(frame_parts)} parts in frame")

    return frame


def abduce_frame(checker, antecedent: Formula, consequent: Formula) -> Optional[Formula]:
    """
    Abductive frame inference: Find R such that P * R |- Q

    This finds the "missing" heap that needs to be added to P to prove Q.
    This is the key technique used by Infer, Sleek, and other state-of-the-art
    separation logic solvers for automatic specification inference.

    Algorithm:
    1. Identify parts of Q that are not in P (the "gap")
    2. Try to synthesize R using:
       a. Goal-directed folding (synthesize predicates)
       b. Direct heap synthesis (concrete cells)
       c. Lemma application (infer missing predicates)
    3. Verify that P * R |- Q
    4. Return minimal R that makes the entailment valid

    Args:
        checker: The EntailmentChecker instance
        antecedent: Formula P (what we have)
        consequent: Formula Q (what we want to prove)

    Returns:
        Frame R such that P * R |- Q, or None if no such R exists

    Example:
        P = x |-> y
        Q = list(x)
        Abduced R = list(y)  # Because x |-> y * list(y) |- list(x)
    """
    if checker.verbose:
        print(f"[Frame Abduction] Finding R such that {antecedent} * R |- {consequent}")

    # Quick check: if P already entails Q, frame is emp
    if checker.check(antecedent, consequent).valid:
        if checker.verbose:
            print(f"[Frame Abduction] Already valid, frame is emp")
        return Emp()

    # Step 1: Extract parts from consequent that might need synthesis
    cons_parts = checker.analyzer._extract_sepconj_parts(consequent)
    ante_parts = checker.analyzer._extract_sepconj_parts(antecedent)

    # Remove emp parts
    cons_parts = [p for p in cons_parts if not isinstance(p, Emp)]
    ante_parts = [p for p in ante_parts if not isinstance(p, Emp)]

    # Step 2: Identify which consequent parts are "missing" from antecedent
    missing_parts = []

    for cons_part in cons_parts:
        found_match = False

        # Check if this consequent part is already in antecedent
        for ante_part in ante_parts:
            if checker.analyzer.formulas_syntactically_equal(ante_part, cons_part):
                found_match = True
                break

        if not found_match:
            missing_parts.append(cons_part)

    if not missing_parts:
        # All consequent parts are in antecedent, but entailment still fails
        # This might be due to pure constraints or complex reasoning
        if checker.verbose:
            print(f"[Frame Abduction] All spatial parts matched, but entailment fails")
            print(f"[Frame Abduction] This might require pure constraint synthesis")
        return None

    if checker.verbose:
        print(f"[Frame Abduction] Missing parts: {missing_parts}")

    # Step 3: Try to synthesize the missing parts
    # IMPORTANT: Order matters! We prioritize structural synthesis (Strategy B)
    # over direct synthesis (Strategy A) because structural synthesis gives
    # more meaningful specifications for automatic inference.
    candidate_frames = []

    # Strategy B: Use goal-directed folding to synthesize predicates (FIRST)
    # For example, if consequent is list(x) and antecedent is x |-> y,
    # we want to synthesize list(y) rather than just list(x)
    # This follows the structural pattern (list cons lemma)
    if checker.use_folding:
        for cons_part in missing_parts:
            if isinstance(cons_part, PredicateCall):
                # Try to infer what heap we need to fold into this predicate
                # Look at the predicate's arguments and the antecedent structure
                pred_name = cons_part.name
                pred_args = cons_part.args

                # For list predicates, try to synthesize missing segments
                if pred_name in ["list", "ls"]:
                    # Try to infer missing list segments from antecedent structure
                    abduced = abduce_list_frame(checker, antecedent, cons_part)
                    if abduced:
                        # Prioritize structural abduction by adding it first
                        candidate_frames.insert(0, abduced)

    # Strategy A: Direct synthesis (if missing parts are concrete heap cells)
    # This is a fallback - try adding the missing part directly
    # Try each missing part as a potential frame
    for missing_part in missing_parts:
        candidate_frames.append(missing_part)

    # Try combinations of missing parts
    if len(missing_parts) > 1:
        combined = checker.analyzer._build_sepconj(missing_parts)
        candidate_frames.append(combined)

    # Step 4: Verify each candidate frame
    for candidate in candidate_frames:
        # Build P * R
        augmented = SepConj(antecedent, candidate)

        # Check if P * R |- Q
        if checker.check(augmented, consequent).valid:
            if checker.verbose:
                print(f"[Frame Abduction] ✓ Found valid frame: {candidate}")
            return candidate

    if checker.verbose:
        print(f"[Frame Abduction] ✗ No valid frame found")

    return None


def abduce_list_frame(checker, antecedent: Formula, target: PredicateCall) -> Optional[Formula]:
    """
    Helper method to abduce list/list segment frames.

    For example:
    - Antecedent: x |-> y
    - Target: list(x)
    - Abduced: list(y)  # Because x |-> y * list(y) |- list(x)

    Args:
        checker: The EntailmentChecker instance
        antecedent: The formula we have
        target: The list predicate we're trying to prove

    Returns:
        Abduced frame, or None if cannot abduce
    """
    if target.name not in ["list", "ls"]:
        return None

    # Extract points-to facts from antecedent
    ante_parts = checker.analyzer._extract_sepconj_parts(antecedent)
    pto_facts = [p for p in ante_parts if isinstance(p, PointsTo)]

    if target.name == "list" and len(target.args) == 1:
        # Target: list(x)
        # Look for: x |-> y in antecedent
        # Abduce: list(y)
        target_root = target.args[0]

        for pto in pto_facts:
            if isinstance(pto.location, Var) and isinstance(target_root, Var):
                if pto.location.name == target_root.name:
                    # Found x |-> ...
                    if len(pto.values) > 0 and isinstance(pto.values[0], Var):
                        next_var = pto.values[0]
                        # Abduce: list(next_var)
                        abduced = PredicateCall("list", [next_var])
                        if checker.verbose:
                            print(f"[Frame Abduction] Abduced list segment: {abduced}")
                        return abduced

    elif target.name == "ls" and len(target.args) == 2:
        # Target: ls(x, z)
        # Look for: x |-> y in antecedent
        # Abduce: ls(y, z)
        target_start = target.args[0]
        target_end = target.args[1]

        for pto in pto_facts:
            if isinstance(pto.location, Var) and isinstance(target_start, Var):
                if pto.location.name == target_start.name:
                    # Found x |-> ...
                    if len(pto.values) > 0 and isinstance(pto.values[0], Var):
                        next_var = pto.values[0]
                        # Abduce: ls(next_var, target_end)
                        abduced = PredicateCall("ls", [next_var, target_end])
                        if checker.verbose:
                            print(f"[Frame Abduction] Abduced list segment: {abduced}")
                        return abduced

    return None
