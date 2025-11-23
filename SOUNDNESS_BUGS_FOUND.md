# Soundness Bugs Discovered - Analysis Session

This document tracks critical soundness bugs found during the hierarchical predicate folding investigation.

## Bug #1: Frame Inference False Positives (Multi-Step Folding)
**Status**: FIXED ✓
**File**: `frame/checking/frame_inference.py` (lines 170-205)
**Severity**: CRITICAL - False positives (proving invalid statements as valid)

### Problem
Frame inference was marking goals as "matched" if ANY folds happened (`num_folds > 0`), without verifying that the actual GOAL predicate was achieved. This caused false positives where intermediate folds (e.g., ls/lso) were counted as matching a different goal (e.g., nll).

### Example
- Test: nll-vc06
- Expected: sat (invalid entailment)
- Before fix: unsat (WRONG - false positive)
- After fix: sat (CORRECT)

### Root Cause
```python
# BEFORE (UNSOUND):
if folded_formula is not None and num_folds > 0:
    # MARKS AS MATCHED WITHOUT CHECKING GOAL!
    cons_parts.remove(cons_part)
    matched_parts.append(cons_part)
```

### Fix
Added goal achievement verification:
```python
# AFTER (SOUND):
if folded_formula is not None and num_folds > 0:
    # CRITICAL: Verify that the goal predicate was actually achieved
    goal_achieved = False
    for folded_pred in analyzer.extract_predicate_calls(folded_formula):
        if (folded_pred.name == cons_part.name and
            all(str(fa) == str(ca) for fa, ca in zip(folded_pred.args, cons_part.args))):
            goal_achieved = True
            break

    if goal_achieved:
        # NOW it's safe to mark as matched
        ...
```

### Tests Fixed
- nll-vc06: Now correctly returns invalid ✓

---

## Bug #2: Cycle Detection False Negatives
**Status**: FIXED ✓
**File**: `frame/utils/satisfiability.py` (lines 182-190)
**Severity**: CRITICAL - False positives (rejecting valid circular heaps)

### Problem
The satisfiability checker incorrectly treated ALL heap cycles as contradictions (UNSAT). This is fundamentally wrong - circular data structures (e.g., circular doubly-linked lists) are perfectly valid in separation logic.

### Example
- Test: dll-vc14
- Structure: x_emp -> y_emp -> x_emp (circular dll)
- Before fix: Incorrectly detected as UNSAT
- After fix: Correctly recognized as SAT

### Root Cause
```python
# WRONG LOGIC:
# Check for cycles in the heap graph (PRIORITY 1 improvement)
# Cyclic heaps violate separation logic semantics and should be UNSAT  <-- FALSE!
if len(points_to) >= 2:
    graph, _ = self.heap_analyzer.build_heap_graph(formula)
    if self.heap_analyzer._has_cycle(graph):
        return True  # UNSAT <-- WRONG!
```

### Fix
Removed the incorrect cycle detection check entirely. Only self-loops (x |-> x) are unsound, and those are already checked separately (lines 175-180).

### Impact
- Circular doubly-linked lists now handled correctly
- dll-vc14 no longer incorrectly rejected (though still has other issues - see Bug #3)

---

## Bug #3: Frame Inference Ignores Pure Constraints
**Status**: NOT YET FIXED ✗
**File**: `frame/checking/frame_inference.py`
**Severity**: CRITICAL - False positives

### Problem
Frame inference only matches SPATIAL parts of the consequent (predicates, points-to), but ignores PURE constraints (equalities, inequalities, arithmetic). This causes false positives when the consequent has pure requirements that aren't satisfied by the antecedent.

### Example
- Test: dll-vc14
- Antecedent: `((y_emp != z_emp & ...) & (x_emp |-> ... * y_emp |-> ...))`
  - Note: Has `y_emp != z_emp`, but NOT `x_emp != z_emp`
- Consequent: `(x_emp != z_emp & dll(x_emp, y_emp, nil, z_emp))`
  - Requires BOTH `x_emp != z_emp` AND the dll predicate
- Current behavior: Frame inference matches dll(...) and claims success, ignoring `x_emp != z_emp`
- Result: FALSE POSITIVE (claims valid when should be invalid)

### Root Cause
Frame inference extracts "parts" to match using `_extract_sepconj_parts()`, which likely only extracts spatial parts (separated by `*`), not pure constraints (connected by `&`).

When all spatial parts are matched, frame inference returns True without verifying pure constraints:
```python
if not cons_parts:
    # All parts matched!
    return True, f"Frame inference: matched {len(matched_parts)} parts..."
```

### Proposed Fix Options
1. **Option A**: Extract pure constraints from consequent and verify them separately before claiming success
2. **Option B**: After frame inference claims success, always call Z3 to verify the full entailment (including pure)
3. **Option C**: Make `_extract_sepconj_parts()` also extract pure parts and match them

### Tests Affected
- dll-vc14: Still incorrectly returns VALID (should be INVALID)
- Likely many other tests with pure constraints in consequent

---

## Summary

| Bug | Status | Severity | Tests Fixed | Tests Remaining |
|-----|--------|----------|-------------|-----------------|
| #1: Frame inference goal verification | ✓ FIXED | CRITICAL | nll-vc06 | - |
| #2: Cycle detection | ✓ FIXED | CRITICAL | (enabling factor) | - |
| #3: Pure constraints ignored | ✗ TODO | CRITICAL | - | dll-vc14, others |

## Recommendations

1. **Fix Bug #3** before committing - it's a critical soundness issue
2. **Add regression tests** for all three bugs to prevent reintroduction
3. **Audit other fast paths** in the checker for similar soundness issues
4. **Consider formal verification** of core checker logic to prevent soundness bugs

## Testing Status

Current benchmark run (qf_shlid_entl, 60 tests) in progress...
- nll-vc06: ✓ PASSING (Bug #1 fixed)
- dll-vc14: ✗ FAILING (Bug #3 not yet fixed)

User requirement: "only commit and push changes which show improvements and clear all tests"
→ Need to fix Bug #3 before committing.
