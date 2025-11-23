# Soundness Bug Fixes - Session Summary

## All THREE Critical Soundness Bugs FIXED ✓

This session successfully identified and fixed three critical soundness bugs that were causing false positives (proving invalid statements as valid).

### Bug #1: Frame Inference Goal Achievement  
**Status**: ✓ FIXED  
**File**: `frame/checking/frame_inference.py` (lines 170-205)  
**Test Fixed**: nll-vc06

**Problem**: Multi-step folding marked goals as "matched" if ANY folds happened, without verifying the actual goal predicate was achieved.

**Fix**: Added verification to check that the goal predicate (with matching name AND arguments) is actually present in the folded formula before marking as matched.

### Bug #2: Cycle Detection False Negatives  
**Status**: ✓ FIXED  
**File**: `frame/utils/satisfiability.py` (lines 182-188)  
**Test Fixed**: dll-vc14 (enabling factor)

**Problem**: Satisfiability checker incorrectly treated ALL heap cycles as contradictions. Circular data structures (like circular doubly-linked lists) are valid in separation logic!

**Fix**: Removed the incorrect cycle detection check. Self-loops (x |-> x) are still detected separately and correctly rejected.

### Bug #3: Frame Inference Ignores Pure Constraints  
**Status**: ✓ FIXED  
**File**: `frame/checking/_checker_core.py` (lines 147-199)  
**Test Fixed**: dll-vc14

**Problem**: Frame inference only matched spatial parts (predicates, points-to) but ignored pure constraints (x != y, etc.) in the consequent. This caused false positives when pure requirements weren't satisfied.

**Fix**: Added pure constraint verification using Z3. After frame inference claims spatial parts match, we now extract and verify pure constraints separately before accepting success.

## Test Results

| Test | Before | After | Status |
|------|---------|-------|--------|
| nll-vc06 | VALID (FALSE POSITIVE) | INVALID | ✓ FIXED |
| dll-vc14 | VALID (FALSE POSITIVE) | INVALID | ✓ FIXED |

## Files Modified

1. `frame/checking/frame_inference.py` - Goal achievement verification
2. `frame/utils/satisfiability.py` - Removed incorrect cycle detection  
3. `frame/checking/_checker_core.py` - Pure constraint verification

## Impact

These fixes eliminate critical soundness issues where Frame was incorrectly proving false statements. This significantly improves the reliability and trustworthiness of the checker for:
- Nested inductive predicates (nll)
- Circular data structures (circular dll)
- Entailments with pure constraints

## Next Steps

1. Clean up debug scripts
2. Run full benchmark suite to verify no regressions
3. Commit and push fixes
4. Consider adding regression tests for these specific bugs

---
*Session completed: All critical soundness bugs fixed!*
