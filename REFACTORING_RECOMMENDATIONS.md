# Refactoring Recommendations

This document identifies large files (> 500 lines) in the Frame codebase and provides concrete refactoring recommendations to improve maintainability.

## Overview

**Total Python Code:**
- Source (`frame/`): 20,519 lines
- Tests: 19,156 lines
- Benchmarks: 4,745 lines

**Files Over 500 Lines:** 18 files (need attention)

---

## Critical Priority - Immediate Refactoring Needed

### 1. `benchmarks/runner.py` - 2,644 lines ⚠️ CRITICAL

**Current State:**
- 1 massive class: `UnifiedBenchmarkRunner` with 37 methods
- Handles SL-COMP, QF_S, QF_AX, QF_BV benchmarks
- Download, run, analyze, visualize all in one file
- 5 top-level command functions

**Refactoring Plan:**
```
benchmarks/
├── runner.py (main entry + orchestration, ~300 lines)
├── core/
│   ├── __init__.py
│   ├── result.py (BenchmarkResult dataclass, ~30 lines)
│   ├── base_runner.py (shared Z3/parsing utilities, ~200 lines)
│   └── analysis.py (analyze_results, print_summary, ~150 lines)
├── downloaders/
│   ├── __init__.py
│   ├── slcomp.py (download_slcomp_*, ~200 lines)
│   ├── qf_s.py (download_qf_s_*, ~500 lines)
│   ├── qf_ax.py (download_qf_ax_*, ~200 lines)
│   ├── qf_bv.py (download_qf_bv_*, ~200 lines)
│   └── utils.py (gdrive, extract_archive, ~100 lines)
├── runners/
│   ├── __init__.py
│   ├── slcomp_runner.py (run_slcomp_*, ~200 lines)
│   ├── qf_s_runner.py (run_qf_s_*, ~150 lines)
│   ├── qf_ax_runner.py (run_qf_ax_*, ~100 lines)
│   └── qf_bv_runner.py (run_qf_bv_*, ~100 lines)
├── curators/
│   ├── __init__.py
│   └── samplers.py (create_*_curated_set, ~400 lines)
└── commands/
    ├── __init__.py
    ├── run_cmd.py (cmd_run, ~100 lines)
    ├── download_cmd.py (cmd_download, ~150 lines)
    ├── analyze_cmd.py (cmd_analyze, ~50 lines)
    └── visualize_cmd.py (cmd_visualize, ~150 lines)
```

**Benefits:**
- Each file < 500 lines
- Clear separation of concerns (download / run / curate / analyze)
- Easy to add new benchmark suites
- Testable components

**Estimated Effort:** 6-8 hours (high impact)

---

### 2. `benchmarks/slcomp_parser.py` - 1,206 lines ⚠️ HIGH PRIORITY

**Current State:**
- 1 class: `SLCompParser` with 26 methods
- Parses complex SL-COMP SMT-LIB 2.6 format
- Handles multiple theories (separation logic, strings, etc.)

**Refactoring Plan:**
```
benchmarks/parsing/
├── __init__.py
├── base_parser.py (common SMT-LIB parsing, ~200 lines)
├── slcomp/
│   ├── __init__.py
│   ├── lexer.py (tokenization, ~150 lines)
│   ├── parser.py (AST building, ~300 lines)
│   ├── spatial.py (separation logic parsing, ~200 lines)
│   ├── predicates.py (predicate parsing, ~150 lines)
│   └── types.py (type inference, ~150 lines)
└── smtlib_string_parser.py (existing, ~540 lines - also needs split)
```

**Benefits:**
- Parser becomes modular and extensible
- Can reuse components for other SMT-LIB parsers
- Easier to debug and test individual parsing stages

**Estimated Effort:** 5-6 hours

---

## High Priority - Refactoring Recommended

### 3. `frame/encoding/encoder.py` - 932 lines

**Current State:**
- 1 class: `Z3Encoder` with 24 methods
- Encodes entire separation logic to Z3
- Handles spatial, pure, arithmetic, strings, bitvectors

**Refactoring Plan:**
```
frame/encoding/
├── encoder.py (main Z3Encoder facade, ~300 lines)
├── _spatial.py (existing, 614 lines - keep as is for now)
├── _wand.py (existing, 900 lines - see below)
├── _pure.py (pure formula encoding, ~150 lines)
├── _arithmetic.py (arithmetic theory, ~150 lines)
├── _strings.py (string theory encoding, ~150 lines)
├── _bitvectors.py (bitvector theory, ~100 lines)
└── _domains.py (domain tracking utilities, ~100 lines)
```

**Benefits:**
- Each theory isolated
- Encoder.py becomes a thin facade delegating to theory encoders
- Easier to add new theories or modify existing ones

**Estimated Effort:** 4-5 hours

---

### 4. `frame/encoding/_wand.py` - 900 lines

**Current State:**
- 1 class: `WandEncoder` with 19 methods
- Complex magic wand encoding (non-trivial separation logic operator)

**Refactoring Plan:**
```
frame/encoding/wand/
├── __init__.py
├── encoder.py (main WandEncoder, ~200 lines)
├── verification.py (wand verification, ~200 lines)
├── inference.py (wand inference, ~200 lines)
├── simplification.py (wand simplification, ~150 lines)
└── utils.py (helper functions, ~150 lines)
```

**Benefits:**
- Magic wand is complex enough to deserve its own submodule
- Each aspect (verification, inference, simplification) in separate file
- Matches academic literature organization

**Estimated Effort:** 4-5 hours

---

### 5. `frame/core/parser.py` - 744 lines

**Current State:**
- 1 class with 35 methods
- Parses Frame's separation logic syntax
- Handles precedence, operators, predicates

**Status:** Acceptable but could be improved

**Optional Refactoring:**
```
frame/core/
├── parser.py (main Parser class, ~300 lines)
├── _lexer.py (tokenization, already extracted!)
├── _precedence.py (operator precedence, ~100 lines)
├── _spatial_parser.py (spatial formula parsing, ~150 lines)
└── _pure_parser.py (pure formula parsing, ~150 lines)
```

**Priority:** Medium (defer until other critical issues resolved)

**Estimated Effort:** 3-4 hours

---

### 6. `frame/checking/checker.py` - 691 lines

**Current State:**
- 2 classes: `EntailmentChecker`, `EntailmentResult`
- Main checking algorithm with heuristics, lemmas, folding

**Status:** Acceptable, well-structured

**Optional Improvements:**
- Extract `EntailmentResult` to `result.py` (~20 lines)
- Extract complex checking strategies to `_strategies.py` (~150 lines)
- Keep main checker at ~500 lines

**Priority:** Low (well-organized already)

**Estimated Effort:** 2 hours

---

## Test Files - Large but Acceptable

These test files are large but follow pytest patterns (class-based tests). Generally acceptable:

- `test_array_bitvector_regression.py` - 925 lines, 15 test classes
- `test_footprint_analysis.py` - 572 lines, 11 test classes
- `test_vulnerability_detection.py` - 557 lines, 9 test classes
- `test_lemma_matcher.py` - 553 lines, 6 test classes
- `test_lemma_substitution.py` - 539 lines, 8 test classes
- `test_incorrectness_logic.py` - 507 lines, 12 test classes
- `test_equality_preprocessing.py` - 501 lines, 7 test classes

**Recommendation:** Keep as-is for now. These are comprehensive test suites. Splitting would reduce cohesion.

**Future:** If any test file exceeds 1000 lines, split by feature area.

---

## Recommended Refactoring Order

**Phase 1 - Critical (Do First):**
1. `benchmarks/runner.py` (2644 → ~12 files × 100-500 lines each)
2. `benchmarks/slcomp_parser.py` (1206 → ~6 files × 150-300 lines each)

**Phase 2 - High Priority:**
3. `frame/encoding/_wand.py` (900 → ~5 files × 150-200 lines each)
4. `frame/encoding/encoder.py` (932 → ~7 files × 100-300 lines each)

**Phase 3 - Nice to Have:**
5. `frame/core/parser.py` (744 → ~5 files × 100-300 lines each)
6. `frame/checking/checker.py` (691 → ~3 files × 200-300 lines each)

---

## General Refactoring Principles

1. **Target File Size:** 200-400 lines (sweet spot)
2. **Maximum File Size:** 500 lines (hard limit for new code)
3. **Module Organization:**
   - Create subpackages for complex features (wand/, parsing/, etc.)
   - Use `__init__.py` to export public API
   - Keep internal helpers in `_private.py` files
4. **Backward Compatibility:**
   - Maintain existing imports: `from frame import EntailmentChecker`
   - Add deprecation warnings if moving public APIs
5. **Testing:**
   - Ensure all tests pass after each refactoring step
   - Add integration tests for refactored modules

---

## Impact Summary

**Before Refactoring:**
- 2 files > 1000 lines (critical)
- 4 files > 700 lines (very large)
- 12 files > 500 lines (large)

**After Refactoring (Phase 1+2):**
- 0 files > 1000 lines ✅
- 1 file > 700 lines (parser.py - acceptable)
- 6 files > 500 lines (test files - acceptable)

**Lines Refactored:** ~6,500 lines reorganized into 35+ smaller, focused modules

**Maintenance Benefit:**
- New developers can understand each module in < 15 minutes
- Bug isolation improved (smaller blast radius)
- Testing becomes more granular
- Code reuse increases (shared utilities extracted)

---

## Conclusion

The Frame codebase is generally well-structured, but `benchmarks/runner.py` (2644 lines) and `benchmarks/slcomp_parser.py` (1206 lines) are critically large and should be refactored as soon as possible. The encoding modules are large but manageable; refactoring them would improve maintainability but is less urgent.

Test files are large but acceptable given their comprehensive nature.

**Next Step:** Begin Phase 1 refactoring of benchmark runner module.
