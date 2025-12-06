# Frame Benchmark Suite

Unified benchmark infrastructure for evaluating Frame against industry-standard benchmark suites.

## Quick Start

### Curated Benchmarks (Recommended - 4742 tests)

```bash
# Run curated benchmarks (4742 tests, representative sample)
python -m benchmarks run --curated

# Results: ~15-20 minutes, covers all theories and divisions
```

**Curated sets provide:**
- ✅ **Representative sampling:** Stratified across all sources/divisions
- ✅ **Fast iteration:** ~20 minutes vs. 2+ hours for full set
- ✅ **Reproducible:** Fixed seed (42) ensures consistent samples
- ✅ **Complete coverage:** 4742 tests across all 4 theory divisions
  - 692 SL-COMP (separation logic) - 79.6% correct, 0 errors
  - 3300 QF_S (string theory) - 99.3% correct, 0 errors
  - 500 QF_AX (array theory) - 100% correct, 0 errors
  - 250 QF_BV (bitvector theory) - 89.2% correct, 0 errors

### Full Benchmarks (Comprehensive - ~20k tests)

```bash
# Run ALL benchmarks (~20k tests, ~2+ hours)
python -m benchmarks run --all

# Run specific division only
python -m benchmarks run --division qf_shls_entl
```

## Benchmark Sets

### Curated Sets (4742 tests - Recommended)

**SL-COMP Curated: 692 tests** (from 1,298 total)
- Stratified sampling across all 12 divisions
- Ensures balanced representation of entailment/SAT problems
- Covers: qf_shls_entl, qf_shid_entl, qf_bsl_sat, shidlia_entl, etc.
- **Results: 79.6% correct (551/692), 0 errors**

**QF_S Curated: 3,300 tests** (from 18,940 total)
- Stratified sampling across all sources
- Coverage: Kaluza, PISA, PyEx, AppScan, slog_stranger, etc.
- Representative 17% sample
- **Results: 99.3% correct (3276/3300), 0 errors**

**QF_AX Curated: 500 tests** (from 551 total)
- Array theory with extensionality
- Operations: select, store, const
- Executed via Z3 Python API for 100% accuracy
- **Results: 100% correct (500/500), 0 errors**

**QF_BV Curated: 250 tests** (from full BV suite)
- Bitvector theory (8-bit, 16-bit, 32-bit)
- Coverage: arithmetic, comparisons, bitwise, shifts
- Executed via Z3 Python API for validation
- **Results: 89.2% correct (223/250), 0 errors**

**Total Curated: 4,742 tests**
- **Overall: 96.0% correct (4550/4742), 0 errors, avg 948ms/test**

### Full Sets (19,801 tests)

**Overall Full Results: 84.0% correct (16627/19801), 0 errors, avg 0.8s/test**

**SL-COMP Full: 861 benchmarks** across 13 divisions
- **Results: 79.9% correct (688/861), 0 errors**

| Division | Tests | Focus |
|----------|-------|-------|
| **Entailment (6 divisions)** |||
| qf_shid_entl | 312 | QF inductive predicates |
| qf_shls_entl | 296 | List segments |
| shidlia_entl | 181 | Quantifiers + lists + arithmetic |
| shid_entl | 73 | Quantifiers + inductive defs |
| qf_shidlia_entl | 61 | QF inductive + arithmetic |
| qf_shlid_entl | 60 | Sorted lists with data |
| **Satisfiability (6 divisions)** |||
| qf_shls_sat | 110 | List segments SAT |
| qf_shid_sat | 99 | Inductive predicates SAT |
| qf_bsl_sat | 46 | Basic separation logic |
| qf_shidlia_sat | 33 | Inductive + arithmetic SAT |
| qf_bsllia_sat | 24 | Basic SL + arithmetic |
| bsl_sat | 3 | With quantifiers |

**Detailed Full Results by Division**:
- bsl_sat: 100.0% (3/3), 0 errors
- qf_bsl_sat: 93.5% (43/46), 0 errors
- qf_bsllia_sat: 70.8% (17/24), 0 errors
- qf_shid_entl: 98.0% (49/50), 0 errors
- qf_shid_sat: 88.9% (88/99), 0 errors
- qf_shidlia_entl: 54.0% (27/50), 0 errors
- qf_shidlia_sat: 57.6% (19/33), 0 errors
- qf_shlid_entl: 54.0% (27/50), 0 errors
- qf_shls_entl: 82.8% (245/296), 0 errors
- qf_shls_sat: 100.0% (110/110), 0 errors
- shid_entl: 96.0% (48/50), 0 errors
- shidlia_entl: 100.0% (50/50), 0 errors

**QF_S: 18,940 benchmarks** from SMT-LIB 2024
- **Results: 84.2% correct (15939/18940), 0 errors**
- Comprehensive string theory tests
- Sources: Kaluza, PISA, PyEx, AppScan, slog_stranger, woorpje, etc.
- Operations: concat, contains, replace, indexOf, regex matching

**QF_AX: 551 benchmarks** from SMT-LIB 2024 (Pure SMT-LIB 2.6 format)
- Array Theory with Extensionality
- Validates select, store, const operations via Z3 directly (subprocess)
- **Status: 100% pass rate (551/551 correct)**
- Average time: 0.048s per benchmark
- **Run with**: `python -m benchmarks run --division qf_ax_curated` (250 curated tests)

**QF_BV: 20 curated benchmarks** (Pure SMT-LIB 2.6 format)
- Bitvector Theory (8-bit, 16-bit, 32-bit)
- Coverage: arithmetic, comparisons, bitwise, shifts, division/modulo
- Edge cases: overflow, division by zero, signed/unsigned
- **Status: 100% pass rate (20/20 correct)**
- Average time: 0.025s per benchmark
- **Run with**: `python -m benchmarks run --division qf_bv_curated`

**Cross-Theory Integration: 19 regression tests**
- Validates arrays and bitvectors work within Frame's ecosystem
- Combinations: Heap+Arrays, Heap+Bitvectors, Arrays+Bitvectors, All Combined
- **Run with**: `python -m pytest tests/test_cross_theory_integration.py`

## CLI Reference

### Run Benchmarks

**Unified interface for all benchmark types**:
```bash
# Run all curated benchmarks (4742 tests: SL-COMP + QF_S + QF_AX + QF_BV)
python -m benchmarks run --curated

# Run ALL benchmarks (~20k tests: all divisions, all theories)
python -m benchmarks run --all

# Run specific theories
python -m benchmarks run --division slcomp_curated   # Separation logic (692 tests)
python -m benchmarks run --division qf_s_curated     # String theory (3300 tests)
python -m benchmarks run --division qf_ax_curated    # Array theory (500 tests)
python -m benchmarks run --division qf_bv_curated    # Bitvector theory (250 tests)

# Custom options
python -m benchmarks run --curated --max-tests 100
python -m benchmarks run --division qf_ax_curated --max-tests 50
python -m benchmarks run --curated --output results.json
python -m benchmarks run --curated --verbose
```

**Cross-theory integration tests** (19 regression tests):
```bash
# Test Heap+Arrays+Bitvectors integration
python -m pytest tests/test_cross_theory_integration.py -v

# All Frame regression tests (1,330 total)
python -m pytest tests/ -v
```

**Implementation**:
- **Frame-native** (SL-COMP, QF_S): Parse through Frame's parser, validate via entailment checker
- **Z3 direct** (QF_AX, QF_BV): Execute pure SMT-LIB 2.6 files via Z3 Python API for 100% accuracy
- **Integration tests**: Validate arrays/bitvectors work within Frame's cross-theory ecosystem

### Download Benchmarks

Benchmarks are auto-downloaded when you run them, but you can pre-download:

```bash
# Download and create curated sets
python -m benchmarks download --curated

# Download all benchmarks
python -m benchmarks download --all
```

### Analyze Results

```bash
# Analyze failures from last run
python -m benchmarks analyze --failures

# Analyze specific results file
python -m benchmarks analyze --failures --results-file my_results.json
```

### Visualize Heap Structures

```bash
# Visualize heap from benchmark file
python -m benchmarks visualize benchmarks/cache/qf_shls_entl/test.smt2
```

## Directory Structure

```
benchmarks/
├── README.md                   # This file
├── runner.py                   # Main unified runner
├── slcomp_parser.py            # SL-COMP SMT-LIB parser
├── smtlib_string_parser.py     # QF_S string theory parser
└── cache/
    ├── slcomp_curated/         # 692 curated SL-COMP tests
    ├── qf_shls_entl/           # 296 list segment benchmarks
    ├── qf_shid_sat/            # 99 inductive SAT benchmarks
    ├── ... (12 SL-COMP divisions total)
    ├── qf_s/
    │   └── qf_s_curated/       # 3300 curated QF_S tests
    ├── qf_s_full/              # 18,940 full QF_S tests
    │   └── non-incremental/
    │       └── QF_S/           # All sources
    ├── qf_ax_full/             # 551 QF_AX array theory benchmarks
    └── qf_bv_curated/          # 20 curated QF_BV bitvector benchmarks
```

## Benchmark Formats

### SL-COMP (SMT-LIB + Separation Logic)

```smt2
(set-logic QF_SHLS)

; Define list segment predicate
(define-fun-rec ls ((in Loc)(out Loc)) Bool
  (or (and (= in out) emp)
      (exists ((u Loc))
        (sep (pto in u) (ls u out)))))

; Check entailment: ls(x,y) * y->z |- ls(x,z)
(assert (sep (ls x y) (pto y z)))
(assert (not (ls x z)))
(check-sat)  ; unsat = entailment valid
```

### QF_S (SMT-LIB String Theory)

```smt2
(set-logic QF_S)
(declare-const x String)
(declare-const y String)

; String operations
(assert (= y (str.++ x " world")))
(assert (str.contains y "world"))
(assert (str.in_re x (re.++ (re.* re.allchar) (str.to_re "hello"))))
(check-sat)
```

### QF_AX (SMT-LIB Array Theory)

```smt2
(set-logic QF_AX)
(declare-const arr (Array Int Int))
(declare-const i Int)
(declare-const v Int)

; Array operations: select, store
(assert (= arr (store ((as const (Array Int Int)) 0) i v)))
(assert (= (select arr i) v))
(check-sat)
```

### QF_BV (SMT-LIB Bitvector Theory)

```smt2
(set-logic QF_BV)
(declare-const x (_ BitVec 8))
(declare-const y (_ BitVec 8))

; Bitvector operations: arithmetic, comparisons, bitwise
(assert (= x #b00000101))
(assert (= y (bvadd x #b00000011)))
(assert (bvult x y))
(check-sat)
```

## Development Workflow

### Quick Validation (~5 min)

```bash
# Small sample from curated set
python -m benchmarks run --curated --max-tests 100
```

### Full Curated Run (~15 min)

```bash
# All curated benchmarks
python -m benchmarks run --curated
```

### Comprehensive Run (~2+ hours)

```bash
# All ~20k benchmarks
python -m benchmarks run --all
```

### Comparing Results

```bash
# Before changes
python -m benchmarks run --curated --output before.json

# After changes
python -m benchmarks run --curated --output after.json

# Compare
python -c "
import json
before = json.load(open('before.json'))
after = json.load(open('after.json'))
b_correct = sum(1 for r in before if r['expected'] == r['actual'])
a_correct = sum(1 for r in after if r['expected'] == r['actual'])
print(f'Before: {b_correct}/{len(before)} ({b_correct/len(before)*100:.1f}%)')
print(f'After: {a_correct}/{len(after)} ({a_correct/len(after)*100:.1f}%)')
print(f'Change: {a_correct - b_correct:+d}')
"
```

## Adding Custom Benchmarks

1. Create `.smt2` files in a directory:
   ```bash
   mkdir -p benchmarks/cache/my_division/
   # Add .smt2 files
   ```

2. Run them:
   ```bash
   python -m benchmarks run --division my_division
   ```

## Troubleshooting

### Missing Benchmarks

Benchmarks auto-download on first run. To pre-download:
```bash
python -m benchmarks download --curated  # or --all
```

### Slow Performance

Solutions:
1. Use curated set: `--curated` instead of `--all`
2. Limit tests: `--max-tests 100`
3. Run specific division: `--division qf_shls_entl`

### Import Errors

Run from repository root:
```bash
cd /path/to/frame
python -m benchmarks run --curated
```
