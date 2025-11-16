# Frame - Separation Logic Solver

A fast, practical separation logic solver combining heap reasoning, string constraint solving, and automated bug detection.

[![Tests](https://img.shields.io/badge/tests-1147%2F1147-green)]() [![Python](https://img.shields.io/badge/python-3.7%2B-blue)]() [![License](https://img.shields.io/badge/license-Apache%202.0-blue)]()

## Features

**Unique Capabilities** - The only solver combining:
- **Separation Logic**: Heap structure reasoning (points-to, predicates, entailments)
- **String Theory** (QF_S): SMT-LIB string operations with 90.6% accuracy
- **Incorrectness Logic**: Under-approximate reasoning for bug detection
- **Taint Analysis**: Source-to-sink tracking for security vulnerabilities

**Performance**:
- 10-50x faster than Z3/CVC5 on string benchmarks (2.8ms avg vs 50-100ms)
- <1ms reflexivity fast path
- Parallel heuristic checking before Z3

**Benchmarks**:
- 1,147 unit tests (100% passing)
- 19,854 total benchmarks across multiple suites
- 90.6% accuracy on QF_S string benchmarks
- 66.7% accuracy on SL-COMP separation logic benchmarks

## Installation

```bash
# Clone repository
git clone https://github.com/codelion/proofs.git
cd proofs

# Install dependencies
pip install -r requirements.txt

# Run all tests
python -m pytest tests/ -q
```

**Requirements**: Python 3.7+, Z3, zstandard (see requirements.txt)

### Quick Test

```bash
# Download sample benchmarks (optional)
python -m benchmarks download --suite qf_s

# Run string benchmarks
python -m benchmarks run --suite qf_s

# Or test directly with Python
python -c "from frame import EntailmentChecker; print(EntailmentChecker().check_entailment('x |-> 5 |- x |-> 5').valid)"
```

## Quick Start

### Separation Logic

```python
from frame import EntailmentChecker

checker = EntailmentChecker()

# Entailment checking
result = checker.check_entailment("x |-> 5 * y |-> 3 |- x |-> 5")
print(result.valid)  # True

# Predicate unfolding
result = checker.check_entailment("x |-> y * list(y) |- list(x)")
print(result.valid)  # True
```

### String Constraints

```python
from frame import parse

# String operations
formula = parse('x = "hello" & y = (str.++ x " world")')
print(checker.is_satisfiable(formula))  # True

# Complex constraints
formula = parse('x = "testing" & y = (str.substr x 0 4) & (str.len y) = 4')
print(checker.is_satisfiable(formula))  # True
```

### Bug Detection

```python
from frame import IncorrectnessChecker, Var

checker = IncorrectnessChecker()

# Null pointer dereference
state = parse('ptr = nil & Allocated(buffer)')
bug = checker.find_null_deref(state, Var("ptr"))
print(bug.found)  # True

# Use-after-free
state = parse('Allocated(ptr) & Freed(ptr)')
bug = checker.find_use_after_free(state, Var("ptr"))
print(bug.found)  # True

# SQL injection
state = parse('TaintedInput(user_input) & query = (str.++ "SELECT * FROM users WHERE id=" user_input)')
bug = checker.find_sql_injection(state, Var("query"))
print(bug.found)  # True
```

## Supported Theories

### Separation Logic
- **Spatial**: Points-to (`x |-> 5`), empty heap (`emp`), separating conjunction (`*`), magic wand (`-*`)
- **Pure**: Equality, boolean logic, linear integer arithmetic
- **Predicates**: Lists (`ls`, `list`), trees (`tree`), doubly-linked lists (`dll`)

### String Theory (QF_S)
- **Concatenation**: `str.++`, `str.len`
- **Substring**: `str.substr`, `str.at`, `str.contains`, `str.prefixof`, `str.suffixof`
- **Searching**: `str.indexof`, `str.replace`
- **Coverage**: 10/10 operation categories, 90.6% accuracy

### Security & Lifecycle
- **Heap Lifecycle**: `Allocated`, `Freed`, `ArrayBounds`, `ArrayPointsTo`
- **Taint Analysis**: `TaintedInput`, `Sanitized`, `TaintFlow`

## Benchmarks

Frame includes 19,854 benchmarks across multiple suites with a unified interface.

### Usage

```bash
# Download benchmarks (one-time, 2.9MB compressed)
python -m benchmarks download --all

# Run benchmarks
python -m benchmarks run --suite qf_s          # String theory benchmarks
python -m benchmarks run --suite slcomp        # Separation logic benchmarks

# Analyze results
python -m benchmarks analyze --failures
python -m benchmarks visualize <file.smt2>
```

### Results Summary

**String Theory (QF_S)**: 90.6% accuracy (48/53 samples, 2.8ms avg)
- Kaluza: 90.0% (40 tests) - Concatenation, contains, substr, indexof, replace
- Woorpje: 100% (5 tests) - Word equations
- PISA: 80.0% (5 tests) - Path-sensitive analysis
- **Full Set**: 18,940 tests from SMT-LIB 2024 available

**Separation Logic (SL-COMP)**: 66.7% accuracy (574/861 tests)
- Best: `shidlia_entl` (100%, 50/50), `shid_entl` (94%, 47/50)
- Largest: `qf_shls_entl` (77%, 228/296) - List segments

**Performance**: 10-50x faster than Z3/CVC5 on string constraints

See `benchmarks/README.md` for detailed results and `docs/QF_S_BENCHMARK_REPORT.md` for analysis.

## Architecture

Frame uses a modular architecture with specialized components:

```
frame/
├── core/          # AST, parser
├── encoding/      # Z3 SMT encoding
├── checking/      # Entailment checking and heuristics
├── analysis/      # Formula analysis and reasoning
├── heap/          # Heap graph and pattern detection
├── folding/       # Predicate folding/unfolding
├── predicates/    # Inductive predicate definitions
├── lemmas/        # Lemma library
└── utils/         # Utilities and proof management
```

**Algorithm**: Parse → Preprocess → Fold → Unfold → Encode → Solve

**Key Optimizations**: Reflexivity fast path (<1ms), goal-directed folding, heuristic checks, lemma library

## Testing

```bash
# Run all tests (1,147 tests, ~47s)
python -m pytest tests/ -q

# Run specific tests
python -m pytest tests/test_string_theory.py
python -m pytest tests/ -k "incorrectness"
```

**Coverage**: Separation logic, string theory, incorrectness logic, taint analysis, 21 legacy SL-COMP suites

## API Reference

### EntailmentChecker

```python
from frame import EntailmentChecker

checker = EntailmentChecker(timeout=10000, use_folding=True, verbose=False)

# Check entailment: P |- Q
result = checker.check_entailment("P |- Q")
# Returns: EntailmentResult(valid, model, reason)

# Check satisfiability
is_sat = checker.is_satisfiable(formula)

# Check equivalence
equiv = checker.check_equiv(formula1, formula2)
```

### IncorrectnessChecker

```python
from frame import IncorrectnessChecker, Var

checker = IncorrectnessChecker()

# Memory bugs
bug = checker.find_null_deref(state, Var("ptr"))
bug = checker.find_use_after_free(state, Var("ptr"))
bug = checker.find_buffer_overflow(state, Var("array"), Var("index"))
bug = checker.find_double_free(state, Var("ptr"))

# Security vulnerabilities
bug = checker.find_sql_injection(state, Var("query"))
bug = checker.find_xss(state, Var("output"))
bug = checker.find_command_injection(state, Var("cmd"))

# Returns: BugReport(found, type, location, trace)
```

## Custom Predicates

Define your own recursive predicates:

```python
from frame import PredicateRegistry, EntailmentChecker

registry = PredicateRegistry()

bst_def = """
(bst ?x ?lo ?hi) :=
  ((= ?x nil) * emp) |
  (exists ?v ?l ?r.
    (?x |-> (?v, ?l, ?r)) *
    (?lo < ?v) * (?v < ?hi) *
    (bst ?l ?lo ?v) * (bst ?r ?v ?hi))
"""

registry.register_from_smt2("bst", bst_def)
checker = EntailmentChecker(predicate_registry=registry)

result = checker.check_entailment("x |-> (5, l, r) * bst(l, 0, 5) * bst(r, 5, 10) |- bst(x, 0, 10)")
print(result.valid)  # True
```

## Known Limitations

- **String Theory**: Missing some advanced axioms (length non-negativity, regex support)
- **Bounded Unfolding**: Default depth 10 (increase with `registry.max_unfold_depth = 15`)
- **Predicate Synthesis**: Heuristic-based, may miss some valid foldings

## Contributing

Contributions welcome! Areas: string theory axiomatization, regex support, security patterns, performance optimizations.

## Citation

If you use Frame in academic work, please cite:

```bibtex
@software{frame_solver,
  title = {Frame: Separation Logic Solver with String Theory and Bug Detection},
  author = {Frame Contributors},
  year = {2025},
  url = {https://github.com/codelion/proofs}
}
```

## References

**Separation Logic**:
- Reynolds, O'Hearn (2002). [Separation Logic: A Logic for Shared Mutable Data Structures](https://doi.org/10.1109/LICS.2002.1029817)
- Piskac, Wies, Zufferey (2013). [Automating Separation Logic with Trees and Data](https://doi.org/10.1007/978-3-642-39799-8_53)

**String Constraint Solving**:
- Saxena et al. (2010). [A Symbolic Execution Framework for JavaScript](https://doi.org/10.1109/SP.2010.38) (Kaluza)
- Zheng et al. (2013). [Z3-str: A Z3-based String Solver](https://doi.org/10.1007/978-3-642-45221-5_55)

**Incorrectness Logic**:
- O'Hearn (2020). [Incorrectness Logic](https://doi.org/10.1145/3371078)

## License

Apache License 2.0 - see LICENSE file for details.

## Acknowledgments

Built with:
- [Z3 SMT Solver](https://github.com/Z3Prover/z3) - Microsoft Research
- [SL-COMP Benchmarks](https://sl-comp.github.io/) - Community benchmark suite
- [SMT-LIB](https://smtlib.cs.uiowa.edu/) - Standard format for SMT solvers

Inspired by:
- Sleek/HIP (NUS), Cyclist (UCL), Grasshopper (NYU), SPEN (Verimag)
