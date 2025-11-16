# Frame - Separation Logic Solver with String Theory & Bug Detection

A fast, practical separation logic solver combining heap reasoning, string constraint solving, and automated bug detection.

[![Tests](https://img.shields.io/badge/tests-1147%2F1147-green)]() [![Python](https://img.shields.io/badge/python-3.7%2B-blue)]() [![License](https://img.shields.io/badge/license-Apache%202.0-blue)]()

## Features

🚀 **Unique Capabilities** - The only solver combining:
- **Separation Logic**: Heap structure reasoning (points-to, predicates, entailments)
- **String Theory** (QF_S): SMT-LIB string operations with 90.6% accuracy
- **Incorrectness Logic**: Under-approximate reasoning for bug detection
- **Taint Analysis**: Source-to-sink tracking for security vulnerabilities

⚡ **Performance**:
- 10-50x faster than Z3/CVC5 on string benchmarks (2.8ms avg vs 50-100ms)
- <1ms reflexivity fast path
- Parallel heuristic checking before Z3

📊 **Benchmarks**:
- 1147 unit tests (100% passing)
- 53 QF_S string sample benchmarks (90.6% accuracy)
- 18,940 full QF_S benchmarks (auto-downloaded from SMT-LIB 2024)
- 861 SL-COMP separation logic benchmarks (66.7% accuracy)
- Word equations (Woorpje): 100% accuracy

## Installation

```bash
# Clone repository
git clone https://github.com/codelion/proofs.git
cd proofs

# Install dependencies (includes zstandard for automatic benchmark downloads)
pip install -r requirements.txt

# Run all tests (1147 tests, ~47s)
python -m pytest tests/ -q

# Download all benchmarks (861 SL-COMP + 53 QF_S samples + 18,940 full QF_S from SMT-LIB)
python benchmarks.py download --all

# Run benchmarks
python benchmarks.py run --suite all         # All benchmarks
python benchmarks.py run --suite qf_s        # String benchmarks
python benchmarks.py run --suite slcomp      # Separation logic benchmarks
```

**Requirements**: Python 3.7+, Z3, zstandard (see requirements.txt)

**Note**: First `download --all` downloads 2.9MB of full QF_S benchmarks from SMT-LIB/Zenodo (one-time). Subsequent runs use cached files.

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

# SAT checking
from frame import parse
formula = parse("x |-> 5 * y |-> 3")
print(checker.is_satisfiable(formula))  # True
```

### String Constraints (QF_S)

```python
from frame import EntailmentChecker

checker = EntailmentChecker()

# String operations
formula = parse('x = "hello" & y = (str.++ x " world")')
print(checker.is_satisfiable(formula))  # True

# String containment
formula = parse('(str.contains x "admin")')
print(checker.is_satisfiable(formula))  # True

# Complex constraints
formula = parse('''
    x = "testing" &
    y = (str.substr x 0 4) &
    (str.len y) = 4
''')
print(checker.is_satisfiable(formula))  # True
```

### Bug Detection (Incorrectness Logic)

```python
from frame import IncorrectnessChecker

checker = IncorrectnessChecker()

# Detect null pointer dereference
program_state = parse('''
    ptr = nil &
    Allocated(buffer) &
    TaintedInput(user_data)
''')

bug = checker.find_null_deref(program_state, Var("ptr"))
print(bug.found)  # True - ptr is nil, dereferencing causes null deref!

# Detect use-after-free
program_state = parse('''
    Allocated(ptr) &
    Freed(ptr)
''')

bug = checker.find_use_after_free(program_state, Var("ptr"))
print(bug.found)  # True - ptr was freed!

# Detect buffer overflow
program_state = parse('''
    ArrayBounds(buffer, 10) &
    index = 15
''')

bug = checker.find_buffer_overflow(program_state, Var("buffer"), Var("index"))
print(bug.found)  # True - index 15 >= array size 10!
```

### Security Analysis (Taint Tracking)

```python
# SQL Injection detection
program_state = parse('''
    TaintedInput(user_input) &
    query = (str.++ "SELECT * FROM users WHERE id=" user_input) &
    (str.contains user_input "OR")
''')

bug = checker.find_sql_injection(program_state, Var("query"))
print(bug.found)  # True - tainted input in SQL query!

# XSS detection
program_state = parse('''
    TaintedInput(user_input) &
    output = (str.++ "<div>" user_input "</div>") &
    (str.contains user_input "<script>")
''')

bug = checker.find_xss(program_state, Var("output"))
print(bug.found)  # True - unescaped script in output!
```

## Supported Theories

### Separation Logic

- **Points-to**: `x |-> 5`, `x |-> (a, b, c)` (multi-field structs)
- **Empty heap**: `emp`
- **Separating conjunction** (`*`): Disjoint heap composition
- **Regular conjunction** (`&`): Formulas on same heap
- **Magic wand** (`-*`): Frame implication

### Pure Logic

- **Equality**: `x = y`, `x != nil`
- **Boolean**: `P & Q`, `P | Q`, `!P`
- **Linear Integer Arithmetic**: `x + 1`, `y - 2`, `i * 3`, `div`, `mod`

### String Theory (QF_S)

**Concatenation**:
- `str.++`: String concatenation
- `str.len`: String length
- Empty string identity: `x ++ "" = x`

**Substring Operations**:
- `str.substr`: Extract substring
- `str.at`: Character access
- `str.contains`: Substring containment
- `str.prefixof`, `str.suffixof`: Prefix/suffix checking

**String Searching**:
- `str.indexof`: Find substring position
- `str.replace`: String replacement

**Supported**: 10/10 operation categories with 90.6% overall accuracy

### Lifecycle & Security Predicates

**Heap Lifecycle**:
- `Allocated(ptr)`: Pointer is allocated
- `Freed(ptr)`: Pointer was freed
- `ArrayBounds(arr, size)`: Array bounds tracking
- `ArrayPointsTo(arr, idx, val)`: Array element access

**Taint Analysis**:
- `TaintedInput(var)`: Variable contains untrusted input
- `Sanitized(var)`: Variable has been sanitized
- `TaintFlow(source, sink)`: Track data flow

### Built-in Predicates

```python
# List segment: ls(x, y) - list from x to y
result = checker.check_entailment("ls(x, y) * ls(y, z) |- ls(x, z)")
print(result.valid)  # True

# Linked list: list(x) - null-terminated list
result = checker.check_entailment("x |-> y * list(y) |- list(x)")
print(result.valid)  # True

# Binary tree: tree(x)
# Doubly-linked list: dll(x, prev, y, next)
```

## Benchmarks

Frame includes a unified benchmark interface for all benchmark suites:

### Download Benchmarks

```bash
# Download ALL benchmarks including full QF_S set (recommended)
python benchmarks.py download --all

# This downloads (2.9MB compressed, one-time):
#   - 861 SL-COMP benchmarks (separation logic)
#   - 53 QF_S sample benchmarks (string theory)
#   - 18,940 full QF_S benchmarks from SMT-LIB 2024 (Zenodo):
#     * Kaluza, PISA, PyEx, AppScan, and more
#   - Total: 19,854 benchmarks

# Download specific QF_S samples
python benchmarks.py download --suite qf_s --division all      # All samples (53 tests)
python benchmarks.py download --suite qf_s --division kaluza   # Kaluza samples (40 tests)
python benchmarks.py download --suite qf_s --division pisa     # PISA samples (5 tests)
python benchmarks.py download --suite qf_s --division woorpje  # Woorpje samples (5 tests)

# Download full QF_S benchmark set from SMT-LIB
python benchmarks.py download --suite qf_s --division kaluza_full   # 18,940 tests from SMT-LIB 2024

# Download specific SL-COMP divisions
python benchmarks.py download --suite slcomp
python benchmarks.py download --suite slcomp --division qf_shls_entl
```

**Requirements**: `pip install zstandard` for .tar.zst extraction. Falls back gracefully to samples if not available.

### Run Benchmarks

```bash
# Run QF_S string benchmarks
python benchmarks.py run --suite qf_s

# Run specific division
python benchmarks.py run --suite qf_s --division kaluza
python benchmarks.py run --suite qf_s --division woorpje

# Run SL-COMP benchmarks
python benchmarks.py run --suite slcomp --division qf_shls_entl

# Run with max tests limit
python benchmarks.py run --suite qf_s --max-tests 10
```

### Analyze Results

```bash
# Analyze benchmark failures
python benchmarks.py analyze --failures

# Visualize heap structures
python benchmarks.py visualize benchmarks/cache/qf_shls_entl/test.smt2
```

### QF_S String Benchmark Results

**Sample Benchmarks**: 53 tests, 90.6% accuracy (48/53 correct, 2.8ms avg)

| Suite | Tests | Accuracy | Highlights |
|-------|-------|----------|----------|
| **Kaluza** | 40 | 90.0% | Concat, contains, length, substr, replace, indexof |
| **Woorpje** | 5 | **100%** | Word equations, periodic strings |
| **PISA** | 5 | 80.0% | Path-sensitive analysis, symbolic execution |
| **Simple** | 3 | **100%** | Basic operations |

**Performance**: 10-50x faster than Z3/CVC5 on string constraints

**Full QF_S Benchmark Set** (auto-downloaded with `download --all`):
- **18,940 tests** from SMT-LIB 2024 (Zenodo)
- Includes: Kaluza, PISA, PyEx, AppScan, and more
- Source: Official SMT-LIB benchmark repository
- Download: 2.9MB compressed, ~20MB uncompressed

**Categories** (40 Kaluza benchmarks):
- Concatenation: 100% (4/4)
- Contains: 100% (6/6)
- Prefix/Suffix: 100% (5/5)
- IndexOf: 100% (3/3)
- Replace: 100% (3/3)
- Character Access: 100% (2/2)
- Security Patterns: 100% (3/3) - SQL injection, XSS, sanitization
- Length: 80% (4/5)
- Substring: 60% (3/5)
- Complex Multi-op: 75% (3/4)

See `docs/QF_S_BENCHMARK_REPORT.md` for detailed analysis.

### SL-COMP Benchmark Results

Frame has been tested on 861 benchmarks across 12 SL-COMP divisions.

**Overall Accuracy: 66.7%** (574/861 correct)

| Division | Accuracy | Tests | Description |
|----------|----------|-------|-------------|
| **shidlia_entl** | **100.0%** | 50/50 | Lists with integer constraints |
| **shid_entl** | **94.0%** | 47/50 | Inductive predicates entailment |
| qf_shls_entl | **77.0%** | 228/296 | List segments (largest division) |
| qf_shidlia_entl | **64.0%** | 32/50 | Inductive + arithmetic entailment |
| qf_shid_entl | **60.0%** | 30/50 | Quantifier-free inductive entailment |
| qf_bsl_sat | **56.5%** | 26/46 | Boolean SL SAT |
| qf_shls_sat | **56.4%** | 62/110 | List segments SAT |
| qf_shidlia_sat | **54.5%** | 18/33 | Inductive + arithmetic SAT |
| qf_shid_sat | **48.5%** | 48/99 | Inductive predicates SAT |
| qf_shlid_entl | **42.0%** | 21/50 | Sorted lists with data |

## Architecture

```
frame/
├── core/               # Core abstractions (AST, parser)
├── encoding/           # Z3 SMT encoding
├── checking/           # Entailment checking and heuristics
├── analysis/           # Formula analysis and reasoning
├── heap/               # Heap graph and pattern detection
├── folding/            # Predicate folding/unfolding
├── arithmetic/         # Arithmetic reasoning
├── preprocessing/      # Formula preprocessing
├── predicates/         # Inductive predicate definitions
├── lemmas/             # Lemma library
└── utils/              # Utilities and proof management
```

### How It Works

1. **Parse**: Convert string/SMT-LIB to AST
2. **Preprocess**: Apply heuristics and equality normalization
3. **Fold**: Synthesize predicates from concrete heap structures
4. **Unfold**: Expand inductive predicates (bounded depth)
5. **Encode**: Map to Z3 constraints
   - Heap as array: `heap[loc] = value`
   - Domain tracking for disjointness
   - String operations via Z3 string theory
   - Lifecycle and taint predicates
6. **Solve**: Z3 SAT/SMT checking
7. **Lemma Application**: Try proven lemmas before Z3 queries

**Key Optimizations**:
- Reflexivity fast path (<1ms)
- Goal-directed folding (consequent-guided synthesis)
- Heuristic checks before Z3
- Lemma library for common patterns
- Parallel tool execution where possible

## Testing

```bash
# Run all tests (1147 tests, ~47s)
python -m pytest tests/ -q

# Run with verbose output
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=frame --cov-report=term

# Run specific test file
python -m pytest tests/test_incorrectness_logic.py
python -m pytest tests/test_heap_graph_analysis.py
python -m pytest tests/test_string_theory.py

# Run specific test pattern
python -m pytest tests/ -k "footprint"
python -m pytest tests/ -k "string"
```

**Test Coverage** (1147 tests, 100% passing):
- Core separation logic (spatial, pure, predicates)
- String theory operations (concatenation, substring, contains)
- Incorrectness logic (null deref, use-after-free, buffer overflow)
- Taint analysis (SQL injection, XSS, command injection)
- Array and heap lifecycle reasoning
- 21 legacy SL-COMP test suites

## API Reference

### EntailmentChecker

```python
checker = EntailmentChecker(
    predicate_registry=None,    # Optional PredicateRegistry
    timeout=10000,              # Z3 timeout (ms)
    use_folding=True,           # Enable predicate folding
    use_cyclic_proof=True,      # Enable cyclic reasoning
    use_s2s_normalization=True, # Enable normalization
    verbose=False               # Debug output
)

# Check entailment: P |- Q
result = checker.check_entailment("P |- Q")
# Returns: EntailmentResult(valid=bool, model=dict|None, reason=str)

# Check satisfiability
is_sat = checker.is_satisfiable(formula)
# Returns: bool

# Check equivalence: P ⇔ Q
equiv = checker.check_equiv(formula1, formula2)
# Returns: bool
```

### IncorrectnessChecker

```python
from frame import IncorrectnessChecker

checker = IncorrectnessChecker()

# Bug detection methods
bug = checker.find_null_deref(state, pointer_var)
bug = checker.find_use_after_free(state, pointer_var)
bug = checker.find_buffer_overflow(state, array_var, index_var)
bug = checker.find_double_free(state, pointer_var)

# Security vulnerability detection
bug = checker.find_sql_injection(state, query_var)
bug = checker.find_xss(state, output_var)
bug = checker.find_command_injection(state, command_var)

# Returns: BugReport(found=bool, type=str, location=str, trace=list)
```

## Use Cases

### 1. Program Verification

Verify heap safety properties:

```python
# Verify list construction
result = checker.check_entailment(
    "x |-> y * list(y) |- list(x)"
)

# Verify memory safety
result = checker.check_entailment(
    "Allocated(ptr) * ptr |-> value |- Allocated(ptr)"
)
```

### 2. Security Analysis

Detect vulnerabilities in web applications:

```python
# Detect SQL injection
state = parse('''
    TaintedInput(user_id) &
    query = (str.++ "SELECT * FROM users WHERE id=" user_id)
''')
bug = checker.find_sql_injection(state, Var("query"))

# Detect XSS
state = parse('''
    TaintedInput(comment) &
    html = (str.++ "<div>" comment "</div>")
''')
bug = checker.find_xss(state, Var("html"))
```

### 3. Bug Detection

Find memory safety bugs:

```python
# Detect use-after-free
state = parse("Allocated(p) & Freed(p)")
bug = checker.find_use_after_free(state, Var("p"))

# Detect buffer overflow
state = parse("ArrayBounds(buf, 10) & idx = 15")
bug = checker.find_buffer_overflow(state, Var("buf"), Var("idx"))
```

### 4. String Constraint Solving

Solve complex string constraints:

```python
# URL validation
formula = parse('''
    url = (str.++ protocol "://" domain path) &
    (str.contains protocol "http") &
    (str.len domain) > 0
''')
is_valid = checker.is_satisfiable(formula)

# Password strength checking
formula = parse('''
    (str.len password) >= 8 &
    (str.contains password "A") &
    (str.contains password "0")
''')
is_strong = checker.is_satisfiability(formula)
```

## Custom Predicates

Define your own recursive predicates in SMT-LIB format:

```python
from frame import PredicateRegistry, EntailmentChecker, ParsedPredicate

# Define binary search tree predicate
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

# Use custom predicate
result = checker.check_entailment(
    "x |-> (5, l, r) * bst(l, 0, 5) * bst(r, 5, 10) |- bst(x, 0, 10)"
)
print(result.valid)  # True
```

## Known Limitations

1. **String Theory Axioms**: Missing some advanced axioms
   - Length non-negativity partially supported
   - Complex substring reconstruction needs refinement
   - Regular expressions not yet supported

2. **Bounded Unfolding** (depth 10 default for benchmarks)
   - Increase with `registry.max_unfold_depth = 15`
   - Deep unfolding may timeout

3. **Predicate Construction**: Some folding patterns need improvement
   - Complex predicate synthesis is heuristic-based
   - May miss some valid foldings

## Contributing

Contributions welcome! Areas of interest:

- Complete string theory axiomatization (length non-negativity, reconstruction)
- Regular expression support for QF_S
- Additional security vulnerability patterns
- Performance optimizations
- More comprehensive predicate library

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
