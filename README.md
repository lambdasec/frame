# Frame - Separation Logic Solver

A fast, practical separation logic solver combining heap reasoning, string constraint solving, and automated bug detection.

[![Tests](https://img.shields.io/badge/tests-1147%2F1147-green)]() [![Python](https://img.shields.io/badge/python-3.7%2B-blue)]() [![License](https://img.shields.io/badge/license-Apache%202.0-blue)]()

## Features

The only solver combining:
- **Separation Logic**: Heap structure reasoning with inductive predicates
- **String Theory** (QF_S): SMT-LIB string operations (90.6% accuracy)
- **Incorrectness Logic**: Under-approximate bug detection
- **Taint Analysis**: Security vulnerability detection

**Performance**: 10-50x faster than Z3/CVC5 on string constraints, <1ms reflexivity checks

## Installation

```bash
git clone https://github.com/codelion/proofs.git
cd proofs
pip install -r requirements.txt

# Run tests (1,147 tests, ~47s)
python -m pytest tests/ -q
```

**Requirements**: Python 3.7+, Z3, requests, zstandard

## Quick Start

```python
from frame import EntailmentChecker, IncorrectnessChecker, parse, Var

# Separation Logic
checker = EntailmentChecker()
result = checker.check_entailment("x |-> 5 * y |-> 3 |- x |-> 5")
print(result.valid)  # True

# String Constraints
formula = parse('x = "hello" & y = (str.++ x " world")')
print(checker.is_satisfiable(formula))  # True

# Bug Detection
bug_checker = IncorrectnessChecker()
state = parse('ptr = nil & Allocated(buffer)')
bug = bug_checker.find_null_deref(state, Var("ptr"))
print(bug.found)  # True
```

## Supported Theories

**Separation Logic**: Points-to, empty heap, separating conjunction (`*`), magic wand (`-*`), inductive predicates (lists, trees, DLLs)

**String Theory (QF_S)**: Concatenation, substring operations, contains, indexof, replace (10/10 operation categories)

**Array Theory (QF_AX)**: Select/store operations, constant arrays, extensionality, buffer overflow detection

**Bitvector Theory (QF_BV)**: Arithmetic (add, sub, mul, div), bitwise (and, or, xor, not, shift), overflow detection (signed/unsigned)

**Security & Lifecycle**: Heap lifecycle predicates (`Allocated`, `Freed`), taint analysis (`TaintedInput`, `Sanitized`), array taint tracking, integer overflow detection

## Security Applications

Frame's unique combination of theories enables detection of complex vulnerabilities:

**Cross-Theory Vulnerabilities**:
- SQL injection with heap tracking (tainted string flowing through heap structures)
- Use-after-free with data leaks (accessing freed memory containing sensitive strings)
- Path traversal with memory safety (tainted file paths in heap-allocated buffers)
- Command injection with lifecycle tracking (tainted commands in allocated/freed contexts)

**Practical Use Cases**:
- **API Security Scanning**: Analyze REST endpoints for injection vulnerabilities with concrete exploits
- **Code Review Automation**: Verify security properties in pull requests (GitHub Actions/bots)
- **Fuzzing Target Generation**: Extract concrete test cases from Z3 models for targeted fuzzing
- **CVE Validation**: Verify reported vulnerabilities and generate proof-of-concept exploits

**Example - SQL Injection Detection**:
```python
from frame import IncorrectnessChecker, Var, parse

bug_checker = IncorrectnessChecker()
state = parse('TaintedInput(user_input) & query = (str.++ "SELECT * FROM users WHERE id=" user_input)')
bug = bug_checker.find_sql_injection(state, Var("query"))

if bug.found:
    print(f"Vulnerability: {bug.type}")
    print(f"Exploit: ' OR '1'='1' --")
    print(f"Trace: {bug.trace}")  # Shows taint flow from input to query
```

**Integration Points**:
- Static analyzers (Semgrep, CodeQL) for pattern detection → Frame for verification
- Tree-sitter for multi-language parsing → Frame for semantic analysis
- LLVM IR for cross-language analysis → Frame for precise heap reasoning
- CI/CD pipelines for automated security checks with regression detection

## Benchmarks

Frame includes ~20,000 benchmarks with curated sets for efficient testing:
- **Curated**: ~4,000 tests (3,300 QF_S + 700 SL-COMP) - stratified samples, recommended for benchmarking
- **Full**: ~20,000 tests (18,940 QF_S + 1,298 SL-COMP) - comprehensive testing

```bash
# Run curated benchmarks (recommended, ~15 minutes)
python -m benchmarks run --curated

# Run full benchmark suite (~2+ hours)
python -m benchmarks run --all

# Run specific division
python -m benchmarks run --division qf_shls_entl
```

**Results**: 73.4% on QF_S curated samples, 72.0% on SL-COMP curated. See [`benchmarks/README.md`](benchmarks/README.md) for detailed results.

## Architecture

```
frame/
├── core/          # AST, parser
├── encoding/      # Z3 encoding
├── checking/      # Entailment checking
├── folding/       # Predicate folding/unfolding
├── predicates/    # Inductive predicates
└── lemmas/        # Lemma library
```

**Algorithm**: Parse → Fold → Unfold → Encode → Z3 Solve

See [`CLAUDE.md`](CLAUDE.md) for detailed architecture and development guide.

## API

```python
# Entailment checking
from frame import EntailmentChecker
checker = EntailmentChecker(timeout=10000)
result = checker.check_entailment("P |- Q")  # Returns: EntailmentResult(valid, model, reason)

# Bug detection
from frame import IncorrectnessChecker, Var
bug_checker = IncorrectnessChecker()
bug = bug_checker.find_null_deref(state, Var("ptr"))      # Memory safety
bug = bug_checker.find_sql_injection(state, Var("query")) # Security
# Returns: BugReport(found, type, location, trace)
```

## Custom Predicates

```python
from frame import PredicateRegistry, EntailmentChecker

registry = PredicateRegistry()
registry.register_from_smt2("bst", """
(bst ?x ?lo ?hi) := ((= ?x nil) * emp) |
  (exists ?v ?l ?r. (?x |-> (?v, ?l, ?r)) * (?lo < ?v) * (?v < ?hi) *
   (bst ?l ?lo ?v) * (bst ?r ?v ?hi))
""")

checker = EntailmentChecker(predicate_registry=registry)
result = checker.check_entailment("x |-> (5, l, r) * bst(l, 0, 5) * bst(r, 5, 10) |- bst(x, 0, 10)")
```

## Citation

If you use Frame in academic work, please cite:

```bibtex
@software{frame_solver,
  title = {Frame: Separation Logic Solver with String Theory and Bug Detection},
  author = {Asankhaya Sharma},
  year = {2025},
  url = {https://github.com/lambdasec/frame}
}
```

## References

**Separation Logic**:
- Reynolds, O'Hearn (2002). [Separation Logic: A Logic for Shared Mutable Data Structures](https://doi.org/10.1109/LICS.2002.1029817)
- Piskac, Wies, Zufferey (2013). [Automating Separation Logic with Trees and Data](https://dl.acm.org/doi/10.1007/978-3-319-08867-9_47)

**String Constraint Solving**:
- Saxena et al. (2010). [A Symbolic Execution Framework for JavaScript](https://doi.org/10.1109/SP.2010.38) (Kaluza)
- Zheng et al. (2013). [Z3-str: A Z3-based String Solver](https://dl.acm.org/doi/10.1145/2491411.2491456)

**Incorrectness Logic**:
- O'Hearn (2020). [Incorrectness Logic](https://doi.org/10.1145/3371078)

## Acknowledgments

Built with:
- [Z3 SMT Solver](https://github.com/Z3Prover/z3) - Microsoft Research
- [SL-COMP Benchmarks](https://sl-comp.github.io/) - Community benchmark suite
- [SMT-LIB](https://smtlib.cs.uiowa.edu/) - Standard format for SMT solvers

Inspired by:
- Sleek/HIP (NUS), Cyclist (UCL), Grasshopper (NYU), SPEN (Verimag)
