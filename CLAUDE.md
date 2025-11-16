# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Frame is a separation logic entailment checker that uses Z3 SMT solver to verify entailments of the form `P |- Q`. The system supports:
- Core separation logic: empty heap (`emp`), points-to (`x |-> y`), separating conjunction (`*`)
- Pure formulas: equality, boolean logic, arithmetic
- Inductive predicates: lists, trees, custom data structures
- Frame reasoning with automatic inference

## Commands

### Testing
```bash
# Run all tests (553 tests: 532 pytest + 21 legacy suites)
python -m pytest tests/

# Run with verbose output
python -m pytest tests/ -v

# Run with coverage report
python -m pytest tests/ --cov=frame --cov-report=term

# Run specific test file
python -m pytest tests/test_footprint_analysis.py
python -m pytest tests/test_heap_graph_analysis.py

# Run specific legacy suite (all SL-COMP tests, old test files)
python -m pytest tests/test_legacy_suites.py -v

# Run tests matching a pattern
python -m pytest tests/ -k "footprint"
python -m pytest tests/ -k "slcomp"

# Run quietly (suppress warnings)
python -m pytest tests/ -q -W ignore::pytest.PytestCollectionWarning
```

### Benchmarking
```bash
# Run SL-COMP benchmarks
python benchmarks/run_slcomp.py

# Analyze failures
python benchmarks/analyze_failures.py

# Visualize heap structures
python benchmarks/visualize_heap.py
```

### Development
```bash
# Install dependencies
pip install -r requirements.txt

# Run specific test cases interactively
python -c "from frame import EntailmentChecker; checker = EntailmentChecker(); print(checker.check_entailment('x |-> 5 * y |-> 3 |- x |-> 5'))"
```

## Architecture

The codebase is organized into logical modules for better maintainability:

```
frame/
├── core/           # Core abstractions (AST, parser)
├── encoding/       # Z3 SMT encoding
├── checking/       # Entailment checking and heuristics
├── analysis/       # Formula analysis and reasoning
├── heap/           # Heap graph and pattern detection
├── folding/        # Predicate folding/unfolding
├── arithmetic/     # Arithmetic reasoning
├── preprocessing/  # Formula preprocessing
├── predicates/     # Inductive predicate definitions
├── lemmas/         # Lemma library
└── utils/          # Utilities and proof management
```

### Core Components

**frame/core/ast.py** - Abstract Syntax Tree
- Defines all formula types: `Expr`, `Formula`, `Var`, `Const`, `ArithExpr`
- Spatial formulas: `Emp`, `PointsTo`, `SepConj`, `Wand`
- Pure formulas: `And`, `Or`, `Not`, `Eq`, `Neq`, `True_`, `False_`
- Quantifiers: `Exists`, `Forall`
- Predicate calls: `PredicateCall`

**frame/core/parser.py** - Parser
- Converts string formulas to AST
- Two-stage: Lexer tokenizes, Parser builds AST
- Supports entailment syntax: `"P |- Q"` for parsing both sides
- Handles precedence: quantifiers > disjunction > conjunction > separating conjunction

**frame/encoding/encoder.py** - Z3 Encoding
- Encodes separation logic formulas to Z3 SMT constraints
- Heap represented as Z3 array from locations to values
- Explicit domain tracking for allocated locations
- Key methods:
  - `encode_expr()`: Converts AST expressions to Z3
  - `encode_heap_assertion()`: Encodes spatial formulas with disjointness
  - `encode_pure()`: Encodes pure boolean/arithmetic constraints
- Delegates spatial encoding to `frame/encoding/_spatial.py`

**frame/checking/checker.py** - Entailment Checker
- Main interface: `EntailmentChecker` class
- Algorithm:
  1. Parse formulas to AST
  2. Unfold predicates (bounded, depth 3 default)
  3. Encode to Z3 with heap + domain tracking
  4. Check validity: `P |- Q` is valid if `P & !Q` is unsat
- Fast paths:
  - Reflexivity check (syntactic equality)
  - Heuristic checks before Z3 (via `frame/checking/heuristics.py`)
- Adaptive unfolding based on formula complexity
- Returns `EntailmentResult` with validity, model, and reason

**frame/predicates/** - Inductive Predicates
- `base.py`: `InductivePredicate` abstract base class
- `registry.py`: `PredicateRegistry` manages available predicates
- Built-in predicates:
  - `ListSegment`: `ls(x, y)` - list segment from x to y
  - `LinkedList`: `list(x)` - null-terminated list
  - `Tree`: `tree(x)` - binary tree
  - `DoublyLinkedList`: `dll(x, p, y, n)` - doubly-linked list
- `PredicateValidator`: Checks soundness (strict positivity, free variables, arity)
- `GenericPredicate`: Creates predicates from SMT2 definitions

**frame/lemmas/** - Lemma Library
- `base.py`: Core lemma library with pattern matching and application
- `_matcher.py`: Pattern matching for lemma application (meta-variables)
- `_substitution.py`: Substitution and equality normalization
- Proven lemmas for common predicates (e.g., list segment transitivity)
- Used to prove entailments without unfolding
- Key lemmas:
  - `ls_transitivity`: `ls(x,y) * ls(y,z) |- ls(x,z)`
  - `ls_cons`: `x |-> y * ls(y,z) |- ls(x,z)`
  - `ls_empty`: `ls(x,x) |- emp`

### Data Flow

1. **String Input** → Parser → AST
2. **AST** → Predicate Unfolding (recursive, bounded depth)
3. **Unfolded AST** → Z3 Encoder → SMT Constraints
4. **SMT Constraints** → Z3 Solver → SAT/UNSAT
5. **SAT/UNSAT** → EntailmentResult (valid/invalid + model/reason)

### Key Design Decisions

**Theoretical Foundation**: Frame implements separation logic (Reynolds & O'Hearn, 2002) using SMT-based reasoning with Z3. The core technique is the heap-as-array encoding (Piskac, Wies, Zufferey, 2013), which reduces separation logic entailments to first-order logic queries. See README.md "Theoretical Foundations" section for detailed references and comparison with other solvers (Sleek, Cyclist, Grasshopper, SPEN).

**Heap Representation**: Heap is a Z3 array `heap: Loc -> Val`. Domain is tracked as a set of locations. Disjointness enforced by ensuring domains don't overlap in separating conjunction.

**Predicate Unfolding**: Bounded unfolding (default depth 3) to maintain decidability. Deeper unfolding increases completeness but may hit recursion limits or timeouts. Adaptive unfolding adjusts depth based on formula size.

**Predicate Folding**: Goal-directed folding prioritizes proposals that match the consequent (inspired by Cyclist's cyclic proof techniques but adapted for SMT). Blind folding provides a fallback for general synthesis.

**Lemma Library**: Pattern-based lemma application (similar to Sleek's strategy) handles common entailments without Z3 queries. Proven lemmas for transitivity, reflexivity, and construction patterns.

**Soundness**: All predicates validated for strict positivity (no negation), free variables properly bound, and arity consistency. Parser bug fixed in commit d239d01 - critical fix for storing body text correctly.

**Performance**: Fast paths for reflexivity (<1ms), syntactic checks before Z3. Average 5ms per check on test suite.

## Critical Implementation Notes

### Parser Bug Fix (d239d01)
The parser had a critical bug where it was storing the Formula object instead of the body text when parsing SMT2 predicates. This caused recursive predicate definitions to fail. Always store `body_text` as string, not Formula object.

### Recursion Handling (2233a73)
Predicates with deep recursion can hit Python's recursion limit. The checker now handles `RecursionError` gracefully by returning `unknown` instead of crashing. Consider increasing unfold depth carefully.

### PTO Syntax (3ba90de)
The parser handles SMT2 syntax `(as nil Type)` in struct fields for points-to assertions. This is essential for SL-COMP benchmarks where nil values are typed.

### Wand Implementation
Magic wand (`P -* Q`) is NOT commutative unlike other binary connectives. Handle carefully in syntactic equality checks and encoding.

### Separation of Concerns: Lemmas vs Folding (Critical Architecture)

**IMPORTANT**: Lemmas and folding serve fundamentally different purposes and must NEVER be mixed:

**Lemmas** (`frame/lemmas/`):
- Proven facts about predicates (e.g., `ls(x,y) * ls(y,z) |- ls(x,z)`)
- Apply to predicate calls that already exist in the formula
- Pattern matching against existing structure
- Fast, deterministic application
- Located in `frame/lemmas/base.py` and category files

**Folding** (`frame/folding/`):
- SYNTHESIS of predicates from concrete heap structures
- Converts points-to assertions into predicate calls
- Graph-based pattern detection and proposal generation
- Heuristic, confidence-based selection
- Located in `frame/folding/goal_directed.py` for entailment checking

**Checker Integration Order** (`frame/checking/checker.py`):
1. Goal-directed folding: `fold_towards_goal()` - synthesizes predicates matching consequent
2. Lemma application: `try_apply_lemma()` - applies proven facts about existing predicates

**Why This Separation Matters**:
- Previously, Phase 3 folding was embedded in `LemmaLibrary.try_apply_lemma()`, violating separation of concerns
- This made lemmas responsible for both pattern matching AND synthesis
- Caused confusion about what lemmas should do
- Made the codebase harder to maintain and extend
- The refactoring in November 2025 properly separated these concerns

**When implementing new features**:
- Proven predicate transformations → Add to lemmas
- Heap pattern synthesis → Add to folding module
- Never add folding logic to lemma library
- Never add lemma-style pattern matching to folding (use graph patterns instead)

### Z3 Timeout
Default timeout is 5000ms. Increase for complex benchmarks or decrease for faster feedback. Benchmarks use 10000ms timeout.

## Testing Strategy

**Test Organization**:
- `test_basic.py`: Core spatial formulas and entailments
- `test_frame_rule.py`: Frame reasoning tests
- `test_pure_reasoning.py`: Pure formula logic
- `test_predicates.py`: Predicate registration and validation
- `test_lists.py`: List predicate entailments
- `test_trees.py`: Tree predicate entailments
- `test_negative.py`: Invalid entailments (should fail)
- `test_edge_cases.py`: Corner cases and error handling
- `test_parser_regressions.py`: Parser bug regressions

**Test Pattern**:
```python
def test_something():
    checker = EntailmentChecker()
    result = checker.check_entailment("P |- Q")
    assert result.valid  # or assert not result.valid for negative tests
```

## Benchmarking

SL-COMP benchmarks test against industry-standard separation logic problems. Key divisions:
- `qf_shls_entl`: List segments with entailments
- Results tracked in `docs/archive/` for performance comparison

## Common Issues

**Unfold Depth Too Low**: If entailment should be valid but returns invalid, try increasing `registry.max_unfold_depth`. Symptoms: predicates need deeper unfolding to match.

**Timeout**: Complex formulas may timeout. Increase `timeout` parameter or simplify formula. Check if predicate definitions are efficient.

**Parser Errors**: Ensure formulas use correct syntax. Check `frame/core/parser.py` for supported grammar. Common issues: missing parentheses, wrong operator precedence.

**Predicate Validation**: Custom predicates must pass soundness checks. If validation fails, review strict positivity, free variables, and arity consistency.

## Module Organization (November 2025 Refactoring)

The codebase was reorganized into logical modules to improve maintainability and discoverability:

### Module Structure

**frame/core/** - Core abstractions
- `ast.py` (431 lines): Formula AST definitions
- `parser.py` (417 lines): String to AST parser

**frame/encoding/** - Z3 SMT encoding  
- `encoder.py` (368 lines): Main Z3 encoder
- `_spatial.py` (273 lines): Spatial formula encoding (internal helper)

**frame/checking/** - Entailment checking
- `checker.py` (483 lines): Main entailment checker
- `heuristics.py` (253 lines): Fast heuristic checks
- `_ls_heuristics.py` (290 lines): List segment heuristics (internal helper)

**frame/analysis/** - Formula analysis
- `formula.py` (167 lines): Formula structure analysis
- `unification.py` (339 lines): Unification algorithm
- `predicate_matching.py` (303 lines): Predicate pattern matching
- `footprint.py` (334 lines): Footprint analysis

**frame/heap/** - Heap reasoning
- `graph.py` (386 lines): HeapGraph class
- `graph_analysis.py` (277 lines): Graph pattern detection
- `_fold_proposals.py` (195 lines): Fold proposal generation (internal helper)

**frame/folding/** - Predicate folding/unfolding
- `blind.py` (280 lines): Blind/iterative folding (renamed from driver.py)
- `goal_directed.py` (203 lines): Goal-directed folding (synthesis guided by consequent)
- `verify.py` (287 lines): Fold verification
- `apply.py` (171 lines): Apply folding transformations
- `cyclic_unfold.py` (246 lines): Cyclic unfolding handling

**frame/arithmetic/** - Arithmetic reasoning
- `check.py` (213 lines): Arithmetic constraint checking
- `synth.py` (294 lines): Arithmetic synthesis

**frame/preprocessing/** - Formula preprocessing
- `equality.py` (310 lines): Equality preprocessing

**frame/predicates/** - Inductive predicates (unchanged)
- Well-organized predicate definitions for lists, trees, DLLs, etc.

**frame/lemmas/** - Lemma library (enhanced)
- `base.py` (237 lines): Core lemma library
- `_matcher.py` (249 lines): Pattern matching (internal helper)
- `_substitution.py` (245 lines): Substitution operations (internal helper)
- `list_lemmas.py`, `dll_lemmas.py`, `other_lemmas.py`: Specific lemmas

**frame/utils/** - Utilities
- `proof_state.py` (168 lines): Proof state management
- `satisfiability.py` (249 lines): Satisfiability checking
- `frame_rule.py` (181 lines): Frame rule utilities
- `formula_utils.py` (80 lines): Formula utility functions (spatial/pure extraction)

### Import Conventions

**Public API** (backward compatible):
```python
from frame import EntailmentChecker, Formula, PointsTo, SepConj
```

**Direct module imports** (new paths):
```python
from frame.core.ast import Formula, PointsTo
from frame.core.parser import parse
from frame.checking.checker import EntailmentChecker
from frame.encoding.encoder import Z3Encoder
```

**Internal helpers** (prefixed with `_`):
- `frame/encoding/_spatial.py`
- `frame/checking/_ls_heuristics.py`
- `frame/heap/_fold_proposals.py`
- `frame/lemmas/_matcher.py`
- `frame/lemmas/_substitution.py`

These are internal implementation details and should not be imported directly by external code.

### Benefits

- **Better discoverability**: Related functionality is co-located
- **Clear boundaries**: Each module has a focused responsibility
- **Room to grow**: Modules can expand without cluttering the root
- **Professional structure**: Matches organization of mature Python projects
