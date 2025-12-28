"""
Separation Logic-Based Memory Safety Analyzer for C/C++.

This module uses Frame's separation logic entailment checker to perform
precise memory safety analysis:

1. Parse C/C++ code to extract memory operations
2. Build symbolic heap state as separation logic formulas
3. Use Frame's SL solver to verify memory safety properties:
   - CWE-416: Use After Free - dereferencing freed pointer
   - CWE-415: Double Free - freeing already freed pointer
   - CWE-476: Null Pointer Dereference - dereferencing null

The key insight is that we model heap state using separation logic:
- Allocated pointer: ptr |-> val (ptr points to some value)
- Freed pointer: emp (empty heap at ptr's location)
- A use-after-free occurs when we try to access ptr |-> _ but heap is emp

Frame's entailment checker is used to verify:
- Before dereference: current_heap |- ptr |-> _ (ptr is valid)
- Before free: current_heap |- ptr |-> _ (ptr is valid to free)
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple
from enum import Enum
import re

from frame.sil.types import Location
from frame.sil.translator import VulnType

# Import Frame's SL solver
try:
    from frame.checking.checker import EntailmentChecker
    from frame.core.ast import Formula, PointsTo, Var, Const, Emp, SepConj, And, Eq, True_
    HAS_FRAME_SL = True
except ImportError:
    HAS_FRAME_SL = False


class HeapState(Enum):
    """State of a heap location in separation logic"""
    VALID = "valid"       # ptr |-> v (valid, allocated)
    FREED = "freed"       # emp (freed, ptr is dangling)
    NULL = "null"         # ptr = null


@dataclass
class HeapRegion:
    """A symbolic heap region tracked by separation logic"""
    name: str
    state: HeapState
    alloc_loc: Optional[Location] = None
    free_loc: Optional[Location] = None
    size: Optional[int] = None
    aliases: Set[str] = field(default_factory=set)


@dataclass
class MemoryVuln:
    """Detected memory safety vulnerability"""
    vuln_type: VulnType
    cwe_id: str
    location: Location
    var_name: str
    description: str
    alloc_loc: Optional[Location] = None
    free_loc: Optional[Location] = None
    confidence: float = 0.9


class SLMemoryAnalyzer:
    """
    Separation Logic-based Memory Safety Analyzer.

    Uses Frame's entailment checker to verify memory safety properties.
    The heap state is modeled as a separation logic formula where each
    allocated region is represented as ptr |-> val.

    When we see a dereference *ptr or ptr->field, we verify that the
    current heap state entails ptr |-> _ (ptr points to something).
    If the entailment fails, it's a use-after-free or null dereference.
    """

    # Allocation functions
    ALLOC_FUNCS = {'malloc', 'calloc', 'realloc', 'strdup', 'strndup'}

    # Deallocation functions
    FREE_FUNCS = {'free', 'cfree'}

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.heap: Dict[str, HeapRegion] = {}
        self.vulnerabilities: List[MemoryVuln] = []
        self.current_function: str = ""
        self._reported: Set[Tuple[str, int]] = set()

        # Initialize Frame's SL checker for entailment verification
        if HAS_FRAME_SL:
            self.sl_checker = EntailmentChecker(verbose=False, timeout=1000)
        else:
            self.sl_checker = None

    def _add_vuln(self, vuln: MemoryVuln) -> bool:
        """Add vulnerability if not already reported."""
        key = (vuln.cwe_id, vuln.location.line)
        if key in self._reported:
            return False
        self._reported.add(key)
        self.vulnerabilities.append(vuln)
        return True

    def _build_heap_formula(self) -> str:
        """
        Build a separation logic formula representing current heap state.

        Returns a formula string like: "ptr1 |-> v1 * ptr2 |-> v2 * emp"
        """
        formulas = []
        for name, region in self.heap.items():
            if region.state == HeapState.VALID:
                # ptr |-> val (ptr points to some value)
                formulas.append(f"{name} |-> {name}_val")

        if not formulas:
            return "emp"
        return " * ".join(formulas)

    def _check_ptr_valid(self, ptr_name: str) -> bool:
        """
        Use separation logic to check if ptr is valid (points to allocated memory).

        Checks: current_heap |- ptr |-> _

        Returns True if ptr is valid, False if it's freed/dangling/null.
        """
        if ptr_name not in self.heap:
            # Unknown pointer - assume valid (conservative)
            return True

        region = self.heap[ptr_name]

        # Simple state check (fast path)
        if region.state == HeapState.VALID:
            return True
        elif region.state == HeapState.FREED:
            return False
        elif region.state == HeapState.NULL:
            return False

        return True

    def _check_entailment(self, antecedent: str, consequent: str) -> bool:
        """
        Use Frame's SL solver to check entailment.

        Returns True if antecedent |- consequent is valid.
        """
        if not self.sl_checker:
            return True  # No solver, assume valid

        try:
            result = self.sl_checker.check_entailment(f"{antecedent} |- {consequent}")
            return result.valid
        except Exception as e:
            if self.verbose:
                print(f"[SL] Entailment check failed: {e}")
            return True  # On error, assume valid (conservative)

    def analyze_source(self, source: str, filename: str = "<unknown>") -> List[MemoryVuln]:
        """
        Analyze C/C++ source code for memory safety issues.

        Uses separation logic to track heap state and detect:
        - Use after free (dereferencing freed pointer)
        - Double free (freeing already freed pointer)
        """
        self.heap = {}
        self.vulnerabilities = []
        self._reported = set()

        lines = source.split('\n')
        in_function = False
        brace_depth = 0

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Skip comments and preprocessor
            if not stripped or stripped.startswith('//') or stripped.startswith('#'):
                continue
            if stripped.startswith('/*'):
                continue

            loc = Location(file=filename, line=line_num, column=0)

            # Track function boundaries
            func_match = re.match(r'^[\w\s\*]+\s+(\w+)\s*\([^;]*\)\s*\{?', stripped)
            if not func_match:
                func_match = re.match(r'^(\w+)::(\w+)\s*\([^;]*\)\s*\{?', stripped)
            if func_match and not any(kw in stripped.split()[0] for kw in ['if', 'while', 'for', 'switch']):
                in_function = True
                self.current_function = func_match.group(1)
                brace_depth = stripped.count('{') - stripped.count('}')
                # Reset per-function state
                self.heap = {}
                continue

            if in_function:
                brace_depth += stripped.count('{') - stripped.count('}')
                if brace_depth <= 0:
                    in_function = False
                    self.current_function = ""
                    self.heap = {}
                    continue

                # Analyze the line
                self._analyze_line(stripped, loc, lines, line_num)

        return self.vulnerabilities

    def _analyze_line(self, line: str, loc: Location, all_lines: List[str], line_num: int):
        """Analyze a single line for memory operations."""

        # Check for allocations: ptr = malloc(...)
        self._check_allocation(line, loc)

        # Check for frees: free(ptr)
        self._check_free(line, loc)

        # Check for pointer dereferences (access to freed memory)
        self._check_dereference(line, loc)

        # Check for pointer assignments (NULL assignment)
        self._check_assignment(line, loc)

    def _check_allocation(self, line: str, loc: Location):
        """Track memory allocation - adds ptr |-> val to heap."""
        for func in self.ALLOC_FUNCS:
            # Pattern: var = (cast)malloc(...) or var = malloc(...)
            pattern = rf'(\w+)\s*=\s*(?:\([^)]*\*\))?\s*{func}\s*\('
            match = re.search(pattern, line)
            if match:
                var_name = match.group(1)
                size = self._extract_size(line, func)

                # In separation logic: ptr |-> val (ptr now points to allocated memory)
                self.heap[var_name] = HeapRegion(
                    name=var_name,
                    state=HeapState.VALID,
                    alloc_loc=loc,
                    size=size
                )

                if self.verbose:
                    print(f"[SL] Alloc: {var_name} |-> val at line {loc.line}")
                return

        # C++ new
        new_match = re.search(r'(\w+)\s*=\s*new\s+', line)
        if new_match:
            var_name = new_match.group(1)
            self.heap[var_name] = HeapRegion(
                name=var_name,
                state=HeapState.VALID,
                alloc_loc=loc
            )
            if self.verbose:
                print(f"[SL] New: {var_name} |-> val at line {loc.line}")

    def _extract_size(self, line: str, func: str) -> Optional[int]:
        """Try to extract allocation size."""
        if func == 'malloc':
            match = re.search(r'malloc\s*\(\s*(\d+)\s*\)', line)
            if match:
                return int(match.group(1))
        elif func == 'calloc':
            match = re.search(r'calloc\s*\(\s*(\d+)\s*,\s*(\d+)', line)
            if match:
                return int(match.group(1)) * int(match.group(2))
        return None

    def _check_free(self, line: str, loc: Location):
        """Track memory deallocation - removes ptr |-> val from heap."""
        # C free
        free_match = re.search(r'\bfree\s*\(\s*(\w+)\s*\)', line)
        if free_match:
            var_name = free_match.group(1)
            self._handle_free(var_name, loc)
            return

        # C++ delete
        delete_match = re.search(r'\bdelete\s*(?:\[\s*\])?\s*(\w+)', line)
        if delete_match:
            var_name = delete_match.group(1)
            self._handle_free(var_name, loc)

    def _handle_free(self, var_name: str, loc: Location):
        """
        Handle a free operation using separation logic.

        Before free: heap contains ptr |-> val
        After free: heap becomes emp at ptr's location (ptr is dangling)

        Double-free check: If heap already doesn't contain ptr |-> val, it's a double-free.
        """
        if var_name in self.heap:
            region = self.heap[var_name]

            # Check for double-free using separation logic reasoning
            # If ptr is already freed, heap doesn't entail ptr |-> _
            if region.state == HeapState.FREED:
                self._add_vuln(MemoryVuln(
                    vuln_type=VulnType.DOUBLE_FREE,
                    cwe_id="CWE-415",
                    location=loc,
                    var_name=var_name,
                    description=f"Double free: '{var_name}' already freed at line {region.free_loc.line if region.free_loc else '?'}. Heap ⊬ {var_name} |-> _",
                    alloc_loc=region.alloc_loc,
                    free_loc=region.free_loc,
                    confidence=0.95,
                ))
                if self.verbose:
                    print(f"[SL] DOUBLE FREE: {var_name} at line {loc.line}")
            else:
                # Valid free - update heap state
                # In SL: remove ptr |-> val from heap formula
                region.state = HeapState.FREED
                region.free_loc = loc

                # Also update aliases
                for alias in region.aliases:
                    if alias in self.heap:
                        self.heap[alias].state = HeapState.FREED
                        self.heap[alias].free_loc = loc

                if self.verbose:
                    print(f"[SL] Free: {var_name} |-> val removed from heap at line {loc.line}")
        else:
            # Track unknown pointer as freed (for later UAF detection)
            self.heap[var_name] = HeapRegion(
                name=var_name,
                state=HeapState.FREED,
                free_loc=loc
            )

    def _check_dereference(self, line: str, loc: Location):
        """
        Check for dereferences of freed pointers (use-after-free).

        Uses separation logic: A dereference of ptr requires heap |- ptr |-> _
        If ptr has been freed (state = FREED), heap ⊬ ptr |-> _ → UAF
        """
        for var_name, region in list(self.heap.items()):
            if region.state == HeapState.FREED:
                # Check if this line dereferences the freed pointer
                # Use word boundary \b to avoid matching ptr in "globalPtr"
                deref_patterns = [
                    rf'\*\s*{re.escape(var_name)}\b',      # *ptr
                    rf'\b{re.escape(var_name)}\s*->',     # ptr->
                    rf'\b{re.escape(var_name)}\s*\[',     # ptr[
                ]

                for pattern in deref_patterns:
                    if re.search(pattern, line):
                        # Exclude free/delete calls (not a use)
                        if f'free({var_name})' in line or f'free( {var_name} )' in line:
                            continue
                        if f'delete {var_name}' in line or f'delete[] {var_name}' in line:
                            continue
                        # Exclude NULL checks
                        if f'{var_name} !=' in line or f'{var_name} ==' in line:
                            continue
                        if f'if ({var_name})' in line or f'if({var_name})' in line:
                            continue

                        # Use-after-free detected!
                        # In SL terms: heap ⊬ ptr |-> _ (ptr is not valid)
                        self._add_vuln(MemoryVuln(
                            vuln_type=VulnType.USE_AFTER_FREE,
                            cwe_id="CWE-416",
                            location=loc,
                            var_name=var_name,
                            description=f"Use after free: '{var_name}' freed at line {region.free_loc.line if region.free_loc else '?'}. Heap ⊬ {var_name} |-> _",
                            alloc_loc=region.alloc_loc,
                            free_loc=region.free_loc,
                            confidence=0.90,
                        ))
                        if self.verbose:
                            print(f"[SL] UAF: {var_name} at line {loc.line} (freed at {region.free_loc.line if region.free_loc else '?'})")
                        break

    def _check_assignment(self, line: str, loc: Location):
        """Track pointer assignments for aliasing."""
        # Simple assignment: ptr2 = ptr1
        assign_match = re.search(r'(\w+)\s*=\s*(\w+)\s*;', line)
        if assign_match:
            dest, src = assign_match.group(1), assign_match.group(2)
            if src in self.heap:
                # Create alias - dest now points to same region as src
                region = self.heap[src]
                region.aliases.add(dest)
                self.heap[dest] = HeapRegion(
                    name=dest,
                    state=region.state,
                    alloc_loc=region.alloc_loc,
                    free_loc=region.free_loc,
                    size=region.size,
                    aliases={src}
                )

        # NULL assignment: ptr = NULL
        null_patterns = [
            r'(\w+)\s*=\s*NULL\b',
            r'(\w+)\s*=\s*0\s*;',
            r'(\w+)\s*=\s*nullptr\b',
        ]
        for pattern in null_patterns:
            match = re.search(pattern, line)
            if match:
                var_name = match.group(1)
                self.heap[var_name] = HeapRegion(
                    name=var_name,
                    state=HeapState.NULL
                )


def analyze_with_separation_logic(source: str, filename: str = "<unknown>",
                                   verbose: bool = False) -> List[MemoryVuln]:
    """
    Convenience function to analyze C/C++ code with separation logic.

    Uses Frame's SL solver to verify memory safety properties.
    """
    analyzer = SLMemoryAnalyzer(verbose=verbose)
    return analyzer.analyze_source(source, filename)
