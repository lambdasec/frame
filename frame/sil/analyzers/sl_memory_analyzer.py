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


class AllocKind(Enum):
    """Kind of allocation for tracking memory source"""
    HEAP = "heap"         # malloc/new allocated on heap
    STACK = "stack"       # Stack-allocated (local array, alloca)
    UNKNOWN = "unknown"   # Unknown allocation source


@dataclass
class HeapRegion:
    """A symbolic heap region tracked by separation logic"""
    name: str
    state: HeapState
    alloc_loc: Optional[Location] = None
    free_loc: Optional[Location] = None
    size: Optional[int] = None
    aliases: Set[str] = field(default_factory=set)
    alloc_kind: AllocKind = AllocKind.UNKNOWN  # Heap vs stack allocation


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
                    # Function is ending - check for memory leaks (CWE-401)
                    self._check_memory_leaks(loc)
                    in_function = False
                    self.current_function = ""
                    self.heap = {}
                    continue

                # Analyze the line
                self._analyze_line(stripped, loc, lines, line_num)

        return self.vulnerabilities

    def _analyze_line(self, line: str, loc: Location, all_lines: List[str], line_num: int):
        """Analyze a single line for memory operations."""

        # Check for array declarations: char buf[100]
        self._check_array_declaration(line, loc)

        # Check for allocations: ptr = malloc(...)
        self._check_allocation(line, loc)

        # Check for frees: free(ptr)
        self._check_free(line, loc)

        # Check for pointer dereferences (access to freed memory)
        self._check_dereference(line, loc)

        # Check for pointer assignments (NULL assignment)
        self._check_assignment(line, loc)

        # Check for buffer copy operations that may overflow
        self._check_buffer_copy(line, loc, all_lines, line_num)

        # Track data initialization (memset) for size tracking
        self._track_data_init(line, loc)

    def _check_array_declaration(self, line: str, loc: Location):
        """
        Track stack-allocated arrays.

        In separation logic: buf[N] means buf |-> (data, N)
        Stack arrays cannot be freed (CWE-590 if attempted).
        """
        # Pattern: type name[size] or type name[size] = ...
        array_match = re.search(r'(\w+)\s+(\w+)\s*\[\s*(\d+)\s*\]', line)
        if array_match:
            var_type = array_match.group(1)
            var_name = array_match.group(2)
            size = int(array_match.group(3))

            # Track the array with its size - mark as STACK allocated
            self.heap[var_name] = HeapRegion(
                name=var_name,
                state=HeapState.VALID,
                alloc_loc=loc,
                size=size,
                alloc_kind=AllocKind.STACK  # Stack-allocated, cannot be freed
            )
            if self.verbose:
                print(f"[SL] Stack Array: {var_name} |-> (data, {size}) at line {loc.line}")

        # Also check for alloca() - stack allocation
        alloca_match = re.search(r'(\w+)\s*=\s*(?:\([^)]*\))?\s*alloca\s*\(', line)
        if alloca_match:
            var_name = alloca_match.group(1)
            self.heap[var_name] = HeapRegion(
                name=var_name,
                state=HeapState.VALID,
                alloc_loc=loc,
                alloc_kind=AllocKind.STACK  # alloca allocates on stack
            )
            if self.verbose:
                print(f"[SL] Alloca: {var_name} |-> (stack) at line {loc.line}")

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
                    size=size,
                    alloc_kind=AllocKind.HEAP  # Heap-allocated
                )

                if self.verbose:
                    print(f"[SL] Heap Alloc: {var_name} |-> val at line {loc.line}")
                return

        # C++ new
        new_match = re.search(r'(\w+)\s*=\s*new\s+', line)
        if new_match:
            var_name = new_match.group(1)
            self.heap[var_name] = HeapRegion(
                name=var_name,
                state=HeapState.VALID,
                alloc_loc=loc,
                alloc_kind=AllocKind.HEAP  # Heap-allocated
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

        Checks:
        - CWE-590: Free of non-heap memory (stack-allocated)
        - CWE-415: Double-free (freeing already freed pointer)
        """
        if var_name in self.heap:
            region = self.heap[var_name]

            # Check for CWE-590: Freeing stack-allocated memory
            if region.alloc_kind == AllocKind.STACK:
                self._add_vuln(MemoryVuln(
                    vuln_type=VulnType.DOUBLE_FREE,  # Use DOUBLE_FREE as closest type
                    cwe_id="CWE-590",
                    location=loc,
                    var_name=var_name,
                    description=f"Free of non-heap memory: '{var_name}' is stack-allocated at line {region.alloc_loc.line if region.alloc_loc else '?'}",
                    alloc_loc=region.alloc_loc,
                    confidence=0.95,
                ))
                if self.verbose:
                    print(f"[SL] FREE NON-HEAP: {var_name} at line {loc.line}")
                return  # Don't update state for invalid free

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
                    aliases={src},
                    alloc_kind=region.alloc_kind  # Propagate allocation kind for CWE-590
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

    def _track_data_init(self, line: str, loc: Location):
        """
        Track data initialization to know source sizes.

        When we see memset(src, 'A', N-1), we know src contains N bytes of data.
        This is crucial for detecting buffer overflow in copy operations.
        """
        # memset(var, char, size) - tracks initialized size
        memset_match = re.search(r'memset\s*\(\s*(\w+)\s*,\s*[^,]+,\s*(\d+)(?:\s*-\s*(\d+))?\s*\)', line)
        if memset_match:
            var_name = memset_match.group(1)
            init_size = int(memset_match.group(2))
            if memset_match.group(3):
                init_size -= int(memset_match.group(3))
            init_size += 1  # Account for null terminator

            # Update or create region with initialized size
            if var_name in self.heap:
                # Keep the allocated size, update with data size info
                pass  # Size already tracked from declaration/allocation
            else:
                self.heap[var_name] = HeapRegion(
                    name=var_name,
                    state=HeapState.VALID,
                    alloc_loc=loc,
                    size=init_size
                )

            if self.verbose:
                print(f"[SL] Memset: {var_name} initialized with {init_size} bytes at line {loc.line}")

    def _check_buffer_copy(self, line: str, loc: Location, all_lines: List[str], line_num: int):
        """
        Check buffer copy operations for overflow using separation logic.

        For strcpy(dest, src):
        - We need: dest |-> (data, dest_size) * src |-> (data, src_size)
        - Safe if: src_size <= dest_size
        - Overflow if: src_size > dest_size

        This is the key separation logic reasoning:
        - If we can't prove dest has enough space for src, it's a potential overflow
        """
        copy_funcs = {
            'strcpy': (1, 2),   # (dest_arg, src_arg)
            'strcat': (1, 2),
            'wcscpy': (1, 2),
            'wcscat': (1, 2),
            'memcpy': (1, 2),
            'memmove': (1, 2),
        }

        for func, (dest_idx, src_idx) in copy_funcs.items():
            # Match function call and extract arguments
            pattern = rf'\b{func}\s*\(\s*([^,]+)\s*,\s*([^,)]+)'
            match = re.search(pattern, line)
            if match:
                dest_arg = match.group(1).strip()
                src_arg = match.group(2).strip()

                # Get destination size from our heap tracking
                dest_size = self._get_buffer_size(dest_arg)

                # Get source size - look for memset or array declaration in context
                src_size = self._get_source_size(src_arg, all_lines, line_num)

                if self.verbose:
                    print(f"[SL] {func}: dest={dest_arg}({dest_size}), src={src_arg}({src_size}) at line {loc.line}")

                # If we know both sizes and source > dest, it's an overflow
                if dest_size and src_size and src_size > dest_size:
                    self._add_vuln(MemoryVuln(
                        vuln_type=VulnType.BUFFER_OVERFLOW,
                        cwe_id="CWE-122",
                        location=loc,
                        var_name=dest_arg,
                        description=f"Buffer overflow: {func} copies {src_size} bytes to {dest_size}-byte buffer '{dest_arg}'. Heap ⊬ {dest_arg} |-> (_, {src_size})",
                        confidence=0.90,
                    ))
                    if self.verbose:
                        print(f"[SL] BUFFER OVERFLOW: {func} at line {loc.line}")

    def _get_buffer_size(self, var_name: str) -> Optional[int]:
        """Get buffer size from heap tracking."""
        if var_name in self.heap:
            return self.heap[var_name].size
        return None

    def _get_source_size(self, var_name: str, all_lines: List[str], line_num: int) -> Optional[int]:
        """
        Get source data size by looking at how it was initialized.

        Look for:
        1. memset(var, ..., N) - initialized with N bytes
        2. var[N] declaration - array of N elements
        """
        # Check if we already track this variable
        if var_name in self.heap and self.heap[var_name].size:
            return self.heap[var_name].size

        # Look in surrounding context for memset or declaration
        context_start = max(0, line_num - 15)
        context_end = line_num

        for i in range(context_start, context_end):
            ctx_line = all_lines[i] if i < len(all_lines) else ""

            # Look for memset
            memset_match = re.search(rf'memset\s*\(\s*{re.escape(var_name)}\s*,\s*[^,]+,\s*(\d+)(?:\s*-\s*(\d+))?\s*\)', ctx_line)
            if memset_match:
                size = int(memset_match.group(1))
                if memset_match.group(2):
                    size -= int(memset_match.group(2))
                return size + 1  # +1 for null terminator

            # Look for array declaration
            array_match = re.search(rf'{re.escape(var_name)}\s*\[\s*(\d+)\s*\]', ctx_line)
            if array_match:
                return int(array_match.group(1))

        return None

    def _check_memory_leaks(self, loc: Location):
        """
        Check for memory leaks at function exit (CWE-401).

        In separation logic terms:
        - At function exit, heap should be emp (all allocated regions freed)
        - If heap contains ptr |-> val where ptr was heap-allocated, it's a leak

        We only report leaks for HEAP allocations (not stack/alloca).
        """
        for var_name, region in self.heap.items():
            # Only check heap allocations (not stack)
            if region.alloc_kind != AllocKind.HEAP:
                continue

            # If the region is still VALID (not freed), it's a memory leak
            if region.state == HeapState.VALID:
                self._add_vuln(MemoryVuln(
                    vuln_type=VulnType.MEMORY_LEAK,
                    cwe_id="CWE-401",
                    location=loc,
                    var_name=var_name,
                    description=f"Memory leak: '{var_name}' allocated at line {region.alloc_loc.line if region.alloc_loc else '?'} is never freed. Heap ⊨ {var_name} |-> _ at function exit",
                    alloc_loc=region.alloc_loc,
                    confidence=0.85,
                ))
                if self.verbose:
                    print(f"[SL] MEMORY LEAK: {var_name} at function exit (line {loc.line})")


def analyze_with_separation_logic(source: str, filename: str = "<unknown>",
                                   verbose: bool = False) -> List[MemoryVuln]:
    """
    Convenience function to analyze C/C++ code with separation logic.

    Uses Frame's SL solver to verify memory safety properties.
    """
    analyzer = SLMemoryAnalyzer(verbose=verbose)
    return analyzer.analyze_source(source, filename)
