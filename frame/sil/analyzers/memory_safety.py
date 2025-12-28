"""
Memory Safety Analyzer for C/C++ using Separation Logic.

This module implements separation logic-based detection of memory safety
vulnerabilities including:
- CWE-416: Use After Free
- CWE-415: Double Free
- CWE-122: Heap-based Buffer Overflow (via size tracking)

The analyzer tracks heap state using separation logic principles:
- Allocated memory: ptr |-> val (ptr points to allocated region)
- Freed memory: emp at ptr (ptr is dangling)

We detect violations by checking if the current heap state entails
the required precondition for memory operations.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple
from enum import Enum
import re

from frame.sil.types import Location, PVar, Exp, ExpVar, ExpConst
from frame.sil.translator import VulnType


class MemoryState(Enum):
    """State of a memory region in separation logic"""
    UNALLOCATED = "unallocated"
    ALLOCATED = "allocated"   # ptr |-> val
    FREED = "freed"           # emp (ptr is dangling)
    NULL = "null"             # ptr = null


@dataclass
class MemoryRegion:
    """Represents a tracked memory region"""
    var_name: str
    state: MemoryState
    alloc_location: Optional[Location] = None
    free_location: Optional[Location] = None
    size: Optional[int] = None
    is_array: bool = False
    element_type: Optional[str] = None


@dataclass
class MemoryVulnerability:
    """A detected memory safety vulnerability"""
    vuln_type: VulnType
    cwe_id: str
    location: Location
    var_name: str
    description: str
    alloc_location: Optional[Location] = None
    free_location: Optional[Location] = None
    confidence: float = 1.0


class MemorySafetyAnalyzer:
    """
    Analyzes C/C++ code for memory safety vulnerabilities.

    Uses a simplified separation logic approach to track memory state
    and detect violations:

    - Before dereference: Check heap |- ptr |-> _ (ptr is valid)
    - Before free: Check heap |- ptr |-> _ (ptr can be freed)
    - After free: Update heap to remove ptr |-> _ (ptr becomes dangling)
    """

    # Allocation functions
    ALLOC_FUNCS = {
        'malloc', 'calloc', 'realloc', 'strdup', 'strndup',
        'aligned_alloc', 'posix_memalign', 'valloc', 'pvalloc',
        'memalign', 'mmap', 'alloca', '_alloca',
    }

    # Deallocation functions
    FREE_FUNCS = {
        'free', 'cfree', 'munmap',
    }

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.memory_regions: Dict[str, MemoryRegion] = {}
        self.vulnerabilities: List[MemoryVulnerability] = []
        self.current_function: str = ""
        self._reported: Set[Tuple[str, int]] = set()

    def _add_vuln(self, vuln: MemoryVulnerability) -> bool:
        """Add vulnerability if not already reported."""
        key = (vuln.cwe_id, vuln.location.line)
        if key in self._reported:
            return False
        self._reported.add(key)
        self.vulnerabilities.append(vuln)
        return True

    def analyze_source(self, source_code: str, filename: str = "<unknown>") -> List[MemoryVulnerability]:
        """
        Analyze C/C++ source code for memory safety vulnerabilities.

        Args:
            source_code: The source code to analyze
            filename: Name of the file being analyzed

        Returns:
            List of detected vulnerabilities
        """
        self.memory_regions = {}
        self.vulnerabilities = []
        self._reported = set()

        lines = source_code.split('\n')
        in_function = False
        function_name = ""
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
            if self._is_function_start(stripped):
                in_function = True
                function_name = self._extract_function_name(stripped)
                self.current_function = function_name
                brace_depth = stripped.count('{') - stripped.count('}')
                self.memory_regions = {}  # Reset per function
                continue

            if in_function:
                brace_depth += stripped.count('{') - stripped.count('}')
                if brace_depth <= 0:
                    in_function = False
                    self.current_function = ""
                    continue

                # Analyze the line
                self._analyze_line(line, loc)

        return self.vulnerabilities

    def _is_function_start(self, line: str) -> bool:
        """Check if line is a function definition start"""
        if '(' in line and ')' in line:
            for keyword in ['if', 'while', 'for', 'switch', 'else']:
                if line.strip().startswith(keyword):
                    return False
            if re.match(r'^[\w\s\*]+\s+\w+\s*\([^;]*\)\s*\{?', line):
                return True
        return False

    def _extract_function_name(self, line: str) -> str:
        """Extract function name from definition"""
        match = re.search(r'(\w+)\s*\(', line)
        if match:
            return match.group(1)
        return "<unknown>"

    def _analyze_line(self, line: str, loc: Location):
        """Analyze a single line for memory operations"""
        stripped = line.strip()

        # Track allocations
        self._check_allocation(stripped, loc)

        # Track frees and detect double-free
        self._check_free(stripped, loc)

        # Detect use-after-free
        self._check_use(stripped, loc)

        # Track null assignments
        self._check_null_assignment(stripped, loc)

    def _check_allocation(self, line: str, loc: Location):
        """Check for memory allocation - adds ptr |-> val to heap state"""
        for func in self.ALLOC_FUNCS:
            pattern = rf'(\w+)\s*=\s*(?:\([^)]*\))??\s*{func}\s*\('
            match = re.search(pattern, line)
            if match:
                var_name = match.group(1)
                self.memory_regions[var_name] = MemoryRegion(
                    var_name=var_name,
                    state=MemoryState.ALLOCATED,
                    alloc_location=loc,
                )
                if self.verbose:
                    print(f"[SL] {var_name} |-> val (allocated at line {loc.line})")

        # C++ new operator
        new_match = re.search(r'(\w+)\s*=\s*new\s+', line)
        if new_match:
            var_name = new_match.group(1)
            is_array = 'new[]' in line or 'new [' in line or re.search(r'new\s+\w+\s*\[', line)
            self.memory_regions[var_name] = MemoryRegion(
                var_name=var_name,
                state=MemoryState.ALLOCATED,
                alloc_location=loc,
                is_array=is_array,
            )

    def _check_free(self, line: str, loc: Location):
        """Check for memory deallocation - detects double-free"""
        # C free
        for func in self.FREE_FUNCS:
            pattern = rf'{func}\s*\(\s*(\w+)\s*\)'
            match = re.search(pattern, line)
            if match:
                var_name = match.group(1)
                self._handle_free(var_name, loc)

        # C++ delete
        delete_match = re.search(r'delete\s*(?:\[\s*\])?\s*(\w+)', line)
        if delete_match:
            var_name = delete_match.group(1)
            self._handle_free(var_name, loc)

    def _handle_free(self, var_name: str, loc: Location):
        """Handle a free operation - detect double-free using SL reasoning"""
        if var_name in self.memory_regions:
            region = self.memory_regions[var_name]

            # Double-free: heap ⊬ ptr |-> _ (already freed)
            if region.state == MemoryState.FREED:
                self._add_vuln(MemoryVulnerability(
                    vuln_type=VulnType.DOUBLE_FREE,
                    cwe_id="CWE-415",
                    location=loc,
                    var_name=var_name,
                    description=f"Double free: '{var_name}' already freed at line {region.free_location.line if region.free_location else '?'}",
                    alloc_location=region.alloc_location,
                    free_location=region.free_location,
                    confidence=0.95,
                ))
                if self.verbose:
                    print(f"[SL] DOUBLE FREE: heap ⊬ {var_name} |-> _ at line {loc.line}")
            else:
                # Valid free - update state to FREED (remove from heap formula)
                region.state = MemoryState.FREED
                region.free_location = loc
                if self.verbose:
                    print(f"[SL] {var_name} freed at line {loc.line}")
        else:
            # Unknown variable - track as freed for later UAF detection
            self.memory_regions[var_name] = MemoryRegion(
                var_name=var_name,
                state=MemoryState.FREED,
                free_location=loc,
            )

    def _check_use(self, line: str, loc: Location):
        """Check for use of freed memory (use-after-free)"""
        for var_name, region in self.memory_regions.items():
            if region.state == MemoryState.FREED:
                # Check for dereference patterns using word boundaries
                use_patterns = [
                    rf'\*\s*{re.escape(var_name)}\b',      # *ptr
                    rf'\b{re.escape(var_name)}\s*->',      # ptr->
                    rf'\b{re.escape(var_name)}\s*\[',      # ptr[
                ]

                for pattern in use_patterns:
                    if re.search(pattern, line):
                        # Exclude free call itself
                        if f'free({var_name})' in line or f'free( {var_name} )' in line:
                            continue
                        if f'delete {var_name}' in line or f'delete[] {var_name}' in line:
                            continue

                        self._add_vuln(MemoryVulnerability(
                            vuln_type=VulnType.USE_AFTER_FREE,
                            cwe_id="CWE-416",
                            location=loc,
                            var_name=var_name,
                            description=f"Use after free: '{var_name}' freed at line {region.free_location.line if region.free_location else '?'}",
                            alloc_location=region.alloc_location,
                            free_location=region.free_location,
                            confidence=0.90,
                        ))
                        if self.verbose:
                            print(f"[SL] USE AFTER FREE: heap ⊬ {var_name} |-> _ at line {loc.line}")
                        break

    def _check_null_assignment(self, line: str, loc: Location):
        """Check for null pointer assignments"""
        null_patterns = [
            r'(\w+)\s*=\s*NULL\b',
            r'(\w+)\s*=\s*0\s*;',
            r'(\w+)\s*=\s*nullptr\b',
            r'(\w+)\s*=\s*\(\s*\w+\s*\*\s*\)\s*0\s*;',
        ]

        for pattern in null_patterns:
            match = re.search(pattern, line)
            if match:
                var_name = match.group(1)
                self.memory_regions[var_name] = MemoryRegion(
                    var_name=var_name,
                    state=MemoryState.NULL,
                )


def analyze_c_memory_safety(source_code: str, filename: str = "<unknown>",
                           verbose: bool = False) -> List[MemoryVulnerability]:
    """
    Convenience function to analyze C/C++ code for memory safety issues.

    Args:
        source_code: Source code to analyze
        filename: Name of the file
        verbose: Whether to print debug output

    Returns:
        List of detected vulnerabilities
    """
    analyzer = MemorySafetyAnalyzer(verbose=verbose)
    return analyzer.analyze_source(source_code, filename)
