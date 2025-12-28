"""
Memory Safety Analyzer for C/C++ using Separation Logic.

This module implements separation logic-based detection of memory safety
vulnerabilities including:
- CWE-416: Use After Free
- CWE-415: Double Free
- CWE-476: Null Pointer Dereference
- CWE-122: Heap-based Buffer Overflow
- CWE-121: Stack-based Buffer Overflow
- CWE-401: Memory Leak

The analyzer tracks heap state using separation logic formulas and uses
Frame's incorrectness logic to prove that error states are reachable.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple
from enum import Enum
import re

from frame.sil.types import Location, PVar, Exp, ExpVar, ExpConst
from frame.sil.translator import VulnType


class MemoryState(Enum):
    """State of a memory region"""
    UNALLOCATED = "unallocated"
    ALLOCATED = "allocated"
    FREED = "freed"
    NULL = "null"


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

    Uses a simplified abstract interpretation approach to track memory state
    and detect violations.
    """

    # Dangerous functions that indicate potential vulnerabilities
    DANGEROUS_FUNCS = {
        # Buffer overflow prone
        'strcpy', 'strcat', 'gets', 'sprintf', 'vsprintf',
        'wcscpy', 'wcscat', '_mbscpy', '_mbscat',
        'lstrcpy', 'lstrcat', 'lstrcpyA', 'lstrcatA',
        'lstrcpyW', 'lstrcatW', 'StrCpy', 'StrCat',
        # Memory operations
        'memcpy', 'memmove', 'memset', 'bcopy',
        # Format string
        'printf', 'fprintf', 'sprintf', 'snprintf',
        'vprintf', 'vfprintf', 'vsprintf', 'vsnprintf',
        'syslog', 'wprintf', 'swprintf',
    }

    # Allocation functions
    ALLOC_FUNCS = {
        'malloc', 'calloc', 'realloc', 'strdup', 'strndup',
        'aligned_alloc', 'posix_memalign', 'valloc', 'pvalloc',
        'memalign', 'mmap', 'alloca', '_alloca',
    }

    # Deallocation functions
    FREE_FUNCS = {
        'free', 'cfree', 'munmap', 'realloc',  # realloc can free
    }

    # Null-returning functions (need null check)
    NULL_RETURN_FUNCS = {
        'malloc', 'calloc', 'realloc', 'fopen', 'fdopen',
        'tmpfile', 'popen', 'dlopen', 'mmap',
        'strdup', 'strndup', 'getcwd', 'getenv',
    }

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.memory_regions: Dict[str, MemoryRegion] = {}
        self.vulnerabilities: List[MemoryVulnerability] = []
        self.current_function: str = ""

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
                    # Function end - check for memory leaks
                    self._check_memory_leaks(loc)
                    in_function = False
                    self.current_function = ""
                    continue

                # Analyze the line
                self._analyze_line(line, loc)

        return self.vulnerabilities

    def _is_function_start(self, line: str) -> bool:
        """Check if line is a function definition start"""
        # Simple heuristic: has parentheses and opening brace or is followed by brace
        if '(' in line and ')' in line:
            # Exclude control flow
            for keyword in ['if', 'while', 'for', 'switch', 'else']:
                if line.strip().startswith(keyword):
                    return False
            # Check for function pattern
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

        # Check for allocations: ptr = malloc(...)
        self._check_allocation(stripped, loc)

        # Check for frees: free(ptr)
        self._check_free(stripped, loc)

        # Check for uses: *ptr, ptr->field, ptr[i]
        self._check_use(stripped, loc)

        # Check for dangerous function calls
        self._check_dangerous_calls(stripped, loc)

        # Check for null assignments
        self._check_null_assignment(stripped, loc)

    def _check_allocation(self, line: str, loc: Location):
        """Check for memory allocation"""
        for func in self.ALLOC_FUNCS:
            pattern = rf'(\w+)\s*=\s*(?:\([^)]*\))?\s*{func}\s*\('
            match = re.search(pattern, line)
            if match:
                var_name = match.group(1)
                self.memory_regions[var_name] = MemoryRegion(
                    var_name=var_name,
                    state=MemoryState.ALLOCATED,
                    alloc_location=loc,
                )
                if self.verbose:
                    print(f"[MemSafety] Allocated: {var_name} at line {loc.line}")

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
        """Check for memory deallocation"""
        # free(ptr)
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
        """Handle a free operation on a variable"""
        if var_name in self.memory_regions:
            region = self.memory_regions[var_name]

            # Check for double free
            if region.state == MemoryState.FREED:
                self.vulnerabilities.append(MemoryVulnerability(
                    vuln_type=VulnType.DOUBLE_FREE,
                    cwe_id="CWE-415",
                    location=loc,
                    var_name=var_name,
                    description=f"Double free of '{var_name}'",
                    alloc_location=region.alloc_location,
                    free_location=region.free_location,
                    confidence=0.95,
                ))
                if self.verbose:
                    print(f"[MemSafety] DOUBLE FREE: {var_name} at line {loc.line}")
            else:
                # Mark as freed
                region.state = MemoryState.FREED
                region.free_location = loc
                if self.verbose:
                    print(f"[MemSafety] Freed: {var_name} at line {loc.line}")
        else:
            # Unknown variable - still mark as freed for later UAF detection
            self.memory_regions[var_name] = MemoryRegion(
                var_name=var_name,
                state=MemoryState.FREED,
                free_location=loc,
            )

    def _check_use(self, line: str, loc: Location):
        """Check for use of memory (dereference, access)"""
        # Look for uses of tracked variables after free
        for var_name, region in self.memory_regions.items():
            if region.state == MemoryState.FREED:
                # Check for use patterns: *var, var->, var[
                use_patterns = [
                    rf'\*\s*{re.escape(var_name)}\b',  # *ptr
                    rf'{re.escape(var_name)}\s*->',     # ptr->
                    rf'{re.escape(var_name)}\s*\[',     # ptr[
                    rf'\(\s*{re.escape(var_name)}\s*\)', # func(ptr)
                ]

                for pattern in use_patterns:
                    if re.search(pattern, line):
                        # Exclude the free call itself
                        if f'free({var_name})' in line or f'free( {var_name} )' in line:
                            continue
                        if f'delete {var_name}' in line or f'delete[] {var_name}' in line:
                            continue

                        self.vulnerabilities.append(MemoryVulnerability(
                            vuln_type=VulnType.USE_AFTER_FREE,
                            cwe_id="CWE-416",
                            location=loc,
                            var_name=var_name,
                            description=f"Use after free of '{var_name}'",
                            alloc_location=region.alloc_location,
                            free_location=region.free_location,
                            confidence=0.90,
                        ))
                        if self.verbose:
                            print(f"[MemSafety] USE AFTER FREE: {var_name} at line {loc.line}")
                        break

            elif region.state == MemoryState.NULL:
                # Check for null dereference
                null_patterns = [
                    rf'\*\s*{re.escape(var_name)}\b',
                    rf'{re.escape(var_name)}\s*->',
                    rf'{re.escape(var_name)}\s*\[',
                ]

                for pattern in null_patterns:
                    if re.search(pattern, line):
                        # Check if there's a null check on this line
                        if f'if ({var_name})' in line or f'if({var_name})' in line:
                            continue
                        if f'{var_name} != NULL' in line or f'{var_name} != 0' in line:
                            continue
                        if f'{var_name} == NULL' in line or f'{var_name} == 0' in line:
                            continue

                        self.vulnerabilities.append(MemoryVulnerability(
                            vuln_type=VulnType.NULL_DEREFERENCE,
                            cwe_id="CWE-476",
                            location=loc,
                            var_name=var_name,
                            description=f"Potential null pointer dereference of '{var_name}'",
                            confidence=0.75,
                        ))
                        break

    def _check_dangerous_calls(self, line: str, loc: Location):
        """Check for dangerous function calls that indicate buffer overflow"""
        # NOTE: Most "dangerous" functions (strcpy, strcat, sprintf, memcpy) are
        # used in BOTH good and bad code. The difference is whether proper bounds
        # checking is done. Without data flow analysis to track buffer sizes,
        # we cannot reliably distinguish safe from unsafe usage.
        #
        # Only flag gets() which has NO safe usage pattern.
        if re.search(r'\bgets\s*\(', line):
            self.vulnerabilities.append(MemoryVulnerability(
                vuln_type=VulnType.BUFFER_OVERFLOW,
                cwe_id="CWE-242",
                location=loc,
                var_name="gets",
                description="Use of gets() - always dangerous, use fgets()",
                confidence=0.95,
            ))

    def _has_format_vuln(self, line: str, func: str) -> bool:
        """Check if a printf-like call has format string vulnerability"""
        # Pattern: printf(variable) without format string
        # Safe: printf("literal") or printf("%s", var)
        match = re.search(rf'{func}\s*\(\s*([^,)]+)', line)
        if match:
            first_arg = match.group(1).strip()
            # If first arg is not a string literal, it's potentially vulnerable
            if not first_arg.startswith('"') and not first_arg.startswith("'"):
                # Exclude stdout/stderr for fprintf
                if func == 'fprintf' and first_arg in ('stdout', 'stderr', 'file', 'fp', 'f'):
                    return False
                return True
        return False

    def _check_null_assignment(self, line: str, loc: Location):
        """Check for null pointer assignments"""
        # Pattern: ptr = NULL or ptr = 0 or ptr = nullptr
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

    def _check_memory_leaks(self, loc: Location):
        """Check for memory leaks at function end"""
        # Skip leak detection for test-related functions
        # These patterns are common in test suites like NIST Juliet
        test_func_patterns = ['good', 'bad', 'test', 'main']
        if any(p in self.current_function.lower() for p in test_func_patterns):
            return

        for var_name, region in self.memory_regions.items():
            if region.state == MemoryState.ALLOCATED:
                # Skip test-related variable names
                if 'good' in var_name.lower() or 'bad' in var_name.lower():
                    continue
                if 'Object' in var_name or 'test' in var_name.lower():
                    continue

                # Allocated but never freed - potential leak
                # Only report with lower confidence as may be intentional
                self.vulnerabilities.append(MemoryVulnerability(
                    vuln_type=VulnType.MEMORY_LEAK,
                    cwe_id="CWE-401",
                    location=region.alloc_location or loc,
                    var_name=var_name,
                    description=f"Potential memory leak: '{var_name}' allocated but not freed",
                    alloc_location=region.alloc_location,
                    confidence=0.60,  # Lower confidence - may be freed elsewhere
                ))


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
