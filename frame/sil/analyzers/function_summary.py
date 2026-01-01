"""
Enhanced Function Summary Data Structures for Inter-procedural Analysis.

This module provides comprehensive data structures for tracking function effects
on memory state, using tree-sitter AST parsing for accurate extraction.

Key capabilities:
1. Parameter effects (freed, dereferenced, modified, taint propagation)
2. Member variable effects (allocated, freed, modified)
3. Return value tracking (allocation source, parameter propagation)
4. Taint flow analysis between parameters and return values
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional
from enum import Enum


class ReturnSource(Enum):
    """Where return value originates from"""
    ALLOCATION = "allocation"      # Returns malloc/new result
    PARAMETER = "parameter"        # Returns a parameter (passthrough)
    MEMBER = "member"              # Returns a class member
    LOCAL = "local"                # Returns local variable
    LITERAL = "literal"            # Returns literal value
    UNKNOWN = "unknown"


class HeapEffect(Enum):
    """Effect a function has on heap state"""
    ALLOCATE = "allocate"          # Allocates memory
    FREE = "free"                  # Frees memory
    READ = "read"                  # Reads from pointer
    WRITE = "write"                # Writes to pointer
    RETURN_ALLOC = "return_alloc"  # Returns allocated memory


@dataclass
class ParameterInfo:
    """Information about a function parameter"""
    index: int                     # Parameter position (0-based)
    name: str                      # Parameter name
    type_str: str                  # Full C/C++ type string
    is_pointer: bool = False       # Is pointer type
    is_reference: bool = False     # Is reference type (C++)
    is_const: bool = False         # Has const qualifier


@dataclass
class ParameterEffect:
    """Effects on a specific parameter during function execution"""
    param_index: int
    param_name: str
    is_freed: bool = False         # Parameter is freed (free/delete)
    is_dereferenced: bool = False  # Parameter is dereferenced (*param)
    is_modified: bool = False      # *param = x or param->field = x
    is_returned: bool = False      # Parameter is returned
    propagates_taint_to_return: bool = False  # Taint flows to return value


@dataclass
class MemberEffect:
    """Effects on a class member variable"""
    member_name: str
    member_type: str = "unknown"
    is_allocated: bool = False     # Member is allocated (new/malloc)
    is_freed: bool = False         # Member is freed (delete/free)
    is_dereferenced: bool = False  # Member is dereferenced
    is_modified: bool = False      # Member is assigned to


@dataclass
class FunctionSummary:
    """
    Comprehensive summary of a function's effects on memory state.

    This captures all information needed for inter-procedural analysis:
    - What the function does to its parameters
    - What the function does to class members (for methods)
    - Where the return value comes from
    - Whether the function allocates or frees memory
    """
    name: str
    qualified_name: str            # Full name with class/namespace

    # Context information
    class_name: Optional[str] = None
    namespace: Optional[str] = None
    is_constructor: bool = False
    is_destructor: bool = False
    is_virtual: bool = False
    is_static: bool = False
    is_template: bool = False
    template_params: List[str] = field(default_factory=list)

    # Function signature
    parameters: List[ParameterInfo] = field(default_factory=list)
    return_type: str = "void"

    # Parameter effects - what happens to each parameter
    param_effects: Dict[int, ParameterEffect] = field(default_factory=dict)

    # Member effects (for class methods)
    member_effects: Dict[str, MemberEffect] = field(default_factory=dict)

    # Return value information
    return_source: ReturnSource = ReturnSource.UNKNOWN
    return_source_param_idx: Optional[int] = None   # If PARAMETER, which one
    return_source_member: Optional[str] = None      # If MEMBER, which one
    returns_allocated: bool = False                 # Returns newly allocated memory

    # Aggregate flags for quick filtering
    has_heap_ops: bool = False     # Any heap operation
    allocates: bool = False        # Calls malloc/new
    frees: bool = False            # Calls free/delete

    # Legacy compatibility fields (match old FunctionSummary)
    @property
    def frees_params(self) -> Set[int]:
        """Parameter indices that are freed."""
        return {idx for idx, eff in self.param_effects.items() if eff.is_freed}

    @property
    def derefs_params(self) -> Set[int]:
        """Parameter indices that are dereferenced."""
        return {idx for idx, eff in self.param_effects.items() if eff.is_dereferenced}

    @property
    def modifies_members(self) -> Set[str]:
        """Member names that are modified."""
        return {name for name, eff in self.member_effects.items() if eff.is_modified}

    @property
    def frees_members(self) -> Set[str]:
        """Member names that are freed."""
        return {name for name, eff in self.member_effects.items() if eff.is_freed}


@dataclass
class ClassSummary:
    """Summary of a class's memory management characteristics."""
    name: str
    qualified_name: str
    namespace: Optional[str] = None

    # Member variables
    members: Dict[str, str] = field(default_factory=dict)  # name -> type
    pointer_members: Set[str] = field(default_factory=set)

    # Special methods
    constructor_summaries: List[FunctionSummary] = field(default_factory=list)
    destructor_summary: Optional[FunctionSummary] = None
    copy_constructor: Optional[FunctionSummary] = None
    copy_assignment: Optional[FunctionSummary] = None  # operator=

    # Regular methods
    method_summaries: Dict[str, FunctionSummary] = field(default_factory=dict)

    # Inheritance
    base_classes: List[str] = field(default_factory=list)

    # Lifecycle analysis results
    members_allocated_in_ctor: Set[str] = field(default_factory=set)
    members_freed_in_dtor: Set[str] = field(default_factory=set)

    # Vulnerability indicators
    has_raw_pointer_members: bool = False
    missing_copy_constructor: bool = False
    missing_copy_assignment: bool = False
    potential_double_free: bool = False
