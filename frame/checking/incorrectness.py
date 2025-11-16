"""
Incorrectness Separation Logic for Bug Finding

Based on Peter O'Hearn's Incorrectness Logic (2019), this module implements
bug-finding analysis using under-approximate reasoning.

Key differences from correctness logic:
- Proves bugs ARE reachable (not that they're absent)
- Uses satisfiability checking instead of validity
- Zero false positives (may have false negatives)
- Produces concrete witnesses when bugs are found

References:
- O'Hearn, "Incorrectness Logic", POPL 2020
- Raad et al., "Local Reasoning About the Presence of Bugs", CAV 2020
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Any
from enum import Enum

import z3

from frame.core.ast import Formula, PointsTo, Var, Const, SepConj, And, Eq, Neq, True_, False_, NullDeref
from frame.core.parser import parse
from frame.encoding.encoder import Z3Encoder
from frame.predicates.registry import PredicateRegistry


class BugType(Enum):
    """Types of bugs that can be detected"""
    NULL_DEREFERENCE = "null_dereference"
    USE_AFTER_FREE = "use_after_free"
    BUFFER_OVERFLOW = "buffer_overflow"
    DOUBLE_FREE = "double_free"
    MEMORY_LEAK = "memory_leak"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    TAINT_FLOW = "taint_flow"


@dataclass
class BugWitness:
    """Concrete values that trigger a bug"""
    variables: Dict[str, Any]  # Variable assignments
    heap: Dict[str, Any]  # Heap state (pointer -> value mappings)
    trace: List[str]  # Execution steps leading to bug

    def __str__(self):
        lines = ["Bug Witness:"]
        if self.variables:
            lines.append("  Variables:")
            for var, val in sorted(self.variables.items()):
                lines.append(f"    {var} = {val}")
        if self.heap:
            lines.append("  Heap:")
            for ptr, val in sorted(self.heap.items()):
                lines.append(f"    {ptr} -> {val}")
        if self.trace:
            lines.append("  Trace:")
            for step in self.trace:
                lines.append(f"    {step}")
        return "\n".join(lines)


@dataclass
class BugReport:
    """Report of a detected bug"""
    reachable: bool
    bug_type: BugType
    description: str
    witness: Optional[BugWitness] = None
    confidence: float = 1.0  # Confidence in the bug (1.0 = certain)

    def __str__(self):
        if self.reachable:
            lines = [f"BUG FOUND: {self.bug_type.value}"]
            lines.append(f"Description: {self.description}")
            lines.append(f"Confidence: {self.confidence:.0%}")
            if self.witness:
                lines.append("")
                lines.append(str(self.witness))
            return "\n".join(lines)
        else:
            return f"No bug reachable: {self.description}"


class IncorrectnessChecker:
    """
    Incorrectness Separation Logic checker for bug finding.

    Uses satisfiability checking to prove bugs ARE reachable,
    providing concrete witnesses when bugs are found.
    """

    def __init__(self, registry: Optional[PredicateRegistry] = None, timeout: int = 5000):
        """Initialize incorrectness checker

        Args:
            registry: Predicate registry for unfolding
            timeout: Z3 timeout in milliseconds
        """
        self.registry = registry or PredicateRegistry()
        self.timeout = timeout
        self.encoder = Z3Encoder()

    def check_bug_reachability(
        self,
        precondition: Formula,
        error_condition: Formula
    ) -> BugReport:
        """
        Check if error condition is reachable from precondition.

        In incorrectness logic: [P] C [Q] means:
        - If P holds initially, then C CAN terminate in state satisfying Q
        - We check: P ∧ error_condition is satisfiable
        - If SAT → bug is reachable (with witness)
        - If UNSAT → bug is not reachable from this precondition

        Args:
            precondition: Initial state condition
            error_condition: Error state to check reachability

        Returns:
            BugReport with reachability and witness if found
        """
        # Combine precondition and error condition
        combined = SepConj(precondition, error_condition)

        # Encode to Z3
        solver = z3.Solver()
        solver.set("timeout", self.timeout)

        try:
            # Use encode_formula to get the full encoding
            constraints, heap, domain = self.encoder.encode_formula(combined)
            solver.add(constraints)

            result = solver.check()

            if result == z3.sat:
                # Bug is reachable! Extract witness
                model = solver.model()
                witness = self._extract_witness(model, precondition, error_condition)

                return BugReport(
                    reachable=True,
                    bug_type=BugType.TAINT_FLOW,  # Default, override in specific methods
                    description="Error condition is reachable",
                    witness=witness,
                    confidence=1.0
                )
            elif result == z3.unsat:
                # Bug is not reachable from this precondition
                return BugReport(
                    reachable=False,
                    bug_type=BugType.TAINT_FLOW,
                    description="Error condition is not reachable",
                    confidence=1.0
                )
            else:
                # Unknown (timeout or other issue)
                return BugReport(
                    reachable=False,
                    bug_type=BugType.TAINT_FLOW,
                    description="Could not determine reachability (timeout or unknown)",
                    confidence=0.0
                )
        except Exception as e:
            return BugReport(
                reachable=False,
                bug_type=BugType.TAINT_FLOW,
                description=f"Error during analysis: {e}",
                confidence=0.0
            )

    def _extract_witness(
        self,
        model: z3.ModelRef,
        precondition: Formula,
        error_condition: Formula
    ) -> BugWitness:
        """Extract concrete witness values from Z3 model

        Args:
            model: Z3 model from satisfiable check
            precondition: Original precondition
            error_condition: Error condition

        Returns:
            BugWitness with concrete values
        """
        variables = {}
        heap = {}
        trace = []

        # Extract variable values
        for decl in model.decls():
            var_name = decl.name()
            value = model[decl]

            # Convert Z3 values to Python values
            if value is not None:
                try:
                    # Try to get concrete value
                    if hasattr(value, 'as_long'):
                        variables[var_name] = value.as_long()
                    elif hasattr(value, 'as_string'):
                        variables[var_name] = value.as_string()
                    else:
                        variables[var_name] = str(value)
                except:
                    variables[var_name] = str(value)

        # Build trace
        trace.append(f"Initial state satisfies: {precondition}")
        trace.append(f"Reaches error state: {error_condition}")

        return BugWitness(
            variables=variables,
            heap=heap,
            trace=trace
        )

    # =============================================================================
    # Memory Safety Bug Detection
    # =============================================================================

    def check_null_dereference(
        self,
        precondition: Formula,
        pointer: str
    ) -> BugReport:
        """
        Check if null pointer dereference is reachable.

        Args:
            precondition: Initial state
            pointer: Variable name that might be null

        Returns:
            BugReport indicating if null dereference is reachable
        """
        # Error condition: Use NullDeref predicate
        error = NullDeref(Var(pointer))

        report = self.check_bug_reachability(precondition, error)
        report.bug_type = BugType.NULL_DEREFERENCE
        report.description = f"Null pointer dereference on variable '{pointer}'"

        return report

    def check_use_after_free(
        self,
        precondition: Formula,
        pointer: str
    ) -> BugReport:
        """
        Check if use-after-free is reachable.

        Uses the Freed predicate to track freed pointers and detects
        when a freed pointer is dereferenced.

        Args:
            precondition: Initial state
            pointer: Variable that might be used after free

        Returns:
            BugReport indicating if use-after-free is reachable
        """
        from frame.core.ast import Freed, UseAfterFree

        # Error condition: pointer is freed AND we try to dereference it
        # The UseAfterFree predicate combines both checks
        error = SepConj(
            Freed(Var(pointer)),
            PointsTo(Var(pointer), Var("_"))  # Trying to use freed memory
        )

        report = self.check_bug_reachability(precondition, error)
        report.bug_type = BugType.USE_AFTER_FREE
        report.description = f"Use-after-free on variable '{pointer}'"

        return report

    def check_buffer_overflow(
        self,
        precondition: Formula,
        buffer: str,
        index: str,
        size: int
    ) -> BugReport:
        """
        Check if buffer overflow is reachable.

        Uses ArrayBounds to specify buffer size and detects when
        array access is out of bounds (index >= size or index < 0).

        Args:
            precondition: Initial state
            buffer: Buffer variable
            index: Index variable
            size: Buffer size

        Returns:
            BugReport indicating if buffer overflow is reachable
        """
        from frame.core.ast import Gt, Lt, Or, ArrayBounds, ArrayPointsTo

        # Error condition: bounds(buffer, size) AND (index >= size OR index < 0) AND access
        # We model the access to show the bug is reached
        error = SepConj(
            ArrayBounds(Var(buffer), Const(size)),
            SepConj(
                Or(
                    Gt(Var(index), Const(size - 1)),  # index >= size
                    Lt(Var(index), Const(0))           # index < 0
                ),
                ArrayPointsTo(Var(buffer), Var(index), Var("_"))  # Out-of-bounds access
            )
        )

        report = self.check_bug_reachability(precondition, error)
        report.bug_type = BugType.BUFFER_OVERFLOW
        report.description = f"Buffer overflow: {buffer}[{index}] with size {size}"

        return report

    # =============================================================================
    # Security Vulnerability Detection
    # =============================================================================

    def check_sql_injection(
        self,
        precondition: Formula,
        user_input_var: str,
        query_var: str
    ) -> BugReport:
        """
        Check if SQL injection is reachable.

        Args:
            precondition: Initial state with taint tracking
            user_input_var: Variable containing user input
            query_var: Variable containing SQL query

        Returns:
            BugReport indicating if SQL injection is reachable
        """
        from frame.core.ast import Taint, Sink, Source

        # Error condition: tainted user input flows to SQL sink
        error = SepConj(
            Source(Var(user_input_var), "user"),
            SepConj(
                Taint(Var(user_input_var)),
                SepConj(
                    Eq(Var(query_var), Var(user_input_var)),  # Simplified flow
                    Sink(Var(query_var), "sql")
                )
            )
        )

        report = self.check_bug_reachability(precondition, error)
        report.bug_type = BugType.SQL_INJECTION
        report.description = f"SQL injection: tainted '{user_input_var}' flows to SQL query '{query_var}'"

        return report

    def check_xss(
        self,
        precondition: Formula,
        user_input_var: str,
        html_var: str
    ) -> BugReport:
        """
        Check if XSS (Cross-Site Scripting) is reachable.

        Args:
            precondition: Initial state with taint tracking
            user_input_var: Variable containing user input
            html_var: Variable containing HTML output

        Returns:
            BugReport indicating if XSS is reachable
        """
        from frame.core.ast import Taint, Sink, Source

        # Error condition: tainted user input flows to HTML sink
        error = SepConj(
            Source(Var(user_input_var), "user"),
            SepConj(
                Taint(Var(user_input_var)),
                SepConj(
                    Eq(Var(html_var), Var(user_input_var)),  # Simplified flow
                    Sink(Var(html_var), "html")
                )
            )
        )

        report = self.check_bug_reachability(precondition, error)
        report.bug_type = BugType.XSS
        report.description = f"XSS: tainted '{user_input_var}' flows to HTML '{html_var}'"

        return report

    def check_command_injection(
        self,
        precondition: Formula,
        user_input_var: str,
        command_var: str
    ) -> BugReport:
        """
        Check if command injection is reachable.

        Args:
            precondition: Initial state with taint tracking
            user_input_var: Variable containing user input
            command_var: Variable containing shell command

        Returns:
            BugReport indicating if command injection is reachable
        """
        from frame.core.ast import Taint, Sink, Source

        # Error condition: tainted user input flows to shell sink
        error = SepConj(
            Source(Var(user_input_var), "user"),
            SepConj(
                Taint(Var(user_input_var)),
                SepConj(
                    Eq(Var(command_var), Var(user_input_var)),  # Simplified flow
                    Sink(Var(command_var), "shell")
                )
            )
        )

        report = self.check_bug_reachability(precondition, error)
        report.bug_type = BugType.COMMAND_INJECTION
        report.description = f"Command injection: tainted '{user_input_var}' flows to shell command '{command_var}'"

        return report

    def check_taint_flow(
        self,
        precondition: Formula,
        source_var: str,
        sink_var: str,
        sink_type: str
    ) -> BugReport:
        """
        Generic taint flow check.

        Args:
            precondition: Initial state
            source_var: Source variable
            sink_var: Sink variable
            sink_type: Type of sink ("sql", "html", "shell", etc.)

        Returns:
            BugReport indicating if taint flow is reachable
        """
        from frame.core.ast import Taint, Sink, Source

        # Error condition: tainted source flows to sink
        error = SepConj(
            Source(Var(source_var), "user"),
            SepConj(
                Taint(Var(source_var)),
                SepConj(
                    Eq(Var(sink_var), Var(source_var)),
                    Sink(Var(sink_var), sink_type)
                )
            )
        )

        report = self.check_bug_reachability(precondition, error)
        report.bug_type = BugType.TAINT_FLOW
        report.description = f"Taint flow: '{source_var}' flows to {sink_type} sink '{sink_var}'"

        return report
