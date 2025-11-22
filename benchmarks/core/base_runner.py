"""Base utilities for running benchmarks"""

import z3
from typing import Tuple, Optional


def run_smt2_with_z3(filepath: str, timeout: int = 10) -> Tuple[str, Optional[str]]:
    """
    Run an SMT-LIB 2.6 file directly with Z3 Python API

    Args:
        filepath: Path to .smt2 file
        timeout: Timeout in seconds

    Returns:
        (result, error) where result is 'sat', 'unsat', 'unknown', or 'timeout'
    """
    try:
        # Create solver with timeout
        solver = z3.Solver()
        solver.set("timeout", timeout * 1000)  # Z3 expects milliseconds

        # Parse the SMT2 file and add assertions to solver
        # Using parse_smt2_file is more reliable than parse_smt2_string
        # for complex SMT-LIB files with string/bitvector theories
        assertions = z3.parse_smt2_file(filepath)

        # Add assertions to solver (handles both AstVector and single assertions)
        solver.add(assertions)

        # Check satisfiability
        check_result = solver.check()

        if check_result == z3.sat:
            return 'sat', None
        elif check_result == z3.unsat:
            return 'unsat', None
        else:  # z3.unknown
            # Check if it's a timeout or genuinely unknown
            reason = solver.reason_unknown()
            if 'timeout' in reason.lower() or 'canceled' in reason.lower():
                return 'timeout', f'Z3 timeout: {reason}'
            else:
                return 'unknown', None

    except FileNotFoundError:
        return 'error', 'File not found'
    except z3.Z3Exception as e:
        # Z3-specific errors (parsing, etc.)
        return 'error', f'Z3 error: {str(e)}'
    except Exception as e:
        return 'error', str(e)


def parse_smt2_expected(filepath: str) -> Optional[str]:
    """
    Parse expected result from SMT2 file

    Looks for (set-info :status sat/unsat/unknown) in the file

    Args:
        filepath: Path to .smt2 file

    Returns:
        Expected status ('sat', 'unsat', 'unknown') or None if not found
    """
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('(set-info :status'):
                    # Extract status: (set-info :status sat) -> 'sat'
                    parts = line.split()
                    if len(parts) >= 3:
                        status = parts[2].rstrip(')')
                        return status.lower()
        return None
    except Exception:
        return None
