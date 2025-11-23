"""Base utilities for running benchmarks"""

import subprocess
import z3
from typing import Tuple, Optional


def run_smt2_with_z3(filepath: str, timeout: int = 10) -> Tuple[str, Optional[str]]:
    """
    Run an SMT-LIB 2.6 file with Z3

    Tries Z3 binary first (more robust, handles all SMT-LIB features),
    falls back to Python API if binary not available (for CI).

    Args:
        filepath: Path to .smt2 file
        timeout: Timeout in seconds

    Returns:
        (result, error) where result is 'sat', 'unsat', 'unknown', or 'timeout'
    """
    # Try Z3 binary first - it's more robust and handles all SMT-LIB 2.6 features
    try:
        result = subprocess.run(
            ['z3', filepath, f'-T:{timeout}'],
            capture_output=True,
            text=True,
            timeout=timeout + 1
        )

        output = result.stdout.strip()

        if 'sat' in output and 'unsat' not in output:
            return 'sat', None
        elif 'unsat' in output:
            return 'unsat', None
        else:
            return 'unknown', None

    except subprocess.TimeoutExpired:
        return 'timeout', 'Z3 timeout'
    except FileNotFoundError:
        # Z3 binary not found, fall back to Python API
        pass
    except Exception as e:
        # Other subprocess errors, fall back to Python API
        pass

    # Fallback: Use Z3 Python API (for CI environments without z3 binary)
    try:
        assertions = z3.parse_smt2_file(filepath)

        solver = z3.Solver()
        solver.set("timeout", timeout * 1000)  # Z3 expects milliseconds
        solver.add(assertions)

        check_result = solver.check()

        if check_result == z3.sat:
            return 'sat', None
        elif check_result == z3.unsat:
            return 'unsat', None
        else:  # z3.unknown
            reason = solver.reason_unknown()
            if 'timeout' in reason.lower() or 'canceled' in reason.lower():
                return 'timeout', f'Z3 timeout: {reason}'
            else:
                return 'unknown', None

    except FileNotFoundError:
        return 'error', 'File not found'
    except z3.Z3Exception as e:
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
