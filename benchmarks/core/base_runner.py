"""Base utilities for running benchmarks"""

import subprocess
from typing import Tuple, Optional


def run_smt2_with_z3(filepath: str, timeout: int = 10) -> Tuple[str, Optional[str]]:
    """
    Run an SMT-LIB 2.6 file directly with Z3

    Args:
        filepath: Path to .smt2 file
        timeout: Timeout in seconds

    Returns:
        (result, error) where result is 'sat', 'unsat', 'unknown', or 'timeout'
    """
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
        return 'error', 'Z3 not found in PATH'
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
