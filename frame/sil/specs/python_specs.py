"""
Library specifications for Python (Flask, Django, SQLAlchemy, subprocess, ...).

The table itself is data: `data/python.toml` (one `[[spec]]` per call name, in lookup
order), loaded by `frame/sil/specs/tables.py`. Edit the TOML, then run the benchmark sweep.
"""

from typing import Dict

from frame.sil.procedure import ProcSpec
from frame.sil.specs.tables import load_table

PYTHON_SPECS: Dict[str, ProcSpec] = load_table("python")


def get_python_specs() -> Dict[str, ProcSpec]:
    """Get all Python library specifications"""
    return PYTHON_SPECS.copy()
