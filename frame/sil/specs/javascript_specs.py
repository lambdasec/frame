"""
Library specifications for JavaScript and TypeScript (Express, Node.js, MongoDB, DOM, ...).

The table itself is data: `data/javascript.toml` (one `[[spec]]` per call name, in lookup
order), loaded by `frame/sil/specs/tables.py`. Edit the TOML, then run the benchmark sweep.
"""

from typing import Dict

from frame.sil.procedure import ProcSpec
from frame.sil.specs.tables import load_table

JAVASCRIPT_SPECS: Dict[str, ProcSpec] = load_table("javascript")
TYPESCRIPT_SPECS = JAVASCRIPT_SPECS
