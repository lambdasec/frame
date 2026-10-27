"""
Library specifications for C# (ASP.NET Core, ADO.NET, EF, System.Diagnostics, ...).

The table itself is data: `data/csharp.toml` (one `[[spec]]` per call name, in lookup
order), loaded by `frame/sil/specs/tables.py`. Edit the TOML, then run the benchmark sweep.
"""

from typing import Dict

from frame.sil.procedure import ProcSpec
from frame.sil.specs.tables import load_table

CSHARP_SPECS: Dict[str, ProcSpec] = load_table("csharp")
