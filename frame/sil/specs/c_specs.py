"""
Library specifications for C and C++ (libc, POSIX, sockets, OpenSSL, STL, ...).

The table itself is data: `data/c.toml` and `data/cpp.toml` (one `[[spec]]` per call name, in lookup
order), loaded by `frame/sil/specs/tables.py`. Edit the TOML, then run the benchmark sweep.
"""

from typing import Dict

from frame.sil.procedure import ProcSpec
from frame.sil.specs.tables import load_table

C_SPECS: Dict[str, ProcSpec] = load_table("c")
CPP_SPECS: Dict[str, ProcSpec] = load_table("cpp")
