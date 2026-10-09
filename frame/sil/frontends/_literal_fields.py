"""Shared helper: a synthetic procedure holding string-literal field initializers.

Class fields (Java/C# ``String password = "..."``) and JavaScript object
properties never execute inside a method body, so they never reached the
literal scanner (``FrameScanner._scan_literals``), and a hardcoded credential
declared as a field -- by far the commonest place for one -- was invisible.

Only plain string-literal initializers are lowered. Anything else (calls,
concatenations, ...) is left alone, so this adds no taint sources or sinks and
cannot change taint results; the literal scanner's value-shape gate still
decides whether a given literal is actually a secret.
"""

from typing import List, Optional

from frame.sil.instructions import Assign
from frame.sil.procedure import NodeKind, Procedure
from frame.sil.types import Location, Typ


def literal_init_procedure(name: str, loc: Optional[Location],
                           assigns: List[Assign]) -> Optional[Procedure]:
    """Build a one-block procedure containing ``assigns``; ``None`` if empty."""
    if not assigns:
        return None
    proc = Procedure(name=name, params=[], ret_type=Typ.unknown_type(),
                     loc=loc, is_method=True)
    proc.is_static = True
    entry = proc.new_node(NodeKind.ENTRY)
    proc.add_node(entry)
    proc.entry_node = entry.id
    for a in assigns:
        entry.add_instr(a)
    exit_node = proc.new_node(NodeKind.EXIT)
    proc.add_node(exit_node)
    proc.exit_node = exit_node.id
    proc.connect(entry.id, exit_node.id)
    return proc
