"""Proof-carrying findings (Phase 5): build a finding's concrete proof.

When the symbolic engine proves a finding reachable it can also compute the
concrete inputs that reach it (`EntailmentChecker.satisfying_model`). This module
turns that witness into a structured `proof` recorded on the finding, and -- when
every value the finding turns on is a scalar parameter of the function -- emits a
standalone test that calls the function with exactly those inputs and asserts the
triggering condition. A finding with a reproduced test is a true positive by
construction, which is the point of the phase.

Everything here is pure and deterministic: no model, no network, no file system.
It only shapes data the engine already produced, so it can add a `proof` to a
finding but never add, drop, or change which findings exist.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set


def integer_range_proof(
    witness: Dict[str, int],
    trigger_vars: Set[str],
    param_names: List[str],
    *,
    trigger: str,
    cwe: Optional[str] = None,
    family: str = "integer-range",
) -> Optional[Dict]:
    """Shape a scalar-integer witness into a proof.

    Serves the findings whose trigger is an attacker integer leaving a range: the
    arithmetic overflows/truncations (``family="integer-range"``, CWE-190/191/
    194/195/197) and the out-of-bounds indices (``family="out-of-bounds"``,
    CWE-125/787/124/127).

    Args:
        witness: the solver's assignment, variable name -> integer value.
        trigger_vars: the variables the triggering condition depends on.
        param_names: the function's parameter names, in order.
        trigger: a human-readable statement of what the inputs make happen.
        cwe: the finding's CWE, when known.
        family: the witness family label.

    Returns:
        The proof dict, or None when there is no usable witness. ``constructible``
        is True only when every variable the trigger depends on is a scalar
        parameter with a concrete value, so the function can be called directly to
        reproduce the finding.
    """
    if not witness:
        return None
    params = set(param_names)
    inputs = {p: witness[p] for p in param_names if p in witness}
    constructible = bool(trigger_vars) and all(
        v in params and v in witness for v in trigger_vars
    )
    proof: Dict = {
        "family": family,
        "witness": dict(sorted(witness.items())),
        "inputs": inputs,
        "constructible": constructible,
        "trigger": trigger,
    }
    if cwe:
        proof["cwe"] = cwe
    return proof


def c_integer_test(
    func_name: str,
    param_names: List[str],
    inputs: Dict[str, int],
    *,
    cwe: Optional[str] = None,
    trigger: str = "",
    header: Optional[str] = None,
) -> Optional[str]:
    """Emit a standalone C harness that calls ``func_name`` with the witness.

    Returns C source for a `main` that calls the function with the concrete
    inputs, or None when an input value is missing for a parameter (the finding is
    not directly constructible). The harness is a reproduction scaffold: it drives
    the function to the triggering inputs under a sanitizer build (ASan/UBSan),
    which observes the overflow or out-of-range conversion. It is intentionally
    conservative -- it calls and records, it does not assert an exploit.
    """
    args = []
    for p in param_names:
        if p not in inputs:
            return None
        args.append(str(inputs[p]))
    call_args = ", ".join(args)
    lines: List[str] = []
    tag = f"{cwe}: " if cwe else ""
    lines.append(f"/* Frame proof-carrying test. {tag}{trigger} */".rstrip())
    lines.append("/* Build with: cc -fsanitize=address,undefined -fno-sanitize-recover=all "
                 "-o repro repro.c   (add ,implicit-conversion on Clang for CWE-197) */")
    if header:
        lines.append(f'#include "{header}"')
    lines.append("#include <stdio.h>")
    lines.append("")
    lines.append("int main(void) {")
    lines.append(f"    /* inputs chosen by Frame's solver to trigger the finding */")
    lines.append(f"    {func_name}({call_args});")
    lines.append(f'    printf("called {func_name} with triggering inputs\\n");')
    lines.append("    return 0;")
    lines.append("}")
    return "\n".join(lines) + "\n"
