"""Proof-carrying findings (Phase 5b, model-free core): confirm a finding by running it.

For a C integer-range or out-of-bounds finding whose witness is directly
constructible (every triggering value is a scalar parameter, see
`frame.sil.proof_tests`), this compiles a harness that calls the function with
the solver's inputs under AddressSanitizer + UndefinedBehaviorSanitizer and runs
it. If the sanitizer observes the fault, the finding is reproduced -- a true
positive by construction, raised to the ``exploit-confirmed`` evidence level.

This is deterministic and offline: no model, no network, no live target. It is a
confirmation step the caller invokes explicitly, never part of a scan. It fails
safe: anything other than an observed fault (a function that will not compile on
its own, a missing compiler, a timeout) leaves the finding exactly as it was.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from frame.sil.proof_tests import c_integer_test

# Sanitizer messages that mean the fault actually happened at runtime.
_FAULT_MARKERS = (
    "runtime error:",            # UBSan (signed overflow, out-of-range conversion)
    "AddressSanitizer",          # ASan (out-of-bounds)
    "SUMMARY: UndefinedBehaviorSanitizer",
    "SUMMARY: AddressSanitizer",
)


@dataclass
class ProofRun:
    """The outcome of trying to reproduce a finding by running it.

    status:
      * ``confirmed``       -- the sanitizer observed the fault; a true positive.
      * ``not-reproduced``  -- it built and ran, but no fault was observed.
      * ``not-constructible`` -- the witness is not directly constructible.
      * ``build-failed``    -- the function is not self-contained enough to compile alone.
      * ``skipped``         -- no compiler, or an unsupported proof family.
    """
    status: str
    detail: str = ""
    output: str = ""

    @property
    def confirmed(self) -> bool:
        return self.status == "confirmed"


def _compiler(cc: Optional[str]) -> Optional[str]:
    if cc:
        return cc if (os.path.isabs(cc) or shutil.which(cc)) else None
    return os.environ.get("CC") or shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")


_SANITIZER_CACHE: Dict[str, str] = {}


def _probe_flag(compiler: str, flag: str) -> bool:
    """Does the compiler accept this flag? (compiles a trivial program)."""
    try:
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "probe.c"
            src.write_text("int main(void){return 0;}\n")
            r = subprocess.run([compiler, flag, str(src), "-o", str(Path(d) / "probe")],
                               capture_output=True, text=True, errors="replace", timeout=30)
            return r.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def _sanitize_flag(compiler: str) -> str:
    """The `-fsanitize=` list this compiler supports. `address,undefined` is
    universal (Clang and GCC); `implicit-conversion` is Clang-only (it traps a
    value-changing narrowing/sign change, CWE-197/194/195), so it is probed and
    added only when supported. On GCC those conversions simply are not auto-
    confirmed -- never a wrong flag that fails every build (the 1.1.1 bug)."""
    if compiler not in _SANITIZER_CACHE:
        groups = ["address", "undefined"]
        if _probe_flag(compiler, "-fsanitize=implicit-conversion"):
            groups.append("implicit-conversion")
        _SANITIZER_CACHE[compiler] = "-fsanitize=" + ",".join(groups)
    return _SANITIZER_CACHE[compiler]


def confirm_c_integer_proof(
    source: str,
    func_name: str,
    proof: Dict,
    *,
    cc: Optional[str] = None,
    timeout: int = 30,
) -> ProofRun:
    """Compile and run a constructible C integer/out-of-bounds proof under sanitizers.

    Args:
        source: C source that defines ``func_name`` (and nothing that needs an
            external object to link -- a self-contained function).
        func_name: the function the harness calls.
        proof: a proof dict from `frame.sil.proof_tests` (families ``integer-range``
            or ``out-of-bounds``).
        cc: compiler to use; defaults to $CC, then cc/clang/gcc on PATH.
        timeout: seconds for the compile and for the run, each.

    Returns:
        A ProofRun. Only ``confirmed`` asserts the finding is real; every other
        status leaves the caller's evidence untouched.
    """
    if not proof or proof.get("family") not in ("integer-range", "out-of-bounds"):
        return ProofRun("skipped", "unsupported proof family")
    if not proof.get("constructible"):
        return ProofRun("not-constructible", "witness is not a function of parameters alone")
    inputs = proof.get("inputs") or {}
    # Parameter order: the keys of inputs follow the function's parameter order as
    # recorded by the proof builder (it iterates param_names).
    param_names: List[str] = list(inputs.keys())
    harness = c_integer_test(func_name, param_names, inputs,
                             cwe=proof.get("cwe"), trigger=proof.get("trigger", ""))
    if harness is None:
        return ProofRun("not-constructible", "an input value is missing for a parameter")

    combined = source.rstrip() + "\n\n" + harness
    outcome = compile_and_run_c(combined, cc=cc, timeout=timeout)
    if outcome.status == "skipped":
        return ProofRun("skipped", outcome.detail)
    if outcome.status == "build-failed":
        return ProofRun("build-failed", "the function did not compile standalone",
                        output=outcome.output)
    if outcome.faulted:
        return ProofRun("confirmed", f"{func_name}({', '.join(map(str, inputs.values()))}) "
                        f"faulted under the sanitizer", output=outcome.output)
    return ProofRun("not-reproduced", outcome.detail or "ran without an observed fault",
                    output=outcome.output)


@dataclass
class RunOutcome:
    """The result of compiling and running one complete C translation unit."""
    faulted: bool
    status: str          # "ran" | "build-failed" | "skipped"
    detail: str = ""
    output: str = ""


def compile_and_run_c(source: str, *, stdin: Optional[str] = None,
                      cc: Optional[str] = None, timeout: int = 30) -> RunOutcome:
    """Compile a complete C source (it must contain its own ``main``) under
    AddressSanitizer + UndefinedBehaviorSanitizer and run it, optionally feeding
    ``stdin``. ``faulted`` is True when the sanitizer reported a fault or the
    program exited non-zero. The shared sandbox for confirmation and reproduction;
    never raises."""
    compiler = _compiler(cc)
    if compiler is None:
        return RunOutcome(False, "skipped", "no C compiler available")
    with tempfile.TemporaryDirectory() as d:
        src_path = Path(d) / "repro.c"
        bin_path = Path(d) / "repro"
        src_path.write_text(source)
        # Compiler-aware sanitizer set (Clang gets implicit-conversion, GCC does not):
        # a wrong flag would fail every build. address+undefined cover signed overflow
        # and out-of-bounds on both; implicit-conversion (Clang) adds CWE-197/194/195.
        build = [compiler, "-g", "-O0",
                 _sanitize_flag(compiler),
                 "-fno-sanitize-recover=all",
                 str(src_path), "-o", str(bin_path)]
        try:
            bp = subprocess.run(build, capture_output=True, text=True,
                                errors="replace", timeout=timeout)
        except (subprocess.TimeoutExpired, OSError) as exc:
            return RunOutcome(False, "build-failed", f"compile error: {exc}")
        if bp.returncode != 0:
            return RunOutcome(False, "build-failed", "did not compile",
                              output=(bp.stderr or "")[-2000:])
        env = dict(os.environ,
                   UBSAN_OPTIONS="halt_on_error=1:abort_on_error=1:print_stacktrace=0",
                   ASAN_OPTIONS="abort_on_error=0:detect_leaks=0")
        try:
            # cwd is the temp dir, so a reproduction program that writes files
            # (an agent may open one to feed stdin) leaves nothing in the project.
            rp = subprocess.run([str(bin_path)], input=stdin, capture_output=True,
                                text=True, errors="replace", timeout=timeout, env=env,
                                cwd=d)
        except (subprocess.TimeoutExpired, OSError) as exc:
            return RunOutcome(False, "ran", f"run error: {exc}")
        out = (rp.stdout or "") + (rp.stderr or "")
        # A fault is ONLY a sanitizer report (a UBSan/ASan marker in the output).
        # A bare crash signal or non-zero exit is NOT trusted: the reproduction
        # program is written by an agent, which could call abort()/exit() to forge
        # a "fault" for code that has none (observed: an agent adding its own
        # overflow-check + abort around defined unsigned wraparound). A genuine
        # fault of the families we cover always emits a sanitizer marker; a forged
        # abort does not, so requiring the marker rejects the fabrication and keeps
        # every real case. Unsigned overflow is defined (no marker), so such a
        # finding is correctly never confirmed.
        faulted = any(m in out for m in _FAULT_MARKERS)
        return RunOutcome(faulted, "ran",
                          "faulted" if faulted else "ran without an observed fault",
                          output=out[-2000:])
