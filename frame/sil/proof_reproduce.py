"""Proof-carrying findings (Phase 5b): reproduce a finding whose input is not a bare parameter.

`frame.sil.proof_run` confirms a finding deterministically when the triggering
value is a scalar parameter. Many real C findings are not like that: the value
is read from stdin, argv or a file, so there is no parameter to pass. This module
closes that gap for C with a small, seeded agent loop.

The task is defensive QA, not offence: write a reproduction test -- a `main` that
feeds the program the input that makes the bug manifest -- so the bug can be fixed
and guarded against regression. The agent is seeded with the solver's witness (the
concrete value that triggers the finding) and the function, writes a complete C
program, and the harness compiles and runs it under AddressSanitizer +
UndefinedBehaviorSanitizer (`compile_and_run_c`). The loop is oracle-terminating:
success is an observed sanitizer fault, never the model's say-so. Everything runs
in a local sandbox against the project's own code; there is no network target.

Gated and opt-in; off by default. It adds no configuration of its own -- the model
endpoint and any budget come from the existing `[llm]` settings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from frame.sil.llm_agent import run_agent
from frame.sil.proof_run import compile_and_run_c

REPRODUCE_SYSTEM = (
    "You are a software engineer writing a REGRESSION TEST for a bug that static "
    "analysis has already found in your own C code. Your job is to make the bug "
    "manifest at runtime so it can be fixed and a guard added -- ordinary defensive "
    "QA, nothing more.\n\n"
    "You are given the source and a concrete input value the analyzer's solver says "
    "triggers the fault. Write ONE complete, self-contained C program: the given "
    "source, plus a `main` that drives the program's real input path (stdin, argv, "
    "or a direct call) with that value so the faulty line executes. The program is "
    "compiled under AddressSanitizer and UndefinedBehaviorSanitizer; a correct "
    "reproduction makes the sanitizer report the fault.\n\n"
    "Call the `try_program` tool with your full C source. Read the compiler and "
    "sanitizer output it returns and fix your program until the sanitizer reports "
    "the fault. Submit only the C program, no prose."
)

_TOOLS = [
    {"type": "function", "function": {
        "name": "try_program",
        "description": ("Compile the given complete C program under ASan+UBSan and run it. "
                        "Returns the compiler and sanitizer output. A reproduction succeeds "
                        "when the sanitizer reports the fault."),
        "parameters": {"type": "object",
                       "properties": {"source": {"type": "string",
                                                 "description": "the full C program source"}},
                       "required": ["source"]}}},
]

_STALL = ("Do not stop. Call `try_program` with your current best complete C program "
          "and iterate on the sanitizer output.")


@dataclass
class ReproduceResult:
    reproduced: bool
    test_source: str = ""
    detail: str = ""
    steps: int = 0
    output: str = ""
    transcript: List[Dict[str, Any]] = field(default_factory=list)


# How the attacker value enters, detected from the source, with how to drive each
# channel from the agent's own `main` (it writes the whole program, so it sets these up).
_CHANNELS = [
    ("stdin", ("fgets", "scanf", "getchar", "fread", "gets", "read("),
     "reads stdin: feed the value with `freopen` on a temp file, or the harness stdin"),
    ("environment", ("getenv", "secure_getenv"),
     "reads an environment variable: `setenv(\"NAME\", \"<value>\", 1)` before calling"),
    ("file", ("fopen", "open(", "fscanf"),
     "reads a file: create a temp file with the value, then point the code at it"),
    ("argv", ("argv", "main(int"),
     "reads argv: call the inner function directly with the value (the harness passes no args)"),
    ("socket", ("recv", "accept", "socket("),
     "reads a socket: if a server is impractical, call the function that processes the "
     "received bytes directly with the value"),
]


def _detect_channels(source: str) -> List[str]:
    out = []
    for name, needles, how in _CHANNELS:
        if any(n in source for n in needles):
            out.append(f"- {name}: the code {how}.")
    return out


def _seed(source: str, proof: Dict) -> str:
    witness = proof.get("witness") or {}
    vals = ", ".join(f"{k} = {v}" for k, v in witness.items())
    channels = _detect_channels(source)
    hint = ("\nThe input appears to enter through:\n" + "\n".join(channels) +
            "\n") if channels else ""
    return (f"Finding: {proof.get('cwe', '')} -- {proof.get('trigger', '')}\n"
            f"The solver's triggering values: {vals or '(none recorded)'}\n"
            f"{hint}\n"
            f"Source under test:\n```c\n{source.rstrip()}\n```\n\n"
            "Write a complete C program (the given source plus your own `main`) that drives "
            "the input through its real channel so this fault fires, and submit it with "
            "`try_program`. You write the whole program, so set up the channel yourself "
            "(set an env var, write a temp file, redirect stdin) rather than calling the "
            "vulnerable function with the value directly.")


def reproduce_c_finding(source: str, proof: Dict, config: Any,
                        client: Any = None, *,
                        max_steps: int = 6,
                        cc: Optional[str] = None,
                        timeout: int = 30) -> ReproduceResult:
    """Drive a seeded agent to write a C program that reproduces the finding.

    Args:
        source: the C source that contains the faulty function.
        proof: the finding's proof (`frame.sil.proof_tests`); its ``witness`` seeds the agent.
        config: an LLM config (``[llm]`` settings); the endpoint comes from there.
        client: reuse an LLMClient, else one is built from config.
        max_steps: tool turns the agent gets.

    Returns:
        A ReproduceResult. ``reproduced`` is True only when the sanitizer observed
        the fault on the agent's program -- the oracle, never the model's claim.
    """
    try:
        from frame.sil.llm_client import LLMClient
    except ImportError:
        return ReproduceResult(False, detail="LLM client unavailable")
    if client is None:
        client = LLMClient(config)

    state: Dict[str, Any] = {"source": "", "output": ""}

    def _exec(name: str, args: Dict[str, Any]) -> str:
        if name != "try_program":
            return f"error: unknown tool {name!r}"
        prog = args.get("source", "")
        if not prog.strip():
            return "error: empty program"
        outcome = compile_and_run_c(prog, cc=cc, timeout=timeout)
        if outcome.status == "skipped":
            return "error: no C compiler available"
        if outcome.faulted:
            state["source"] = prog
            state["output"] = outcome.output
            return "SANITIZER REPORTED THE FAULT -- reproduced:\n" + outcome.output
        if outcome.status == "build-failed":
            return "did not compile:\n" + outcome.output
        return "ran without a sanitizer fault; adjust the input:\n" + outcome.output

    def _done():
        return True if state["source"] else None

    messages = [
        {"role": "system", "content": REPRODUCE_SYSTEM},
        {"role": "user", "content": _seed(source, proof)},
    ]
    res = run_agent(messages, client, tools=_TOOLS, exec_tool=_exec,
                    max_steps=max_steps, check_done=_done, stall_nudge=_STALL)
    return ReproduceResult(
        reproduced=bool(state["source"]),
        test_source=state["source"],
        detail="reproduced under the sanitizer" if state["source"] else "not reproduced",
        steps=res.steps,
        output=state["output"],
        transcript=res.transcript,
    )
