"""Proof-carrying findings (Phase 5a): recovering the concrete witness.

`EntailmentChecker.satisfying_model` re-solves an already-satisfiable pure
arithmetic formula and returns the integer assignment Z3 found, so a C
integer-range finding can be turned into a test that calls the code with inputs
that actually trigger it. These tests pin that the witness is concrete and that
it genuinely satisfies the formula (a false witness is worse than none).
"""

from frame.checking.checker import EntailmentChecker
from frame.core.ast import Var, Const, And, Gt, Ge, Le, Lt, Or, ArithExpr

INT32_MAX = (1 << 31) - 1
INT32_MIN = -(1 << 31)


def _in_int32(v):
    return And(Ge(v, Const(INT32_MIN)), Le(v, Const(INT32_MAX)))


def test_overflow_witness_is_a_concrete_int_that_overflows():
    # n is an int32; can n * n exceed INT32_MAX? (CWE-190 shape)
    checker = EntailmentChecker()
    n = Var("n")
    formula = And(_in_int32(n), Gt(ArithExpr("*", n, n), Const(INT32_MAX)))
    model = checker.satisfying_model(formula)
    assert model is not None
    assert "n" in model
    val = model["n"]
    assert INT32_MIN <= val <= INT32_MAX          # respects the declared type
    assert val * val > INT32_MAX                   # really overflows


def test_underflow_witness_respects_bounds():
    # d - e below INT32_MIN with both in range (CWE-191 shape)
    checker = EntailmentChecker()
    d, e = Var("d"), Var("e")
    formula = And(And(_in_int32(d), _in_int32(e)),
                  Lt(ArithExpr("-", d, e), Const(INT32_MIN)))
    model = checker.satisfying_model(formula)
    assert model is not None
    assert INT32_MIN <= model["d"] <= INT32_MAX
    assert INT32_MIN <= model["e"] <= INT32_MAX
    assert model["d"] - model["e"] < INT32_MIN


def test_truncation_witness_is_outside_narrow_range():
    # i is an int32 that falls outside int8 range when stored into a char (CWE-197)
    checker = EntailmentChecker()
    i = Var("i")
    formula = And(_in_int32(i), Or(Lt(i, Const(-128)), Gt(i, Const(127))))
    model = checker.satisfying_model(formula)
    assert model is not None
    v = model["i"]
    assert v < -128 or v > 127


def test_unsatisfiable_formula_has_no_model():
    # A guard that pins the value in range makes the overflow impossible.
    checker = EntailmentChecker()
    n = Var("n")
    formula = And(And(_in_int32(n), Lt(n, Const(1000))),
                  Gt(ArithExpr("*", n, Const(2)), Const(INT32_MAX)))
    assert checker.satisfying_model(formula) is None


def test_model_extraction_never_raises_on_non_arithmetic():
    # A spatial formula is out of scope; must return None, not raise.
    from frame.core.ast import PointsTo
    checker = EntailmentChecker()
    model = checker.satisfying_model(PointsTo(Var("x"), Var("y")))
    assert model is None or isinstance(model, dict)


# --- the pure proof builder -------------------------------------------------

from frame.sil.proof_tests import integer_range_proof, c_integer_test


def test_proof_is_constructible_when_the_trigger_var_is_a_parameter():
    proof = integer_range_proof(
        {"n": 70000}, {"n"}, ["n"], trigger="n*n overflows int", cwe="CWE-190")
    assert proof is not None
    assert proof["constructible"] is True
    assert proof["inputs"] == {"n": 70000}
    assert proof["cwe"] == "CWE-190"


def test_proof_is_not_constructible_when_the_trigger_var_is_a_local():
    # The overflowing value is a local derived elsewhere, not a parameter.
    proof = integer_range_proof(
        {"tmp": 70000}, {"tmp"}, ["unrelated"], trigger="tmp overflows")
    assert proof is not None
    assert proof["constructible"] is False
    assert proof["inputs"] == {}            # no parameter got a value
    assert proof["witness"] == {"tmp": 70000}   # the witness is still recorded


def test_proof_none_without_a_witness():
    assert integer_range_proof({}, {"n"}, ["n"], trigger="x") is None


def test_c_test_emits_the_call_with_witness_values():
    src = c_integer_test("f", ["a", "b"], {"a": 5, "b": 70000},
                         cwe="CWE-190", trigger="a*b overflows")
    assert src is not None
    assert "f(5, 70000);" in src
    assert "-fsanitize" in src
    assert "CWE-190" in src


def test_c_test_none_when_a_parameter_has_no_witness_value():
    # b is a parameter but the witness never bound it: not directly constructible.
    assert c_integer_test("f", ["a", "b"], {"a": 5}) is None


# --- end to end on a real C function (needs the C grammar; CI) --------------

HDR_C = "#include <stdio.h>\n#include <stdlib.h>\n"


def _scan_c_all(src):
    import pytest
    pytest.importorskip("tree_sitter_c")
    from frame.sil.scanner import FrameScanner
    r = FrameScanner(language="c", verify=False).scan(src, "t.c")
    assert not r.errors, r.errors
    return list(r.vulnerabilities)


def _scan_c(src):
    return [v for v in _scan_c_all(src) if (v.cwe_id or "") == "CWE-190"]


def test_c_overflow_from_a_parameter_is_a_constructible_proof():
    # Attacker data flows into scale's int parameter n; n * n overflows int32,
    # so the finding is directly reproducible by calling scale(witness).
    src = (HDR_C
           + "void scale(int n) {\n int r = n * n;\n printf(\"%d\", r);\n}\n"
           + "void handler(void) {\n char in[16]; fgets(in, 16, stdin);\n"
             " int d = atoi(in);\n scale(d);\n}\n")
    overflow = _scan_c(src)
    proved = [v for v in overflow if v.proof and v.procedure == "scale"]
    assert proved, "the parameter-driven overflow should carry a proof"
    proof = proved[0].proof
    assert proof["family"] == "integer-range" and proof["cwe"] == "CWE-190"
    n = proof["witness"]["n"]
    assert n * n > (1 << 31) - 1          # the witness really overflows int32
    assert proof["constructible"] is True
    assert proof["inputs"] == {"n": n}
    # a reproduction harness can be emitted from a constructible proof
    assert c_integer_test("scale", ["n"], proof["inputs"], cwe="CWE-190")
    assert proved[0].to_dict()["proof"]["witness"] == proof["witness"]


def test_c_out_of_bounds_index_carries_a_proof_labelled_out_of_bounds():
    # Attacker data flows into get's index parameter i; buf has extent 64, so an
    # unguarded buf[i] can read past the end. The witness is a concrete index.
    src = (HDR_C
           + "int get(int i) {\n static int buf[64];\n return buf[i];\n}\n"
           + "void handler(void) {\n char in[16]; fgets(in, 16, stdin);\n"
             " int d = atoi(in);\n printf(\"%d\", get(d));\n}\n")
    overflow = [v for v in _scan_c_all(src) if (v.cwe_id or "") == "CWE-125"]
    proved = [v for v in overflow if v.proof]
    assert proved, "the out-of-bounds read should carry a proof"
    proof = proved[0].proof
    assert proof["family"] == "out-of-bounds"
    assert proof["constructible"] is True
    assert proof["inputs"]["i"] >= 64          # the witness index is past the extent


def test_c_overflow_from_stdin_records_the_witness_but_is_not_constructible():
    # The overflowing value is a local read from stdin, not a parameter, so the
    # witness is recorded (a concrete overflowing value) but constructible is False.
    src = (HDR_C + "void f(void) {\n char in[16]; fgets(in, 16, stdin);\n"
           " int d = atoi(in);\n int r = d * d;\n printf(\"%d\", r);\n}\n")
    overflow = _scan_c(src)
    proved = [v for v in overflow if v.proof]
    assert proved, "the finding should still carry a witness"
    proof = proved[0].proof
    assert proof["constructible"] is False
    assert proof["inputs"] == {}
    d = proof["witness"]["d"]
    assert d * d > (1 << 31) - 1


# --- running a constructible proof under sanitizers (needs a C compiler) ----

def _need_cc():
    import shutil, pytest
    if not (shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")):
        pytest.skip("no C compiler available")


def test_run_confirms_a_constructible_overflow():
    _need_cc()
    from frame.sil.proof_run import confirm_c_integer_proof
    proof = {"family": "integer-range", "cwe": "CWE-190", "constructible": True,
             "inputs": {"n": 1476388701}, "trigger": "n*n overflows int"}
    r = confirm_c_integer_proof("int scale(int n){ return n*n; }\n", "scale", proof)
    assert r.confirmed, (r.status, r.output)
    assert "overflow" in r.output.lower()


def test_run_confirms_a_constructible_out_of_bounds():
    _need_cc()
    from frame.sil.proof_run import confirm_c_integer_proof
    proof = {"family": "out-of-bounds", "cwe": "CWE-125", "constructible": True,
             "inputs": {"i": 64}, "trigger": "buf[i] out of bounds"}
    r = confirm_c_integer_proof("int get(int i){ static int buf[64]; return buf[i]; }\n",
                                "get", proof)
    assert r.confirmed, (r.status, r.output)


def test_run_leaves_a_non_constructible_proof_alone():
    from frame.sil.proof_run import confirm_c_integer_proof
    r = confirm_c_integer_proof("int f(void){return 0;}", "f",
                                {"family": "integer-range", "constructible": False, "inputs": {}})
    assert r.status == "not-constructible"
    assert not r.confirmed


def test_run_reports_build_failure_without_crashing():
    _need_cc()
    from frame.sil.proof_run import confirm_c_integer_proof
    # references an undeclared external symbol -> will not compile standalone
    proof = {"family": "integer-range", "cwe": "CWE-190", "constructible": True,
             "inputs": {"n": 70000}, "trigger": "x"}
    r = confirm_c_integer_proof("int scale(int n){ return helper(n)*n; }\n", "scale", proof)
    assert r.status in ("build-failed", "not-reproduced")
    assert not r.confirmed


def test_a_safe_function_is_not_reproduced():
    _need_cc()
    from frame.sil.proof_run import confirm_c_integer_proof
    # guarded: the value is clamped, so the call does not overflow
    proof = {"family": "integer-range", "cwe": "CWE-190", "constructible": True,
             "inputs": {"n": 10}, "trigger": "x"}
    r = confirm_c_integer_proof("int scale(int n){ if (n>100) n=100; return n*n; }\n",
                                "scale", proof)
    assert r.status == "not-reproduced"
    assert not r.confirmed


# --- scanner integration: confirm_proofs upgrades evidence, emits the test ----

def test_scanner_confirm_proofs_upgrades_evidence_and_writes_test(tmp_path):
    _need_cc()
    import pytest
    pytest.importorskip("tree_sitter_c")
    from frame.sil.scanner import FrameScanner
    src = (HDR_C + "int scale(int n) {\n int r = n * n;\n return r;\n}\n"
           "void handler(void) {\n char in[16]; fgets(in, 16, stdin);\n"
           " int d = atoi(in);\n printf(\"%d\", scale(d));\n}\n")
    out = tmp_path / "proofs"
    scanner = FrameScanner(language="c", verify=False,
                           confirm_proofs=True, proof_tests_dir=str(out))
    result = scanner.scan(src, "t.c")
    confirmed = [v for v in result.vulnerabilities
                 if v.evidence == "exploit-confirmed" and (v.cwe_id or "") == "CWE-190"]
    assert confirmed, "the constructible overflow should be confirmed"
    proof = confirmed[0].proof
    assert proof["run"]["status"] == "confirmed"
    # a regression test was written and is itself self-contained C
    written = list(out.glob("*.c"))
    assert written, "a reproduction test should be written"
    assert "int main(void)" in written[0].read_text()


def test_scanner_confirm_proofs_is_off_by_default(tmp_path):
    import pytest
    pytest.importorskip("tree_sitter_c")
    from frame.sil.scanner import FrameScanner
    src = (HDR_C + "int scale(int n) {\n int r = n * n;\n return r;\n}\n"
           "void handler(void) {\n char in[16]; fgets(in, 16, stdin);\n"
           " int d = atoi(in);\n printf(\"%d\", scale(d));\n}\n")
    result = FrameScanner(language="c", verify=False).scan(src, "t.c")
    # findings still carry a proof, but nothing is run, so none is exploit-confirmed
    assert all(v.evidence != "exploit-confirmed" for v in result.vulnerabilities)
    proofs = [v.proof for v in result.vulnerabilities if v.proof]
    assert proofs and all("run" not in p for p in proofs)


def test_both_cli_parsers_accept_confirm_proofs():
    # The flag must parse on the installed `frame` entrypoint AND the sil CLI.
    from frame.cli import create_parser as frame_parser
    from frame.sil.cli import create_parser as sil_parser
    for make in (frame_parser, sil_parser):
        args = make().parse_args(["scan", "x.c", "--confirm-proofs",
                                  "--proof-tests-dir", "out"])
        assert args.confirm_proofs is True
        assert args.proof_tests_dir == "out"


# --- reproduction loop for non-constructible findings (stub client, no network) ---

import json as _json


class _StubClient:
    """A canned LLM client: emits one try_program tool call, then stops."""
    def __init__(self, program):
        self._program = program
        self._n = 0
        self.last_call = {}

    def chat_raw(self, messages, tools):
        self._n += 1
        if self._n == 1:
            return {"content": "", "tool_calls": [{"id": "1", "function": {
                "name": "try_program",
                "arguments": _json.dumps({"source": self._program})}}]}
        return {"content": "done", "tool_calls": []}


def test_reproduce_confirms_when_the_agents_program_faults():
    _need_cc()
    from frame.sil.proof_reproduce import reproduce_c_finding
    source = ("#include <stdlib.h>\nint scale(int n){ int r=n*n; return r; }\n")
    proof = {"cwe": "CWE-190", "trigger": "n*n overflows int",
             "witness": {"d": 46341}, "family": "integer-range", "constructible": False}
    # the agent drives the witness value into the function
    program = ("#include <stdlib.h>\nint scale(int n){ int r=n*n; return r; }\n"
               "int main(void){ return scale(46341); }\n")
    r = reproduce_c_finding(source, proof, config=None,
                            client=_StubClient(program), max_steps=4)
    assert r.reproduced is True
    assert "overflow" in r.output.lower()
    assert r.test_source


def test_reproduce_fails_when_the_program_does_not_fault():
    _need_cc()
    from frame.sil.proof_reproduce import reproduce_c_finding
    source = "int scale(int n){ return n; }\n"
    proof = {"cwe": "CWE-190", "trigger": "x", "witness": {"d": 5},
             "family": "integer-range", "constructible": False}
    safe = "int scale(int n){ return n; }\nint main(void){ return scale(5); }\n"
    r = reproduce_c_finding(source, proof, config=None,
                            client=_StubClient(safe), max_steps=3)
    assert r.reproduced is False
    assert not r.test_source


def test_reproduce_seed_names_the_witness_and_cwe():
    from frame.sil.proof_reproduce import _seed
    s = _seed("int f(void){return 0;}", {"cwe": "CWE-125", "trigger": "oob",
                                         "witness": {"i": 99}})
    assert "CWE-125" in s and "i = 99" in s


def test_reproduce_proofs_flag_parses_on_both_parsers_and_implies_confirm():
    from frame.cli import create_parser as frame_parser
    from frame.sil.cli import create_parser as sil_parser
    from frame.sil.scanner import FrameScanner
    for make in (frame_parser, sil_parser):
        args = make().parse_args(["scan", "x.c", "--reproduce-proofs"])
        assert args.reproduce_proofs is True
    s = FrameScanner(language="c", verify=False, reproduce_proofs=True)
    assert s.confirm_proofs and s.reproduce_proofs      # reproduce implies confirm


def test_reproduce_without_an_endpoint_skips_gracefully(monkeypatch):
    import pytest
    pytest.importorskip("tree_sitter_c")
    for k in ("FRAME_LLM_BASE_URL", "FRAME_LLM_MODEL", "FRAME_LLM_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    from frame.sil.scanner import FrameScanner
    src = (HDR_C + "int f(void) {\n char in[16]; fgets(in, 16, stdin);\n"
           " int d = atoi(in);\n int r = d * d;\n return r;\n}\n")
    result = FrameScanner(language="c", verify=False, reproduce_proofs=True).scan(src, "t.c")
    nc = [v for v in result.vulnerabilities if v.proof and not v.proof["constructible"]]
    assert nc, "expected a non-constructible finding"
    # no endpoint: recorded as skipped, evidence left untouched (never falsely confirmed)
    assert nc[0].proof["run"]["status"] == "skipped"
    assert nc[0].evidence != "exploit-confirmed"


def test_a_forged_abort_is_not_a_reproduction():
    # The reproduction program is agent-written; a bare abort()/crash with NO
    # sanitizer report must NOT count as a fault (else an agent forges proof).
    _need_cc()
    from frame.sil.proof_run import compile_and_run_c
    forged = ("#include <stdlib.h>\nint main(void){ abort(); }\n")
    out = compile_and_run_c(forged)
    assert out.status == "ran"
    assert out.faulted is False, "a forged abort must not be treated as a fault"


def test_reproduce_rejects_a_program_that_forges_a_fault():
    _need_cc()
    from frame.sil.proof_reproduce import reproduce_c_finding
    source = "#include <stdlib.h>\nunsigned f(unsigned d){ return d << 20; }\n"  # defined, no UB
    proof = {"cwe": "CWE-190", "trigger": "shift", "witness": {"d": 4096},
             "family": "integer-range", "constructible": False}
    # agent tries to fake it with its own abort(): must be rejected
    forged = ("#include <stdlib.h>\nunsigned f(unsigned d){ return d << 20; }\n"
              "int main(void){ if (4096u > (0xffffffffu >> 20)) abort(); return 0; }\n")
    r = reproduce_c_finding(source, proof, config=None,
                            client=_StubClient(forged), max_steps=3)
    assert r.reproduced is False
    assert not r.test_source
