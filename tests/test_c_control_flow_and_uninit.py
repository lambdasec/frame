"""C control flow the frontend used to drop, and CWE-457 decided by the solver.

1. `break` / `continue`, comma expressions in `for`, nested `x++` / `--x`, and
   the `TRUE` / `FALSE` macros are lowered into the IR. Dropping them made the
   CFG and the path facts describe paths that do not exist (a `while (TRUE)`
   loop left only by `break` could "exit" before its body ran; `n++` inside an
   expression left a stale `n == 0` fact).
2. A function-like macro defined in the file may assign its arguments, so a
   bare variable passed to one is not a by-value read.
3. "x has no value yet" is a ghost path fact (`x#uninit`), and a read is
   reported only if the solver finds a feasible path on which it still holds.

Each behavioural test came from a false positive on real C (bitarray, cffi,
psutil) or pins the true positive next to it.
"""

import pytest

from frame.core.ast import Const, Eq, False_, Var
from frame.sil.frontends.c_frontend import CFrontend
from frame.sil.instructions import Assign, Prune
from frame.sil.procedure import NodeKind
from frame.sil.scanner import FrameScanner
from frame.sil.translator import SILTranslator

HDR = "#include <stdio.h>\n#include <stdlib.h>\n"


def translate(*lines):
    return CFrontend().translate(HDR + "\n".join(lines) + "\n", "t.c")


def proc_of(*lines, name="f"):
    return translate(*lines).procedures[name]


def reachable(proc):
    seen, stack = set(), [proc.entry_node]
    while stack:
        n = stack.pop()
        if n in seen or n not in proc.nodes:
            continue
        seen.add(n)
        stack.extend(proc.nodes[n].succs)
    return seen


def cwes(*lines, verify=False):
    r = FrameScanner(language="c", verify=verify).scan(HDR + "\n".join(lines) + "\n", "t.c")
    assert not r.errors, r.errors
    return {v.cwe_id for v in r.vulnerabilities}


def writes(proc):
    return [(str(i.id), str(i.exp)) for n in proc.nodes.values() for i in n.instrs
            if isinstance(i, Assign) and not getattr(i, "is_uninit_decl", False)]


# ---- 1. control flow and writes the frontend used to drop ------------------------

def test_break_jumps_to_the_loop_exit_and_ends_the_path():
    proc = proc_of("void use(int);", "void f(int n){", "while (n > 0) {", "break;", "use(1);", "}", "}")
    live = reachable(proc)
    # `use(1)` sits after the break: it must not be reachable.
    assert not any("use" in str(i) for nid in live for i in proc.nodes[nid].instrs
                   if not isinstance(i, Prune))


def test_continue_in_a_for_loop_skips_the_rest_of_the_body_but_runs_the_update():
    from frame.sil.instructions import Call
    proc = proc_of("void use(int);", "void f(int n){", "int i;",
                   "for (i = 0; i < n; i++) {", "if (i == 2) continue;", "use(i);", "}", "}")
    update = next(nid for nid, node in proc.nodes.items()
                  if any(isinstance(i, Assign) and str(i.id) == "i" and str(i.exp) == "(i + 1)"
                         for i in node.instrs))
    branch = next(node for node in proc.nodes.values()
                  if any(isinstance(i, Prune) and str(i.condition) == "(i == 2)" for i in node.instrs))
    # From the `i == 2` true edge, the update is reachable without running use(i).
    seen, stack = set(), [branch.succs[0]]
    while stack:
        nid = stack.pop()
        if nid in seen:
            continue
        if any(isinstance(i, Call) for i in proc.nodes[nid].instrs):
            continue   # this path ran use(i)
        seen.add(nid)
        if nid == update:
            break
        stack.extend(proc.nodes[nid].succs)
    assert update in seen


def test_break_inside_a_switch_does_not_leave_the_enclosing_loop():
    proc = proc_of("void use(int);", "void f(int n, int c){", "while (n > 0) {",
                   "switch (c) {", "case 1:", "if (n) { break; }", "use(1);", "break;", "}",
                   "n = n - 1;", "}", "}")
    assert any(w == ("n", "(n - 1)") for w in writes(proc))
    live = reachable(proc)
    assert any(any(isinstance(i, Assign) and str(i.id) == "n" for i in proc.nodes[nid].instrs)
               for nid in live)


def test_comma_expressions_in_for_initializer_and_update_are_lowered():
    w = writes(proc_of("void use(int);", "void f(int n, int s){", "int i, j;",
                       "for (i = 0, j = s; i < n; i++, j += 2) use(j);", "}"))
    for expected in [("i", "0"), ("j", "s"), ("i", "(i + 1)"), ("j", "(j + 2)")]:
        assert expected in w, expected


def test_nested_increment_is_a_write_and_postfix_yields_the_old_value():
    w = writes(proc_of("void use(int);", "void f(){", "int n = 0;", "use(n++);", "use(--n);", "}"))
    assert ("n", "(n + 1)") in w and ("n", "(n - 1)") in w
    olds = [t for t, e in w if e == "n" and t.startswith("$")]
    assert olds, "the postfix value is read into a temporary before the bump"


def test_a_nested_write_removes_the_stale_fact():
    prog = translate("void use(int);", "void f(){", "int n = 0;", "use(n++);", "}")
    proc = prog.procedures["f"]
    t = SILTranslator(prog)
    t._cur_proc = proc
    facts = []
    for i in proc.nodes[proc.entry_node].instrs:
        facts = t._advance_path_facts(facts, i)
    assert "n = 0" not in [str(g) for g in facts]


def test_loop_condition_side_effect_runs_in_the_loop_head():
    proc = proc_of("void use(int);", "void f(int n){", "while (n--) {", "use(n);", "}", "}")
    head = next(n for n in proc.nodes.values() if n.kind == NodeKind.LOOP_HEAD)
    assert any(isinstance(i, Assign) and str(i.id) == "n" for i in head.instrs)


def test_a_constant_false_loop_exit_is_never_taken_by_the_path_facts():
    # `while (TRUE)` / `while (1)` can only be left by `break`; the exit edge of
    # the condition is dead, so nothing after a break-less loop is reachable.
    for cond in ("TRUE", "1"):
        prog = translate("void use(int);", "void f(int c){", f"while ({cond}) {{", "use(c);", "}",
                         "use(0);", "}")
        proc = prog.procedures["f"]
        t = SILTranslator(prog)
        t._cur_proc = proc
        entry = t._path_fact_fixpoint(proc)
        after = [nid for nid, node in proc.nodes.items()
                 if any("use" in str(getattr(i, "func", "")) and "0" in str(getattr(i, "args", ""))
                        for i in node.instrs)]
        assert after and not any(nid in entry for nid in after), cond


# ---- 2. function-like macros ---------------------------------------------------

def test_function_like_macros_defined_in_the_file_are_recorded():
    prog = translate("#define GET(x, v) ((x) = (v))", "#define N 4", "void f(){ }")
    assert prog.function_macros == {"GET"}


def test_bare_argument_to_a_macro_may_be_written_but_to_a_function_is_read():
    assert "CWE-457" not in cwes("#define GET(x, v) ((x) = (v))", "void use(int);",
                                 "void f(){", "int x;", "GET(x, 3);", "use(x);", "}")
    assert "CWE-457" in cwes("void get(int, int);", "void use(int);",
                             "void f(){", "int x;", "get(x, 3);", "}")


# ---- 3. CWE-457 decided by the solver ------------------------------------------

@pytest.mark.parametrize("name, body", [
    ("uninitialized on the else path", ["int f(int c){", "int x;", "if (c) x = 1;", "return x;", "}"]),
    ("read by value", ["void use(int);", "void f(){", "int data;", "use(data);", "}"]),
    ("loop that may not run", ["void use(int);", "void f(int n){", "int x;", "int i;",
                               "for (i = 0; i < n; i++) { x = i; }", "use(x);", "}"]),
])
def test_feasible_uninitialized_read_is_reported(name, body):
    assert "CWE-457" in cwes(*body), name


@pytest.mark.parametrize("name, body", [
    ("assigned and read under the same condition (bitarray ssqi)",
     ["void use(int);", "void f(int c){", "int x;", "if (c > 5) x = 1;", "if (c > 5) use(x);", "}"]),
    ("early return on the other condition",
     ["unsigned long g(void);", "int h(unsigned long);", "int f(unsigned long n, unsigned long lim){",
      "unsigned long res;", "if (n <= lim)", "res = g();", "if (n > lim)", "return -1;",
      "return h(res);", "}"]),
    ("assigned on both branches", ["int f(int c){", "int x;", "if (c) x = 1; else x = 2;", "return x;", "}"]),
    ("loop left only by break (psutil get_proc_info)",
     ["int next(void);", "void use(int);", "void f(){", "int s;", "while (TRUE) {",
      "s = next();", "if (s > 0) break;", "}", "use(s);", "}"]),
    ("comma initializer (bitarray getslice)",
     ["void use(int);", "void f(int n, int s){", "int i, j;",
      "for (i = 0, j = s; i < n; i++, j += 2) use(j);", "}"]),
    ("macro assigns its argument (cffi lib_setattr)",
     ["#define GET(x, v) ((x) = (v))", "void use(int);", "void f(){", "int x;", "GET(x, 3);",
      "use(x);", "}"]),
])
def test_infeasible_uninitialized_read_is_not_reported(name, body):
    assert "CWE-457" not in cwes(*body), name


def test_definedness_is_a_ghost_fact_not_memory():
    prog = translate("void g(void);", "void f(int c){", "int x;", "if (c) x = 1;", "g();", "}")
    proc = prog.procedures["f"]
    t = SILTranslator(prog)
    t._cur_proc = proc
    facts = t._advance_path_facts([], proc.nodes[proc.entry_node].instrs[0], ghosts=True)
    assert [str(g) for g in facts] == [str(Eq(Var("x#uninit"), Const(1)))]
    # A call cannot reach definedness, so it does not havoc the ghost.
    assert not any(v.endswith("#uninit") for v in t._havoc_vars(
        next(i for n in proc.nodes.values() for i in n.instrs if "g" in str(getattr(i, "func", ""))),
        facts))


def test_statement_compound_assignment_keeps_the_old_value():
    w = writes(proc_of("int g(void);", "void f(int a){", "int x = 1;", "x += a;", "x <<= 2;",
                       "x -= g();", "}"))
    assert ("x", "(x + a)") in w and ("x", "(x << 2)") in w
    assert any(t == "x" and e.startswith("(x - ") for t, e in w)


# ---- precision of the path facts (found on real C) -----------------------------

def test_forgetting_a_variable_weakens_only_its_atoms():
    from frame.core.ast import And, Neq, Not, Or
    t = SILTranslator(translate("void f(){ }"))
    keep = And(Eq(Var("raddr"), Const(None)), Eq(Var("rport#uninit"), Const(1)))
    fact = Or(Eq(Var("rport#uninit"), Const(0)), And(keep, Eq(Var("g(x)"), Const(0))))
    [weaker] = t._forget([fact], {"g(x)"})
    assert str(weaker) == str(Or(Eq(Var("rport#uninit"), Const(0)), keep))
    # Under a negation a forgotten atom becomes unknown too, never a new fact.
    assert t._forget([Not(Eq(Var("g(x)"), Const(0)))], {"g(x)"}) == []
    assert t._forget([And(Neq(Var("a"), Const(0)), Eq(Var("b"), Const(1)))], {"a"})[0].free_vars() == {"b"}


def test_a_call_result_atom_does_not_take_the_branch_correlation_with_it():
    # psutil aix process_file: rport is set exactly where raddr is, and read under
    # `raddr != NULL`; a call result inside the joined fact was invalidated by the
    # next call and used to discard the whole disjunction.
    body = ["int probe(int);", "int use(int, int);", "int f(int fam){",
            "unsigned char *raddr = (unsigned char *)NULL;", "int rport;", "int x = 0;",
            "if (fam == 6) {", "if (probe(fam) == 0) {", "raddr = (unsigned char *)&x;",
            "rport = probe(1);", "}", "}", "probe(2);",
            "if (raddr != NULL) {", "return use(rport, 0);", "}", "return 0;", "}"]
    assert "CWE-457" not in cwes(*body)


def test_oversized_join_forgets_volatile_atoms_before_giving_up():
    from frame.sil.procedure import Program, Procedure
    t = SILTranslator(Program(language="c"))
    p = Procedure(name="f", params=[])
    p.locals = {"x": None}
    t._cur_proc = p
    noise1 = [Eq(Var(f"s.f{i}"), Const(i)) for i in range(40)]
    noise2 = [Eq(Var(f"s.g{i}"), Const(i)) for i in range(40)]
    joined = t._join_path_conditions(noise1 + [Eq(Var("x"), Const(1))],
                                     noise2 + [Eq(Var("x"), Const(2))])
    assert [str(g) for g in joined] == ["(x = 1 | x = 2)"]


def test_guard_arithmetic_is_over_the_real_variable():
    # bitarray ba2hex: `str` is set when `nbits % 4 == 0` and read only after
    # `if (nbits % 4) return`; a call in between used to forget the opaque
    # "(nbits % 4)" name.
    body = ["char *conv(int);", "void lock(void);", "int put(char*);", "int f(int nbits){",
            "char *str;", "if (nbits % 4 == 0)", "str = conv(nbits);", "lock();",
            "if (nbits % 4)", "return -1;", "return put(str);", "}"]
    assert "CWE-457" not in cwes(*body)
    t = SILTranslator(translate("void f(){ }"))
    from frame.sil.types import ExpBinOp, ExpCast, ExpConst, ExpVar, PVar
    from frame.sil.types import Typ
    guard = t._feasibility_guard(ExpBinOp("%", ExpCast(ExpVar(PVar("n")), Typ.unknown_type()),
                                          ExpConst.integer(4)), assume_true=True)
    assert guard.free_vars() == {"n"}


# ---- #if / #ifdef inside a function body ---------------------------------------

def test_every_arm_of_a_preprocessor_conditional_is_lowered():
    proc = proc_of("int a(void); int b(void); int c(void);", "void f(){", "int x;",
                   "#ifdef A", "x = a();", "#elif defined(B)", "x = b();", "#else", "x = c();",
                   "#endif", "#if 0", "x = 99;", "#endif", "}")
    w = writes(proc)
    assert sum(1 for t, _ in w if t == "x") == 3, w
    assert ("x", "99") not in w, "an #if 0 arm is dead code"
    # The three arms branch from one node and rejoin.
    branch = [n for n in proc.nodes.values() if len(n.succs) == 3]
    assert len(branch) == 1


def test_assignment_in_both_preprocessor_arms_defines_the_variable():
    # bitarray setmask_bitarray: `src` assigned in `#ifdef ... #else ... #endif`.
    body = ["void *cp(void*);", "int f(void *other){", "void *src;", "#ifdef GIL",
            "src = cp(other);", "#else", "src = other;", "#endif", "if (src == 0) return -1;",
            "return 0;", "}"]
    assert "CWE-457" not in cwes(*body)
    one_arm = ["void *cp(void*);", "int f(void *other){", "void *src;", "#ifdef GIL",
               "src = cp(other);", "#endif", "if (src == 0) return -1;", "return 0;", "}"]
    assert "CWE-457" in cwes(*one_arm), "without #else, the other configuration reads it uninitialized"
