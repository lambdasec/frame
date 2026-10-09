"""CWE-476 as a separation-logic / Z3 question, not a name set.

Null-ness is a pure path fact (`p == nil`). Branch guards, assignments and
joins maintain the path condition (joins as a DISJUNCTION of the incoming
conditions), and a dereference is reported only when Frame's checker proves
`pc |- p == nil`, i.e. `pc & p != nil` is UNSAT. The finding is then discharged
by the incorrectness checker (`pc * null_deref(p)` SAT), which yields a witness.

Each positive below needs the solver (an equality chain, a disjunctive join, a
loop fixpoint); each negative is a correct idiom a name-set tracker gets wrong.
"""

import pytest

from frame.core.ast import And, Const, Eq, Neq, Or, Var
from frame.sil.scanner import FrameScanner
from frame.sil.translator import SILTranslator

HDR = "#include <stdio.h>\n#include <stdlib.h>\n"


def scan(*lines, verify=True):
    r = FrameScanner(language="c", verify=verify).scan(HDR + "\n".join(lines) + "\n", "t.c")
    assert not r.errors, r.errors
    return [v for v in r.vulnerabilities if v.cwe_id == "CWE-476"]


@pytest.mark.parametrize("name, body", [
    ("store", ["void f(){", "int *p = NULL;", "*p = 5;", "}"]),
    ("arrow", ["struct S{int a;};", "int f(){", "struct S *p = NULL;", "return p->a;", "}"]),
    ("guard confirms null", ["void f(int *p){", "if (p == NULL) {", "*p = 1;", "}", "}"]),
    ("negated guard", ["void f(int *p){", "if (!p) {", "*p = 1;", "}", "}"]),
    ("null on both branches", ["void f(int c){", "int *p;", "if (c) p = NULL; else p = 0;", "*p = 1;", "}"]),
    ("equality chain", ["void f(){", "int *p = NULL;", "int *q = p;", "*q = 1;", "}"]),
    ("after a loop", ["void f(int n){", "int *p = NULL;", "int i;",
                      "for (i = 0; i < n; i++) { }", "*p = 1;", "}"]),
])
def test_provably_null_dereference_is_reported(name, body):
    assert scan(*body), name


@pytest.mark.parametrize("name, body", [
    ("allocated on one branch, checked", ["void f(int c){", "int *p = NULL;",
                                          "if (c) p = (int*)malloc(4);", "if (p) *p = 1;", "}"]),
    ("null on one branch only", ["void f(int c){", "int x;", "int *p;",
                                 "if (c) p = NULL; else p = &x;", "*p = 1;", "}"]),
    ("correlated branches", ["void f(int c){", "int *p = NULL;", "int x;",
                             "if (c) p = &x;", "if (c) *p = 1;", "}"]),
    ("loop bound correlated with allocation",
     ["void f(int n){", "int *p = NULL;", "int j;",
      "if (n > 0) {", "p = (int*)malloc(n * sizeof(int));", "if (p == NULL) return;", "}",
      "for (j = 0; j < n; j++) {", "p[j] = j;", "}", "}"]),
    ("assignment inside the loop condition",
     ["struct M{char *f;};", "struct M *getm(void*);", "void g(char*);",
      "void f(void *file){", "struct M *e = NULL;", "while ((e = getm(file))) {", "g(e->f);", "}", "}"]),
    ("assignment inside an if condition",
     ["void f(int n){", "int *p;", "if ((p = (int*)malloc(n)) == NULL) return;", "*p = 1;", "free(p);", "}"]),
    ("written through an alias", ["void f(){", "int *p = NULL;", "int **pp = &p;", "int x;",
                                  "*pp = &x;", "*p = 1;", "}"]),
    ("address passed to a callee", ["void init(int**);", "void f(){", "int *p = NULL;",
                                    "init(&p);", "*p = 5;", "}"]),
    ("global reset by a callee", ["int *g;", "void h();", "void f(){", "g = NULL;", "h();", "*g = 5;", "}"]),
])
def test_correct_idioms_stay_clean(name, body):
    assert not scan(*body), name


def test_finding_is_verified_with_a_concrete_witness():
    hits = scan("void f(){", "int *p = NULL;", "*p = 5;", "}")
    assert hits and hits[0].confidence == 1.0
    assert "p = 0" in (hits[0].witness or "")


def test_finding_carries_the_facts_it_rests_on():
    from frame.sil.frontends.c_frontend import CFrontend
    prog = CFrontend().translate(HDR + "void f(){\nint *p = NULL;\n*p = 5;\n}\n", "t.c")
    checks = [c for c in SILTranslator(prog).translate_program()
              if c.vuln_type.value == "null_dereference"]
    assert checks and [str(g) for g in checks[0].path_condition] == ["p = nil"]


# ---- the join itself --------------------------------------------------------------

def _translator():
    from frame.sil.procedure import Program
    t = SILTranslator(Program(language="c"))
    return t


def test_join_keeps_shared_facts_and_disjoins_the_rest():
    t = _translator()
    a, b, c = Eq(Var("a"), Const(1)), Eq(Var("p"), Const(None)), Neq(Var("p"), Const(None))
    joined = t._join_path_conditions([a, b], [a, c])
    assert str(joined[0]) == str(a)
    assert isinstance(joined[1], Or)


def test_join_with_a_weaker_side_is_the_weaker_side():
    t = _translator()
    a, b = Eq(Var("a"), Const(1)), Eq(Var("p"), Const(None))
    assert [str(g) for g in t._join_path_conditions([a, b], [a])] == [str(a)]


def test_oversized_disjunction_collapses_to_shared_facts():
    t = _translator()
    big = [Eq(Var(f"v{i}"), Const(i)) for i in range(60)]
    assert t._join_path_conditions(big, [Eq(Var("w"), Const(0))]) == []


def test_provably_null_uses_only_connected_facts():
    t = _translator()
    pc = [Eq(Var("p"), Var("q")), Eq(Var("q"), Const(None)), Eq(Var("z"), Const(3))]
    assert [str(g) for g in t._relevant_facts("p", pc)] == ["p = q", "q = nil"]
    assert t._provably_null("p", pc)
    assert not t._provably_null("p", [Or(Eq(Var("p"), Const(None)), Neq(Var("p"), Const(None)))])
    # An infeasible path proves nothing.
    assert not t._provably_null("p", [Eq(Var("p"), Const(None)), Neq(Var("p"), Const(None))])


def test_scanner_verifier_runs_instead_of_raising():
    # _verify_check once named VulnType members that do not exist, so it raised
    # for every finding and nothing was ever verified (all kept at 0.7).
    src = ("from flask import request\nimport os\n"
           "def f():\n    os.system(request.args.get('c'))\n")
    r = FrameScanner(language="python", verify=True).scan(src, "t.py")
    assert r.vulnerabilities and all(v.confidence == 1.0 for v in r.vulnerabilities)


# ---- frontend: assignments inside expressions are real writes ----------------------

def _proc(src, name="f"):
    from frame.sil.frontends.c_frontend import CFrontend
    return CFrontend().translate(HDR + src, "t.c").procedures[name]


def _loop_head(proc):
    from frame.sil.procedure import NodeKind
    heads = [n for n in proc.nodes.values() if n.kind == NodeKind.LOOP_HEAD]
    assert len(heads) == 1
    return heads[0]


@pytest.mark.parametrize("loop", [
    "while ((e = next(f))) { use(e); }",
    "for (; (e = next(f)); ) { use(e); }",
    "do { use(e); } while ((e = next(f)));",
])
def test_assignment_in_a_loop_condition_is_lowered_into_the_loop_head(loop):
    from frame.sil.instructions import Assign, Prune
    src = "int *next(void*); void use(int*);\nvoid f(void *f){\nint *e = NULL;\n" + loop + "\n}\n"
    head = _loop_head(_proc(src))
    kinds = [type(i).__name__ for i in head.instrs]
    assert kinds[0] == "Assign" and str(head.instrs[0].id) == "e"
    prunes = [i for i in head.instrs if isinstance(i, Prune)]
    # The condition now tests the assigned variable, so the edge guard is `e != 0`.
    assert prunes and all(str(p.condition) == "e" for p in prunes)


def test_assignment_inside_an_if_condition_is_lowered_before_the_branch():
    from frame.sil.instructions import Assign
    proc = _proc("void f(int n){\nint *p;\nif ((p = (int*)malloc(n)) == NULL) return;\n*p = 1;\n}\n")
    entry = proc.nodes[proc.entry_node]
    assigns = [i for i in entry.instrs if isinstance(i, Assign) and str(i.id) == "p"
               and not getattr(i, "is_uninit_decl", False)]
    assert assigns


def test_compound_and_chained_assignments_in_expressions():
    from frame.sil.instructions import Assign
    proc = _proc("void f(int a){\nint x = 0;\nint y;\nint z;\nz = (y = 3);\nif ((x += a) > 0) { }\n}\n")
    writes = {str(i.id): str(i.exp) for n in proc.nodes.values() for i in n.instrs
              if isinstance(i, Assign) and not getattr(i, "is_uninit_decl", False)}
    assert writes["y"] == "3" and writes["z"] == "y"
    assert writes["x"] == "(x + a)"


def test_value_assigned_in_a_loop_condition_is_not_uninitialized():
    found = FrameScanner(language="c", verify=False).scan(
        HDR + "int next(void);\nvoid use(int);\nvoid f(){\nint x;\nwhile ((x = next()) > 0) {\nuse(x);\n}\n}\n",
        "t.c").vulnerabilities
    assert "CWE-457" not in {v.cwe_id for v in found}


# ---- havoc rules -------------------------------------------------------------------

def test_a_parameter_fact_survives_a_call():
    # A callee cannot change the caller's by-value parameter, so the confirmed
    # `p == NULL` still holds after g().
    assert scan("void g(void);", "void f(int *p){", "if (p == NULL) {", "g();", "*p = 1;", "}", "}")


def test_a_local_fact_survives_a_call_that_cannot_reach_it():
    assert scan("void g(void);", "void f(){", "int *p = NULL;", "g();", "*p = 1;", "}")


# ---- leak path uses the same solver query ------------------------------------------

def test_failed_allocation_bailed_on_is_not_a_leak():
    found = FrameScanner(language="c", verify=False).scan(
        HDR + "void f(){\nchar *p = (char*)malloc(4);\nif (p == NULL) return;\nfree(p);\n}\n", "t.c")
    assert "CWE-401" not in {v.cwe_id for v in found.vulnerabilities}


# ---- the verifier can reject --------------------------------------------------------

def test_verifier_drops_a_null_finding_its_facts_contradict():
    from frame.sil.translator import VulnerabilityCheck, VulnType
    from frame.sil.types import Location
    from frame.core.ast import NullDeref
    sc = FrameScanner(language="c", verify=True)
    check = VulnerabilityCheck(formula=NullDeref(Var("p")), vuln_type=VulnType.NULL_DEREFERENCE,
                               location=Location("t.c", 1, 0), description="x", tainted_var="p",
                               procedure_name="f")
    check.path_condition = [Neq(Var("p"), Const(None))]
    assert not sc._verify_check(check).reachable
    check.path_condition = [Eq(Var("p"), Const(None))]
    assert sc._verify_check(check).reachable


# ---- scope: other languages keep the old join ---------------------------------------

def test_join_is_only_disjunctive_for_c():
    from frame.sil.procedure import Program
    from frame.sil.translator import SymbolicState
    a, b = SymbolicState(), SymbolicState()
    a.feasibility_constraints = [Eq(Var("x"), Const(1))]
    b.feasibility_constraints = [Eq(Var("x"), Const(2))]
    assert SILTranslator(Program(language="python"))._merge_states(a, b).feasibility_constraints == []
    merged = SILTranslator(Program(language="c"))._merge_states(a, b).feasibility_constraints
    assert len(merged) == 1 and isinstance(merged[0], Or)
