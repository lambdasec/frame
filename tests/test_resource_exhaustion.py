"""The resource-exhaustion cluster: CWE-770, CWE-674 and CWE-835.

Three detectors, all of them structural rather than textual:

* **CWE-770 (Allocation Without Limits)** is a taint flow like any other. A new
  `alloc_size` sink kind marks the size/count argument of the allocation APIs
  listed in the per-language spec tables, and a finding is raised when an
  attacker-controlled value reaches one with no branch condition on the path that
  constrains it.
* **CWE-835 (Loop with Unreachable Exit)** needs two facts: the loop condition is
  a literal that is always true, so the exit prune can never fire, and the body
  contains no statement that can leave the loop. The second fact comes from the
  frontend, because `break` carries no SIL instruction and is invisible in the
  CFG.
* **CWE-674 (Uncontrolled Recursion)** deletes the self-call's block from the CFG
  and asks whether the entry can still reach a return. If it cannot, every run
  recurses and no base case exists.

CWE-400 is deliberately not a detector of its own. It is the MITRE parent of
CWE-770, and `cwe_taxonomy.is_a` already makes a CWE-770 finding answer a query
for it, so emitting both would double-count one weakness.

The negative cases carry most of the weight here. All three classes are prone to
false positives (legitimate recursion has a base case, `while True:` service
loops are ordinary and correct, plenty of allocations are sized by a constant),
and a detector that fires on correct code is worse than one that stays quiet. So
each rule is narrow by design, and the tests below pin down what it declines to
say as much as what it says.
"""

from frame.sil import FrameScanner
from frame.sil.cwe_taxonomy import is_a


def _cwes(src, language="python", filename="t"):
    """Every CWE id reported for `src`."""
    result = FrameScanner(language=language, verify=False).scan(src, filename)
    return {v.cwe_id for v in result.vulnerabilities}


def _lines(src, cwe, language="python", filename="t"):
    """Lines at which `cwe` is reported for `src`."""
    result = FrameScanner(language=language, verify=False).scan(src, filename)
    return [v.line for v in result.vulnerabilities if v.cwe_id == cwe]


# =============================================================================
# CWE-835: Loop with Unreachable Exit Condition
# =============================================================================

def test_while_true_without_any_exit_is_reported():
    # The condition is a literal, so the exit edge assumes `True` is false and can
    # never be taken, and nothing in the body transfers control out. The loop
    # provably cannot terminate.
    src = (
        "def spin():\n"
        "    while True:\n"
        "        do_work()\n"
    )
    assert _lines(src, "CWE-835") == [2]


def test_while_true_with_break_is_not_reported():
    # The canonical service loop. `break` has no SIL instruction, so the CFG alone
    # would still look non-terminating; the frontend records the syntactic fact
    # that the body can leave, and that is what keeps this quiet.
    src = (
        "def serve():\n"
        "    while True:\n"
        "        if should_stop():\n"
        "            break\n"
        "        do_work()\n"
    )
    assert "CWE-835" not in _cwes(src)


def test_while_true_with_return_is_not_reported():
    src = (
        "def poll():\n"
        "    while True:\n"
        "        item = next_item()\n"
        "        if item:\n"
        "            return item\n"
    )
    assert "CWE-835" not in _cwes(src)


def test_while_true_with_raise_is_not_reported():
    # Raising leaves the loop just as surely as breaking does.
    src = (
        "def retry():\n"
        "    while True:\n"
        "        if attempts_exhausted():\n"
        "            raise TimeoutError()\n"
        "        attempt()\n"
    )
    assert "CWE-835" not in _cwes(src)


def test_while_true_generator_is_not_reported():
    # A `while True: yield ...` producer terminates by being abandoned: the
    # consumer decides how many items to take, so the loop is not a hang.
    src = (
        "def counter():\n"
        "    n = 0\n"
        "    while True:\n"
        "        yield n\n"
        "        n = n + 1\n"
    )
    assert "CWE-835" not in _cwes(src)


def test_while_true_with_only_continue_is_reported():
    # `continue` re-tests the condition, which is the constant True, so it is not
    # a way out. This is still a hang.
    src = (
        "def spin():\n"
        "    while True:\n"
        "        if skip():\n"
        "            continue\n"
        "        do_work()\n"
    )
    assert _lines(src, "CWE-835") == [2]


def test_iteration_over_a_collection_is_not_reported():
    # A `for` head is lowered with a constant-true placeholder condition, which
    # would look exactly like `while True:` if the detector went by the condition
    # alone. It does not: only `while`-style heads carry the body's exit fact, so
    # ordinary iteration is never a candidate.
    src = (
        "def process(items):\n"
        "    for item in items:\n"
        "        handle(item)\n"
    )
    assert "CWE-835" not in _cwes(src)


def test_non_literal_loop_condition_is_not_reported():
    # `running` is never assigned in this function, so a human can see the loop
    # spins forever. Frame stays silent anyway: concluding otherwise means
    # reasoning about what a variable holds, and guessing there is precisely how
    # this class of detector turns into noise.
    src = (
        "def spin(running):\n"
        "    while running:\n"
        "        do_work()\n"
    )
    assert "CWE-835" not in _cwes(src)


def test_java_while_true_is_reported():
    src = (
        "public class T {\n"
        "  public void spin() {\n"
        "    while (true) {\n"
        "      doWork();\n"
        "    }\n"
        "  }\n"
        "}\n"
    )
    assert _lines(src, "CWE-835", language="java", filename="T.java") == [3]


def test_java_while_true_with_break_is_not_reported():
    src = (
        "public class T {\n"
        "  public void serve() {\n"
        "    while (true) {\n"
        "      if (stop) { break; }\n"
        "      doWork();\n"
        "    }\n"
        "  }\n"
        "}\n"
    )
    assert "CWE-835" not in _cwes(src, language="java", filename="T.java")


def test_javascript_while_true_is_reported():
    src = (
        "function spin() {\n"
        "  while (true) {\n"
        "    doWork();\n"
        "  }\n"
        "}\n"
    )
    assert _lines(src, "CWE-835", language="javascript", filename="t.js") == [2]


def test_c_while_one_is_reported():
    # `while (1)` is the same weakness spelled with an integer literal.
    src = (
        "void spin(void) {\n"
        "  while (1) {\n"
        "    work();\n"
        "  }\n"
        "}\n"
    )
    assert _lines(src, "CWE-835", language="c", filename="t.c") == [2]


# =============================================================================
# CWE-674: Uncontrolled Recursion
# =============================================================================

def test_self_call_with_no_base_case_is_reported():
    # Deleting the recursive call's block leaves no path from the entry to a
    # return, so every execution recurses.
    src = (
        "def fact(n):\n"
        "    return n * fact(n - 1)\n"
    )
    assert _lines(src, "CWE-674") == [2]


def test_recursion_with_a_base_case_is_not_reported():
    # `if n <= 1: return 1` is a return reachable without the recursive call, so
    # a base case exists and nothing is reported.
    src = (
        "def fact(n):\n"
        "    if n <= 1:\n"
        "        return 1\n"
        "    return n * fact(n - 1)\n"
    )
    assert "CWE-674" not in _cwes(src)


def test_recursion_guarded_by_a_ternary_is_not_reported():
    # The frontend hoists a call out of the expression that contains it, so the
    # recursive call looks unconditional in the block even though it only runs on
    # one arm of the conditional. The base case is real and must not be missed.
    src = (
        "def walk(node):\n"
        "    return walk(node.parent) if node.parent else node\n"
    )
    assert "CWE-674" not in _cwes(src)


def test_recursion_guarded_by_short_circuit_is_not_reported():
    # Same hoisting problem, spelled with `or`: the recursive call runs only when
    # the left operand is falsy.
    src = (
        "def countdown(n):\n"
        "    return n <= 0 or countdown(n - 1)\n"
    )
    assert "CWE-674" not in _cwes(src)


def test_recursion_inside_a_loop_is_not_reported():
    # Tree traversal. The loop's exit edge reaches the function exit without the
    # recursive call, so the call is avoidable and the recursion is bounded by the
    # data, which is exactly the common correct shape.
    src = (
        "def walk(node):\n"
        "    for child in node.children:\n"
        "        walk(child)\n"
    )
    assert "CWE-674" not in _cwes(src)


def test_recursion_with_an_exception_base_case_is_not_reported():
    # The frontends inline handler bodies without giving them edges, so a CFG
    # containing a try understates how control can leave. The argument for
    # CWE-674 rests entirely on "no path leaves without recursing", which that CFG
    # cannot support, so the detector abstains for any procedure with a handler.
    src = (
        "def wrap(n):\n"
        "    try:\n"
        "        return wrap(n - 1)\n"
        "    except RecursionError:\n"
        "        return 0\n"
    )
    assert "CWE-674" not in _cwes(src)


def test_call_on_another_object_sharing_the_name_is_not_reported():
    # `self.conn.close()` inside `close()` has the same simple name but a
    # different receiver. Matching on the bare name would make every delegating
    # wrapper look recursive.
    src = (
        "class Session:\n"
        "    def close(self):\n"
        "        self.conn.close()\n"
    )
    assert "CWE-674" not in _cwes(src)


def test_python_method_delegating_to_a_free_function_is_not_reported():
    # A very common Python layout: a method forwarding to a module-level helper
    # imported under the same name. Python resolves the unqualified call to the
    # free function, never to the method, so this is not recursion at all.
    src = (
        "from helpers import find_frame\n"
        "\n"
        "class Checker:\n"
        "    def find_frame(self, a, b):\n"
        "        return find_frame(self, a, b)\n"
    )
    assert "CWE-674" not in _cwes(src)


def test_python_method_recursing_through_self_is_reported():
    # The receiver-qualified form is unambiguous recursion in Python.
    src = (
        "class Worker:\n"
        "    def spin(self):\n"
        "        self.spin()\n"
    )
    assert _lines(src, "CWE-674") == [3]


def test_java_unqualified_method_recursion_is_reported():
    # Java resolves an unqualified call against the implicit receiver, so `rec()`
    # inside `rec()` really is recursion. This is the mirror image of the Python
    # delegation case above, which is why the rule consults the language.
    src = (
        "public class T {\n"
        "  public void rec() {\n"
        "    rec();\n"
        "  }\n"
        "}\n"
    )
    assert _lines(src, "CWE-674", language="java", filename="T.java") == [3]


def test_ordinary_non_recursive_function_is_not_reported():
    src = (
        "def total(items):\n"
        "    result = 0\n"
        "    for item in items:\n"
        "        result = result + item\n"
        "    return result\n"
    )
    assert "CWE-674" not in _cwes(src)


# =============================================================================
# CWE-770: Allocation of Resources Without Limits or Throttling
# =============================================================================

def test_tainted_allocation_size_is_reported():
    # The request parameter reaches the size argument of an allocator with no
    # branch condition constraining it anywhere on the path.
    src = (
        "import numpy\n"
        "from flask import request\n"
        "def handler():\n"
        "    n = int(request.args.get('n'))\n"
        "    return numpy.zeros(n)\n"
    )
    assert _lines(src, "CWE-770") == [5]


def test_constant_allocation_size_is_not_reported():
    src = (
        "import numpy\n"
        "def handler():\n"
        "    return numpy.zeros(4096)\n"
    )
    assert "CWE-770" not in _cwes(src)


def test_allocation_size_bound_to_a_constant_is_not_reported():
    src = (
        "import numpy\n"
        "def handler():\n"
        "    n = 4096\n"
        "    return numpy.zeros(n)\n"
    )
    assert "CWE-770" not in _cwes(src)


def test_range_checked_allocation_size_is_not_reported():
    # The guard on the path to the allocator constrains `n`. Frame does not try to
    # decide whether 4096 is a small enough ceiling: whether a particular limit is
    # adequate is a policy question, and answering it here would turn every
    # deliberate bound into a finding.
    src = (
        "import numpy\n"
        "from flask import request\n"
        "def handler():\n"
        "    n = int(request.args.get('n'))\n"
        "    if n > 4096:\n"
        "        return 'too large'\n"
        "    return numpy.zeros(n)\n"
    )
    assert "CWE-770" not in _cwes(src)


def test_allocation_size_checked_by_a_range_test_is_not_reported():
    src = (
        "import numpy\n"
        "from flask import request\n"
        "def handler():\n"
        "    n = int(request.args.get('n'))\n"
        "    if 0 < n <= 4096:\n"
        "        return numpy.zeros(n)\n"
        "    return 'rejected'\n"
    )
    assert "CWE-770" not in _cwes(src)


def test_untainted_allocation_size_is_not_reported():
    # A size computed from local data is not attacker-controlled, so there is
    # nothing to bound.
    src = (
        "import numpy\n"
        "def handler(items):\n"
        "    n = len(items)\n"
        "    return numpy.zeros(n)\n"
    )
    assert "CWE-770" not in _cwes(src)


def test_java_tainted_buffer_capacity_is_reported():
    src = (
        "public class T {\n"
        "  public void handle(javax.servlet.http.HttpServletRequest req) {\n"
        "    String s = req.getParameter(\"n\");\n"
        "    int n = Integer.parseInt(s);\n"
        "    java.nio.ByteBuffer b = java.nio.ByteBuffer.allocate(n);\n"
        "  }\n"
        "}\n"
    )
    assert _lines(src, "CWE-770", language="java", filename="T.java") == [5]


def test_java_constant_buffer_capacity_is_not_reported():
    src = (
        "public class T {\n"
        "  public void handle() {\n"
        "    java.nio.ByteBuffer b = java.nio.ByteBuffer.allocate(1024);\n"
        "  }\n"
        "}\n"
    )
    assert "CWE-770" not in _cwes(src, language="java", filename="T.java")


def test_data_argument_is_not_treated_as_a_size():
    # Only arguments that a spec designates as a size are allocation sinks. A
    # tainted string flowing into an ordinary call is somebody else's finding, not
    # unbounded allocation.
    src = (
        "import numpy\n"
        "from flask import request\n"
        "def handler():\n"
        "    name = request.args.get('name')\n"
        "    return numpy.array(name)\n"
    )
    assert "CWE-770" not in _cwes(src)


# =============================================================================
# Relationship to the CWE-400 parent
# =============================================================================

def test_findings_answer_a_cwe_400_query_through_the_hierarchy():
    # Frame reports the specific child weakness. An advisory or policy citing the
    # CWE-400 parent still matches, which is why CWE-400 is not a separate
    # detector: emitting both would count one weakness twice.
    src = (
        "import numpy\n"
        "from flask import request\n"
        "def handler():\n"
        "    n = int(request.args.get('n'))\n"
        "    return numpy.zeros(n)\n"
    )
    assert _cwes(src) == {"CWE-770"}
    assert is_a("CWE-770", "CWE-400")

    # The non-termination pair sits under CWE-834 (Excessive Iteration) instead,
    # so neither of them answers a CWE-400 query.
    assert is_a("CWE-674", "CWE-834")
    assert is_a("CWE-835", "CWE-834")
    assert not is_a("CWE-835", "CWE-400")
