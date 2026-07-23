"""Directional memory safety (CWE-787, CWE-125) and the allocation/permission pair.

Four detectors, all structural: each reads the finished SIL IR and fires only
where the IR settles the question outright, never where it would have to guess
at a value.

* **CWE-787 (Out-of-bounds Write)** and **CWE-125 (Out-of-bounds Read)** are the
  directional siblings of CWE-120. Frame already reports CWE-120 wherever a
  buffer is overrun with the direction unestablished; these two are reported
  where the IR establishes it. A subscripted assignment target is lowered to a
  `Store`, so it is a write. A subscript anywhere a value is read is lowered to
  an `ExpIndex`, so it is a read. The direction comes from the instruction, not
  from a function name.
* **CWE-789 (Allocation with Excessive Size)** is the sibling of the CWE-770
  detector: there the size is attacker-controlled and unbounded, here it is a
  constant written into the program that is excessive on its face. Restricted to
  STACK allocation, because the stack has a fixed platform limit while "is this
  heap allocation too big" is a policy question with no defensible answer.
* **CWE-732 (Incorrect Permission Assignment)** reads the mode argument named by
  the per-language spec tables and fires when a literal mode carries the
  world-write bit. `umask` inverts, since its argument names bits to CLEAR.

Both halves of the out-of-bounds rule have to be constants: the declared extent
of the array and the index. That is deliberately narrow. An index the IR cannot
pin down may well be in range on every execution, and reporting it would mean
asserting something about values these detectors have no basis for. The negative
cases below carry most of the weight, because a bounds-checked access, an
in-range constant and a restrictive mode are all vastly more common in real code
than the bugs, and a detector that fires on them is worse than one that misses.
"""

from frame.sil import FrameScanner
from frame.sil.cwe_taxonomy import is_a


def _cwes(src, language="c", filename="t.c"):
    """Every CWE id reported for `src`."""
    result = FrameScanner(language=language, verify=False).scan(src, filename)
    return {v.cwe_id for v in result.vulnerabilities}


def _lines(src, cwe, language="c", filename="t.c"):
    """Lines at which `cwe` is reported for `src`."""
    result = FrameScanner(language=language, verify=False).scan(src, filename)
    return [v.line for v in result.vulnerabilities if v.cwe_id == cwe]


# =============================================================================
# CWE-787: Out-of-bounds Write
# =============================================================================

def test_constant_index_past_the_end_is_reported_as_a_write():
    # `buf[12] = 'a'` on a 10-element array. The assignment target reaches the
    # IR as a Store, which is what makes this a write rather than a read.
    src = (
        "void f(void) {\n"
        "  char buf[10];\n"
        "  buf[12] = 'a';\n"
        "}\n"
    )
    assert _lines(src, "CWE-787") == [3]


def test_index_equal_to_the_bound_is_reported():
    # The classic off-by-one: valid indices run 0..9, so 10 is one past the end.
    src = (
        "void f(void) {\n"
        "  char buf[10];\n"
        "  buf[10] = 'a';\n"
        "}\n"
    )
    assert _lines(src, "CWE-787") == [3]


def test_negative_index_is_reported():
    # A constant index BELOW element zero is an access before the start of the
    # buffer, so the specific under-the-start weakness (CWE-124, a write) is
    # reported rather than the over-the-top CWE-787. The IR pins the index, so
    # the direction is exact.
    src = (
        "void f(void) {\n"
        "  char buf[10];\n"
        "  buf[-1] = 'a';\n"
        "}\n"
    )
    assert _lines(src, "CWE-124") == [3]
    assert "CWE-787" not in _cwes(src)


def test_index_held_by_a_single_assignment_constant_is_reported():
    # `int i = 20; buf[i] = ...` is the same weakness as `buf[20] = ...` and has
    # to read the same way. `i` is assigned exactly once, and only to a literal,
    # so its value at the access is not in question.
    src = (
        "void f(void) {\n"
        "  char buf[10];\n"
        "  int i = 20;\n"
        "  buf[i] = 'a';\n"
        "}\n"
    )
    assert _lines(src, "CWE-787") == [4]


def test_last_valid_index_is_not_reported():
    # Index 9 into a 10-element array is the last valid slot, not an overflow.
    src = (
        "void f(void) {\n"
        "  char buf[10];\n"
        "  buf[9] = 'a';\n"
        "}\n"
    )
    assert "CWE-787" not in _cwes(src)


def test_bounds_checked_access_is_not_reported():
    # The required negative case. The index is guarded before use, and it is not
    # a constant anyway, so there is nothing for either half of the rule to
    # match. Frame stays silent.
    src = (
        "void f(int i) {\n"
        "  char buf[10];\n"
        "  if (i >= 0 && i < 10) {\n"
        "    buf[i] = 'a';\n"
        "  }\n"
        "}\n"
    )
    assert "CWE-787" not in _cwes(src)


def test_unknown_index_is_not_reported():
    # An unguarded parameter index into a fixed buffer is a real bug a human can
    # see. Frame declines it anyway: the IR does not pin `i` to any value, so
    # concluding it is out of range would be a guess, and guessing here is
    # precisely how this class of detector turns into noise.
    src = (
        "void f(int i) {\n"
        "  char buf[10];\n"
        "  buf[i] = 'a';\n"
        "}\n"
    )
    assert "CWE-787" not in _cwes(src)


def test_index_into_a_pointer_of_unknown_extent_is_not_reported():
    # `p` is a parameter with no declared extent, so no bound is known and no
    # index can be shown to exceed it.
    src = (
        "void f(char *p) {\n"
        "  p[9999] = 'a';\n"
        "}\n"
    )
    assert "CWE-787" not in _cwes(src)


def test_reassigned_index_variable_is_not_reported():
    # `i` is written twice, so which value reaches the access depends on the
    # path. Only a name bound exactly once is treated as a constant.
    src = (
        "void f(int n) {\n"
        "  char buf[10];\n"
        "  int i = 20;\n"
        "  i = n;\n"
        "  buf[i] = 'a';\n"
        "}\n"
    )
    assert "CWE-787" not in _cwes(src)


def test_conflicting_declarations_of_one_name_are_not_reported():
    # Two arrays of different sizes share a name across scopes. The IR has no
    # scopes and cannot say which one the index refers to, so the bound is
    # dropped rather than guessed at.
    src = (
        "void f(int c) {\n"
        "  char buf[100];\n"
        "  if (c) {\n"
        "    char buf[4];\n"
        "    buf[50] = 'a';\n"
        "  }\n"
        "}\n"
    )
    assert "CWE-787" not in _cwes(src)


def test_cpp_out_of_bounds_write_is_reported():
    # The C++ grammar wraps a subscript index in a `subscript_argument_list`
    # rather than exposing an `index` field, so the two frontends reach the same
    # IR by different routes and both need pinning down.
    src = (
        "void f() {\n"
        "  char buf[8];\n"
        "  buf[9] = 0;\n"
        "}\n"
    )
    assert _lines(src, "CWE-787", language="cpp", filename="t.cpp") == [3]


# =============================================================================
# CWE-125: Out-of-bounds Read
# =============================================================================

def test_constant_index_past_the_end_is_reported_as_a_read():
    # Same access, other direction: a subscript in a value position is a read.
    src = (
        "void f(void) {\n"
        "  char buf[10];\n"
        "  char c = buf[11];\n"
        "}\n"
    )
    assert _lines(src, "CWE-125") == [3]


def test_over_read_in_a_call_argument_is_reported():
    # The subscript is nested inside a call argument rather than standing alone,
    # so the rule has to look through the whole expression, not just its root.
    src = (
        "void f(void) {\n"
        "  char buf[4];\n"
        "  use(buf[7]);\n"
        "}\n"
    )
    assert _lines(src, "CWE-125") == [3]


def test_over_read_on_the_value_side_of_a_store_is_a_read_not_a_write():
    # `dst[0] = src[9]` writes in bounds and reads out of bounds. The direction
    # is per-subscript, not per-instruction, so this must be CWE-125 alone.
    src = (
        "void f(void) {\n"
        "  char dst[10];\n"
        "  char src[4];\n"
        "  dst[0] = src[9];\n"
        "}\n"
    )
    reported = _cwes(src)
    assert "CWE-125" in reported
    assert "CWE-787" not in reported


def test_in_range_read_is_not_reported():
    src = (
        "void f(void) {\n"
        "  char buf[10];\n"
        "  char c = buf[0];\n"
        "}\n"
    )
    assert "CWE-125" not in _cwes(src)


def test_bounds_checked_read_is_not_reported():
    src = (
        "void f(int i) {\n"
        "  char buf[10];\n"
        "  if (i < 10 && i >= 0) {\n"
        "    char c = buf[i];\n"
        "  }\n"
        "}\n"
    )
    assert "CWE-125" not in _cwes(src)


def test_cpp_out_of_bounds_read_is_reported():
    src = (
        "void f() {\n"
        "  char buf[8];\n"
        "  int x = buf[9];\n"
        "}\n"
    )
    assert _lines(src, "CWE-125", language="cpp", filename="t.cpp") == [3]


# =============================================================================
# CWE-789: Memory Allocation with Excessive Size
# =============================================================================

def test_excessive_constant_stack_allocation_is_reported():
    # 16 MB on the stack. The smallest default thread stack among mainstream
    # platforms is 1 MB, so this cannot fit: a platform fact, not a judgment
    # about whether some number is large.
    src = (
        "void f(void) {\n"
        "  char *p = alloca(16777216);\n"
        "}\n"
    )
    assert _lines(src, "CWE-789") == [2]


def test_small_constant_stack_allocation_is_not_reported():
    # The required negative case: a constant size that is entirely reasonable.
    src = (
        "void f(void) {\n"
        "  char *p = alloca(1024);\n"
        "}\n"
    )
    assert "CWE-789" not in _cwes(src)


def test_large_heap_allocation_is_not_reported():
    # Deliberately silent. Whether a 16 MB malloc is excessive depends on what
    # the program is for, and Frame has no basis to decide. Only the stack, with
    # its hard limit, supports the claim.
    src = (
        "void f(void) {\n"
        "  char *p = malloc(16777216);\n"
        "}\n"
    )
    assert "CWE-789" not in _cwes(src)


def test_non_constant_stack_allocation_size_is_not_reported():
    # A variable-length stack allocation may or may not be excessive. That is
    # the CWE-770 question (is the size bounded), not this one.
    src = (
        "void f(int n) {\n"
        "  char *p = alloca(n);\n"
        "}\n"
    )
    assert "CWE-789" not in _cwes(src)


# =============================================================================
# CWE-732: Incorrect Permission Assignment
# =============================================================================

def test_world_writable_chmod_mode_is_reported():
    src = (
        "void f(void) {\n"
        "  chmod(\"/tmp/x\", 0777);\n"
        "}\n"
    )
    assert _lines(src, "CWE-732") == [2]


def test_restrictive_chmod_modes_are_not_reported():
    # The required negative case. 0644 and 0600 are the ordinary correct modes
    # and must never produce a finding.
    for mode in ("0644", "0600", "0755", "0640", "0400"):
        src = (
            "void f(void) {\n"
            f"  chmod(\"/tmp/x\", {mode});\n"
            "}\n"
        )
        assert "CWE-732" not in _cwes(src), mode


def test_group_writable_mode_is_not_reported():
    # 0664 grants group write but not world write. Whether a group should be
    # trusted is a deployment question; only the world-write bit is decidable
    # here, so that is the only bit tested.
    src = (
        "void f(void) {\n"
        "  chmod(\"/tmp/x\", 0664);\n"
        "}\n"
    )
    assert "CWE-732" not in _cwes(src)


def test_permissive_umask_is_reported():
    # umask inverts: it names the bits to CLEAR, so a mask without the
    # world-write bit leaves every created file world-writable.
    src = (
        "void f(void) {\n"
        "  umask(0);\n"
        "}\n"
    )
    assert _lines(src, "CWE-732") == [2]


def test_restrictive_umask_is_not_reported():
    # 022 masks off group and world write, the conventional correct value.
    src = (
        "void f(void) {\n"
        "  umask(022);\n"
        "}\n"
    )
    assert "CWE-732" not in _cwes(src)


def test_non_literal_mode_is_not_reported():
    # A mode assembled from S_I* constants reaches the IR as an expression whose
    # value Frame does not know. It is left alone rather than guessed at, even
    # though this particular one is in fact world-writable.
    src = (
        "void f(void) {\n"
        "  chmod(\"/tmp/x\", S_IRWXU | S_IRWXG | S_IRWXO);\n"
        "}\n"
    )
    assert "CWE-732" not in _cwes(src)


def test_open_without_a_mode_argument_is_not_reported():
    # The two-argument form of open() takes no mode at all. Reading a mode out
    # of the missing third argument would report a permission that is never set.
    src = (
        "void f(void) {\n"
        "  int fd = open(\"/tmp/x\", 0);\n"
        "}\n"
    )
    assert "CWE-732" not in _cwes(src)


def test_python_world_writable_chmod_is_reported():
    src = (
        "import os\n"
        "def f():\n"
        "    os.chmod('/tmp/x', 0o777)\n"
    )
    assert _lines(src, "CWE-732", language="python", filename="t.py") == [3]


def test_python_restrictive_chmod_is_not_reported():
    src = (
        "import os\n"
        "def f():\n"
        "    os.chmod('/tmp/x', 0o600)\n"
    )
    assert "CWE-732" not in _cwes(src, language="python", filename="t.py")


def test_python_permissive_umask_is_reported():
    src = (
        "import os\n"
        "def f():\n"
        "    os.umask(0)\n"
    )
    assert _lines(src, "CWE-732", language="python", filename="t.py") == [3]


def test_python_restrictive_umask_is_not_reported():
    src = (
        "import os\n"
        "def f():\n"
        "    os.umask(0o022)\n"
    )
    assert "CWE-732" not in _cwes(src, language="python", filename="t.py")


def test_python_symbolic_mode_is_not_reported():
    src = (
        "import os\n"
        "import stat\n"
        "def f():\n"
        "    os.chmod('/tmp/x', stat.S_IRWXU)\n"
    )
    assert "CWE-732" not in _cwes(src, language="python", filename="t.py")


# =============================================================================
# C octal literals
# =============================================================================

def test_c_octal_literals_reach_the_ir_with_their_real_value():
    # `int(text, 0)` rejects the C leading-zero octal form, so 0777 used to fall
    # back to 0 and arrived looking like the most restrictive mode there is.
    # Every permission rule reads that argument, so this is load-bearing.
    from frame.sil.frontends.c_frontend import parse_c_integer

    assert parse_c_integer("0777") == 0o777
    assert parse_c_integer("0644") == 0o644
    assert parse_c_integer("0") == 0
    assert parse_c_integer("10") == 10
    assert parse_c_integer("0x1F") == 0x1F
    assert parse_c_integer("10UL") == 10
    assert parse_c_integer("0x1FULL") == 0x1F
    assert parse_c_integer("not_a_number") is None


# =============================================================================
# Relationship to the broader classes
# =============================================================================

def test_directional_findings_answer_a_query_for_the_generic_class():
    # CWE-787 and CWE-125 are both children of CWE-119, so an advisory citing
    # the broad memory-corruption class still matches either. The relation is
    # one-way, as everywhere else in the taxonomy: a query for the specific
    # CWE-787 is not answered by a generic CWE-119 finding.
    assert is_a("CWE-787", "CWE-119")
    assert is_a("CWE-125", "CWE-119")
    assert not is_a("CWE-119", "CWE-787")

    # A write is not a read and a read is not a write, however close the
    # weaknesses are: they are siblings, not ancestors of one another.
    assert not is_a("CWE-787", "CWE-125")
    assert not is_a("CWE-125", "CWE-787")


def test_excessive_allocation_answers_the_cwe_770_and_cwe_400_queries():
    # CWE-789 sits under CWE-770, which sits under CWE-400, so the constant-size
    # and tainted-size weaknesses answer the same broad resource-consumption
    # query without either detector having to emit the parent itself.
    assert is_a("CWE-789", "CWE-770")
    assert is_a("CWE-789", "CWE-400")


def test_permission_assignment_answers_a_cwe_668_query():
    assert is_a("CWE-732", "CWE-668")
    assert is_a("CWE-732", "CWE-664")
