"""Phase 4 of the C/C++ cluster: variable and tainted buffer bounds.

Three structural detectors extend Tier 1's constant-index out-of-bounds check
(`char b[8]; b[10]=1`) to the two remaining sound, high-value index cases, all
reasoning over the SIL IR, the CFG, and the symbolic state, never over source
text:

* **Loop-bound overflow (CWE-787 / CWE-125)** is structural over the finished
  CFG. A fixed-array access `b[i]` inside a counting loop whose entry guard lets
  the unit-step counter reach or pass the array's element count overruns it on
  the final iteration. `for(i=0;i<=B;i++) b[i]` reaches index B and is flagged;
  `for(i=0;i<B;i++) b[i]` stops at B-1 and is not.

* **Tainted index (CWE-787 / CWE-125)** is taint plus a Z3 feasibility query. An
  attacker-controlled index into a fixed array is flagged only when the path
  condition does NOT force it below the array size, i.e. `path AND index >= B`
  is satisfiable. The trigger is taint: an ordinary opaque parameter index is
  never flagged. A guard `if(i<B)` or a mask `i % B` makes the query
  unsatisfiable and stays silent.

* **Direction (CWE-124 / CWE-127)** refines the constant-index arm: an index
  below element zero is an access before the start of the buffer, reported as
  the specific under-the-start weakness rather than the over-the-top 787/125.

As in Phases 1-3 the negatives carry the weight. The two that matter most are an
opaque untainted index and a correctly bounded loop: a detector that fires on
either is a failure. Each rule also declines to fire on the guarded, masked, and
in-bounds idioms it is most likely to be confused by.
"""

from frame.sil import FrameScanner


def _cwes(src, language="c", filename="t.c"):
    """Every CWE id reported for a C/C++ snippet."""
    result = FrameScanner(language=language, verify=False).scan(src, filename)
    return {v.cwe_id for v in result.vulnerabilities}


def _lines(src, cwe, language="c", filename="t.c"):
    """Sorted lines at which `cwe` is reported."""
    result = FrameScanner(language=language, verify=False).scan(src, filename)
    return sorted(v.line for v in result.vulnerabilities if v.cwe_id == cwe)


# =============================================================================
# Loop-bound overflow (positives)
# =============================================================================

def test_loop_off_by_one_write_is_reported():
    src = "void f(){char b[8];int i;for(i=0;i<=8;i++)b[i]=1;}"
    assert "CWE-787" in _cwes(src)


def test_loop_off_by_one_read_is_reported():
    src = "void f(){char b[8];int i;char c;for(i=0;i<=8;i++)c=b[i];}"
    reported = _cwes(src)
    assert "CWE-125" in reported
    # A read must not be reported as a write.
    assert "CWE-787" not in reported


def test_loop_reaching_two_past_the_end_is_reported():
    src = "void f(){char b[8];int i;for(i=0;i<=9;i++)b[i]=1;}"
    assert "CWE-787" in _cwes(src)


def test_loop_from_nonzero_start_still_reaches_the_end():
    src = "void f(){char b[8];int i;for(i=2;i<=8;i++)b[i]=1;}"
    assert "CWE-787" in _cwes(src)


# =============================================================================
# Loop-bound overflow (negatives) -- the correctly bounded loop is the case
# that must never fire.
# =============================================================================

def test_loop_bounded_below_size_is_not_reported():
    src = "void f(){char b[8];int i;for(i=0;i<8;i++)b[i]=1;}"
    assert "CWE-787" not in _cwes(src)


def test_loop_bounded_below_size_read_is_not_reported():
    src = "void f(){char b[8];int i;char c;for(i=0;i<8;i++)c=b[i];}"
    assert "CWE-125" not in _cwes(src)


def test_loop_le_size_minus_one_is_not_reported():
    src = "void f(){char b[8];int i;for(i=0;i<=7;i++)b[i]=1;}"
    assert "CWE-787" not in _cwes(src)


def test_loop_with_non_unit_step_is_not_reported():
    # A step other than one is not proven to land on the boundary value, so the
    # detector declines to reason about it.
    src = "void f(){char b[8];int i;for(i=0;i<=8;i+=2)b[i]=1;}"
    assert "CWE-787" not in _cwes(src)


def test_loop_over_a_larger_array_is_not_reported():
    src = "void f(){char b[16];int i;for(i=0;i<=8;i++)b[i]=1;}"
    assert "CWE-787" not in _cwes(src)


# =============================================================================
# Tainted index (positives)
# =============================================================================

def test_tainted_index_write_is_reported():
    src = 'void f(){char b[8];int i=atoi(getenv("X"));b[i]=1;}'
    assert "CWE-787" in _cwes(src)


def test_tainted_index_read_is_reported():
    src = 'void f(){char b[8];int i=atoi(getenv("X"));char c=b[i];}'
    reported = _cwes(src)
    assert "CWE-125" in reported
    assert "CWE-787" not in reported


def test_tainted_offset_expression_is_reported():
    # The taint reaches the index through an arithmetic expression.
    src = 'void f(){char b[8];int i=atoi(getenv("X"));b[i+1]=1;}'
    assert "CWE-787" in _cwes(src)


# =============================================================================
# Tainted index (negatives) -- the opaque untainted index is the case that must
# never fire, and the guarded / masked idioms follow.
# =============================================================================

def test_opaque_untainted_index_write_is_not_reported():
    src = "void f(int i){char b[8]; b[i]=1;}"
    assert "CWE-787" not in _cwes(src)


def test_opaque_untainted_index_read_is_not_reported():
    src = "void f(int i){char b[8]; char c=b[i];}"
    assert "CWE-125" not in _cwes(src)


def test_tainted_index_guarded_below_size_is_not_reported():
    src = 'void f(){char b[8];int i=atoi(getenv("X"));if(i<8)b[i]=1;}'
    assert "CWE-787" not in _cwes(src)


def test_tainted_index_early_return_guard_is_not_reported():
    src = 'void f(){char b[8];int i=atoi(getenv("X"));if(i>=8)return;b[i]=1;}'
    assert "CWE-787" not in _cwes(src)


def test_tainted_index_masked_by_modulo_is_not_reported():
    src = 'void f(){char b[8];int i=atoi(getenv("X"));b[i%8]=1;}'
    assert "CWE-787" not in _cwes(src)


def test_tainted_index_masked_read_is_not_reported():
    src = 'void f(){char b[8];int i=atoi(getenv("X"));char c=b[i%8];}'
    assert "CWE-125" not in _cwes(src)


# =============================================================================
# Direction: below the start (CWE-124 / CWE-127)
# =============================================================================

def test_negative_constant_write_is_underwrite():
    src = "void f(){char b[8]; b[-1]=1;}"
    reported = _cwes(src)
    assert "CWE-124" in reported
    assert "CWE-787" not in reported


def test_negative_constant_read_is_underread():
    src = "void f(){char b[8]; char c=b[-1];}"
    reported = _cwes(src)
    assert "CWE-127" in reported
    assert "CWE-125" not in reported


# =============================================================================
# Constant in-bounds and the preserved Tier-1 over-the-top constant write.
# =============================================================================

def test_constant_in_bounds_is_not_reported():
    src = "void f(){char b[8]; b[3]=1;}"
    reported = _cwes(src)
    assert "CWE-787" not in reported
    assert "CWE-124" not in reported


def test_constant_over_the_top_write_still_reported():
    # Tier 1 must keep firing on the constant-index write.
    src = "void f(){char b[8]; b[10]=1;}"
    assert _lines(src, "CWE-787") == [1]


def test_cpp_loop_off_by_one_is_reported():
    src = "void f(){char b[8];int i;for(i=0;i<=8;i++)b[i]=1;}"
    assert "CWE-787" in _cwes(src, language="cpp", filename="t.cpp")


# =============================================================================
# Taxonomy: the new directional CWEs resolve to the CWE-119 family.
# =============================================================================

def test_directional_cwes_resolve_to_the_buffer_family():
    from frame.sil.cwe_taxonomy import is_a
    assert is_a("CWE-124", "CWE-119")
    assert is_a("CWE-127", "CWE-119")
    assert is_a("CWE-122", "CWE-119")
    # A generic CWE-119 finding does not answer a specific-direction query.
    assert not is_a("CWE-119", "CWE-124")
