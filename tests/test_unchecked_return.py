"""CWE-252: the result of a call that can only fail silently is discarded.

Unchecked-return checking has a bad reputation, and it is deserved. Most return
values in most programs are ignored perfectly correctly: nobody tests what
`printf` returned, `list.append` returns nothing worth having, and a failed
`close()` in a cleanup path is usually not actionable. A rule that fires on those
is not a detector, it is noise with a CWE number attached. So this one is narrow
along two independent axes, and both have to hold before anything is reported.

**Which functions.** Only APIs whose spec sets `return_must_be_checked`, and the
per-language spec tables set it only for the privilege-management family:
setuid, setgid and their relatives, plus chroot. These are the case where there
is no reading under which discarding the result is intended. If `setuid()` fails
and nothing notices, the process carries on holding the privileges it believes it
gave up, and every later access-control decision in that program is wrong. The
list stops there on purpose: `unlink`, `mkdir` and `close` fail routinely and are
ignored deliberately all the time.

**Which call sites.** Only calls with NO destination at all. `Call.ret` is None
exactly when the source wrote the call as a bare statement, so the value is
discarded before anything could have tested it. A call inside a branch condition
never becomes a Call instruction at all (it is inlined into the condition), and an
assigned result carries a destination, so neither is a candidate.

That second rule gives up a real bug: a result that is stored and then genuinely
never read. Frame will miss it. The alternative is to decide whether an assigned
value is "really" tested somewhere, and being wrong about that fires on correct
code. Missing a finding costs a finding. Guessing costs the detector its
credibility, which is worth more.

CWE-754 (Improper Check for Unusual Conditions) is deliberately not a detector of
its own. It is the MITRE parent of CWE-252, and `cwe_taxonomy.is_a` already makes
a CWE-252 finding answer a query for it, so emitting both would count one
weakness twice. This is the same argument that keeps CWE-400 from being its own
detector alongside CWE-770.

One caveat about what these tests measure. A SEPARATE, older CWE-252 reporter
lives in `analyzers/interprocedural_analyzer.py` and matches a regular expression
against each source line, over a much longer function list that includes
`unlink`, `close`, `mkdir`, `read` and `malloc`. It reports discarded results
from all of them, which is the false-positive behavior this detector is built to
avoid. It is left untouched here, so the negative cases below assert that the
STRUCTURAL rule stays silent, identified by the procedure the finding is
attributed to: findings from the regex reporter carry the synthetic procedure
name `<interprocedural-analysis>`, findings from this one carry the real
procedure. `test_the_older_regex_reporter_still_fires_on_ignorable_functions`
records the overlap explicitly rather than leaving it to be discovered.
"""

from frame.sil import FrameScanner

from frame.sil.cwe_taxonomy import is_a

# Findings from the older regex-based CWE-252 reporter are attributed to this
# synthetic procedure rather than to the procedure that contains the call.
_REGEX_REPORTER = "<interprocedural-analysis>"


def _cwes(src, language="c", filename="t.c"):
    """Every CWE id reported for `src`."""
    result = FrameScanner(language=language, verify=False).scan(src, filename)
    return {v.cwe_id for v in result.vulnerabilities}


def _lines(src, cwe, language="c", filename="t.c"):
    """Lines at which `cwe` is reported for `src`."""
    result = FrameScanner(language=language, verify=False).scan(src, filename)
    return [v.line for v in result.vulnerabilities if v.cwe_id == cwe]


def _structural_252_lines(src, language="c", filename="t.c"):
    """Lines where the STRUCTURAL CWE-252 rule fires, excluding the regex one."""
    result = FrameScanner(language=language, verify=False).scan(src, filename)
    return [
        v.line for v in result.vulnerabilities
        if v.cwe_id == "CWE-252" and v.procedure != _REGEX_REPORTER
    ]


# =============================================================================
# The reported shape
# =============================================================================

def test_discarded_setuid_result_is_reported():
    # A bare call statement: the return value has nowhere to go, so nothing
    # could have tested it. If the call fails the process keeps root.
    src = (
        "void drop(void) {\n"
        "  setuid(1000);\n"
        "}\n"
    )
    assert _lines(src, "CWE-252") == [2]


def test_discarded_setgid_result_is_reported():
    src = (
        "void drop(void) {\n"
        "  setgid(1000);\n"
        "}\n"
    )
    assert _lines(src, "CWE-252") == [2]


def test_discarded_result_of_the_canonical_drop_idiom_is_reported():
    # `setuid(getuid())` is THE way a privilege drop is written, and it is the
    # case a line-matching rule cannot see: the inner call's parenthesis ends
    # the match early. Reading the IR instead makes the nesting irrelevant.
    src = (
        "void drop(void) {\n"
        "  setuid(getuid());\n"
        "}\n"
    )
    assert _structural_252_lines(src) == [2]


def test_discarded_result_of_a_call_split_across_lines_is_reported():
    # Same argument for formatting: a call broken over several lines is not on
    # "a line" at all, but it is one Call instruction in the IR.
    src = (
        "void drop(void) {\n"
        "  setuid(\n"
        "    1000\n"
        "  );\n"
        "}\n"
    )
    assert _structural_252_lines(src) == [2]


def test_discarded_chroot_result_is_reported():
    # A chroot that silently failed leaves the process with the real filesystem
    # root while the program proceeds as though it is confined.
    src = (
        "void confine(void) {\n"
        "  chroot(\"/var/empty\");\n"
        "}\n"
    )
    assert _lines(src, "CWE-252") == [2]


# =============================================================================
# Checked results: none of these may fire
# =============================================================================

def test_result_tested_in_a_branch_condition_is_not_reported():
    # The required negative case, in its most common spelling. The call is
    # inlined into the branch condition and never becomes a Call instruction,
    # so it is not even a candidate.
    src = (
        "void drop(void) {\n"
        "  if (setuid(1000) != 0) {\n"
        "    abort();\n"
        "  }\n"
        "}\n"
    )
    assert "CWE-252" not in _cwes(src)


def test_result_assigned_then_tested_is_not_reported():
    src = (
        "void drop(void) {\n"
        "  int rc = setuid(1000);\n"
        "  if (rc != 0) {\n"
        "    abort();\n"
        "  }\n"
        "}\n"
    )
    assert "CWE-252" not in _cwes(src)


def test_result_passed_to_an_assertion_is_not_reported():
    src = (
        "void drop(void) {\n"
        "  assert(setuid(1000) == 0);\n"
        "}\n"
    )
    assert "CWE-252" not in _cwes(src)


def test_result_assigned_but_never_tested_is_not_reported():
    # A known and accepted miss. The value is stored and nothing ever looks at
    # it, which is the same bug; but distinguishing "stored and never read" from
    # "stored and read somewhere the analysis did not follow" is exactly the
    # judgment call that makes this detector class fire on correct code, so the
    # presence of a destination is taken at face value.
    src = (
        "void drop(void) {\n"
        "  int rc = setuid(1000);\n"
        "}\n"
    )
    assert "CWE-252" not in _cwes(src)


def test_result_returned_to_the_caller_is_not_reported():
    # Forwarding the result makes checking the caller's obligation, which is a
    # perfectly ordinary and correct design.
    src = (
        "int drop(void) {\n"
        "  return setuid(1000);\n"
        "}\n"
    )
    assert "CWE-252" not in _cwes(src)


# =============================================================================
# Conventionally ignorable returns: the reason the function list is short
# =============================================================================

def test_discarded_printf_result_is_not_reported():
    # printf returns a character count that essentially no program tests. This
    # is the canonical false positive for this CWE and must stay silent.
    src = (
        "void log_it(void) {\n"
        "  printf(\"hello\\n\");\n"
        "}\n"
    )
    assert "CWE-252" not in _cwes(src)


def test_discarded_results_of_ordinary_posix_calls_are_not_reported():
    # unlink, close, mkdir and fclose all fail routinely, and ignoring them in
    # a cleanup path is normal correct code rather than a weakness. None of them
    # carries `return_must_be_checked`, so the structural rule says nothing.
    # (The older regex reporter does report these; see the module docstring.)
    src = (
        "void cleanup(int fd) {\n"
        "  unlink(\"/tmp/x\");\n"
        "  close(fd);\n"
        "  mkdir(\"/tmp/y\", 0755);\n"
        "}\n"
    )
    assert _structural_252_lines(src) == []


def test_the_older_regex_reporter_still_fires_on_ignorable_functions():
    # Not an endorsement: a record of behavior this change deliberately did not
    # touch. `unlink()` in a cleanup path is correct code, and the line-matching
    # reporter calls it CWE-252 anyway. The structural rule above is the reason
    # that list is not simply extended, and closing the gap means retiring the
    # regex reporter, which is a separate change with its own regression risk.
    src = (
        "void cleanup(void) {\n"
        "  unlink(\"/tmp/x\");\n"
        "}\n"
    )
    assert _lines(src, "CWE-252") == [2]
    assert _structural_252_lines(src) == []


def test_discarded_memcpy_result_is_not_reported():
    # memcpy returns its destination pointer, which is never worth reading.
    src = (
        "void copy(char *d, char *s) {\n"
        "  memcpy(d, s, 4);\n"
        "}\n"
    )
    assert "CWE-252" not in _cwes(src)


def test_discarded_result_of_an_unknown_function_is_not_reported():
    # A function with no spec says nothing about whether its result matters, and
    # silence is the only defensible answer. Firing on every unspecified call
    # would report most lines of most programs.
    src = (
        "void run(void) {\n"
        "  do_something(1, 2);\n"
        "}\n"
    )
    assert "CWE-252" not in _cwes(src)


def test_python_append_style_discarded_results_are_not_reported():
    # The Python analogue: list.append returns None and str.strip returns a new
    # string that a statement-level call throws away. Neither is a weakness, and
    # no Python function carries `return_must_be_checked` at all.
    src = (
        "def f(items, s):\n"
        "    items.append(1)\n"
        "    s.strip()\n"
        "    print('done')\n"
    )
    assert "CWE-252" not in _cwes(src, language="python", filename="t.py")


# =============================================================================
# Relationship to the CWE-754 parent
# =============================================================================

def test_findings_answer_a_cwe_754_query_through_the_hierarchy():
    # Frame reports the specific child weakness. A policy or advisory citing the
    # CWE-754 parent still matches, which is why CWE-754 is not a detector of
    # its own: emitting both would count one weakness twice.
    src = (
        "void drop(void) {\n"
        "  setuid(1000);\n"
        "}\n"
    )
    assert "CWE-252" in _cwes(src)
    assert is_a("CWE-252", "CWE-754")
    assert is_a("CWE-252", "CWE-703")

    # One-way, as everywhere else: a query for the specific CWE-252 is not
    # answered by a generic CWE-754 finding.
    assert not is_a("CWE-754", "CWE-252")
