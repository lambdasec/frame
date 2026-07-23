"""CWE hierarchy relations.

The point of this module is to let a query for a broad weakness class match the
specific weakness Frame actually proved. The tests below pin both directions of
that: what must match, and, just as importantly, what must NOT. An over-broad
hierarchy would manufacture agreement between unrelated findings and advisories,
which is worse than missing a match.
"""

import pytest

from frame.sil.cwe_taxonomy import (
    CHILD_OF, ancestors, is_a, matches_any, normalize, parents,
)


# --- normalization -----------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("CWE-79", "CWE-79"),
    ("cwe-79", "CWE-79"),
    ("cwe_79", "CWE-79"),
    ("CWE79", "CWE-79"),
    ("79", "CWE-79"),
    (79, "CWE-79"),
    (" CWE-079 ", "CWE-79"),
])
def test_normalize_accepts_common_spellings(raw, expected):
    assert normalize(raw) == expected


@pytest.mark.parametrize("raw", [None, "", "not-a-cwe", "CWE-", "CWE-abc"])
def test_normalize_rejects_garbage(raw):
    assert normalize(raw) is None


# --- the relation holds where MITRE says it does -----------------------------

def test_sql_injection_is_an_injection():
    # CWE-89 -> CWE-943 -> CWE-74
    assert is_a("CWE-89", "CWE-74")


def test_transitive_to_pillar():
    # CWE-79 -> CWE-74 -> CWE-707
    assert is_a("CWE-79", "CWE-707")
    assert "CWE-707" in ancestors("CWE-79")


def test_os_command_injection_chain():
    assert is_a("CWE-78", "CWE-77")
    assert is_a("CWE-78", "CWE-74")


def test_authorization_classes_share_a_parent():
    # Missing (862) and Incorrect (863) authorization are siblings under 285.
    assert is_a("CWE-862", "CWE-285")
    assert is_a("CWE-863", "CWE-285")
    assert is_a("CWE-639", "CWE-863")      # IDOR is a kind of incorrect authz
    assert is_a("CWE-639", "CWE-284")      # ... and of improper access control


def test_resource_exhaustion_chain():
    assert is_a("CWE-770", "CWE-400")      # unbounded allocation is resource consumption
    assert is_a("CWE-674", "CWE-834")      # uncontrolled recursion is excessive iteration
    assert is_a("CWE-835", "CWE-834")      # infinite loop likewise
    assert is_a("CWE-835", "CWE-691")


def test_memory_safety_chain():
    assert is_a("CWE-787", "CWE-119")
    assert is_a("CWE-120", "CWE-119")
    assert is_a("CWE-401", "CWE-772")      # memory leak is a missing release


def test_identity_always_matches():
    for cwe in ("CWE-89", "CWE-400", "CWE-22", "CWE-9999"):
        assert is_a(cwe, cwe)


# --- the relation must NOT hold where it does not ----------------------------

def test_relation_is_one_way():
    # A generic Injection finding does not satisfy a query for SQL injection.
    assert is_a("CWE-89", "CWE-74")
    assert not is_a("CWE-74", "CWE-89")


def test_improper_input_validation_is_not_a_parent_of_injection():
    # CWE-20 is a SIBLING of CWE-74 under CWE-707, not its ancestor. Advisories
    # often cite CWE-20 loosely; treating it as a parent would manufacture
    # matches for most of Frame's findings. This must stay false.
    assert not is_a("CWE-89", "CWE-20")
    assert not is_a("CWE-79", "CWE-20")
    assert not is_a("CWE-22", "CWE-20")


def test_siblings_do_not_match():
    assert not is_a("CWE-862", "CWE-863")
    assert not is_a("CWE-863", "CWE-862")
    assert not is_a("CWE-79", "CWE-89")


def test_unrelated_classes_do_not_match():
    assert not is_a("CWE-89", "CWE-400")     # injection is not resource exhaustion
    assert not is_a("CWE-401", "CWE-74")     # memory leak is not injection
    assert not is_a("CWE-327", "CWE-284")    # weak crypto is not access control


def test_unknown_cwe_matches_only_itself():
    # An incomplete table must lose matches, never invent them.
    assert is_a("CWE-99999", "CWE-99999")
    assert not is_a("CWE-99999", "CWE-74")
    assert not is_a("CWE-89", "CWE-99999")
    assert ancestors("CWE-99999") == set()


def test_garbage_never_matches():
    assert not is_a(None, "CWE-74")
    assert not is_a("CWE-89", None)
    assert not is_a("bogus", "CWE-74")


# --- structural integrity ----------------------------------------------------

def test_no_cycles_and_ancestors_terminate():
    for cwe in CHILD_OF:
        anc = ancestors(cwe)          # would hang or recurse forever on a cycle
        assert cwe not in anc, f"{cwe} is its own ancestor"


def test_every_parent_is_a_known_node():
    # A parent that is not itself a key would silently truncate ancestry.
    for child, ps in CHILD_OF.items():
        for p in ps:
            assert p in CHILD_OF, f"{child} has parent {p} missing from the table"


def test_all_keys_normalize_to_themselves():
    for cwe in CHILD_OF:
        assert normalize(cwe) == cwe


def test_matches_any():
    assert matches_any("CWE-89", ["CWE-400", "CWE-74"])
    assert not matches_any("CWE-89", ["CWE-400", "CWE-20"])
    assert not matches_any("CWE-89", [])


def test_parents_accessor():
    assert parents("CWE-89") == ("CWE-943",)
    assert parents("CWE-707") == ()
    assert parents("CWE-99999") == ()


# --- the Tier 1 additions ----------------------------------------------------

def test_directional_memory_safety_sits_under_the_generic_class():
    # CWE-787 and CWE-125 are the directional siblings of CWE-120. All three are
    # children of CWE-119, so an advisory citing the broad memory-corruption
    # class matches whichever one Frame was able to prove.
    assert is_a("CWE-787", "CWE-119")
    assert is_a("CWE-125", "CWE-119")
    assert is_a("CWE-120", "CWE-119")
    assert is_a("CWE-787", "CWE-118")
    assert is_a("CWE-125", "CWE-664")


def test_a_write_is_not_a_read():
    # Siblings, not ancestors of one another. Reporting the direction is only
    # worth doing if the two do not collapse into each other on query.
    assert not is_a("CWE-787", "CWE-125")
    assert not is_a("CWE-125", "CWE-787")
    assert not is_a("CWE-787", "CWE-120")
    assert not is_a("CWE-120", "CWE-787")


def test_excessive_allocation_sits_under_the_resource_classes():
    # CWE-789 (excessive constant size) and CWE-770 (unbounded tainted size) are
    # not siblings: 789 is 770's child, so a CWE-770 query catches both.
    assert is_a("CWE-789", "CWE-770")
    assert is_a("CWE-789", "CWE-400")
    assert is_a("CWE-789", "CWE-664")
    assert not is_a("CWE-770", "CWE-789")


def test_unchecked_return_sits_under_improper_check():
    # CWE-754 is the MITRE parent of CWE-252, which is why Frame emits only the
    # specific child: a CWE-754 query is answered through the hierarchy.
    assert is_a("CWE-252", "CWE-754")
    assert is_a("CWE-252", "CWE-703")
    assert not is_a("CWE-754", "CWE-252")

    # It is not an availability weakness, whatever the surface similarity.
    assert not is_a("CWE-252", "CWE-400")


def test_permission_assignment_sits_under_resource_exposure():
    assert is_a("CWE-732", "CWE-668")
    assert is_a("CWE-732", "CWE-664")

    # A world-writable file is not an access-control-check weakness: CWE-732
    # lives under resource exposure, not under CWE-284.
    assert not is_a("CWE-732", "CWE-284")


def test_new_cwes_are_all_reachable_from_a_pillar():
    # Every CWE Frame emits should terminate at a CWE-1000 pillar rather than
    # dangling, otherwise a broad policy query silently misses it.
    pillars = {"CWE-664", "CWE-691", "CWE-693", "CWE-703", "CWE-707", "CWE-710", "CWE-682"}
    for cwe in ("CWE-787", "CWE-125", "CWE-789", "CWE-252", "CWE-732"):
        assert ancestors(cwe) & pillars, f"{cwe} does not reach a pillar"
