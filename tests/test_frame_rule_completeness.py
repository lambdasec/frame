"""Valid entailments the frame rule and antecedent existentials used to lose,
and the invalid neighbours that must stay invalid."""

import pytest

from frame import EntailmentChecker


@pytest.fixture(scope="module")
def checker():
    return EntailmentChecker()


@pytest.mark.parametrize("entailment", [
    # Cancelling z |-> w dropped the cell that rules out a cycle through z.
    "ls(x, y) * ls(y, z) * z |-> w |- ls(x, z) * z |-> w",
    # Cancelling both cells dropped what their separation implied.
    "x |-> 1 * y |-> 2 |- x |-> 1 * y |-> 2 & x != y",
    "x |-> 1 * y |-> 2 |- x |-> 1 * y |-> 2 & x != nil",
    # An existential in the antecedent hid its cells from folding.
    "exists z. x |-> z * z |-> nil |- ls(x, nil)",
])
def test_valid(checker, entailment):
    assert checker.check_entailment(entailment).valid


@pytest.mark.parametrize("entailment", [
    "ls(x, y) * ls(y, z) |- ls(x, z)",
    "x |-> 1 * y |-> 2 |- x |-> 1 * y |-> 2 & x = y",
    "x |-> 5 |- x |-> 5 * y |-> 3",
    "x |-> y * y |-> z |- ls(x, z)",
    # The bound z is not the free z of the consequent.
    "exists z. x |-> z |- x |-> z",
    "exists z. x |-> z * z |-> nil |- x |-> z * z |-> nil",
    "exists z. x |-> z * z |-> nil |- x |-> nil",
])
def test_invalid(checker, entailment):
    assert not checker.check_entailment(entailment).valid
