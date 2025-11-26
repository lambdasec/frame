"""
Lemmas for Magic Wand Reasoning

Key properties:
  1. Wand Elimination (Modus Ponens): (P -* Q) * P |- Q
  2. Wand Introduction: If P * R |- Q, then R |- P -* Q (adjunction)
  3. Wand Transitivity: (P -* Q) * (Q -* R) |- (P -* R)
  4. Wand Frame: (P -* Q) |- (P * R) -* (Q * R)
  5. Emp Wand: (emp -* Q) |- Q

These lemmas provide the core reasoning principles for magic wand.
The most important is modus ponens (wand elimination), which is used
frequently in practice.
"""

from frame.core.ast import *


def initialize_wand_lemmas(library):
    """Initialize wand lemmas in the library"""

    # Lemma 1: Wand Elimination (Modus Ponens) - Most Important!
    # Pattern: (P -* Q) * P |- Q
    library.add_lemma(
        name="wand_elimination",
        antecedent=SepConj(Wand(Var("P"), Var("Q")), Var("P")),
        consequent=Var("Q"),
        description="Wand elimination (modus ponens): (P -* Q) * P |- Q"
    )

    # Also register reverse order: P * (P -* Q) |- Q
    library.add_lemma(
        name="wand_elimination_rev",
        antecedent=SepConj(Var("P"), Wand(Var("P"), Var("Q"))),
        consequent=Var("Q"),
        description="Wand elimination (reverse order): P * (P -* Q) |- Q"
    )

    # Lemma 2: Emp Wand - Simple Case
    # Pattern: (emp -* Q) |- Q
    library.add_lemma(
        name="wand_emp_left",
        antecedent=Wand(Emp(), Var("Q")),
        consequent=Var("Q"),
        description="Wand with empty antecedent: (emp -* Q) |- Q"
    )

    # NOTE: wand_reflexivity lemma REMOVED for soundness in Multi-Step Lemma application
    #
    # The lemma: P |- (emp -* P)
    #
    # The problem: When used in Multi-Step Lemma application with the meta-variable P,
    # it can match ANY formula part and convert it to a wand. This can "hide" spatial
    # assertions in wands, causing the checker to lose track of heap allocations.
    #
    # Example (dll-entl-08.smt2 false positive):
    #   Current: ldll(E1, ...) * E2 |-> (...) * ldll(E2, ...)
    #   Applied wand_reflexivity (P = ldll(E1, ...))
    #   New formula: (emp -* P) * E2 |-> (...) * ldll(E2, ...)
    #
    # This transformation is SOUND in isolation, but in Multi-Step Lemma application
    # it can lead to incorrect conclusions because subsequent lemma applications may
    # treat the wand differently than the original spatial assertion.
    #
    # The wand_emp_left lemma (emp -* Q) |- Q can undo this, but the interaction
    # between these lemmas in multi-step application is unpredictable.
    #
    # Fix: Keep wand_emp_left (safe), remove wand_reflexivity (unsafe in multi-step)

    # Lemma 4: Wand Transitivity
    # Pattern: (P -* Q) * (Q -* R) |- (P -* R)
    library.add_lemma(
        name="wand_transitivity",
        antecedent=SepConj(Wand(Var("P"), Var("Q")), Wand(Var("Q"), Var("R"))),
        consequent=Wand(Var("P"), Var("R")),
        description="Wand transitivity: (P -* Q) * (Q -* R) |- (P -* R)"
    )

    # NOTE: wand_pto_intro and wand_pred_intro lemmas REMOVED
    # Same issue as wand_reflexivity - wrapping spatial parts in wands
    # can hide heap allocations and lead to unsound Multi-Step Lemma derivations

    # Lemma 7: Wand Curry/Uncurry
    # Pattern: (P * Q -* R) |- (P -* (Q -* R))
    library.add_lemma(
        name="wand_curry",
        antecedent=Wand(SepConj(Var("P"), Var("Q")), Var("R")),
        consequent=Wand(Var("P"), Wand(Var("Q"), Var("R"))),
        description="Wand curry: (P * Q -* R) |- (P -* (Q -* R))"
    )

    # Uncurrying (reverse direction)
    library.add_lemma(
        name="wand_uncurry",
        antecedent=Wand(Var("P"), Wand(Var("Q"), Var("R"))),
        consequent=Wand(SepConj(Var("P"), Var("Q")), Var("R")),
        description="Wand uncurry: (P -* (Q -* R)) |- (P * Q -* R)"
    )

    # Lemma 8: Wand Modus Ponens for List Segments
    # Pattern: ((ls(x,y) -* ls(z,w)) * ls(x,y)) |- ls(z,w)
    library.add_lemma(
        name="wand_modus_ponens_ls",
        antecedent=SepConj(
            Wand(
                PredicateCall("ls", [Var("X"), Var("Y")]),
                PredicateCall("ls", [Var("Z"), Var("W")])
            ),
            PredicateCall("ls", [Var("X"), Var("Y")])
        ),
        consequent=PredicateCall("ls", [Var("Z"), Var("W")]),
        description="Magic wand modus ponens for list segments"
    )

    # Reverse order
    library.add_lemma(
        name="wand_modus_ponens_ls_rev",
        antecedent=SepConj(
            PredicateCall("ls", [Var("X"), Var("Y")]),
            Wand(
                PredicateCall("ls", [Var("X"), Var("Y")]),
                PredicateCall("ls", [Var("Z"), Var("W")])
            )
        ),
        consequent=PredicateCall("ls", [Var("Z"), Var("W")]),
        description="Magic wand modus ponens for list segments (reverse order)"
    )

    # Lemma 9: Simple Wand Combination
    # Pattern: (emp -* P) * (emp -* Q) |- (emp -* P * Q)
    library.add_lemma(
        name="wand_emp_combine",
        antecedent=SepConj(Wand(Emp(), Var("P")), Wand(Emp(), Var("Q"))),
        consequent=Wand(Emp(), SepConj(Var("P"), Var("Q"))),
        description="Combine wands with empty antecedent: (emp -* P) * (emp -* Q) |- (emp -* P * Q)"
    )


__all__ = ['initialize_wand_lemmas']
