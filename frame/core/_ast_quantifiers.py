"""
Quantifier and predicate AST nodes

Defines quantified formulas and predicate calls:
- Existential quantification
- Universal quantification
- Predicate calls for inductive predicates
"""

from typing import Set, List
from frame.core._ast_base import Formula, Expr


class Exists(Formula):
    """Existential quantification: ∃x. P"""

    def __init__(self, var: str, formula: Formula):
        self.var = var
        self.formula = formula

    def __str__(self) -> str:
        return f"exists {self.var}. {self.formula}"

    def free_vars(self) -> Set[str]:
        return self.formula.free_vars() - {self.var}

    def is_spatial(self) -> bool:
        return self.formula.is_spatial()


class Forall(Formula):
    """Universal quantification: ∀x. P"""

    def __init__(self, var: str, formula: Formula):
        self.var = var
        self.formula = formula

    def __str__(self) -> str:
        return f"forall {self.var}. {self.formula}"

    def free_vars(self) -> Set[str]:
        return self.formula.free_vars() - {self.var}

    def is_spatial(self) -> bool:
        return self.formula.is_spatial()


class PredicateCall(Formula):
    """Call to an inductive predicate: ls(x, y) or tree(x)"""

    def __init__(self, name: str, args: List[Expr]):
        self.name = name
        self.args = args

    def __str__(self) -> str:
        args_str = ", ".join(str(arg) for arg in self.args)
        return f"{self.name}({args_str})"

    def free_vars(self) -> Set[str]:
        vars_set = set()
        for arg in self.args:
            vars_set.update(arg.free_vars())
        return vars_set

    def is_spatial(self) -> bool:
        return True
