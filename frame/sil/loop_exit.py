"""Whether a loop body contains a statement that can transfer control out of the loop.

`break` and `continue` carry no SIL instruction: the frontends model them by
falling through to the next basic block, so a `while True:` whose body breaks is
indistinguishable in the CFG from one that spins forever. Deciding CWE-835
(Loop with Unreachable Exit Condition) therefore needs one fact the CFG cannot
supply, and the frontend, which still holds the parse tree, is the only place
that can supply it.

This module answers exactly that question and nothing more. The reasoning that
combines it with the loop condition lives in the translator, so the frontends
stay free of detection policy.

The check is deliberately biased towards saying "yes, it can exit":

  * A `break` inside a NESTED loop leaves only the inner loop, but we still count
    it. Over-reporting an exit can only lose a finding, never invent one, and a
    labelled break (`break outer;` in Java/JS) really does leave the outer loop.
  * A `return` inside a nested closure is not a loop exit either, and is likewise
    counted. Same one-sided error.
  * Any node type we do not recognise is ignored, so an unfamiliar grammar
    silently yields "cannot exit" for the body, which the translator then pairs
    with the much stronger requirement that the loop condition be a constant.

Node-type names come from the tree-sitter grammars, which agree on
`break_statement` / `return_statement` across Python, Java, JavaScript, C and C#.
"""

# Parse-tree node types that transfer control out of the enclosing loop.
# `continue_statement` is deliberately absent: it re-tests the loop condition,
# which for a constant-true condition means the loop still cannot terminate.
_EXIT_NODE_TYPES = frozenset({
    # break, including the labelled forms Java and JavaScript allow
    "break_statement",
    "labeled_break_statement",
    # early return from the enclosing function
    "return_statement",
    # exceptions: Python raises, everything else throws
    "raise_statement",
    "throw_statement",
    "throw_expression",
    # unstructured jumps (C, C#)
    "goto_statement",
    # a generator suspends and its consumer decides when to stop iterating, so a
    # `while True: yield ...` producer terminates by being abandoned
    "yield",
    "yield_statement",
    "yield_expression",
})


def body_can_exit_loop(body) -> bool:
    """True if any statement in `body` (a tree-sitter node) can leave the loop.

    Returns True for a missing body as well: nothing is known, so nothing should
    be concluded.
    """
    if body is None:
        return True

    stack = [body]
    while stack:
        node = stack.pop()
        node_type = getattr(node, "type", None)
        if node_type in _EXIT_NODE_TYPES:
            return True
        children = getattr(node, "children", None)
        if children:
            stack.extend(children)
    return False
