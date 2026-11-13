# Asking the engine: `frame query`

A three-route Flask app (`app.py`): `/items` builds SQL from a query parameter, `/orders/<id>` checks that the caller is an admin before reading an order, and `/orders/<id>/refund` changes an order with no check at all. These are the questions an agent asks while reviewing it, answered by the engine with no model. Every output shown is what the command prints (`tests/test_examples.py` runs them and checks); each answer is longer, with the `evidence`, `resolution`, `limits` and `index` fields every answer carries.

```bash
cd examples/engine-query
```

`--root .` keeps the project to this directory (inside Frame's own repository a scan otherwise reads all of Frame as context).

## 1. Who calls the database helper?

```console
$ frame query . callers --name run_query --root .
        "caller": "items",
        "code": "return str(run_query(\"SELECT * FROM items WHERE name = '\" + name + \"'\"))"
        "caller": "order",
        "caller": "refund",
```

## 2. Does attacker data reach it?

```console
$ frame query . trace --name run_query --root .
        "cwe": "CWE-89",
        "source": "request.args",
        "evidence": "solver-verified"
```

The flow is listed where its sink is, in the helper; its `data_flow` names the call.

## 3. Which sibling skips the check the others make?

```console
$ frame query . siblings --name refund --root .
        "name": "order",
          "noreturn_guard@21: !(current_user.is_admin) -> abort(403)"
        "name": "refund",
        "guards_at_data_access": []
```

## 4. Prove it, path by path

```console
$ frame query . check --name order --line 23 --kind guarded_by --pattern is_admin --root .
    "verdict": "proved",
    "reason": "every feasible path to line 23 passes !(current_user.is_admin) -> abort(403)"

$ frame query . check --name refund --line 28 --kind guarded_by --pattern is_admin --root .
    "verdict": "refuted",
    "reason": "a feasible path reaches line 28 without a condition matching 'is_admin'"
```

`refuted` comes with the witness path. Whether a refund should need an admin is a question of intent, which the engine leaves to the reader (or to `frame scan --hunt-authz`).

## 5. Keep it warm

```console
$ frame query . --serve --root .
{"id": 1, "tool": "callers", "args": {"name": "run_query"}}
```

One JSON request per line in, one answer per line out. The index is built on the first request and reused until a source file changes; frame-mcp keeps one such process per project behind its `engine_*` tools.
