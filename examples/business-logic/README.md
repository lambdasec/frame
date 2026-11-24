# Missing limits: is the number the caller sends bounded?

A small Flask shop (`shop.py`):
- `/cart/add` stores the quantity a form sends, as sent.
- `/cart/set` rejects anything outside 1 to 100 first.
- `/pay` rejects an amount `<= 0`, which a `float` of `"nan"` passes, because NaN fails every comparison.

Whether a quantity may be zero is a business rule. Whether the code enforces a bound is not: on every feasible path to the line that stores the value, the path conditions either entail it or they do not. The engine decides that with Z3, with no model. Every output shown is what the command prints (`tests/test_examples.py` runs them and checks); each answer is longer, with the `evidence`, `resolution`, `limits` and `index` fields every answer carries.

```bash
cd examples/business-logic
```

`--root .` keeps the project to this directory (inside Frame's own repository a scan otherwise reads all of Frame as context).

## 1. A quantity stored as sent

```console
$ frame query . check --name add_item --line 12 --kind lower_bound --var order.quantity --bound 1 --root .
    "verdict": "refuted",
        "value": "order.quantity",
        "equals": 0,
        "from": "request.form"
    "reason": "a feasible path reaches line 12 with order.quantity = 0 (no condition on it on that path)",
    "origin": "order.quantity <- qty <- $qty_1 <- int(request.form[\"qty\"])"
```

`origin` is why the engine says the caller chooses the value. It is a copy of a copy of `int()` applied to a form field. A value that is computed, or read from storage, is `unknown` rather than refuted.

## 2. The same write behind a check

```console
$ frame query . check --name set_item --line 23 --kind lower_bound --var order.quantity --bound 1 --root .
    "verdict": "proved",
    "reason": "every feasible path to line 23 entails order.quantity >= 1 (from: (!qty < 1 & !qty > 100))",
```

## 3. A guard that NaN walks past

```console
$ frame query . check --name pay --line 33 --kind lower_bound --var amount --bound 1 --root .
    "verdict": "refuted",
        "equals": "NaN",
    "reason": "a feasible path reaches line 33 with amount = NaN (it passes: !amount <= 0)",
```

`float("nan") <= 0` is false, so `pay` charges NaN. Writing the guard the other way round, `if not amount > 0: abort(400)`, turns NaN away too: it accepts only what passes the comparison.

## 4. Keeping the rule in CI

The answer to section 1 can live in a pack, so it does not depend on someone asking again. `invariants.toml` states the shop's rule as an `[[invariant]]` entry. Every scan that loads it checks each write of `Order.quantity` against the bound, with no model:

```toml
[[invariant]]
id = "order-quantity-positive"
kind = "bound"
model = "Order"
field = "quantity"
min = 1
max = 100
description = "an order holds 1 to 100 items"
```

```console
$ frame scan . --pack invariants.toml --root .
1. [MEDIUM] 🟡 business_logic_flaw
   Location: shop.py:12:0
   Function: add_item
   Description: invariant order-quantity-positive (Order.quantity >= 1 and Order.quantity <= 100): an order holds 1 to 100 items. Broken in add_item: order.quantity = qty: a feasible path reaches line 12 with order.quantity = 0 (no condition on it on that path)
   CWE: CWE-1284
```

`set_item` writes the same field after checking both ends, so the engine proves the rule there and reports nothing. Put the file in `.frame/packs/` and every scan loads it without `--pack`.

## With a model

`frame scan . --hunt limits` gives each handler unit an agent with these questions as a tool. A finding is `llm-verified` only when the engine refuted the bound in that function. The engine's witness is in the description, for example `engine: order.quantity = 0 reaches line 12 on a feasible path`. `--save-invariants FILE` writes the rule behind each such finding as an entry like the one in section 4. See [docs/ai.md](../../docs/ai.md#hunting-business-logic-flaws---hunt).
