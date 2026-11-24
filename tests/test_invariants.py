"""Invariants as data (frame/sil/invariants.py): `[[invariant]]` pack entries the engine checks on
every scan with no model. Each broken case is paired with the nearest code that keeps the rule."""

import pytest

from frame.sil.packs import PackError, PackSet
from frame.sil.scanner import FrameScanner


def _pack(tmp_path, language, body, name="inv.toml"):
    p = tmp_path / name
    p.write_text(f'[pack]\nname = "invariants"\nlanguage = "{language}"\ndescription = "test"\n\n{body}')
    return str(p)


def _scan(tmp_path, filename, source, pack):
    f = tmp_path / filename
    f.write_text(source)
    res = FrameScanner(packs=[pack]).scan_file(str(f))
    found = [v for v in res.vulnerabilities if (v.sink_type or "").startswith("invariant:")]
    notes = [w for w in res.warnings if "invariant " in w]
    return found, notes


QTY = """[[invariant]]
id = "order-quantity-positive"
kind = "bound"
field = "quantity"
model = "Order"
min = 1
"""

FLASK = """\
from flask import Flask, request, abort
from models import Order, Cart
app = Flask(__name__)

@app.route("/order", methods=["POST"])
def place():
    qty = int(request.form["qty"])
    order = Order.objects.get(id=request.form["id"])
    order.quantity = qty
    order.save()
    Order.objects.create(quantity=qty)
    return "ok"

@app.route("/order/checked", methods=["POST"])
def place_checked():
    qty = int(request.form["qty"])
    if qty < 1:
        abort(400)
    order = Order.objects.get(id=request.form["id"])
    order.quantity = qty
    order.save()
    return "ok"

@app.route("/cart", methods=["POST"])
def cart():
    qty = int(request.form["qty"])
    c = Cart.objects.get(id=request.form["id"])
    c.quantity = qty
    c.save()
    return "ok"

@app.route("/copy", methods=["POST"])
def copy():
    order = Order.objects.get(id=request.form["id"])
    other = Order.objects.get(id=request.form["other"])
    order.quantity = other.quantity - 1
    order.save()
    return "ok"
"""


def test_a_bound_on_a_model_field_python(tmp_path):
    found, notes = _scan(tmp_path, "app.py", FLASK, _pack(tmp_path, "python", QTY))
    lines = sorted(v.line for v in found)
    assert lines == [9, 11]                      # place: the assignment and the keyword argument
    v = next(v for v in found if v.line == 9)
    assert v.procedure == "place" and v.cwe_id == "CWE-1284" and v.evidence == "solver-verified"
    assert "order-quantity-positive" in v.description and "= 0" in v.description
    assert v.witness and "0" in v.witness
    # place_checked refuses qty < 1 (proved, silent); Cart is not an Order (no site); `copy` stores
    # a value read from storage, which the engine cannot say the caller chooses (a warning)
    assert all(v.procedure not in ("place_checked", "cart", "copy") for v in found)
    assert any(":36:" in n and "Undecided in copy" in n for n in notes)


def test_a_bound_in_javascript_lets_nan_through(tmp_path):
    src = """\
const express = require('express');
const app = express();
app.post('/order', async (req, res) => {
  const qty = Number(req.body.qty);
  if (qty < 1) return res.status(400).send('no');
  const order = await Order.findOne({ id: req.body.id });
  order.quantity = qty;
  await order.save();
  res.send('ok');
});
app.post('/order2', async (req, res) => {
  const qty = Number(req.body.qty);
  if (!(qty >= 1)) return res.status(400).send('no');
  await Order.create({ quantity: qty });
  res.send('ok');
});
"""
    found, _ = _scan(tmp_path, "app.js", src, _pack(tmp_path, "javascript", QTY))
    assert [v.line for v in found] == [7]
    assert "NaN" in found[0].description        # NaN fails `qty < 1` and is stored


def test_a_bound_in_java_through_a_setter(tmp_path):
    src = """\
import org.springframework.web.bind.annotation.*;
@RestController
public class Svc {
  @PostMapping("/order")
  public String place(@RequestParam int qty, @RequestParam long id) {
    Order order = repo.findById(id);
    order.setQuantity(qty);
    repo.save(order);
    return "ok";
  }
  @PostMapping("/order2")
  public String placeChecked(@RequestParam int qty, @RequestParam long id) {
    if (qty < 1 || qty > 100) {
      throw new IllegalArgumentException("qty");
    }
    Order order = repo.findById(id);
    order.setQuantity(qty);
    repo.save(order);
    return "ok";
  }
}
"""
    pack = _pack(tmp_path, "java", QTY.replace("min = 1", "min = 1\nmax = 100"))
    found, _ = _scan(tmp_path, "Svc.java", src, pack)
    assert [(v.line, v.procedure) for v in found] == [(7, "Svc.place")]


STATUS = """[[invariant]]
id = "ship-after-payment"
kind = "guarded"
field = "status"
value = "shipped"
guarded_by = "paid"
description = "an order ships only once it is paid"
"""

SHIP = """\
from flask import Flask, request, abort
from models import Order
app = Flask(__name__)

@app.route("/ship", methods=["POST"])
def ship():
    order = Order.objects.get(id=request.form["id"])
    order.status = "shipped"
    order.save()
    return "ok"

@app.route("/ship/checked", methods=["POST"])
def ship_checked():
    order = Order.objects.get(id=request.form["id"])
    if not order.paid:
        abort(409)
    order.status = "shipped"
    order.save()
    return "ok"

@app.route("/cancel", methods=["POST"])
def cancel():
    order = Order.objects.get(id=request.form["id"])
    order.status = "cancelled"
    order.save()
    return "ok"
"""


def test_a_state_a_write_requires(tmp_path):
    found, _ = _scan(tmp_path, "app.py", SHIP, _pack(tmp_path, "python", STATUS))
    assert [(v.line, v.procedure) for v in found] == [(8, "ship")]
    v = found[0]
    assert v.cwe_id == "CWE-841" and "an order ships only once it is paid" in v.description


def test_a_guarded_call_and_a_function_scope(tmp_path):
    src = """\
from flask import Flask, request, abort
from payments import gateway
app = Flask(__name__)

@app.route("/refund", methods=["POST"])
def refund():
    gateway.refund(request.form["charge"])
    return "ok"

@app.route("/admin/refund", methods=["POST"])
def admin_refund():
    gateway.refund(request.form["charge"])
    return "ok"
"""
    body = """[[invariant]]
id = "refund-only-delivered"
kind = "guarded"
call = ["*.refund"]
guarded_by = "delivered"
function = ["refund"]
severity = "high"
"""
    found, _ = _scan(tmp_path, "app.py", src, _pack(tmp_path, "python", body))
    assert [(v.procedure, v.severity.value) for v in found] == [("refund", "high")]


def test_no_invariant_pack_no_value_facts(tmp_path, monkeypatch):
    seen = []
    from frame.sil import translator as tr
    orig = tr.SILTranslator.translate_program

    def spy(self):
        seen.append(getattr(self, "record_value_facts", None))
        return orig(self)
    monkeypatch.setattr(tr.SILTranslator, "translate_program", spy)
    f = tmp_path / "app.py"
    f.write_text(FLASK)
    FrameScanner().scan_file(str(f))
    assert seen == [False]                     # a plain scan never pays for the value facts


@pytest.mark.parametrize("body, error", [
    ('id = "a"\nkind = "bound"\nfield = "q"\n', "min` or `max"),
    ('id = "a"\nkind = "bound"\nmin = 1\n', "needs `field`"),
    ('id = "a"\nkind = "bound"\nfield = "q"\nmin = 2\nmax = 1\n', "min is above max"),
    ('id = "a"\nkind = "bound"\nfield = "q"\nmin = "1"\n', "must be a number"),
    ('id = "a"\nkind = "guarded"\nfield = "s"\n', "needs `guarded_by`"),
    ('id = "a"\nkind = "guarded"\nguarded_by = "p"\n', "`field` or `call`"),
    ('id = "a"\nkind = "guarded"\ncall = ["x.y"]\nvalue = "v"\nguarded_by = "p"\n', "value goes with field"),
    ('id = "a"\nkind = "guarded"\nfield = "s"\nguarded_by = "("\n', "not a valid pattern"),
    ('id = "a"\nkind = "limit"\nfield = "q"\n', "bound or guarded"),
    ('id = "a b"\nkind = "bound"\nfield = "q"\nmin = 1\n', "id must be a name"),
    ('id = "a"\nkind = "bound"\nfield = "q.r"\nmin = 1\n', "field must be a name"),
    ('id = "a"\nkind = "bound"\nfield = "q"\nmin = 1\ncwe = "1284"\n', "cwe must look like"),
    ('id = "a"\nkind = "bound"\nfield = "q"\nmin = 1\nwhere = "x"\n', "where"),
])
def test_invariants_are_validated(tmp_path, body, error):
    with pytest.raises(PackError, match=error):
        PackSet.build([_pack(tmp_path, "python", "[[invariant]]\n" + body)], builtin=False)


def test_invariants_are_code_packs_only(tmp_path):
    with pytest.raises(PackError, match="invariants are checked for"):
        PackSet.build([_pack(tmp_path, "c", QTY)], builtin=False)
    with pytest.raises(PackError, match="used twice"):
        PackSet.build([_pack(tmp_path, "python", QTY + "\n" + QTY)], builtin=False)


def test_a_hunt_check_becomes_an_entry_the_engine_refutes(tmp_path):
    """`learn` turns a refuted check from a hunt into an entry; the saved pack loads and a scan with
    no model reports the same flaw, and stops once the code refuses the value."""
    from frame.sil import invariants
    from frame.sil.cli import save_invariants
    f = tmp_path / "app.py"
    f.write_text(FLASK)
    sc = FrameScanner()
    sc.collect_programs = True
    sc.scan_directory(str(tmp_path), None, project_root=str(tmp_path))
    prog = next(p for p in sc._hunt_programs if "place" in p.procedures)
    check = {"name": "place", "line": 9, "kind": "lower_bound", "var": "qty", "bound": 1,
             "verdict": "refuted"}
    entry = invariants.learn(prog, "place", check, {"mechanism": "missing_limit", "cwe": "CWE-1284",
                                                    "invariant": "an order holds at least one item"})
    assert entry is not None
    assert (entry["kind"], entry["field"], entry["min"], entry["function"]) == ("bound", "quantity", 1, ["place"])
    assert entry["id"] == "place-quantity-missing-limit"
    # a line that is no write gives no entry
    assert invariants.learn(prog, "place", {**check, "line": 7}, {}) is None
    out = tmp_path / ".frame" / "packs" / "invariants.toml"
    written = save_invariants(str(out), [{**entry, "language": "python", "file": "app.py"}])
    assert written == [str(out)]
    # saving again keeps one entry per id
    save_invariants(str(out), [{**entry, "language": "python", "file": "app.py"}])
    assert out.read_text().count("[[invariant]]") == 1
    PackSet.build([str(out)], builtin=False)
    f.unlink()
    found, _ = _scan(tmp_path, "app.py", FLASK, str(out))
    assert [(v.procedure, v.line) for v in found] == [("place", 9), ("place", 11)]
    fixed = FLASK.replace('    qty = int(request.form["qty"])\n    order = Order.objects.get(id=request.form["id"])\n'
                          '    order.quantity = qty\n    order.save()\n    Order.objects.create',
                          '    qty = int(request.form["qty"])\n    if qty < 1:\n        abort(400)\n'
                          '    order = Order.objects.get(id=request.form["id"])\n'
                          '    order.quantity = qty\n    order.save()\n    Order.objects.create', 1)
    assert fixed != FLASK
    found, _ = _scan(tmp_path, "app.py", fixed, str(out))
    assert found == []


def test_saving_refuses_a_pack_with_other_entries(tmp_path):
    from frame.sil.cli import save_invariants
    p = tmp_path / "mixed.toml"
    p.write_text('[pack]\nname = "x"\nlanguage = "python"\n\n[[auth_gate]]\ndecorator = ["login_required"]\n')
    with pytest.raises(ValueError, match="more than invariants"):
        save_invariants(str(p), [{"id": "a", "kind": "bound", "field": "q", "min": 1, "language": "python"}])


def test_a_full_scan_names_stale_invariants(tmp_path):
    """An entry that meets no write on a full scan checks nothing (a renamed function or field):
    the scan says so instead of passing silently."""
    import json
    import subprocess
    import sys
    app = tmp_path / "app"
    app.mkdir()
    (app / "app.py").write_text(FLASK)
    body = QTY + '\n[[invariant]]\nid = "gone"\nkind = "bound"\nfield = "quantity"\nmin = 1\nfunction = ["renamed"]\n'
    pack = _pack(tmp_path, "python", body)
    r = subprocess.run([sys.executable, "-m", "frame.sil.cli", "scan", str(app), "--pack", pack,
                        "--root", str(app), "--format", "json"], capture_output=True, text=True)
    data = json.loads(r.stdout)
    assert data["invariants"] == {"checked": 2, "stale": ["gone"]}
    assert "met no write" in r.stderr and "gone" in r.stderr


def test_the_hunt_learns_entries_from_engine_backed_findings(tmp_path):
    """Only a business-logic finding whose refuted check names a write becomes an entry, and only
    when the entry is refuted on the code again; the hunt's summary carries them."""
    from frame.sil.cli import hunt_summary
    from frame.sil.hunt_tools import HuntContext
    from frame.sil.llm_hunt import _learned_invariants, build_index
    (tmp_path / "app.py").write_text(FLASK)
    sc = FrameScanner()
    sc.collect_programs = True
    results = sc.scan_directory(str(tmp_path), None, project_root=str(tmp_path))
    findings = [v for r in results for v in r.vulnerabilities]
    index = build_index(sc._hunt_programs, findings, str(tmp_path))
    ctx = HuntContext(index, sc._hunt_programs, str(tmp_path), "python", findings)
    fact = {"name": "place", "line": 9, "kind": "lower_bound", "var": "qty", "bound": 1, "verdict": "refuted"}
    hunt = [
        {"handler": "place", "file": "app.py", "hunt_class": "limits", "mechanism": "missing_limit",
         "invariant": "quantity >= 1", "engine_fact": fact},
        {"handler": "place", "file": "app.py", "hunt_class": "limits", "mechanism": "missing_limit",
         "engine_fact": dict(fact)},                                   # the same rule twice: two ids
        {"handler": "place_checked", "file": "app.py", "hunt_class": "limits", "mechanism": "missing_limit",
         "engine_fact": {**fact, "name": "place_checked", "line": 20}},  # holds there: not saved
        {"handler": "place", "file": "app.py", "hunt_class": "limits", "mechanism": "missing_limit"},
        {"handler": "place", "file": "app.py", "hunt_class": "authz", "engine_fact": fact},
    ]
    learned = _learned_invariants(ctx, hunt)
    assert [e["id"] for e in learned] == ["place-quantity-missing-limit", "place-quantity-missing-limit-2"]
    assert learned[0]["language"] == "python" and learned[0]["file"] == "app.py"
    assert learned[0]["cwe"] == "CWE-1284" and learned[0]["description"] == "quantity >= 1"
    summary = hunt_summary({"stop": "finished", "units": [], "invariants": learned})
    assert summary["invariants"] == learned
