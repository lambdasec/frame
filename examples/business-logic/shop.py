from flask import Flask, abort, request

from models import Order, charge, db

app = Flask(__name__)


@app.route("/cart/add", methods=["POST"])
def add_item():
    qty = int(request.form["qty"])
    order = Order.query.get(request.form["order"])
    order.quantity = qty
    db.session.commit()
    return "ok"


@app.route("/cart/set", methods=["POST"])
def set_item():
    qty = int(request.form["qty"])
    if qty < 1 or qty > 100:
        abort(400)
    order = Order.query.get(request.form["order"])
    order.quantity = qty
    db.session.commit()
    return "ok"


@app.route("/pay", methods=["POST"])
def pay():
    amount = float(request.form["amount"])
    if amount <= 0:
        abort(400)
    charge(request.form["order"], amount)
    return "ok"
