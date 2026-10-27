from flask import Flask, request, jsonify

from shop.services import orders

app = Flask(__name__)


@app.route("/orders")
def list_orders():
    customer = request.args.get("customer", "")
    return jsonify(orders.for_customer(customer))


@app.route("/orders/export")
def export_orders():
    fmt = request.args.get("format", "csv")
    return orders.export(fmt)
