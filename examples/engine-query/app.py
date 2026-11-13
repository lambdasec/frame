import sqlite3

from flask import Flask, abort, request
from flask_login import current_user

app = Flask(__name__)


def run_query(sql, params=()):
    return sqlite3.connect("shop.db").execute(sql, params).fetchall()


@app.route("/items")
def items():
    name = request.args.get("name", "")
    return str(run_query("SELECT * FROM items WHERE name = '" + name + "'"))


@app.route("/orders/<int:order_id>")
def order(order_id):
    if not current_user.is_admin:
        abort(403)
    return str(run_query("SELECT * FROM orders WHERE id = ?", (order_id,)))


@app.route("/orders/<int:order_id>/refund", methods=["POST"])
def refund(order_id):
    return str(run_query("UPDATE orders SET refunded = 1 WHERE id = ?", (order_id,)))
