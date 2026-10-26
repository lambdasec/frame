from flask import Flask, jsonify, request

import analytics
import models
import reports

app = Flask(__name__)


@app.route("/people")
def people():
    return jsonify(models.search_people(request.args.get("name", "")))


@app.route("/people/by-city")
def by_city():
    return jsonify(models.by_city(request.args["city"]))


@app.route("/orders")
def orders():
    return jsonify(analytics.orders_for(request.args.get("customer")))


@app.route("/report")
def report():
    return jsonify(reports.monthly(request.args.get("month")))


@app.route("/audit")
def audit():
    return jsonify(reports.audit_rows(request.args.get("actor")))


@app.route("/bulk", methods=["POST"])
def bulk():
    reports.apply_script(request.get_data(as_text=True))
    return "ok"
