from flask import Flask, jsonify, request

import users

app = Flask(__name__)


@app.route("/login", methods=["POST"])
def login():
    body = request.get_json()
    user = users.authenticate(body["username"], body["password"])
    return jsonify({"ok": bool(user)})


@app.route("/users/search")
def search():
    return jsonify(users.search_by_name(request.args.get("name", "")))


@app.route("/users/filter", methods=["POST"])
def filter_users():
    return jsonify(users.filter_users(request.json))


@app.route("/stats")
def stats():
    return jsonify(users.stats_for(request.args["group"]))
