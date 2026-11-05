import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def user():
    name = request.args.get("name")
    db = sqlite3.connect("app.db")
    return str(db.execute("SELECT * FROM users WHERE name = '" + name + "'").fetchall())
