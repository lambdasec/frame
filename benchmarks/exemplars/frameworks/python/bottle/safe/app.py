import os
import sqlite3

from bottle import Bottle, request, response, redirect, static_file, template, run, abort

import repo

app = Bottle()


@app.route("/user")
def show_user():
    uid = request.query.id
    return repo.find_user(uid)


@app.post("/search")
def search():
    term = request.forms.get("q")
    conn = sqlite3.connect("app.db")
    rows = conn.execute("SELECT * FROM items WHERE name = ?", (term,))
    return {"rows": rows.fetchall()}


@app.route("/download/<name>")
def download(name):
    safe = os.path.basename(request.query.file)
    return static_file(safe, root="/srv/files")


@app.route("/hello")
def hello():
    who = request.params.get("who")
    return template("<h1>Hello {{who}}</h1>", who=who)


@app.route("/go")
def go():
    target = request.query.next
    if not target.startswith("/") or target.startswith("//"):
        abort(400)
    redirect("/" + target.lstrip("/"))


if __name__ == "__main__":
    run(app, host="127.0.0.1", port=8080)
