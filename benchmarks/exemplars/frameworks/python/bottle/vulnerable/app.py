import sqlite3

from bottle import Bottle, request, response, redirect, static_file, template, run

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
    rows = conn.execute("SELECT * FROM items WHERE name = '" + term + "'")  # frame-expect: CWE-89
    return {"rows": rows.fetchall()}


@app.route("/download/<name>")
def download(name):
    return static_file(request.query.file, root="/srv/files")  # frame-expect: CWE-22


@app.route("/hello")
def hello():
    who = request.params.get("who")
    return template("<h1>Hello " + who + "</h1>")  # frame-expect: CWE-1336


@app.route("/go")
def go():
    redirect(request.query.next)  # frame-expect: CWE-601


if __name__ == "__main__":
    run(app, host="0.0.0.0", port=8080)
