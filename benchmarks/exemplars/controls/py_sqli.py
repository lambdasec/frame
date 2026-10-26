from flask import Flask, request
import sqlite3
app = Flask(__name__)


@app.route('/u')
def u():
    return str(sqlite3.connect('a.db').execute("SELECT * FROM t WHERE n = '%s'" % request.args.get("n")).fetchall())
