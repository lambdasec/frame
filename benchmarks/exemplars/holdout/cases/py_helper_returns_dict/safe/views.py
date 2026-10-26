from flask import Flask, request
import sqlite3
from filters import read_filters

app = Flask(__name__)


@app.route('/u')
def u():
    f = read_filters()
    return str(sqlite3.connect('a.db').execute("SELECT * FROM u WHERE n = '%s'" % f['name']).fetchall())
