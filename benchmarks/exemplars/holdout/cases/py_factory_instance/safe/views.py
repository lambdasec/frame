from flask import Flask, request
from repo import make_repo

app = Flask(__name__)


@app.route('/f')
def f():
    repo = make_repo()
    return str(repo.find('admin'))
