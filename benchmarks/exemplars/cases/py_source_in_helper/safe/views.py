from flask import Flask, request
app = Flask(__name__)
from params import requested_path


@app.route('/file')
def file():
    return open(requested_path()).read()
