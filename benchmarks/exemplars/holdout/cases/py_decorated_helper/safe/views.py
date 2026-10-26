from flask import Flask, request
from lookup import resolve

app = Flask(__name__)


@app.route('/dns')
def dns():
    return resolve('example.com')
