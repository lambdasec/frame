from flask import Flask, request
from helpers import *

app = Flask(__name__)


@app.route('/r')
def r():
    run_report('daily')
    return 'ok'
