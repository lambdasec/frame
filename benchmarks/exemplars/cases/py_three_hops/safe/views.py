from flask import Flask, request
app = Flask(__name__)
from service import check


@app.route('/ping')
def ping_view():
    return str(check("localhost"))
