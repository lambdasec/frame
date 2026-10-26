from flask import Flask, request
app = Flask(__name__)
from db import find_user


@app.route('/user')
def user():
    return str(find_user(request.args.get("name")))
