from flask import Flask, request
app = Flask(__name__)
from repo import UserRepo

repo = UserRepo()


@app.route('/user')
def user():
    return str(repo.find(request.args.get("name")))
