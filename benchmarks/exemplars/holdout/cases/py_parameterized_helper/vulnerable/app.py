from flask import Flask, request
from services import users as user_svc

app = Flask(__name__)


@app.route('/search')
def search():
    return str(user_svc.search(request.args.get("q")))
