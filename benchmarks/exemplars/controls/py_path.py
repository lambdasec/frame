from flask import Flask, request
app = Flask(__name__)


@app.route('/u')
def u():
    return open(request.args.get("p")).read()
