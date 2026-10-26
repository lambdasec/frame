from flask import Flask, request
import os
app = Flask(__name__)


@app.route('/u')
def u():
    return str(os.system('ls ' + request.args.get("d")))
