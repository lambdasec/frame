from flask import Flask, request
app = Flask(__name__)
import os
from clean import sanitize


@app.route('/ls')
def ls():
    os.system('ls ' + sanitize(request.args.get('d', '')))
    return 'ok'
