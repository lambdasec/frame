import base64
import pickle

import jsonpickle
import yaml
from flask import Flask, request

import importer

app = Flask(__name__)


@app.route("/config", methods=["POST"])
def load_config():
    cfg = yaml.load(request.data, Loader=yaml.Loader)  # frame-expect: CWE-502
    return {"keys": list(cfg)}


@app.route("/session", methods=["POST"])
def restore_session():
    blob = base64.b64decode(request.cookies.get("state", ""))
    state = pickle.loads(blob)  # frame-expect: CWE-502
    return {"user": state.get("user")}


@app.route("/objects", methods=["POST"])
def objects():
    obj = jsonpickle.decode(request.get_data(as_text=True))  # frame-expect: CWE-502
    return {"type": type(obj).__name__}


@app.route("/import/xml", methods=["POST"])
def import_xml():
    return importer.parse_feed(request.data)


@app.route("/import/compiled", methods=["POST"])
def import_compiled():
    return {"loaded": bool(importer.load_compiled(request.data))}
