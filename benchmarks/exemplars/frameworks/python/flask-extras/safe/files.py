import os

from flask import Blueprint, request, redirect, send_file, send_from_directory, render_template_string

files_bp = Blueprint("files", __name__)


@files_bp.route("/get")
def get_file():
    name = request.args.get("name")
    return send_file(os.path.join("/srv/data", os.path.basename(name)))


@files_bp.route("/static")
def static_file():
    return send_from_directory("/srv/static", request.args["path"])


@files_bp.route("/login")
def login():
    return redirect("/" + request.args.get("next", "").lstrip("/"))


@files_bp.route("/banner")
def banner():
    msg = request.args.get("msg", "")
    return render_template_string("<div class='banner'>{{ msg }}</div>", msg=msg)
