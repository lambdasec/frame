from flask import Flask, request
from jinja2 import Environment, FileSystemLoader, Template
from mako.template import Template as MakoTemplate

import mailer

app = Flask(__name__)
env = Environment(loader=FileSystemLoader("templates"))
raw_env = Environment(loader=FileSystemLoader("templates"), autoescape=True)


@app.route("/preview", methods=["POST"])
def preview():
    source = request.form["template"]
    return Template("<p>{{ source }}</p>").render(source=source)


@app.route("/card")
def card():
    tpl = env.from_string("<div>{{ title }}</div>")
    return tpl.render(title=request.args.get("title", ""))


@app.route("/report")
def report():
    body = request.args.get("body", "")
    return MakoTemplate("<h1>Report</h1>\n${body}", default_filters=["h"]).render(body=body)


@app.route("/note")
def note():
    text = request.args.get("text", "")
    return raw_env.get_template("note.html").render(text=text)


@app.route("/mail", methods=["POST"])
def mail():
    return mailer.render_body(request.json["subject_template"])
