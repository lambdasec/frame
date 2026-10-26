from flask import Flask, request
from jinja2 import Environment, FileSystemLoader, Template
from mako.template import Template as MakoTemplate
from markupsafe import Markup

import mailer

app = Flask(__name__)
env = Environment(loader=FileSystemLoader("templates"))
raw_env = Environment(loader=FileSystemLoader("templates"), autoescape=False)


@app.route("/preview", methods=["POST"])
def preview():
    source = request.form["template"]
    return Template(source).render(user="demo")  # frame-expect: CWE-1336


@app.route("/card")
def card():
    tpl = env.from_string("<div>" + request.args.get("title", "") + "</div>")  # frame-expect: CWE-1336
    return tpl.render()


@app.route("/report")
def report():
    body = request.args.get("body", "")
    return MakoTemplate("<h1>Report</h1>\n" + body).render()  # frame-expect: CWE-1336


@app.route("/note")
def note():
    text = request.args.get("text", "")
    return raw_env.get_template("note.html").render(text=Markup(text))  # frame-expect: CWE-79


@app.route("/mail", methods=["POST"])
def mail():
    return mailer.render_body(request.json["subject_template"])
