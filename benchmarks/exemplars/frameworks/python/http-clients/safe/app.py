from flask import Flask, jsonify, request

from fetcher import Fetcher
from webhooks import notify, notify_async

app = Flask(__name__)
fetcher = Fetcher()


@app.route("/preview")
def preview():
    return jsonify(fetcher.preview(request.args["url"]))


@app.route("/avatar")
def avatar():
    return fetcher.download(request.args.get("src"))


@app.route("/hook", methods=["POST"])
def hook():
    notify(request.json["callback"], {"event": "created"})
    return "ok"


@app.route("/probe")
def probe():
    return jsonify({"status": fetcher.head(request.args["host"])})


@app.route("/hook/async", methods=["POST"])
async def hook_async():
    await notify_async(request.json["callback"], {"event": "updated"})
    return "ok"
