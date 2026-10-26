import subprocess

from flask_socketio import emit


def register_chat(socketio):
    @socketio.on("run")
    def handle_run(data):
        subprocess.run(["echo", data["cmd"]])
        emit("done", {"ok": True})

    @socketio.on("message")
    def handle_message(msg):
        emit("message", {"text": msg}, broadcast=True)
