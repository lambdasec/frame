from flask import Flask
from flask_restful import Api
from flask_socketio import SocketIO

from resources import UserResource, ExportResource
from files import files_bp
from chat import register_chat

app = Flask(__name__)
api = Api(app)
socketio = SocketIO(app)

api.add_resource(UserResource, "/api/users/<string:username>")
api.add_resource(ExportResource, "/api/export")
app.register_blueprint(files_bp, url_prefix="/files")
register_chat(socketio)

if __name__ == "__main__":
    socketio.run(app)
