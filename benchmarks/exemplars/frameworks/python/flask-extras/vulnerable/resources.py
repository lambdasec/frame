import subprocess

from flask import request
from flask_restful import Resource, reqparse

import users


class UserResource(Resource):
    def get(self, username):
        return users.lookup(username)

    def post(self, username):
        args = reqparse.RequestParser().add_argument("bio").parse_args()
        return users.update_bio(username, args["bio"])


class ExportResource(Resource):
    def get(self):
        fmt = request.args.get("format", "csv")
        subprocess.run("export-tool --format " + fmt, shell=True)  # frame-expect: CWE-78
        return {"status": "queued"}
