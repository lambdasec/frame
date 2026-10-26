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
        if fmt not in ("csv", "json"):
            fmt = "csv"
        subprocess.run(["export-tool", "--format", fmt])
        return {"status": "queued"}
