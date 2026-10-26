from flask import request


def requested_path():
    return request.args.get("path")
