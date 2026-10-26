from flask import request


def read_filters():
    return {'name': request.args.get('name'), 'page': 1}
