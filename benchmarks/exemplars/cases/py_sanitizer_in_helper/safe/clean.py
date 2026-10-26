import shlex


def sanitize(name):
    return shlex.quote(name)
