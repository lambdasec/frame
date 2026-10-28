"""Link helpers for a small web app, written against Werkzeug 2."""

from werkzeug.urls import url_parse, url_quote


def host_of(url):
    return url_parse(url).host


def quoted(path):
    return url_quote(path)
