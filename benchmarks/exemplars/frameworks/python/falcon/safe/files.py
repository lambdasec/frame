import os

import falcon

ROOT = "/srv/uploads"


class FileResource:
    def on_get(self, req, resp, name):
        path = os.path.join(ROOT, os.path.basename(name))
        with open(path, "rb") as fh:
            resp.data = fh.read()
        resp.content_type = falcon.MEDIA_TEXT
