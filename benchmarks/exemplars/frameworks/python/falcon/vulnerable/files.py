import os

import falcon

ROOT = "/srv/uploads"


class FileResource:
    def on_get(self, req, resp, name):
        path = os.path.join(ROOT, name)
        with open(path, "rb") as fh:  # frame-expect: CWE-22
            resp.data = fh.read()
        resp.content_type = falcon.MEDIA_TEXT
