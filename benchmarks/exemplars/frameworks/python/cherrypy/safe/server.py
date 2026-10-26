import os

import cherrypy
from cherrypy.lib.static import serve_file

import db


class Root:
    @cherrypy.expose
    @cherrypy.tools.json_out()
    def user(self, uid):
        return db.get_user(uid)

    @cherrypy.expose
    def go(self, url="/"):
        raise cherrypy.HTTPRedirect("/")

    @cherrypy.expose
    def download(self, filename):
        return serve_file(os.path.join("/srv/files", os.path.basename(filename)))

    @cherrypy.expose
    def lookup(self):
        q = cherrypy.request.params.get("q")
        return db.search(q)


if __name__ == "__main__":
    cherrypy.quickstart(Root())
