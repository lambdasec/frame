from pyramid.httpexceptions import HTTPFound
from pyramid.response import FileResponse, Response
from pyramid.view import view_config, view_defaults

import models


@view_config(route_name="user", renderer="json")
def user_view(request):
    name = request.matchdict["name"]
    return models.find_user(request.dbsession, name)


@view_config(route_name="search", renderer="json", request_method="POST")
def search_view(request):
    term = request.json_body["term"]
    return models.search_users(request.dbsession, term)


@view_config(route_name="hello")
def hello(request):
    who = request.params.get("who", "world")
    return Response("<h1>Hello " + who + "</h1>")  # frame-expect: CWE-79


@view_config(route_name="go")
def go(request):
    return HTTPFound(location=request.GET["next"])  # frame-expect: CWE-601


@view_defaults(route_name="docs")
class DocViews:
    def __init__(self, request):
        self.request = request

    @view_config(request_method="GET")
    def get(self):
        name = self.request.params["doc"]
        return FileResponse("/srv/docs/" + name, request=self.request)  # frame-expect: CWE-22
