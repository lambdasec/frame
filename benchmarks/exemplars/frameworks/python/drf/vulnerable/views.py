from django.template import Context, Template
from django.http import FileResponse, HttpResponseRedirect
from rest_framework import viewsets
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.views import APIView

import reports
from models import Article


class ArticleSearchView(APIView):
    def get(self, request):
        term = request.query_params.get("q", "")
        return Response(reports.search_articles(term))


class ArticleViewSet(viewsets.ModelViewSet):
    queryset = Article.objects.all()

    def list(self, request):
        order = request.query_params.get("order")
        rows = Article.objects.extra(order_by=[order])  # frame-expect: CWE-89
        return Response(list(rows.values()))

    def retrieve(self, request, pk=None):
        rows = Article.objects.raw("SELECT * FROM articles WHERE id = " + pk)  # frame-expect: CWE-89
        return Response({"rows": [a.title for a in rows]})

    def create(self, request):
        title = request.data["title"]
        Article.objects.raw("SELECT * FROM articles WHERE title = '%s'" % title)  # frame-expect: CWE-89
        return Response(status=201)


@api_view(["GET"])
def download(request):
    path = request.query_params.get("file")
    return FileResponse(open("/srv/exports/" + path, "rb"))  # frame-expect: CWE-22


@api_view(["POST"])
def preview(request):
    tpl = Template(request.data["template"])  # frame-expect: CWE-1336
    return Response({"html": tpl.render(Context({"site": "demo"}))})


@api_view(["GET"])
def go(request):
    return HttpResponseRedirect(request.query_params.get("next"))  # frame-expect: CWE-601
