from django.template import Context, Template
from django.http import FileResponse, HttpResponseRedirect
from rest_framework import viewsets
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.views import APIView

import os
import re

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
        rows = Article.objects.order_by(order if order in ("title", "id") else "id")
        return Response(list(rows.values()))

    def retrieve(self, request, pk=None):
        rows = Article.objects.raw("SELECT * FROM articles WHERE id = %s", [pk])
        return Response({"rows": [a.title for a in rows]})

    def create(self, request):
        title = request.data["title"]
        Article.objects.raw("SELECT * FROM articles WHERE title = %s", [title])
        return Response(status=201)


@api_view(["GET"])
def download(request):
    path = request.query_params.get("file")
    return FileResponse(open(os.path.join("/srv/exports", os.path.basename(path)), "rb"))


@api_view(["POST"])
def preview(request):
    tpl = Template("<p>{{ site }}: {{ msg }}</p>")
    return Response({"html": tpl.render(Context({"site": "demo", "msg": request.data["template"]}))})


@api_view(["GET"])
def go(request):
    return HttpResponseRedirect("/articles/")
