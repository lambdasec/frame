import html as htmllib
import os

from sanic import Sanic
from sanic.response import html, redirect, file, json

import store

app = Sanic("shop")


@app.get("/items/<item_id>")
async def item(request, item_id):
    return json(await store.get_item(item_id))


@app.post("/search")
async def search(request):
    term = request.json["term"]
    return json(await store.search(term))


@app.get("/hello")
async def hello(request):
    name = request.args.get("name", "world")
    return html("<h1>Hello " + htmllib.escape(name) + "</h1>")


@app.get("/go")
async def go(request):
    return redirect("/")


@app.get("/dl")
async def dl(request):
    return await file(os.path.join("/srv/files", os.path.basename(request.args.get("f"))))
