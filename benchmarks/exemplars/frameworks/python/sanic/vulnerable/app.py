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
    return html("<h1>Hello " + name + "</h1>")  # frame-expect: CWE-79


@app.get("/go")
async def go(request):
    return redirect(request.args.get("to"))  # frame-expect: CWE-601


@app.get("/dl")
async def dl(request):
    return await file("/srv/files/" + request.args.get("f"))  # frame-expect: CWE-22
