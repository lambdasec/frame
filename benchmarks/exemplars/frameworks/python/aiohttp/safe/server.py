import html
import os
from urllib.parse import urlparse

import aiohttp
from aiohttp import web

import orders


async def get_order(request):
    order_id = request.match_info["order_id"]
    row = await orders.fetch(request.app["db"], order_id)
    return web.json_response(dict(row))


async def search(request):
    status = request.query.get("status", "open")
    rows = await orders.by_status(request.app["db"], status)
    return web.json_response([dict(r) for r in rows])


async def proxy(request):
    target = request.query["url"]
    if urlparse(target).hostname not in ("api.partner.example",):
        raise web.HTTPBadRequest()
    async with aiohttp.ClientSession() as session:
        async with session.get("https://api.partner.example/v1/") as resp:
            body = await resp.text()
    return web.Response(text=body)


async def hello(request):
    data = await request.post()
    return web.Response(text="<b>" + html.escape(data["name"]) + "</b>", content_type="text/html")


async def go(request):
    raise web.HTTPFound("/")


async def download(request):
    name = request.match_info["name"]
    return web.FileResponse(os.path.join("/srv/files", os.path.basename(name)))


def make_app():
    app = web.Application()
    app.router.add_get("/orders/{order_id}", get_order)
    app.router.add_get("/orders", search)
    app.router.add_get("/proxy", proxy)
    app.router.add_post("/hello", hello)
    app.router.add_get("/go", go)
    app.router.add_get("/files/{name}", download)
    return app
