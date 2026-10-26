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
    async with aiohttp.ClientSession() as session:
        async with session.get(target) as resp:  # frame-expect: CWE-918
            body = await resp.text()
    return web.Response(text=body)


async def hello(request):
    data = await request.post()
    return web.Response(text="<b>" + data["name"] + "</b>", content_type="text/html")  # frame-expect: CWE-79


async def go(request):
    raise web.HTTPFound(request.query["next"])  # frame-expect: CWE-601


async def download(request):
    name = request.match_info["name"]
    return web.FileResponse("/srv/files/" + name)  # frame-expect: CWE-22


def make_app():
    app = web.Application()
    app.router.add_get("/orders/{order_id}", get_order)
    app.router.add_get("/orders", search)
    app.router.add_get("/proxy", proxy)
    app.router.add_post("/hello", hello)
    app.router.add_get("/go", go)
    app.router.add_get("/files/{name}", download)
    return app
