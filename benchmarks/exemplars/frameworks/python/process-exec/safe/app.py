from aiohttp import web

import remote
import worker


async def convert(request):
    data = await request.post()
    code = await worker.transcode(data["input"], data["format"])
    return web.json_response({"exit": code})


async def disk(request):
    host = request.query["host"]
    return web.json_response({"out": remote.disk_usage(host, request.query.get("path", "/"))})


async def deploy(request):
    payload = await request.json()
    return web.json_response({"out": remote.deploy(payload["branch"])})


def make_app():
    app = web.Application()
    app.router.add_post("/convert", convert)
    app.router.add_get("/disk", disk)
    app.router.add_post("/deploy", deploy)
    return app
