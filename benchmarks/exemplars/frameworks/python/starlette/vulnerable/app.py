from starlette.applications import Starlette
from starlette.endpoints import HTTPEndpoint
from starlette.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from starlette.routing import Route

import notes


async def homepage(request):
    name = request.query_params.get("name", "friend")
    return HTMLResponse(f"<h1>Hi {name}</h1>")  # frame-expect: CWE-79


async def leave(request):
    form = await request.form()
    return RedirectResponse(form["return_to"], status_code=303)  # frame-expect: CWE-601


async def attachment(request):
    return FileResponse("/srv/attachments/" + request.path_params["name"])  # frame-expect: CWE-22


async def note_detail(request):
    row = await notes.get_note(request.path_params["note_id"])
    return JSONResponse(dict(row))


class NoteSearch(HTTPEndpoint):
    async def get(self, request):
        term = request.query_params["q"]
        rows = await notes.search(term)
        return JSONResponse([dict(r) for r in rows])


routes = [
    Route("/", homepage),
    Route("/leave", leave, methods=["POST"]),
    Route("/files/{name}", attachment),
    Route("/notes/{note_id}", note_detail),
    Route("/search", NoteSearch),
]

app = Starlette(routes=routes)
