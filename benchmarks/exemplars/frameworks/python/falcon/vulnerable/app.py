import falcon
import falcon.asgi

from notes import NoteStore
from files import FileResource

store = NoteStore("notes.db")


class NotesResource:
    def on_get(self, req, resp):
        term = req.get_param("q")
        resp.media = store.search(term)

    def on_post(self, req, resp):
        body = req.media
        store.add(body["title"], body["text"])
        resp.status = falcon.HTTP_201


class NoteResource:
    def on_get(self, req, resp, note_id):
        resp.media = store.by_id(note_id)


class GoResource:
    def on_get(self, req, resp):
        raise falcon.HTTPFound(req.get_param("to"))  # frame-expect: CWE-601


app = falcon.App()
app.add_route("/notes", NotesResource())
app.add_route("/notes/{note_id}", NoteResource())
app.add_route("/go", GoResource())
app.add_route("/files/{name}", FileResource())
