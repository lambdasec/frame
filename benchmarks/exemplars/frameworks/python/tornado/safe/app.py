import html
import subprocess

import tornado.ioloop
import tornado.web

ALLOWED_NEXT = {"/home", "/profile"}


class GreetHandler(tornado.web.RequestHandler):
    def get(self):
        name = self.get_argument("name", "world")
        self.write("<h1>Hello " + html.escape(name) + "</h1>")


class PingHandler(tornado.web.RequestHandler):
    def post(self):
        host = self.get_body_argument("host")
        subprocess.run(["ping", "-c", "1", host])


class GoHandler(tornado.web.RequestHandler):
    def get(self):
        target = self.get_query_argument("next")
        self.redirect(target if target in ALLOWED_NEXT else "/home")


def make_app():
    return tornado.web.Application([
        (r"/greet", GreetHandler),
        (r"/ping", PingHandler),
        (r"/go", GoHandler),
    ])


if __name__ == "__main__":
    make_app().listen(8888)
    tornado.ioloop.IOLoop.current().start()
