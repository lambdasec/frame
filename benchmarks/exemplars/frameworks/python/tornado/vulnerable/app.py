import os

import tornado.ioloop
import tornado.web


class GreetHandler(tornado.web.RequestHandler):
    def get(self):
        name = self.get_argument("name", "world")
        self.write("<h1>Hello " + name + "</h1>")  # frame-expect: CWE-79


class PingHandler(tornado.web.RequestHandler):
    def post(self):
        host = self.get_body_argument("host")
        os.system("ping -c 1 " + host)  # frame-expect: CWE-78


class GoHandler(tornado.web.RequestHandler):
    def get(self):
        self.redirect(self.get_query_argument("next"))  # frame-expect: CWE-601


def make_app():
    return tornado.web.Application([
        (r"/greet", GreetHandler),
        (r"/ping", PingHandler),
        (r"/go", GoHandler),
    ])


if __name__ == "__main__":
    make_app().listen(8888)
    tornado.ioloop.IOLoop.current().start()
