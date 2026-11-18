import tornado.web


class HelloHandler(tornado.web.RequestHandler):
    def get(self):
        self.write("hello")


def make_app():
    return tornado.web.Application([(r"/", HelloHandler)])
