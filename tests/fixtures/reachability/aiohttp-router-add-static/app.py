from aiohttp import web


def make_app(root):
    app = web.Application()
    app.router.add_static("/static", root, follow_symlinks=True)
    return app
