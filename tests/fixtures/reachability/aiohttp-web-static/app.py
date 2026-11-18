from aiohttp import web


def make_app(root):
    app = web.Application()
    app.add_routes([web.static("/static", root, follow_symlinks=True)])
    return app
