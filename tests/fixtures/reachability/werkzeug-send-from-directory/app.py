from werkzeug.utils import send_from_directory


def download(environ, folder, name):
    return send_from_directory(folder, name, environ)
