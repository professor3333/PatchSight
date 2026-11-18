from werkzeug.security import safe_join


def resolve(base, name):
    return safe_join(base, name)
