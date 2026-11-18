from helpers import security


def resolve(base, name):
    return security.safe_join(base, name)
