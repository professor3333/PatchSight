from git.exc import GitCommandError


def failed(error):
    return isinstance(error, GitCommandError)
