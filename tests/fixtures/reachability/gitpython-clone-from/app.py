from git import Repo


def mirror(url, path):
    return Repo.clone_from(url, path)
