import git


def head_sha(path):
    return git.Repo(path).head.commit.hexsha
