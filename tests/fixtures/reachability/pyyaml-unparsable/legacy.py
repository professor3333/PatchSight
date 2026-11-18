import yaml


def read_config(path):
    print "loading", path
    return yaml.full_load(open(path))
