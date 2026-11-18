import yaml


def read_config(text):
    return yaml.full_load(text)
