import yaml


def full_load(text):
    return yaml.safe_load(text)


def read_config(text):
    return full_load(text)
