import yaml


def read_config(text):
    return yaml.safe_load(text)
