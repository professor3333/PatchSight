import importlib


def read_config(text):
    yaml = importlib.import_module("yaml")
    return yaml.full_load(text)
