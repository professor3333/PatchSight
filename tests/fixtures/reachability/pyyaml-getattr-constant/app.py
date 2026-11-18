import yaml


def read_config(text):
    return getattr(yaml, "full_load")(text)
