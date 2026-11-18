import yaml


def read_config(text, loader: type[yaml.FullLoader] | None = None):
    return yaml.safe_load(text)
