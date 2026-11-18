import yaml as y


def read_config(text):
    return y.load(text, Loader=y.FullLoader)
