import pathlib


def list_images(folder):
    return sorted(pathlib.Path(folder).glob("*.png"))
