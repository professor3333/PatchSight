from PIL import Image


def thumbnail(path, size):
    image = Image.open(path)
    image.thumbnail(size)
    return image
