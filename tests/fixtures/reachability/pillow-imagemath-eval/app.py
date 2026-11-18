from PIL import ImageMath


def blend(a, b):
    return ImageMath.eval("(a + b) / 2", a=a, b=b)
