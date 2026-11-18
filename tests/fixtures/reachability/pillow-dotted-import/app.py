import PIL.ImageMath


def blend(a, b):
    return PIL.ImageMath.eval("(a + b) / 2", a=a, b=b)
