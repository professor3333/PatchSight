from PIL.ImageMath import eval as image_eval


def blend(a, b):
    return image_eval("(a + b) / 2", a=a, b=b)
