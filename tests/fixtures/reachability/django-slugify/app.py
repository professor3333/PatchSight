from django.utils.text import slugify


def url_slug(title):
    return slugify(title)
