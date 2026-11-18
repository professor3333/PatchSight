from jinja2.exceptions import TemplateNotFound


def is_missing(error):
    return isinstance(error, TemplateNotFound)
